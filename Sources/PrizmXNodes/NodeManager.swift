import Foundation
import os
import PrizmXProtocols

// MARK: - Protocol configuration

/// Concrete outbound protocol parameters bound to a node (not to a destination).
@frozen
public enum ProtocolConfig: Sendable, Hashable {
    case shadowsocks(server: Endpoint, password: String, cipher: ShadowsocksCipher)
    case vless(
        server: Endpoint,
        uuid: String,
        sni: String?,
        tls: Bool,
        reality: REALITYConfig?,
        flow: String? = nil
    )
    case trojan(server: Endpoint, password: String, sni: String?)
    case anytls(
        server: Endpoint,
        password: String,
        sni: String,
        skipCertVerify: Bool,
        session: AnyTLSSessionConfig
    )
    /// Unproxied TCP; `NodeFactory` ignores the node server and dials the target.
    case direct
}

/// A named outbound node (one Shadowsocks / VLESS / Direct configuration).
public struct OutboundNode: Sendable, Hashable, Identifiable {
    public let id: String
    public let name: String
    public let protocolConfig: ProtocolConfig

    public init(id: String, name: String, protocolConfig: ProtocolConfig) {
        self.id = id
        self.name = name
        self.protocolConfig = protocolConfig
    }
}

// MARK: - Policy group

/// A selectable set of nodes. `Router.Policy.proxy(targetGroup:)` names this group.
public struct PolicyGroup: Sendable, Hashable {
    public enum Mode: Sendable, Hashable {
        /// Use `selectedNodeID` (or the first member if unset).
        case select
        /// Lowest HTTP RTT to `testURL`, with `tolerance` hysteresis.
        case urlTest
        /// First member that last probed successfully (list order).
        case fallback
        /// Spread flows across live members (`loadBalanceStrategy`).
        case loadBalance

        public var clashType: String {
            switch self {
            case .select: "select"
            case .urlTest: "url-test"
            case .fallback: "fallback"
            case .loadBalance: "load-balance"
            }
        }
    }

    public enum LoadBalanceStrategy: Sendable, Hashable {
        case consistentHashing
        case roundRobin
    }

    public static let defaultTestURL = "http://www.gstatic.com/generate_204"

    public let name: String
    public let mode: Mode
    public let nodeIDs: [String]
    /// Initial selection for `.select` groups.
    public let selectedNodeID: String?
    /// Optional Clash `icon` URL for the group.
    public let iconURL: URL?
    /// Clash `url` — HTTP(S) endpoint probed through each member.
    public let testURL: String
    /// Clash `interval`.
    public let interval: Duration
    /// Clash `tolerance` (url-test hysteresis).
    public let tolerance: Duration
    public let loadBalanceStrategy: LoadBalanceStrategy

    public var usesHealthCheck: Bool {
        switch mode {
        case .urlTest, .fallback, .loadBalance: true
        case .select: false
        }
    }

    public init(
        name: String,
        mode: Mode,
        nodeIDs: [String],
        selectedNodeID: String? = nil,
        iconURL: URL? = nil,
        testURL: String = PolicyGroup.defaultTestURL,
        interval: Duration = .seconds(300),
        tolerance: Duration = .milliseconds(50),
        loadBalanceStrategy: LoadBalanceStrategy = .consistentHashing
    ) {
        self.name = name
        self.mode = mode
        self.nodeIDs = nodeIDs
        self.selectedNodeID = selectedNodeID
        self.iconURL = iconURL
        self.testURL = testURL.isEmpty ? PolicyGroup.defaultTestURL : testURL
        self.interval = interval
        self.tolerance = tolerance
        self.loadBalanceStrategy = loadBalanceStrategy
    }
}

// MARK: - Errors

@frozen
public enum NodeError: Error, Equatable, Sendable {
    case unknownGroup(String)
    case unknownNode(String)
    case emptyGroup(String)
    /// A `REJECT` policy was hit while resolving a group member.
    case rejected(String)
}

// MARK: - Factory

/// Builds an unopened `OutboundConnection` for a node and destination.
public enum NodeFactory: Sendable {
    public static func makeConnection(
        from node: OutboundNode,
        to target: Endpoint,
        command: VLESSCommand = .tcp
    ) throws -> any OutboundConnection {
        switch node.protocolConfig {
        case .shadowsocks(let server, let password, let cipher):
            return ShadowsocksOutboundConnection(
                server: server,
                password: password,
                cipher: cipher,
                target: target
            )
        case .vless(let server, let uuid, let sni, let tls, let reality, let flow):
            return try VLESSOutboundConnection(
                server: server,
                uuid: uuid,
                target: target,
                sni: sni,
                tls: tls,
                reality: reality,
                flow: flow,
                command: command
            )
        case .trojan(let server, let password, let sni):
            return TrojanOutboundConnection(
                server: server,
                password: password,
                target: target,
                sni: sni,
                command: command == .udp ? .udpAssociate : .connect
            )
        case .anytls(let server, let password, let sni, let skipCertVerify, let session):
            return AnyTLSOutboundConnection(
                server: server,
                password: password,
                target: target,
                sni: sni,
                skipCertVerify: skipCertVerify,
                sessionConfig: session
            )
        case .direct:
            return DirectOutboundConnection(endpoint: target)
        }
    }
}

// MARK: - Manager

/// Registry of outbound nodes and policy groups.
///
/// Group selection (manual `select` / `urlTest` winner) is stored separately
/// so the catalog itself stays immutable and `Sendable`.
public final class NodeManager: Sendable {

    public let nodesByID: [String: OutboundNode]
    public let groupsByName: [String: PolicyGroup]

    private struct GroupRuntime: Sendable {
        var selectedNodeID: String?
        var latencies: [String: Duration]
        var rrIndex: UInt64 = 0
    }

    private let runtime: OSAllocatedUnfairLock<[String: GroupRuntime]>

    public init(nodes: [OutboundNode], groups: [PolicyGroup]) {
        var nodesByID: [String: OutboundNode] = [:]
        for node in nodes {
            nodesByID[node.id] = node
        }
        var groupsByName: [String: PolicyGroup] = [:]
        var runtime: [String: GroupRuntime] = [:]
        for group in groups {
            groupsByName[group.name] = group
            runtime[group.name] = GroupRuntime(
                selectedNodeID: group.selectedNodeID,
                latencies: [:],
                rrIndex: 0
            )
        }
        self.nodesByID = nodesByID
        self.groupsByName = groupsByName
        self.runtime = OSAllocatedUnfairLock(initialState: runtime)
    }

    public func node(id: String) -> OutboundNode? {
        nodesByID[id]
    }

    public func group(named name: String) -> PolicyGroup? {
        groupsByName[name]
    }

    /// Resolved leaf of a policy group after walking nested `select` members.
    public enum LeafPolicy: Sendable, Equatable {
        case node(OutboundNode)
        case direct
        case reject
    }

    /// Currently chosen **leaf** node in `groupName` (select / urlTest).
    /// Nested groups (e.g. Google → Proxies → HK01) are walked; DIRECT/REJECT
    /// members yield `nil`.
    public func selectedNode(inGroup groupName: String) -> OutboundNode? {
        if case .node(let node) = selectedLeaf(inGroup: groupName) { return node }
        return nil
    }

    /// Like `selectedNode`, but preserves built-in DIRECT / REJECT leaves.
    public func selectedLeaf(inGroup groupName: String) -> LeafPolicy? {
        var visited = Set<String>()
        return resolveLeaf(name: groupName, visited: &visited)
    }

    private func resolveLeaf(name: String, visited: inout Set<String>) -> LeafPolicy? {
        switch name.uppercased() {
        case "DIRECT":
            return .direct
        case "REJECT", "REJECT-DROP":
            return .reject
        default:
            break
        }
        if let node = nodesByID[name] { return .node(node) }
        guard let group = groupsByName[name] else { return nil }
        guard visited.insert(name).inserted else { return nil }
        guard let next = pickNodeID(in: group, target: Endpoint(domain: group.name, port: 0), advance: false) else { return nil }
        return resolveLeaf(name: next, visited: &visited)
    }

    public func select(nodeID: String, inGroup groupName: String) throws {
        guard let group = groupsByName[groupName] else {
            throw NodeError.unknownGroup(groupName)
        }
        guard group.nodeIDs.contains(nodeID) else {
            throw NodeError.unknownNode(nodeID)
        }
        runtime.withLock { state in
            state[groupName, default: GroupRuntime(selectedNodeID: nil, latencies: [:], rrIndex: 0)]
                .selectedNodeID = nodeID
        }
    }

    /// Overlay persisted Policies selections (nested groups and DIRECT allowed).
    public func applySelections(_ map: [String: String]) {
        for (groupName, member) in map {
            try? select(nodeID: member, inGroup: groupName)
        }
    }

    /// Currently chosen member id (node, nested group, or DIRECT) in `groupName`.
    /// Display-only: never advances load-balance state.
    public func selectedMemberID(inGroup groupName: String) -> String? {
        guard let group = groupsByName[groupName] else { return nil }
        return pickNodeID(in: group, target: Endpoint(domain: group.name, port: 0), advance: false)
    }

    /// Records a probe RTT used by `.urlTest` groups.
    public func recordLatency(_ latency: Duration, nodeID: String, inGroup groupName: String) {
        runtime.withLock { state in
            state[groupName, default: GroupRuntime(selectedNodeID: nil, latencies: [:], rrIndex: 0)]
                .latencies[nodeID] = latency
        }
    }

    public func clearLatency(nodeID: String, inGroup groupName: String) {
        runtime.withLock { state in
            state[groupName]?.latencies[nodeID] = nil
        }
    }

    /// Builds an unopened connection to `target` through the group's selected node.
    /// Members may be nodes, built-in policies (`DIRECT` / `REJECT`), or other
    /// policy groups (nested like Clash).
    public func connection(
        forGroup groupName: String,
        target: Endpoint,
        command: VLESSCommand = .tcp
    ) throws -> any OutboundConnection {
        try resolveConnection(name: groupName, target: target, command: command, visited: [])
    }

    private func resolveConnection(
        name: String,
        target: Endpoint,
        command: VLESSCommand,
        visited: Set<String>
    ) throws -> any OutboundConnection {
        switch name.uppercased() {
        case "DIRECT":
            return DirectOutboundConnection(endpoint: target)
        case "REJECT", "REJECT-DROP":
            throw NodeError.rejected(name)
        default:
            break
        }
        if let node = nodesByID[name] {
            return try NodeFactory.makeConnection(from: node, to: target, command: command)
        }
        guard let group = groupsByName[name] else {
            throw NodeError.unknownGroup(name)
        }
        guard !visited.contains(name) else {
            throw NodeError.emptyGroup(name)
        }
        let members = orderedMembers(in: group, target: target)
        guard !members.isEmpty else {
            throw NodeError.emptyGroup(name)
        }
        let nextVisited = visited.union([name])
        // Clash `select` is sticky (no per-flow failover). url-test / fallback
        // / load-balance still wrap extra members so a dead dial can retry.
        let makers: [(String, () throws -> any OutboundConnection)] = members.map { member in
            (member, { [self] in
                try resolveConnection(name: member, target: target, command: command, visited: nextVisited)
            })
        }
        return FailoverGroupConnection(target: target, groupName: name, makers: makers)
    }

    /// Selected / first member first, then other members with a **distinct**
    /// server:port (display-only aliases that clone the same endpoint are skipped).
    private func orderedMembers(in group: PolicyGroup, target: Endpoint) -> [String] {
        guard let picked = pickNodeID(in: group, target: target) else { return [] }
        if group.mode == .select { return [picked] }
        var seen: Set<String> = []
        var result: [String] = []
        for id in [picked] + group.nodeIDs.filter({ $0 != picked }) {
            let key: String
            if let node = nodesByID[id], let endpoint = node.probeEndpoint {
                key = endpoint.description
            } else {
                key = "name:\(id)"
            }
            if seen.contains(key) { continue }
            seen.insert(key)
            result.append(id)
            if result.count >= 8 { break }
        }
        return result
    }

    public func healthCheckGroups() -> [PolicyGroup] {
        groupsByName.values.filter(\.usesHealthCheck).sorted { $0.name < $1.name }
    }

    /// Probe jobs keyed by `(nodeID, testURL)` so two groups sharing a node
    /// and URL only dial once.
    func urlTestProbeTargets(
        groupNames: Set<String>? = nil
    ) -> [(nodeID: String, url: URL, members: [(group: String, nodeID: String)])] {
        var order: [String] = []
        var byKey: [String: (nodeID: String, url: URL, members: [(group: String, nodeID: String)])] = [:]
        for group in healthCheckGroups() {
            if let groupNames, !groupNames.contains(group.name) { continue }
            guard let url = URL(string: group.testURL), url.host != nil else { continue }
            for nodeID in group.nodeIDs {
                guard nodesByID[nodeID] != nil else { continue }
                let key = "\(nodeID)|\(group.testURL)"
                if byKey[key] == nil {
                    order.append(key)
                    byKey[key] = (nodeID: nodeID, url: url, members: [])
                }
                byKey[key]?.members.append((group.name, nodeID))
            }
        }
        return order.compactMap { byKey[$0] }
    }

    /// HTTP(S) url-test through each member (Clash `url` / `interval`).
    public func probeURLTestGroups(
        groupNames: Set<String>? = nil,
        maxConcurrent: Int = 6
    ) async {
        let targets = urlTestProbeTargets(groupNames: groupNames)
        guard !targets.isEmpty else { return }

        await withTaskGroup(of: (Int, Duration?).self) { group in
            var next = 0
            var inFlight = 0
            func enqueue() {
                while inFlight < maxConcurrent, !Task.isCancelled, next < targets.count {
                    let index = next
                    next += 1
                    inFlight += 1
                    group.addTask {
                        guard let node = self.nodesByID[targets[index].nodeID] else {
                            return (index, nil)
                        }
                        let latency = await URLTestProber.probe(node: node, url: targets[index].url)
                        return (index, latency)
                    }
                }
            }
            enqueue()
            for await (index, latency) in group {
                inFlight -= 1
                for member in targets[index].members {
                    if let latency {
                        recordLatency(latency, nodeID: member.nodeID, inGroup: member.group)
                    } else {
                        clearLatency(nodeID: member.nodeID, inGroup: member.group)
                    }
                }
                enqueue()
            }
        }
    }

    private func pickNodeID(in group: PolicyGroup, target: Endpoint, advance: Bool = true) -> String? {
        let snapshot = runtime.withLock { $0[group.name] }
        switch group.mode {
        case .select:
            if let selected = snapshot?.selectedNodeID, group.nodeIDs.contains(selected) {
                return selected
            }
            return group.nodeIDs.first
        case .urlTest:
            return pickURLTest(group: group, snapshot: snapshot)
        case .fallback:
            let latencies = snapshot?.latencies ?? [:]
            return group.nodeIDs.first { latencies[$0] != nil } ?? group.nodeIDs.first
        case .loadBalance:
            return pickLoadBalance(group: group, snapshot: snapshot, target: target, advance: advance)
        }
    }

    private func pickURLTest(group: PolicyGroup, snapshot: GroupRuntime?) -> String? {
        let latencies = snapshot?.latencies ?? [:]
        let ranked = group.nodeIDs.compactMap { id -> (String, Duration)? in
            guard let latency = latencies[id] else { return nil }
            return (id, latency)
        }
        guard let best = ranked.min(by: { $0.1 < $1.1 }) else {
            return group.nodeIDs.first
        }
        if let current = snapshot?.selectedNodeID,
           group.nodeIDs.contains(current),
           let currentRTT = latencies[current],
           currentRTT <= best.1 + group.tolerance {
            return current
        }
        runtime.withLock { $0[group.name]?.selectedNodeID = best.0 }
        return best.0
    }

    private func pickLoadBalance(
        group: PolicyGroup,
        snapshot: GroupRuntime?,
        target: Endpoint,
        advance: Bool
    ) -> String? {
        let latencies = snapshot?.latencies ?? [:]
        let alive = group.nodeIDs.filter { latencies[$0] != nil }
        let pool = alive.isEmpty ? group.nodeIDs : alive
        guard !pool.isEmpty else { return nil }
        switch group.loadBalanceStrategy {
        case .roundRobin:
            let index = runtime.withLock { state -> Int in
                let current = state[group.name] ?? GroupRuntime(
                    selectedNodeID: nil,
                    latencies: [:],
                    rrIndex: 0
                )
                let slot = Int(current.rrIndex % UInt64(pool.count))
                if advance {
                    var next = current
                    next.rrIndex += 1
                    state[group.name] = next
                }
                return slot
            }
            return pool[index]
        case .consistentHashing:
            // Display calls pass the group name as `target`; show the first
            // live member instead of hashing a placeholder.
            guard advance else { return pool.first }
            let hash = Self.fnv(target.host.description)
            return pool[Int(hash % UInt64(pool.count))]
        }
    }

    private static func fnv(_ string: String) -> UInt64 {
        var hash: UInt64 = 14695981039346656037
        for byte in string.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 1099511628211
        }
        return hash
    }
}

extension OutboundNode {
    /// Server used for url-test TCP probes. `direct` nodes are skipped.
    public var probeEndpoint: Endpoint? {
        switch protocolConfig {
        case .shadowsocks(let server, _, _):
            return server
        case .vless(let server, _, _, _, _, _):
            return server
        case .trojan(let server, _, _):
            return server
        case .anytls(let server, _, _, _, _):
            return server
        case .direct:
            return nil
        }
    }
}
