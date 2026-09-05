import Foundation
import os
import PrizmXProtocols

// MARK: - Protocol configuration

/// Concrete outbound protocol parameters bound to a node (not to a destination).
@frozen
public enum ProtocolConfig: Sendable, Hashable {
    case shadowsocks(server: Endpoint, password: String, cipher: ShadowsocksCipher)
    case vless(server: Endpoint, uuid: String, sni: String?, tls: Bool, reality: REALITYConfig?)
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
        /// Use the member with the lowest recorded latency; falls back to the first member.
        case urlTest
    }

    public let name: String
    public let mode: Mode
    public let nodeIDs: [String]
    /// Initial selection for `.select` groups.
    public let selectedNodeID: String?
    /// Optional Clash `icon` URL for the group.
    public let iconURL: URL?

    public init(
        name: String,
        mode: Mode,
        nodeIDs: [String],
        selectedNodeID: String? = nil,
        iconURL: URL? = nil
    ) {
        self.name = name
        self.mode = mode
        self.nodeIDs = nodeIDs
        self.selectedNodeID = selectedNodeID
        self.iconURL = iconURL
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
        case .vless(let server, let uuid, let sni, let tls, let reality):
            return try VLESSOutboundConnection(
                server: server,
                uuid: uuid,
                target: target,
                sni: sni,
                tls: tls,
                reality: reality,
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
                latencies: [:]
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
        guard let next = pickNodeID(in: group) else { return nil }
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
            state[groupName, default: GroupRuntime(selectedNodeID: nil, latencies: [:])]
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
    public func selectedMemberID(inGroup groupName: String) -> String? {
        guard let group = groupsByName[groupName] else { return nil }
        return pickNodeID(in: group)
    }

    /// Records a probe RTT used by `.urlTest` groups.
    public func recordLatency(_ latency: Duration, nodeID: String, inGroup groupName: String) {
        runtime.withLock { state in
            state[groupName, default: GroupRuntime(selectedNodeID: nil, latencies: [:])]
                .latencies[nodeID] = latency
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
        let members = orderedMembers(in: group)
        guard !members.isEmpty else {
            throw NodeError.emptyGroup(name)
        }
        let nextVisited = visited.union([name])
        // Every group (even single-member) is wrapped so the routing label
        // stays the policy name for per-policy traffic ranking. Clash
        // `select` groups stay sticky; failover only retries on open failure.
        let makers: [(String, () throws -> any OutboundConnection)] = members.map { member in
            (member, { [self] in
                try resolveConnection(name: member, target: target, command: command, visited: nextVisited)
            })
        }
        return FailoverGroupConnection(target: target, groupName: name, makers: makers)
    }

    /// Selected / first member first, then other members with a **distinct**
    /// server:port (display-only aliases that clone the same endpoint are skipped).
    private func orderedMembers(in group: PolicyGroup) -> [String] {
        guard let picked = pickNodeID(in: group) else { return [] }
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

    /// url-test probe targets deduplicated by server: a large catalog is
    /// usually a handful of hosts, so each server is probed once and the
    /// result attributed to every node/group sharing it.
    func urlTestProbeTargets() -> [(endpoint: Endpoint, members: [(group: String, nodeID: String)])] {
        var order: [String] = []
        var byServer: [String: (endpoint: Endpoint, members: [(group: String, nodeID: String)])] = [:]
        for group in groupsByName.values where group.mode == .urlTest {
            for nodeID in group.nodeIDs {
                guard let node = nodesByID[nodeID], let endpoint = node.probeEndpoint else {
                    continue
                }
                let key = endpoint.description
                if byServer[key] == nil {
                    order.append(key)
                    byServer[key] = (endpoint: endpoint, members: [])
                }
                byServer[key]?.members.append((group.name, nodeID))
            }
        }
        return order.compactMap { byServer[$0] }
    }

    /// TCP-connects each url-test server once (bounded fan-out) and records
    /// the RTT for every node sharing that server.
    public func probeURLTestGroups(maxConcurrent: Int = 6) async {
        let targets = urlTestProbeTargets()
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
                        let connection = DirectOutboundConnection(
                            endpoint: targets[index].endpoint,
                            role: .proxyServer
                        )
                        let start = ContinuousClock.now
                        do {
                            try await connection.open()
                            let latency = ContinuousClock.now - start
                            await connection.close()
                            return (index, latency)
                        } catch {
                            await connection.close()
                            return (index, nil)
                        }
                    }
                }
            }
            enqueue()
            for await (index, latency) in group {
                inFlight -= 1
                if let latency {
                    for member in targets[index].members {
                        recordLatency(latency, nodeID: member.nodeID, inGroup: member.group)
                    }
                }
                enqueue()
            }
        }
    }

    private func pickNodeID(in group: PolicyGroup) -> String? {
        let snapshot = runtime.withLock { $0[group.name] }
        switch group.mode {
        case .select:
            if let selected = snapshot?.selectedNodeID, group.nodeIDs.contains(selected) {
                return selected
            }
            return group.nodeIDs.first
        case .urlTest:
            let latencies = snapshot?.latencies ?? [:]
            let ranked = group.nodeIDs.compactMap { id -> (String, Duration)? in
                guard let latency = latencies[id] else { return nil }
                return (id, latency)
            }
            if let best = ranked.min(by: { $0.1 < $1.1 }) {
                return best.0
            }
            return group.nodeIDs.first
        }
    }
}

extension OutboundNode {
    /// Server used for url-test TCP probes. `direct` nodes are skipped.
    public var probeEndpoint: Endpoint? {
        switch protocolConfig {
        case .shadowsocks(let server, _, _):
            return server
        case .vless(let server, _, _, _, _):
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
