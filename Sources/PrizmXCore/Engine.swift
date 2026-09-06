import Foundation
import os
import PrizmXNodes
import PrizmXProtocols
import PrizmXRules

/// Errors raised by `Engine.dispatch`.
@frozen
public enum EngineError: Error, Equatable, Sendable {
    /// Router policy was `.reject`.
    case rejected(Endpoint)
}

/// Top-level dispatcher: `Router` decides the policy, `NodeManager` materializes
/// the outbound connection. Connections are returned **unopened**; the caller
/// invokes `open()` when it is ready to talk to the network.
public final class Engine: Sendable {
    public let router: Router
    public let nodeManager: NodeManager
    public let dns: DNSClient
    public let traffic: TrafficCounter

    private struct Runtime: Sendable {
        var mode: OutboundMode
        var globalGroup: String?
    }

    private let runtime: OSAllocatedUnfairLock<Runtime>
    private let probeTask = OSAllocatedUnfairLock<Task<Void, Never>?>(initialState: nil)

    public init(
        router: Router,
        nodeManager: NodeManager,
        dns: DNSClient = DNSClient(settings: .bootstrap(physicalIPs: [])),
        traffic: TrafficCounter = TrafficCounter(),
        outboundMode: OutboundMode = .rule,
        globalGroup: String? = nil
    ) {
        self.router = router
        self.nodeManager = nodeManager
        self.dns = dns
        self.traffic = traffic
        self.runtime = OSAllocatedUnfairLock(
            initialState: Runtime(
                mode: outboundMode,
                globalGroup: globalGroup ?? Self.inferredGlobalGroup(in: nodeManager)
            )
        )
    }

    public var outboundMode: OutboundMode {
        runtime.withLock { $0.mode }
    }

    /// Clash/Surge Rule · Global · Direct. `globalGroup` is the policy the
    /// Global switch pins to (selected node / GLOBAL / first real group).
    public func setOutboundMode(_ mode: OutboundMode, globalGroup: String? = nil) {
        runtime.withLock { state in
            state.mode = mode
            if let globalGroup, !globalGroup.isEmpty {
                state.globalGroup = globalGroup
            }
        }
        TunnelLog.write(.info, "outbound mode \(mode.rawValue) group=\(globalGroup ?? "-")")
    }

    public func applyGlobalGroup(_ group: String) {
        runtime.withLock { $0.globalGroup = group }
    }

    /// Effective policy after the outbound-mode overlay.
    public func policy(
        for endpoint: Endpoint,
        resolvedIPv4: IPv4Address? = nil,
        resolvedIPv6: IPv6Address? = nil
    ) -> Policy {
        matchTarget(endpoint, resolvedIPv4: resolvedIPv4, resolvedIPv6: resolvedIPv6).policy
    }

    public func matchTarget(
        _ endpoint: Endpoint,
        resolvedIPv4: IPv4Address? = nil,
        resolvedIPv6: IPv6Address? = nil
    ) -> (policy: Policy, rule: String) {
        let state = runtime.withLock { $0 }
        switch state.mode {
        case .direct:
            return (.direct, "MODE,DIRECT")
        case .global:
            let group = state.globalGroup ?? Self.inferredGlobalGroup(in: nodeManager)
            guard let group else { return (.direct, "MODE,DIRECT") }
            return (.proxy(targetGroup: group), "MODE,GLOBAL")
        case .rule:
            let result = router.matchResult(
                endpoint: endpoint,
                resolvedIPv4: resolvedIPv4,
                resolvedIPv6: resolvedIPv6
            )
            return (result.policy, result.rule?.inspectorLabel ?? "FINAL")
        }
    }

    public func resolveIPv4(for endpoint: Endpoint) async -> IPv4Address? {
        switch endpoint.host {
        case .ipv4(let address):
            return address
        case .domain(let domain):
            guard router.needsIPResolution else { return nil }
            return try? await dns.resolve(domain, role: .direct)
        case .ipv6:
            return nil
        }
    }

    /// Matches `target` and returns the corresponding outbound connection.
    public func dispatch(target: Endpoint, command: VLESSCommand = .tcp) throws -> any OutboundConnection {
        try dispatchDetailed(target: target, command: command).connection
    }

    public func dispatchDetailed(
        target: Endpoint,
        command: VLESSCommand = .tcp,
        resolvedIPv4: IPv4Address? = nil,
        resolvedIPv6: IPv6Address? = nil
    ) throws -> (connection: any OutboundConnection, rule: String) {
        let matched = matchTarget(target, resolvedIPv4: resolvedIPv4, resolvedIPv6: resolvedIPv6)
        switch matched.policy {
        case .direct:
            return (DirectOutboundConnection(endpoint: target, role: .direct), matched.rule)
        case .reject:
            TunnelLog.write(.info, "reject \(target)")
            throw EngineError.rejected(target)
        case .proxy(let group):
            do {
                let connection = try nodeManager.connection(forGroup: group, target: target, command: command)
                return (connection, matched.rule)
            } catch {
                TunnelLog.write(.error, "dispatch \(target) group=\(group) failed: \(error.localizedDescription)")
                throw error
            }
        }
    }

    /// FakeDNS-time policy: nested `select` groups that resolve to DIRECT
    /// (or REJECT) must not receive a FakeIP, so the packet never enters TUN.
    public func dnsPolicy(host: String) async -> Policy {
        let endpoint = Endpoint(domain: host, port: 443)
        let ipv4 = await resolveIPv4(for: endpoint)
        switch matchTarget(endpoint, resolvedIPv4: ipv4).policy {
        case .direct:
            return .direct
        case .reject:
            return .reject
        case .proxy(let group):
            switch nodeManager.selectedLeaf(inGroup: group) {
            case .direct:
                return .direct
            case .reject:
                return .reject
            default:
                return .proxy(targetGroup: group)
            }
        }
    }

    /// Prefer `GLOBAL`, then a multi-member group that is not a per-node alias.
    public static func inferredGlobalGroup(in manager: NodeManager) -> String? {
        if manager.group(named: "GLOBAL") != nil { return "GLOBAL" }
        let implicit = Set(manager.nodesByID.keys)
        if let named = manager.groupsByName.keys.sorted().first(where: { !implicit.contains($0) }) {
            return named
        }
        return manager.groupsByName.keys.sorted().first
    }

    /// Probes url-test / fallback / load-balance groups on each group's
    /// Clash `interval`. Call from the tunnel after start; `stopURLTest`
    /// cancels the loop.
    public func startURLTest() {
        stopURLTest()
        let manager = nodeManager
        let dns = self.dns
        let task = Task {
            await DNSClient.$current.withValue(dns) {
                var nextDue: [String: ContinuousClock.Instant] = [:]
                let start = ContinuousClock.now
                for group in manager.healthCheckGroups() {
                    nextDue[group.name] = start
                }
                while !Task.isCancelled {
                    let now = ContinuousClock.now
                    var due: Set<String> = []
                    var sleepFor: Duration = .seconds(300)
                    for group in manager.healthCheckGroups() {
                        let deadline = nextDue[group.name] ?? now
                        if deadline <= now {
                            due.insert(group.name)
                            nextDue[group.name] = now + group.interval
                        } else {
                            let remaining = deadline - now
                            if remaining < sleepFor { sleepFor = remaining }
                        }
                    }
                    if !due.isEmpty {
                        await manager.probeURLTestGroups(groupNames: due)
                    }
                    let wait = sleepFor < .milliseconds(200) ? Duration.milliseconds(200) : sleepFor
                    try? await Task.sleep(for: wait)
                }
            }
        }
        probeTask.withLock { $0 = task }
    }

    public func stopURLTest() {
        probeTask.withLock { task in
            task?.cancel()
            task = nil
        }
    }
}
