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

    private let probeTask = OSAllocatedUnfairLock<Task<Void, Never>?>(initialState: nil)

    public init(
        router: Router,
        nodeManager: NodeManager,
        dns: DNSClient = DNSClient(settings: .bootstrap(physicalIPs: [])),
        traffic: TrafficCounter = TrafficCounter()
    ) {
        self.router = router
        self.nodeManager = nodeManager
        self.dns = dns
        self.traffic = traffic
    }

    /// Matches `target` and returns the corresponding outbound connection.
    public func dispatch(target: Endpoint, command: VLESSCommand = .tcp) throws -> any OutboundConnection {
        switch router.match(endpoint: target) {
        case .direct:
            return DirectOutboundConnection(endpoint: target, role: .direct)
        case .reject:
            TunnelLog.write(.info, "reject \(target)")
            throw EngineError.rejected(target)
        case .proxy(let group):
            do {
                return try nodeManager.connection(forGroup: group, target: target, command: command)
            } catch {
                TunnelLog.write(.error, "dispatch \(target) group=\(group) failed: \(error.localizedDescription)")
                throw error
            }
        }
    }

    /// FakeDNS-time policy: nested `select` groups that resolve to DIRECT
    /// (or REJECT) must not receive a FakeIP, so the packet never enters TUN.
    public func dnsPolicy(host: String) -> Policy {
        switch router.match(host: host, port: 443) {
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

    /// TCP-connects each `urlTest` member and records RTT. Call from the tunnel
    /// after start; `stopURLTest` cancels the loop.
    public func startURLTest(interval: Duration = .seconds(30)) {
        stopURLTest()
        let manager = nodeManager
        let dns = self.dns
        let task = Task {
            await DNSClient.$current.withValue(dns) {
                while !Task.isCancelled {
                    await manager.probeURLTestGroups()
                    try? await Task.sleep(for: interval)
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
