import Foundation
import Network
import Dispatch
import os
import PrizmXCore
import PrizmXNodes
import PrizmXProtocols
import PrizmXRules
import SwiftTCP

private typealias IPv4Address = PrizmXProtocols.IPv4Address

/// Consumes `TUNStack.udpDatagrams()` and forwards DIRECT or through the
/// node's `DatagramOutbound` (SS / VLESS / Trojan UDP).
///
/// The ingest loop never waits on the network: each flow gets its own worker
/// with a small bounded inbox, and policy lookup / DNS / outbound `open()` /
/// sends run there. A slow or dead destination only delays its own flow.
public enum TUNUDPRelay: Sendable {
    public static func run(stack: TUNStack, engine: Engine) async {
        let state = UDPRelayState(stack: stack, engine: engine)
        await stack.setUDPSessionClosedHandler { flow in
            Task { await state.stackClosed(flow) }
        }
        for await datagram in await stack.udpDatagrams() {
            await state.ingest(datagram)
        }
        await stack.setUDPSessionClosedHandler(nil)
        await state.stop()
    }
}

private actor UDPRelayState {
    private let stack: TUNStack
    private let engine: Engine
    private var slots: [UDPFlowKey: FlowSlot] = [:]
    private var keysByFlow: [FlowKey: UDPFlowKey] = [:]

    /// One relayed UDP flow: inbox feeding its worker, plus the session once
    /// the worker has opened it.
    private final class FlowSlot: @unchecked Sendable {
        let id = UUID()
        let flow: FlowKey
        let inbox: AsyncStream<TUNUDPDatagram>.Continuation
        let activity = ActivityStamp()
        var worker: Task<Void, Never>?
        var session: (any UDPSession)?

        /// Latest uplink (ingest) or downlink (session) activity.
        var lastSeen: ContinuousClock.Instant {
            max(activity.value, session?.lastActivity ?? activity.value)
        }

        init(flow: FlowKey, inbox: AsyncStream<TUNUDPDatagram>.Continuation) {
            self.flow = flow
            self.inbox = inbox
        }
    }

    init(stack: TUNStack, engine: Engine) {
        self.stack = stack
        self.engine = engine
    }

    func ingest(_ datagram: TUNUDPDatagram) {
        guard case .ipv4(let clientIP) = datagram.source.host else { return }
        // Keyed by the full 4-tuple (destination host included): FakeIP gives
        // each domain its own address, so this uniquely identifies the target
        // and prevents same-port multi-destination (QUIC/443) misdelivery.
        let key = UDPFlowKey(
            client: clientIP,
            clientPort: datagram.source.port,
            destinationHost: datagram.destination.host.description,
            destinationPort: datagram.destination.port
        )
        if let slot = slots[key] {
            slot.activity.touch()
            slot.inbox.yield(datagram)
            return
        }
        if slots.count >= MemoryWatchdog.maxUDPSessions {
            // Evict the least-recently-active flow instead of dropping all
            // new UDP traffic; SwiftTCP drops its side too.
            if let victim = slots.min(by: { $0.value.lastSeen < $1.value.lastSeen }) {
                let flow = victim.value.flow
                finish(victim.key, id: victim.value.id)
                let stack = self.stack
                Task { await stack.closeUDPSession(flow: flow) }
            }
        }
        let (stream, inbox) = AsyncStream.makeStream(
            of: TUNUDPDatagram.self,
            bufferingPolicy: .bufferingNewest(MemoryWatchdog.udpSessionBuffer)
        )
        let slot = FlowSlot(flow: datagram.flow, inbox: inbox)
        slots[key] = slot
        keysByFlow[datagram.flow] = key
        inbox.yield(datagram)
        let stack = self.stack
        let engine = self.engine
        slot.worker = Task {
            await Self.work(
                state: self, key: key, id: slot.id, first: datagram,
                inbox: stream, stack: stack, engine: engine
            )
        }
    }

    /// Per-flow worker: open the session, then send queued datagrams in
    /// order until the inbox is finished (evicted / closed / peer gone).
    private static func work(
        state: UDPRelayState,
        key: UDPFlowKey,
        id: UUID,
        first: TUNUDPDatagram,
        inbox: AsyncStream<TUNUDPDatagram>,
        stack: TUNStack,
        engine: Engine
    ) async {
        let opener = UDPSessionOpener(stack: stack, engine: engine, key: key, datagram: first)
        guard let session = await opener.open() else {
            await state.finish(key, id: id)
            return
        }
        guard await state.attach(session, key: key, id: id) else {
            await session.close()
            return
        }
        let pump = Task {
            await session.pump()
            await state.finish(key, id: id)
        }
        for await datagram in inbox {
            await session.send(datagram.payload, destination: datagram.destination)
            let domain: String?
            if case .domain(let name) = datagram.destination.host {
                domain = name
            } else {
                domain = nil
            }
            engine.traffic.addBytes(
                up: UInt64(datagram.payload.count),
                down: 0,
                route: session.route,
                app: session.attribution,
                transport: .udp,
                domain: domain
            )
        }
        pump.cancel()
        await session.close()
    }

    private func attach(_ session: any UDPSession, key: UDPFlowKey, id: UUID) -> Bool {
        guard let slot = slots[key], slot.id == id else { return false }
        slot.session = session
        engine.traffic.udpDidOpen()
        return true
    }

    /// Removes the flow; its worker drains out and closes the session.
    private func finish(_ key: UDPFlowKey, id: UUID) {
        guard let slot = slots[key], slot.id == id else { return }
        slots.removeValue(forKey: key)
        if keysByFlow[slot.flow] == key { keysByFlow.removeValue(forKey: slot.flow) }
        slot.inbox.finish()
        if slot.session != nil {
            engine.traffic.udpDidClose()
        }
    }

    /// SwiftTCP dropped the session (idle expiry, its own LRU, shutdown).
    func stackClosed(_ flow: FlowKey) {
        guard let key = keysByFlow[flow], let slot = slots[key] else { return }
        finish(key, id: slot.id)
    }

    func stop() async {
        let all = slots
        slots.removeAll()
        keysByFlow.removeAll()
        for slot in all.values {
            slot.inbox.finish()
            slot.worker?.cancel()
            if let session = slot.session {
                await session.close()
                engine.traffic.udpDidClose()
            }
        }
    }
}

/// Policy + outbound setup for one new UDP flow (runs on the flow's worker).
private struct UDPSessionOpener: Sendable {
    let stack: TUNStack
    let engine: Engine
    let key: UDPFlowKey
    let datagram: TUNUDPDatagram

    func open() async -> (any UDPSession)? {
        switch await engine.resolvePolicy(for: datagram.destination) {
        case .reject:
            await dropUDP(onceKey: "udp-reject", reason: "UDP dropped: reject")
            return nil
        case .direct:
            return await openDirect(route: FlowRoute([FlowRoute.direct]))
        case .proxy(let group):
            return await openProxy(group: group)
        }
    }

    private func attribution() -> FlowAttribution? {
        engine.flowAttributor?.attributeFresh(
            transport: .udp,
            localAddress: key.client.description,
            localPort: key.clientPort,
            remoteAddress: datagram.flow.dst.description,
            remotePort: datagram.flow.dstPort
        )
    }

    private func dropUDP(onceKey: String, reason: String) async {
        TunnelLog.writeOnce(onceKey, .warn, reason)
        // Use the wire addresses: a FakeIP destination is already rewritten
        // to its domain, and without the ICMP the app never falls back
        // (e.g. QUIC → TCP).
        guard case .v4(let client) = datagram.flow.src.kind,
              case .v4(let destination) = datagram.flow.dst.kind else { return }
        await stack.sendICMPPortUnreachable(
            client: IPv4Address(rawValue: client),
            destination: IPv4Address(rawValue: destination),
            sourcePort: datagram.flow.srcPort,
            destinationPort: datagram.flow.dstPort
        )
    }

    private func openDirect(route: FlowRoute) async -> (any UDPSession)? {
        let parameters = NWParameters.udp
        parameters.preferNoProxies = true
        guard let port = NWEndpoint.Port(rawValue: datagram.destination.port) else { return nil }
        let host: NWEndpoint.Host
        do {
            host = try await DNSClient.$current.withValue(engine.dns) {
                try await DNSClient.resolve(datagram.destination.host, role: .direct)
            }
        } catch {
            return nil
        }
        let connection = NWConnection(
            host: host,
            port: port,
            using: parameters
        )
        connection.start(queue: DispatchQueue.global(qos: .userInitiated))
        return DirectUDPSession(
            route: route,
            connection: connection,
            flow: datagram.flow,
            stack: stack,
            traffic: engine.traffic,
            attribution: attribution()
        )
    }

    private func openProxy(group: String) async -> (any UDPSession)? {
        let leaf = engine.nodeManager.selectedLeaf(inGroup: group)
        let route = FlowRoute(engine.nodeManager.selectedChain(inGroup: group))
        switch leaf {
        case .direct:
            return await openDirect(route: route)
        case .reject:
            await dropUDP(onceKey: "udp-reject-\(group)", reason: "UDP dropped: reject")
            return nil
        case nil:
            await dropUDP(
                onceKey: "udp-no-node-\(group)",
                reason: "UDP dropped: no selected node in group \(group)"
            )
            return nil
        case .node:
            break
        }
        guard case .node(let node) = leaf else { return nil }
        if case .direct = node.protocolConfig {
            return await openDirect(route: route)
        }
        do {
            // Use the leaf picked above; dispatching through the group
            // again would re-pick (load-balance round-robin skew).
            guard let outbound = try NodeFactory.makeDatagramOutbound(
                from: node,
                to: datagram.destination
            ) else {
                await dropUDP(
                    onceKey: "udp-proxy-unsupported-\(node.id)",
                    reason: "UDP dropped: node \(node.name) does not relay UDP"
                )
                return nil
            }
            try await DNSClient.$current.withValue(engine.dns) {
                try await outbound.open()
            }
            return ProxyUDPSession(
                outbound: outbound,
                route: route,
                flow: datagram.flow,
                stack: stack,
                traffic: engine.traffic,
                attribution: attribution()
            )
        } catch {
            return nil
        }
    }
}

private struct UDPFlowKey: Hashable, Sendable {
    var client: IPv4Address
    var clientPort: UInt16
    /// Destination host (domain restored from FakeIP, or IP literal).
    var destinationHost: String
    var destinationPort: UInt16
}

private protocol UDPSession: AnyObject, Sendable {
    /// Route for traffic accounting (`FlowRoute`).
    var route: FlowRoute { get }
    var attribution: FlowAttribution? { get }
    /// Last send/receive activity; used to evict the idlest session at capacity.
    var lastActivity: ContinuousClock.Instant { get }
    func send(_ payload: Data, destination: Endpoint) async
    func pump() async
    func close() async
}

/// Shared last-activity timestamp for `UDPSession`s.
private final class ActivityStamp: Sendable {
    private let lock = OSAllocatedUnfairLock(initialState: ContinuousClock.now)
    var value: ContinuousClock.Instant { lock.withLock { $0 } }
    func touch() { lock.withLock { $0 = ContinuousClock.now } }
}

private final class DirectUDPSession: UDPSession, @unchecked Sendable {
    let route: FlowRoute
    let attribution: FlowAttribution?
    private let connection: NWConnection
    private let flow: FlowKey
    private let stack: TUNStack
    private let traffic: TrafficCounter
    private let activity = ActivityStamp()

    var lastActivity: ContinuousClock.Instant { activity.value }

    init(
        route: FlowRoute,
        connection: NWConnection,
        flow: FlowKey,
        stack: TUNStack,
        traffic: TrafficCounter,
        attribution: FlowAttribution?
    ) {
        self.route = route
        self.connection = connection
        self.flow = flow
        self.stack = stack
        self.traffic = traffic
        self.attribution = attribution
    }

    /// The NWConnection is bound to the first destination; the flow key
    /// pins the destination, so `destination` always matches the bound peer.
    func send(_ payload: Data, destination _: Endpoint) async {
        activity.touch()
        connection.send(content: payload, completion: .contentProcessed { _ in })
    }

    func pump() async {
        while !Task.isCancelled {
            guard let data = await connection.receiveDatagram(), !data.isEmpty else { return }
            activity.touch()
            traffic.addBytes(up: 0, down: UInt64(data.count), route: route, app: attribution, transport: .udp)
            await stack.sendUDP(flow: flow, payload: data)
        }
    }

    func close() async {
        connection.cancel()
    }
}

/// A proxied flow: datagrams go through the node's `DatagramOutbound`.
private final class ProxyUDPSession: UDPSession, @unchecked Sendable {
    let route: FlowRoute
    let attribution: FlowAttribution?
    private let outbound: any DatagramOutbound
    private let flow: FlowKey
    private let stack: TUNStack
    private let traffic: TrafficCounter
    private let activity = ActivityStamp()

    var lastActivity: ContinuousClock.Instant { activity.value }

    init(
        outbound: any DatagramOutbound,
        route: FlowRoute,
        flow: FlowKey,
        stack: TUNStack,
        traffic: TrafficCounter,
        attribution: FlowAttribution?
    ) {
        self.outbound = outbound
        self.route = route
        self.attribution = attribution
        self.flow = flow
        self.stack = stack
        self.traffic = traffic
    }

    func send(_ payload: Data, destination: Endpoint) async {
        activity.touch()
        try? await outbound.send(payload, to: destination)
    }

    func pump() async {
        do {
            while !Task.isCancelled {
                guard let payload = try await outbound.receive() else { break }
                activity.touch()
                traffic.addBytes(up: 0, down: UInt64(payload.count), route: route, app: attribution, transport: .udp)
                await stack.sendUDP(flow: flow, payload: payload)
            }
        } catch {
            // Closed.
        }
        await outbound.close()
    }

    func close() async {
        await outbound.close()
    }
}
