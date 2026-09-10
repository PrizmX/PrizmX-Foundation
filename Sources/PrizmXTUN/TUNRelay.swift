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

/// Consumes `TUNStack.udpDatagrams()` and forwards DIRECT / SS-UDP / VLESS-UDP.
public enum TUNUDPRelay: Sendable {
    public static func run(stack: TUNStack, engine: Engine) async {
        let state = UDPRelayState(stack: stack, engine: engine)
        for await datagram in await stack.udpDatagrams() {
            await state.ingest(datagram)
        }
        await state.stop()
    }
}

private actor UDPRelayState {
    private let stack: TUNStack
    private let engine: Engine
    private var sessions: [UDPFlowKey: any UDPSession] = [:]
    private var tasks: [UDPFlowKey: Task<Void, Never>] = [:]

    init(stack: TUNStack, engine: Engine) {
        self.stack = stack
        self.engine = engine
    }

    func ingest(_ datagram: TUNUDPDatagram) async {
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
        if sessions[key] == nil {
            if sessions.count >= MemoryWatchdog.maxUDPSessions {
                // Evict the least-recently-active session instead of dropping
                // all new UDP traffic until tunnel restart.
                guard let victim = sessions.min(by: { $0.value.lastActivity < $1.value.lastActivity })?.key,
                      let evicted = sessions.removeValue(forKey: victim)
                else { return }
                tasks.removeValue(forKey: victim)?.cancel()
                await evicted.close()
            }
            let ipv4 = await engine.resolveIPv4(for: datagram.destination)
            switch engine.policy(for: datagram.destination, resolvedIPv4: ipv4) {
            case .reject:
                await dropUDP(datagram, onceKey: "udp-reject", reason: "UDP dropped: reject")
            case .direct:
                await openDirect(key: key, datagram: datagram)
            case .proxy(let group):
                await openProxy(key: key, datagram: datagram, group: group)
            }
        }
        guard let session = sessions[key] else { return }
        await session.send(datagram.payload, destination: datagram.destination)
        engine.traffic.addBytes(
            up: UInt64(datagram.payload.count),
            down: 0,
            via: session.via,
            app: session.attribution
        )
    }

    /// Called when a session's pump loop exits (peer closed / cancelled):
    /// drop the entry so a later datagram opens a fresh session and the
    /// session table cannot fill up with dead entries.
    private func finishSession(_ key: UDPFlowKey) {
        sessions.removeValue(forKey: key)
        tasks.removeValue(forKey: key)
    }

    /// Registers `session` and starts its pump; the pump's exit removes the
    /// session from the table.
    private func track(_ key: UDPFlowKey, session: any UDPSession) {
        sessions[key] = session
        tasks[key] = Task { [weak self] in
            await session.pump()
            await self?.finishSession(key)
        }
    }

    private func attribution(for key: UDPFlowKey, datagram: TUNUDPDatagram) -> FlowAttribution? {
        engine.flowAttributor?.attribute(
            transport: .udp,
            localAddress: key.client.description,
            localPort: key.clientPort,
            remoteAddress: datagram.destination.host.description,
            remotePort: datagram.destination.port
        )
    }

    func stop() async {
        for task in tasks.values { task.cancel() }
        tasks.removeAll()
        for session in sessions.values {
            await session.close()
        }
        sessions.removeAll()
    }

    private func dropUDP(_ datagram: TUNUDPDatagram, onceKey: String, reason: String) async {
        TunnelLog.writeOnce(onceKey, .warn, reason)
        guard case .ipv4(let client) = datagram.source.host,
              case .ipv4(let destination) = datagram.destination.host else { return }
        await stack.sendICMPPortUnreachable(
            client: client,
            destination: destination,
            sourcePort: datagram.source.port,
            destinationPort: datagram.destination.port
        )
    }

    private func openDirect(key: UDPFlowKey, datagram: TUNUDPDatagram) async {
        let parameters = NWParameters.udp
        parameters.preferNoProxies = true
        guard let port = NWEndpoint.Port(rawValue: datagram.destination.port) else { return }
        let host: NWEndpoint.Host
        do {
            host = try await DNSClient.$current.withValue(engine.dns) {
                try await DNSClient.resolve(datagram.destination.host, role: .direct)
            }
        } catch {
            return
        }
        let connection = NWConnection(
            host: host,
            port: port,
            using: parameters
        )
        connection.start(queue: DispatchQueue.global(qos: .userInitiated))
        let session = DirectUDPSession(
            connection: connection,
            flow: datagram.flow,
            stack: stack,
            traffic: engine.traffic,
            attribution: attribution(for: key, datagram: datagram)
        )
        track(key, session: session)
    }

    private func openProxy(
        key: UDPFlowKey,
        datagram: TUNUDPDatagram,
        group: String
    ) async {
        let leaf = engine.nodeManager.selectedLeaf(inGroup: group)
        switch leaf {
        case .direct:
            await openDirect(key: key, datagram: datagram)
            return
        case .reject:
            await dropUDP(datagram, onceKey: "udp-reject-\(group)", reason: "UDP dropped: reject")
            return
        case nil:
            await dropUDP(
                datagram,
                onceKey: "udp-no-node-\(group)",
                reason: "UDP dropped: no selected node in group \(group)"
            )
            return
        case .node:
            break
        }
        guard case .node(let node) = leaf else { return }
        switch node.protocolConfig {
        case .direct:
            await openDirect(key: key, datagram: datagram)
        case .vless:
            do {
                // Use the leaf picked above; dispatching through the group
                // again would re-pick (load-balance round-robin skew).
                let outbound = try NodeFactory.makeConnection(
                    from: node,
                    to: datagram.destination,
                    command: .udp
                )
                try await outbound.open()
                let session = StreamUDPSession(
                    outbound: outbound,
                    via: group,
                    flow: datagram.flow,
                    stack: stack,
                    traffic: engine.traffic,
                    attribution: attribution(for: key, datagram: datagram)
                )
                track(key, session: session)
            } catch {
                return
            }
        case .trojan, .anytls:
            await dropUDP(
                datagram,
                onceKey: "udp-proxy-unsupported",
                reason: "UDP dropped: proxy protocol does not support UDP relay (trojan/anytls)"
            )
            return
        case .shadowsocks(let server, let password, let cipher):
            let parameters = NWParameters.udp
            parameters.preferNoProxies = true
            guard let port = NWEndpoint.Port(rawValue: server.port) else { return }
            let host: NWEndpoint.Host
            do {
                host = try await DNSClient.$current.withValue(engine.dns) {
                    try await DNSClient.resolve(server.host, role: .proxyServer)
                }
            } catch {
                return
            }
            let connection = NWConnection(
                host: host,
                port: port,
                using: parameters
            )
            connection.start(queue: DispatchQueue.global(qos: .userInitiated))
            let session = ShadowsocksUDPSession(
                connection: connection,
                preSharedKey: cipher.masterKey(fromPassword: password),
                cipher: cipher,
                via: group,
                flow: datagram.flow,
                stack: stack,
                traffic: engine.traffic,
                attribution: attribution(for: key, datagram: datagram)
            )
            track(key, session: session)
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
    /// Routing label for traffic accounting (`direct` / policy name).
    var via: String { get }
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
    let via = "direct"
    let attribution: FlowAttribution?
    private let connection: NWConnection
    private let flow: FlowKey
    private let stack: TUNStack
    private let traffic: TrafficCounter
    private let activity = ActivityStamp()

    var lastActivity: ContinuousClock.Instant { activity.value }

    init(
        connection: NWConnection,
        flow: FlowKey,
        stack: TUNStack,
        traffic: TrafficCounter,
        attribution: FlowAttribution?
    ) {
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
            traffic.addBytes(up: 0, down: UInt64(data.count), via: via, app: attribution)
            await stack.sendUDP(flow: flow, payload: data)
        }
    }

    func close() async {
        connection.cancel()
    }
}

private final class StreamUDPSession: UDPSession, @unchecked Sendable {
    let via: String
    let attribution: FlowAttribution?
    private let outbound: any OutboundConnection
    private let flow: FlowKey
    private let stack: TUNStack
    private let traffic: TrafficCounter
    private let activity = ActivityStamp()

    var lastActivity: ContinuousClock.Instant { activity.value }

    init(
        outbound: any OutboundConnection,
        via: String,
        flow: FlowKey,
        stack: TUNStack,
        traffic: TrafficCounter,
        attribution: FlowAttribution?
    ) {
        self.outbound = outbound
        self.via = via
        self.attribution = attribution
        self.flow = flow
        self.stack = stack
        self.traffic = traffic
    }

    /// The outbound was opened against the first destination; the flow key
    /// pins the destination, so `destination` always matches.
    func send(_ payload: Data, destination _: Endpoint) async {
        activity.touch()
        try? await outbound.writeAll(UDPOverStreamFrame.encode(payload))
    }

    func pump() async {
        var decoder = UDPOverStreamFrame.Decoder()
        do {
            while !Task.isCancelled {
                let chunk = try await outbound.readData(upTo: 16 * 1024)
                if chunk.isEmpty { break }
                activity.touch()
                for payload in decoder.feed(chunk) {
                    traffic.addBytes(up: 0, down: UInt64(payload.count), via: via, app: attribution)
                    await stack.sendUDP(flow: flow, payload: payload)
                }
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

private final class ShadowsocksUDPSession: UDPSession, @unchecked Sendable {
    let via: String
    let attribution: FlowAttribution?
    private let connection: NWConnection
    private let preSharedKey: [UInt8]
    private let cipher: ShadowsocksCipher
    private let flow: FlowKey
    private let stack: TUNStack
    private let traffic: TrafficCounter
    private let activity = ActivityStamp()

    var lastActivity: ContinuousClock.Instant { activity.value }

    init(
        connection: NWConnection,
        preSharedKey: [UInt8],
        cipher: ShadowsocksCipher,
        via: String,
        flow: FlowKey,
        stack: TUNStack,
        traffic: TrafficCounter,
        attribution: FlowAttribution?
    ) {
        self.connection = connection
        self.preSharedKey = preSharedKey
        self.cipher = cipher
        self.via = via
        self.attribution = attribution
        self.flow = flow
        self.stack = stack
        self.traffic = traffic
    }

    func send(_ payload: Data, destination: Endpoint) async {
        activity.touch()
        guard let packet = try? ShadowsocksUDP.encode(
            cipher: cipher,
            preSharedKey: preSharedKey,
            destination: destination,
            payload: payload
        ) else { return }
        connection.send(content: packet, completion: .contentProcessed { _ in })
    }

    func pump() async {
        while !Task.isCancelled {
            guard let data = await connection.receiveDatagram(), !data.isEmpty else { return }
            guard let decoded = try? ShadowsocksUDP.decode(
                cipher: cipher,
                preSharedKey: preSharedKey,
                packet: data
            ) else { continue }
            activity.touch()
            traffic.addBytes(up: 0, down: UInt64(decoded.payload.count), via: via, app: attribution)
            await stack.sendUDP(flow: flow, payload: decoded.payload)
        }
    }

    func close() async {
        connection.cancel()
    }
}
