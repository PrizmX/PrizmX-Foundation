import Foundation
import Network
import Dispatch
import PrizmXCore
import PrizmXNodes
import PrizmXProtocols
import PrizmXRules

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
        let key = UDPFlowKey(
            client: clientIP,
            clientPort: datagram.source.port,
            destinationPort: datagram.destination.port
        )
        if sessions[key] == nil {
            guard sessions.count < MemoryWatchdog.maxUDPSessions else { return }
            switch engine.router.match(endpoint: datagram.destination) {
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
        engine.traffic.addBytes(up: UInt64(datagram.payload.count), down: 0, via: session.via)
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
            client: key.client,
            clientPort: key.clientPort,
            destinationPort: key.destinationPort,
            stack: stack,
            traffic: engine.traffic
        )
        sessions[key] = session
        tasks[key] = Task { await session.pump() }
    }

    private func openProxy(key: UDPFlowKey, datagram: TUNUDPDatagram, group: String) async {
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
                let outbound = try engine.dispatch(target: datagram.destination, command: .udp)
                try await outbound.open()
                let session = StreamUDPSession(
                    outbound: outbound,
                    client: key.client,
                    clientPort: key.clientPort,
                    destinationPort: key.destinationPort,
                    stack: stack,
                    traffic: engine.traffic
                )
                sessions[key] = session
                tasks[key] = Task { await session.pump() }
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
                client: key.client,
                clientPort: key.clientPort,
                destinationPort: key.destinationPort,
                stack: stack,
                traffic: engine.traffic
            )
            sessions[key] = session
            tasks[key] = Task { await session.pump() }
        }
    }
}

private struct UDPFlowKey: Hashable, Sendable {
    var client: IPv4Address
    var clientPort: UInt16
    var destinationPort: UInt16
}

private protocol UDPSession: AnyObject, Sendable {
    /// Routing label for traffic accounting (`direct` / policy name).
    var via: String { get }
    func send(_ payload: Data, destination: Endpoint) async
    func close() async
}

private final class DirectUDPSession: UDPSession, @unchecked Sendable {
    let via = "direct"
    private let connection: NWConnection
    private let client: IPv4Address
    private let clientPort: UInt16
    private let destinationPort: UInt16
    private let stack: TUNStack
    private let traffic: TrafficCounter

    init(
        connection: NWConnection,
        client: IPv4Address,
        clientPort: UInt16,
        destinationPort: UInt16,
        stack: TUNStack,
        traffic: TrafficCounter
    ) {
        self.connection = connection
        self.client = client
        self.clientPort = clientPort
        self.destinationPort = destinationPort
        self.stack = stack
        self.traffic = traffic
    }

    func send(_ payload: Data, destination _: Endpoint) async {
        connection.send(content: payload, completion: .contentProcessed { _ in })
    }

    func pump() async {
        while !Task.isCancelled {
            guard let data = await connection.receiveDatagram(), !data.isEmpty else { return }
            traffic.addBytes(up: 0, down: UInt64(data.count), via: via)
            await stack.sendUDP(
                destinationIP: client.rawValue,
                destinationPort: clientPort,
                sourcePort: destinationPort,
                payload: data
            )
        }
    }

    func close() async {
        connection.cancel()
    }
}

private final class StreamUDPSession: UDPSession, @unchecked Sendable {
    var via: String { outbound.routingLabel }
    private let outbound: any OutboundConnection
    private let client: IPv4Address
    private let clientPort: UInt16
    private let destinationPort: UInt16
    private let stack: TUNStack
    private let traffic: TrafficCounter

    init(
        outbound: any OutboundConnection,
        client: IPv4Address,
        clientPort: UInt16,
        destinationPort: UInt16,
        stack: TUNStack,
        traffic: TrafficCounter
    ) {
        self.outbound = outbound
        self.client = client
        self.clientPort = clientPort
        self.destinationPort = destinationPort
        self.stack = stack
        self.traffic = traffic
    }

    func send(_ payload: Data, destination _: Endpoint) async {
        try? await outbound.writeAll(UDPOverStreamFrame.encode(payload))
    }

    func pump() async {
        var decoder = UDPOverStreamFrame.Decoder()
        do {
            while !Task.isCancelled {
                let chunk = try await outbound.readData(upTo: 16 * 1024)
                if chunk.isEmpty { break }
                for payload in decoder.feed(chunk) {
                    traffic.addBytes(up: 0, down: UInt64(payload.count), via: via)
                    await stack.sendUDP(
                        destinationIP: client.rawValue,
                        destinationPort: clientPort,
                        sourcePort: destinationPort,
                        payload: payload
                    )
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
    let via = "proxy"
    private let connection: NWConnection
    private let preSharedKey: [UInt8]
    private let cipher: ShadowsocksCipher
    private let client: IPv4Address
    private let clientPort: UInt16
    private let destinationPort: UInt16
    private let stack: TUNStack
    private let traffic: TrafficCounter

    init(
        connection: NWConnection,
        preSharedKey: [UInt8],
        cipher: ShadowsocksCipher,
        client: IPv4Address,
        clientPort: UInt16,
        destinationPort: UInt16,
        stack: TUNStack,
        traffic: TrafficCounter
    ) {
        self.connection = connection
        self.preSharedKey = preSharedKey
        self.cipher = cipher
        self.client = client
        self.clientPort = clientPort
        self.destinationPort = destinationPort
        self.stack = stack
        self.traffic = traffic
    }

    func send(_ payload: Data, destination: Endpoint) async {
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
            traffic.addBytes(up: 0, down: UInt64(decoded.payload.count), via: via)
            await stack.sendUDP(
                destinationIP: client.rawValue,
                destinationPort: clientPort,
                sourcePort: destinationPort,
                payload: decoded.payload
            )
        }
    }

    func close() async {
        connection.cancel()
    }
}
