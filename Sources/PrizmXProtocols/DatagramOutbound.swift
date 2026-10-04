import Foundation
import Network
import os

/// A UDP relay through one proxy node for one TUN flow.
///
/// The flow key pins the destination, so `send` normally repeats the first
/// destination; protocols that address every packet (Shadowsocks, Trojan,
/// SOCKS5) still encode it per datagram.
public protocol DatagramOutbound: Sendable {
    /// Dials the node. Runs under the caller's `DNSClient.$current`.
    func open() async throws
    /// Sends one datagram to `destination`.
    func send(_ payload: Data, to destination: Endpoint) async throws
    /// Next downlink datagram payload; `nil` once the relay is closed.
    func receive() async throws -> Data?
    /// Releases the underlying connection. Idempotent.
    func close() async
}

// MARK: - Datagrams framed inside a stream

/// How datagrams are framed on a stream outbound (VLESS / Trojan / VMess).
public protocol DatagramStreamFraming: Sendable {
    /// Wire bytes for one uplink datagram.
    func encode(_ payload: Data, to destination: Endpoint) throws -> Data
    /// Appends stream bytes and returns every datagram now complete.
    mutating func decode(_ chunk: Data) throws -> [Data]
}

/// VLESS `udp` command: `[uint16 length][payload]` per datagram.
public struct LengthPrefixedDatagramFraming: DatagramStreamFraming {
    private var decoder = UDPOverStreamFrame.Decoder()

    public init() {}

    public func encode(_ payload: Data, to _: Endpoint) throws -> Data {
        UDPOverStreamFrame.encode(payload)
    }

    public mutating func decode(_ chunk: Data) throws -> [Data] {
        decoder.feed(chunk)
    }
}

/// Runs datagrams over a stream `OutboundConnection` with a framing.
///
/// `send` and `receive` are called from different tasks (uplink worker and
/// downlink pump); the decoder state is touched only by `receive`.
public final class StreamDatagramOutbound<Framing: DatagramStreamFraming>: DatagramOutbound, @unchecked Sendable {
    private let connection: any OutboundConnection
    private let encoder: Framing
    private var decoder: Framing
    private var pending: [Data] = []

    public init(connection: any OutboundConnection, framing: Framing) {
        self.connection = connection
        self.encoder = framing
        self.decoder = framing
    }

    public func open() async throws {
        try await connection.open()
    }

    public func send(_ payload: Data, to destination: Endpoint) async throws {
        try await connection.writeAll(try encoder.encode(payload, to: destination))
    }

    public func receive() async throws -> Data? {
        while pending.isEmpty {
            let chunk = try await connection.readData(upTo: 64 * 1024)
            if chunk.isEmpty { return nil }
            pending = try decoder.decode(chunk)
        }
        return pending.removeFirst()
    }

    public func close() async {
        await connection.close()
    }
}

// MARK: - Native UDP

/// Shadowsocks AEAD over a UDP socket: `[salt][AEAD(address ‖ payload)]`.
public final class ShadowsocksDatagramOutbound: DatagramOutbound, @unchecked Sendable {
    public let server: Endpoint
    public let cipher: ShadowsocksCipher
    private let preSharedKey: [UInt8]
    private let socket = UDPSocket(label: "prizmx.shadowsocks.udp")

    public init(server: Endpoint, password: String, cipher: ShadowsocksCipher) {
        self.server = server
        self.cipher = cipher
        self.preSharedKey = cipher.masterKey(fromPassword: password)
    }

    public func open() async throws {
        try await socket.open(server)
    }

    public func send(_ payload: Data, to destination: Endpoint) async throws {
        let packet = try ShadowsocksUDP.encode(
            cipher: cipher,
            preSharedKey: preSharedKey,
            destination: destination,
            payload: payload
        )
        socket.send(packet)
    }

    public func receive() async throws -> Data? {
        while let packet = await socket.receive() {
            // Undecryptable packets are dropped (spoofed / stale peer).
            if let decoded = try? ShadowsocksUDP.decode(
                cipher: cipher,
                preSharedKey: preSharedKey,
                packet: packet
            ) {
                return decoded.payload
            }
        }
        return nil
    }

    public func close() async {
        socket.close()
    }
}

/// A connected UDP `NWConnection` to one proxy server (DNS through
/// `DNSClient` with the proxy-server role).
final class UDPSocket: @unchecked Sendable {
    private let queue: DispatchQueue
    private let box = OSAllocatedUnfairLock<NWConnection?>(initialState: nil)
    private let closed = OSAllocatedUnfairLock(initialState: false)

    init(label: String) {
        self.queue = DispatchQueue(label: label, qos: .userInitiated)
    }

    /// Resolves and starts the socket. Datagrams sent before `.ready` are
    /// queued by Network.framework.
    func open(_ server: Endpoint, host resolved: NWEndpoint.Host? = nil) async throws {
        guard let port = NWEndpoint.Port(rawValue: server.port), server.port > 0 else {
            throw OutboundError.invalidEndpoint(server)
        }
        let host: NWEndpoint.Host
        if let resolved {
            host = resolved
        } else {
            host = try await DNSClient.resolve(server.host, role: .proxyServer)
        }
        let parameters = NWParameters.udp
        parameters.preferNoProxies = true
        let connection = NWConnection(host: host, port: port, using: parameters)
        let attached: Bool = box.withLock { current in
            guard current == nil, !closed.withLock({ $0 }) else { return false }
            current = connection
            return true
        }
        guard attached else { throw OutboundError.alreadyClosed(server) }
        connection.start(queue: queue)
    }

    func send(_ packet: Data) {
        box.withLock { $0 }?.send(content: packet, completion: .contentProcessed { _ in })
    }

    /// Next datagram; `nil` once cancelled or failed (an errored receive
    /// yields an empty chunk, which also ends the stream).
    func receive() async -> Data? {
        guard let connection = box.withLock({ $0 }),
              let data = await connection.receiveDatagram(),
              !data.isEmpty
        else { return nil }
        return data
    }

    func close() {
        closed.withLock { $0 = true }
        box.withLock { current -> NWConnection? in
            defer { current = nil }
            return current
        }?.cancel()
    }
}
