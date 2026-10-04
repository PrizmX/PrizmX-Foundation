import Foundation
import os

/// SOCKS5 request command (RFC 1928).
@frozen
public enum SOCKS5Command: UInt8, Hashable, Sendable {
    case connect = 0x01
    case udpAssociate = 0x03
}

/// SOCKS5 client (RFC 1928, username / password per RFC 1929).
///
/// `open()` negotiates the auth method, authenticates when the server picks
/// username / password, then sends the request. For CONNECT the rest of the
/// connection is the raw tunnel; for UDP ASSOCIATE it is the control
/// connection that keeps the relay alive (`SOCKS5DatagramOutbound`).
public final class SOCKS5OutboundConnection: OutboundConnection, @unchecked Sendable {
    public let endpoint: Endpoint
    public let server: Endpoint
    public let command: SOCKS5Command

    public var state: OutboundConnectionState { stream.state }

    /// `BND.ADDR` / `BND.PORT` from the request reply (the UDP relay for
    /// UDP ASSOCIATE). Set once `open()` succeeds.
    public var boundEndpoint: Endpoint? { bound.withLock { $0 } }

    private let stream: HandshakeStream
    private let bound = OSAllocatedUnfairLock<Endpoint?>(initialState: nil)

    /// - Parameters:
    ///   - server: Proxy host and port.
    ///   - target: CONNECT destination (ignored by servers for UDP ASSOCIATE,
    ///     where `0.0.0.0:0` is customary).
    ///   - credentials: Offered as method `0x02` alongside "no auth".
    ///   - command: CONNECT or UDP ASSOCIATE.
    ///   - settings: TCP or TLS (`socks5-tls`) dialing.
    public init(
        server: Endpoint,
        target: Endpoint,
        credentials: ProxyCredentials? = nil,
        command: SOCKS5Command = .connect,
        settings: StreamSettings = StreamSettings()
    ) {
        self.server = server
        self.endpoint = target
        self.command = command
        let bound = self.bound
        self.stream = HandshakeStream(
            label: "prizmx.socks5.outbound",
            server: server,
            target: target,
            settings: settings
        ) { stream in
            try await Self.negotiate(on: stream, credentials: credentials)
            try await stream.sendHandshake(try Self.request(command: command, target: target))
            let reply = try await Self.readReply(on: stream)
            bound.withLock { $0 = reply }
        }
    }

    public func open() async throws { try await stream.open() }

    public func write(_ buffer: UnsafeRawBufferPointer) async throws -> Int {
        try await stream.write(buffer)
    }

    public func read(into buffer: UnsafeMutableRawBufferPointer) async throws -> Int {
        try await stream.read(into: buffer)
    }

    public func close() async { await stream.close() }

    public func closeWrite() async { await stream.closeWrite() }

    public var supportsHalfClose: Bool { stream.supportsHalfClose }

    // MARK: Wire

    private static func negotiate(on stream: HandshakeStream, credentials: ProxyCredentials?) async throws {
        let methods: [UInt8] = credentials == nil ? [0x00] : [0x00, 0x02]
        try await stream.sendHandshake([0x05, UInt8(methods.count)] + methods)
        let choice = try await stream.receive(exactly: 2)
        guard choice[0] == 0x05 else { throw ProxyHandshakeError.malformedResponse }
        switch choice[1] {
        case 0x00:
            return
        case 0x02:
            guard let credentials else { throw ProxyHandshakeError.socksNoAcceptableMethod }
            try await stream.sendHandshake(try authRequest(credentials))
            let status = try await stream.receive(exactly: 2)
            guard status[1] == 0x00 else { throw ProxyHandshakeError.socksAuthenticationFailed }
        default:
            throw ProxyHandshakeError.socksNoAcceptableMethod
        }
    }

    /// RFC 1929 sub-negotiation: `[0x01][ulen][user][plen][pass]`.
    static func authRequest(_ credentials: ProxyCredentials) throws -> [UInt8] {
        let user = Array(credentials.username.utf8)
        let pass = Array(credentials.password.utf8)
        guard user.count <= 255, pass.count <= 255 else {
            throw ProxyHandshakeError.socksAuthenticationFailed
        }
        return [0x01, UInt8(user.count)] + user + [UInt8(pass.count)] + pass
    }

    static func request(command: SOCKS5Command, target: Endpoint) throws -> [UInt8] {
        [0x05, command.rawValue, 0x00] + (try ShadowsocksAddress.encode(target))
    }

    /// `[VER][REP][RSV][ATYP][BND.ADDR][BND.PORT]`; returns the bound endpoint.
    private static func readReply(on stream: HandshakeStream) async throws -> Endpoint {
        let head = try await stream.receive(exactly: 5)
        guard head[0] == 0x05 else { throw ProxyHandshakeError.malformedResponse }
        guard head[1] == 0x00 else { throw ProxyHandshakeError.socksRequestFailed(head[1]) }
        let remaining: Int
        switch head[3] {
        case 0x01: remaining = 4 - 1 + 2
        case 0x04: remaining = 16 - 1 + 2
        case 0x03: remaining = Int(head[4]) + 2
        default: throw ProxyHandshakeError.malformedResponse
        }
        let address = Array(head[3...]) + (try await stream.receive(exactly: remaining))
        do {
            return try address.withUnsafeBytes { try ShadowsocksAddress.decode($0).0 }
        } catch {
            throw ProxyHandshakeError.malformedResponse
        }
    }
}

/// SOCKS5 UDP ASSOCIATE: a control connection plus a UDP socket to the
/// relay it names. Datagrams are `[RSV 2][FRAG][ATYP/ADDR/PORT][payload]`.
public final class SOCKS5DatagramOutbound: DatagramOutbound, @unchecked Sendable {
    public let server: Endpoint
    private let control: SOCKS5OutboundConnection
    private let socket = UDPSocket(label: "prizmx.socks5.udp")

    public init(server: Endpoint, credentials: ProxyCredentials? = nil, settings: StreamSettings = StreamSettings()) {
        self.server = server
        self.control = SOCKS5OutboundConnection(
            server: server,
            target: Endpoint(host: .ipv4(.any), port: 0),
            credentials: credentials,
            command: .udpAssociate,
            settings: settings
        )
    }

    public func open() async throws {
        try await control.open()
        guard let bound = control.boundEndpoint else {
            throw ProxyHandshakeError.malformedResponse
        }
        do {
            try await socket.open(Self.relay(bound: bound, server: server))
        } catch {
            await control.close()
            throw error
        }
    }

    /// An unspecified `BND.ADDR` (`0.0.0.0` / `::`) means "the server's
    /// address"; `BND.PORT` is always the relay port.
    static func relay(bound: Endpoint, server: Endpoint) -> Endpoint {
        switch bound.host {
        case .ipv4(let address) where address == .any:
            return Endpoint(host: server.host, port: bound.port)
        case .ipv6(let address) where address.high == 0 && address.low == 0:
            return Endpoint(host: server.host, port: bound.port)
        default:
            return bound
        }
    }

    public func send(_ payload: Data, to destination: Endpoint) async throws {
        var packet = Data([0x00, 0x00, 0x00])
        packet.append(contentsOf: try ShadowsocksAddress.encode(destination))
        packet.append(payload)
        socket.send(packet)
    }

    public func receive() async throws -> Data? {
        while let packet = await socket.receive() {
            if let payload = Self.payload(of: packet) { return payload }
        }
        return nil
    }

    /// Strips the UDP request header; fragments (`FRAG != 0`) are dropped.
    static func payload(of packet: Data) -> Data? {
        guard packet.count > 4, packet[packet.startIndex + 2] == 0x00 else { return nil }
        let body = packet.dropFirst(3)
        guard let headerCount = try? body.withUnsafeBytes({ try ShadowsocksAddress.decode($0).1 }) else {
            return nil
        }
        return Data(body.dropFirst(headerCount))
    }

    public func close() async {
        socket.close()
        await control.close()
    }
}
