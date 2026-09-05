import Foundation
import Network
import os
import Security

// MARK: - Factory

/// Dials a Trojan server over Network.framework TLS and opens a stream to
/// an arbitrary target.
public struct TrojanOutboundFactory: OutboundConnectionFactory, Sendable {
    public let server: Endpoint
    public let password: String
    public let sni: String?

    public init(server: Endpoint, password: String, sni: String? = nil) {
        self.server = server
        self.password = password
        self.sni = sni
    }

    public func connect(to endpoint: Endpoint) async throws -> any OutboundConnection {
        TrojanOutboundConnection(
            server: server,
            password: password,
            target: endpoint,
            sni: sni
        )
    }
}

// MARK: - Outbound connection

/// Trojan TCP client: TLS handshake, then a one-shot header
/// `hex(SHA224(password)) CRLF CMD SOCKS5-ADDR CRLF`, then a raw byte stream.
public final class TrojanOutboundConnection: OutboundConnection, @unchecked Sendable {

    public let endpoint: Endpoint
    public let server: Endpoint
    public let sni: String?
    public let command: TrojanCommand
    public let passwordHashHex: [UInt8]

    public var state: OutboundConnectionState {
        transport.state
    }

    private let header: TrojanHeader
    private let transport: NWStreamTransport
    private var headerSent = false

    /// - Parameters:
    ///   - server: Trojan server host and port.
    ///   - password: Plaintext password (hashed with SHA-224 on the wire).
    ///   - target: Destination encoded in the Trojan request.
    ///   - sni: TLS server name. Defaults to `server`'s domain.
    ///   - command: CONNECT (TCP) or UDP ASSOCIATE.
    public init(
        server: Endpoint,
        password: String,
        target: Endpoint,
        sni: String? = nil,
        command: TrojanCommand = .connect
    ) {
        self.server = server
        self.endpoint = target
        self.sni = sni
        self.command = command
        let header = TrojanHeader(password: password, destination: target, command: command)
        self.header = header
        self.passwordHashHex = header.passwordHashHex
        self.transport = NWStreamTransport(
            queueLabel: "prizmx.trojan.outbound",
            endpoint: target,
            errorPeer: server
        )
    }

    /// Convenience matching the common `host + port + password` call site.
    public convenience init(
        host: String,
        port: UInt16,
        password: String,
        target: Endpoint,
        sni: String? = nil,
        command: TrojanCommand = .connect
    ) {
        let server = Endpoint(hostname: host, port: port)
            ?? Endpoint(domain: host, port: port)
        self.init(server: server, password: password, target: target, sni: sni, command: command)
    }

    // MARK: OutboundConnection

    public func open() async throws {
        try await transport.open { try await self.connectAndHandshake() }
    }

    public func write(_ buffer: UnsafeRawBufferPointer) async throws -> Int {
        try await transport.write(buffer, connecting: { try await self.connectAndHandshake() }) { buffer in
            // One copy into `Data` at the Network.framework boundary; the caller
            // pointer is not retained across the send completion.
            let data = Data(buffer)
            try await self.transport.send(data)
            return data.count
        }
    }

    public func read(into buffer: UnsafeMutableRawBufferPointer) async throws -> Int {
        if buffer.isEmpty { return 0 }
        try await transport.ensureOpen { try await self.connectAndHandshake() }
        await transport.readMutex.acquire()
        defer { transport.readMutex.release() }
        try transport.ensureNotClosed()

        while true {
            if transport.inbox.readableByteCount > 0 {
                let take = min(buffer.count, transport.inbox.readableByteCount)
                buffer.copyMemory(
                    from: UnsafeRawBufferPointer(rebasing: transport.inbox.readableBytes.prefix(take))
                )
                transport.inbox.consume(take)
                return take
            }
            guard let chunk = try await transport.receiveRaw() else { return 0 }
            transport.inbox.append(chunk)
        }
    }

    public func close() async {
        await transport.close()
    }

    // MARK: Handshake

    private func connectAndHandshake() async throws {
        guard server.port > 0, let nwPort = NWEndpoint.Port(rawValue: server.port) else {
            throw OutboundError.invalidEndpoint(server)
        }
        let serverName = TLSClient.resolvedServerName(explicit: sni, server: server)
        let parameters = TLSClient.parameters(serverName: serverName)
        let host = try await DNSClient.resolve(server.host, role: .proxyServer)
        let nw = NWConnection(host: host, port: nwPort, using: parameters)
        transport.attach(nw)

        do {
            try await transport.waitUntilReady(nw)
            try await sendHeaderIfNeeded()
        } catch {
            transport.failOpen(nw)
            throw error
        }
        transport.markEstablished()
    }

    private func sendHeaderIfNeeded() async throws {
        guard !headerSent else { return }
        try await transport.send(try header.encodedData())
        headerSent = true
    }
}
