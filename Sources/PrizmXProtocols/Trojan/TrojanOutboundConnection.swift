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
    /// Clash `skip-cert-verify`: accept any server certificate.
    public let skipCertVerify: Bool
    /// Transport inside TLS (`tcp`, `ws`, …).
    public let network: StreamTransport

    public init(
        server: Endpoint,
        password: String,
        sni: String? = nil,
        skipCertVerify: Bool = false,
        network: StreamTransport = .tcp
    ) {
        self.server = server
        self.password = password
        self.sni = sni
        self.skipCertVerify = skipCertVerify
        self.network = network
    }

    public func connect(to endpoint: Endpoint) async throws -> any OutboundConnection {
        TrojanOutboundConnection(
            server: server,
            password: password,
            target: endpoint,
            sni: sni,
            skipCertVerify: skipCertVerify,
            network: network
        )
    }
}

// MARK: - Outbound connection

/// Trojan TCP client: TLS handshake (plus the transport, e.g. WebSocket),
/// then a one-shot header `hex(SHA224(password)) CRLF CMD SOCKS5-ADDR CRLF`,
/// then a raw byte stream.
public final class TrojanOutboundConnection: OutboundConnection, @unchecked Sendable {

    public let endpoint: Endpoint
    public let server: Endpoint
    public let sni: String?
    public let command: TrojanCommand
    public let passwordHashHex: [UInt8]
    public let skipCertVerify: Bool
    public let network: StreamTransport

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
    ///   - skipCertVerify: Accept any server certificate (explicit opt-in).
    ///   - network: Transport inside TLS (`tcp`, `ws`, `httpupgrade`).
    public init(
        server: Endpoint,
        password: String,
        target: Endpoint,
        sni: String? = nil,
        command: TrojanCommand = .connect,
        skipCertVerify: Bool = false,
        network: StreamTransport = .tcp
    ) {
        self.server = server
        self.endpoint = target
        self.sni = sni
        self.command = command
        self.skipCertVerify = skipCertVerify
        self.network = network
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
        command: TrojanCommand = .connect,
        skipCertVerify: Bool = false
    ) {
        let server = Endpoint(hostname: host, port: port)
            ?? Endpoint(domain: host, port: port)
        self.init(
            server: server,
            password: password,
            target: target,
            sni: sni,
            command: command,
            skipCertVerify: skipCertVerify
        )
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
        try transport.ensureReadable()

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

    /// Half-close: ends the uplink where the transport can (see
    /// `ByteStream.finishWriting`); the downlink keeps flowing either way.
    public func closeWrite() async {
        await transport.finishWriting()
    }

    public var supportsHalfClose: Bool { true }

    // MARK: Handshake

    private func connectAndHandshake() async throws {
        let settings = StreamSettings(
            tls: TLSSettings(serverName: sni, skipCertVerify: skipCertVerify),
            transport: network
        )
        try await transport.dial(server, settings: settings)
        do {
            try await sendHeaderIfNeeded()
        } catch {
            transport.failOpen()
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
