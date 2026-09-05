import Foundation
import Network
import os
import Security

// MARK: - Factory

/// Dials a VLESS v0 server (optionally with native TLS + SNI, or REALITY) and
/// opens a stream to an arbitrary target.
public struct VLESSOutboundFactory: OutboundConnectionFactory, Sendable {
    public let server: Endpoint
    public let uuid: String
    public let sni: String?
    public let tls: Bool
    public let reality: REALITYConfig?

    public init(
        server: Endpoint,
        uuid: String,
        sni: String? = nil,
        tls: Bool = true,
        reality: REALITYConfig? = nil
    ) {
        self.server = server
        self.uuid = uuid
        self.sni = sni
        self.tls = tls
        self.reality = reality
    }

    public func connect(to endpoint: Endpoint) async throws -> any OutboundConnection {
        let connection = try VLESSOutboundConnection(
            server: server,
            uuid: uuid,
            target: endpoint,
            sni: sni,
            tls: tls,
            reality: reality
        )
        return connection
    }
}

// MARK: - Outbound connection

/// VLESS v0 TCP client over `NWConnection`.
///
/// `open()` waits for `.ready` (including the TLS handshake when enabled) and
/// sends the VLESS request header as the first application payload. Later
/// `write` / `read` calls are a raw byte stream; the first `read` strips the
/// 2-byte (plus addons) server response header.
///
/// When `reality` is set, Network.framework TLS is skipped: a userspace
/// TLS 1.3 ClientHello (REALITY Session ID) runs first, then the VLESS header
/// is sent as TLS application data.
public final class VLESSOutboundConnection: OutboundConnection, @unchecked Sendable {

    public let endpoint: Endpoint
    public let server: Endpoint
    public let userID: UUID
    public let sni: String?
    public let tlsEnabled: Bool
    public let reality: REALITYConfig?
    public let command: VLESSCommand

    public var state: OutboundConnectionState {
        transport.state
    }

    private let transport: NWStreamTransport
    private var realitySession: REALITYSession?
    private var requestHeaderSent = false
    private var responseHeaderConsumed = false

    private enum WireReceive {
        case bytes(Int)
        case needMore
        case eof
    }

    /// - Parameters:
    ///   - server: VLESS server host and port.
    ///   - uuid: User id (hyphenated UUID or 32-char hex).
    ///   - target: Destination encoded in the VLESS request header.
    ///   - sni: TLS server name. Defaults to `server`'s domain when TLS is on.
    ///   - tls: Wrap the TCP connection in Network.framework TLS. Ignored when
    ///     `reality` is set (userspace TLS 1.3 is used instead).
    ///   - reality: Optional REALITY (Xray Vision) handshake provider.
    ///   - command: `tcp` (default) or `udp`.
    public init(
        server: Endpoint,
        uuid: String,
        target: Endpoint,
        sni: String? = nil,
        tls: Bool = true,
        reality: REALITYConfig? = nil,
        command: VLESSCommand = .tcp
    ) throws {
        self.server = server
        self.endpoint = target
        self.userID = try VLESSUserID.parse(uuid)
        self.sni = sni
        self.tlsEnabled = tls
        self.reality = reality
        self.command = command
        self.transport = NWStreamTransport(
            queueLabel: "prizmx.vless.outbound",
            endpoint: target,
            errorPeer: server
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
            try await self.send(data)
            return data.count
        }
    }

    public func read(into buffer: UnsafeMutableRawBufferPointer) async throws -> Int {
        if buffer.isEmpty { return 0 }
        try await transport.ensureOpen { try await self.connectAndHandshake() }
        await transport.readMutex.acquire()
        defer { transport.readMutex.release() }
        try transport.ensureNotClosed()

        try await consumeResponseHeaderIfNeeded()

        while true {
            if transport.inbox.readableByteCount > 0 {
                let take = min(buffer.count, transport.inbox.readableByteCount)
                buffer.copyMemory(
                    from: UnsafeRawBufferPointer(rebasing: transport.inbox.readableBytes.prefix(take))
                )
                transport.inbox.consume(take)
                return take
            }
            if transport.receiveEOF { return 0 }

            switch try await receiveOnce() {
            case .eof:
                return 0
            case .needMore, .bytes:
                continue
            }
        }
    }

    public func close() async {
        await transport.close()
    }

    @discardableResult
    public func write(_ data: Data) async throws -> Int {
        guard !data.isEmpty else { return 0 }
        let scratch = UnsafeMutableRawBufferPointer.allocate(
            byteCount: data.count,
            alignment: MemoryLayout<UInt64>.alignment
        )
        defer { scratch.deallocate() }
        data.withUnsafeBytes { scratch.copyMemory(from: $0) }
        return try await write(UnsafeRawBufferPointer(scratch))
    }

    public func read(maxLength: Int) async throws -> Data {
        Data(try await read(upTo: maxLength))
    }

    // MARK: Handshake

    private func connectAndHandshake() async throws {
        guard server.port > 0, let nwPort = NWEndpoint.Port(rawValue: server.port) else {
            throw OutboundError.invalidEndpoint(server)
        }

        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true

        let useREALITY = reality != nil
        let tlsOptions: NWProtocolTLS.Options?
        if useREALITY {
            tlsOptions = nil
        } else if tlsEnabled {
            let tls = NWProtocolTLS.Options()
            if let name = tlsServerName {
                name.withCString { pointer in
                    sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, pointer)
                }
            }
            tlsOptions = tls
        } else {
            tlsOptions = nil
        }

        let parameters = NWParameters(tls: tlsOptions, tcp: tcp)
        parameters.preferNoProxies = true

        let host = try await DNSClient.resolve(server.host, role: .proxyServer)
        let nw = NWConnection(host: host, port: nwPort, using: parameters)
        transport.attach(nw)

        do {
            try await transport.waitUntilReady(nw)
            if let reality {
                self.realitySession = try await REALITYHandshaker(config: reality)
                    .handshake(on: nw, queue: transport.queue)
            }
            try await sendRequestHeader()
        } catch {
            transport.failOpen(nw)
            throw error
        }

        transport.markEstablished()
    }

    /// SNI: explicit value, otherwise the server domain when the host is not an IP.
    private var tlsServerName: String? {
        if let sni, !sni.isEmpty { return sni }
        if case .domain(let domain) = server.host { return domain }
        return nil
    }

    private func sendRequestHeader() async throws {
        guard !requestHeaderSent else { return }
        let header = VLESSHeader(
            userID: userID,
            destination: endpoint,
            command: command
        )
        let data = try header.encode()
        try await send(data)
        requestHeaderSent = true
    }

    private func consumeResponseHeaderIfNeeded() async throws {
        guard !responseHeaderConsumed else { return }
        while true {
            if let parsed = try VLESSResponseHeader.consume(transport.inbox.readableBytes) {
                transport.inbox.consume(parsed.1)
                responseHeaderConsumed = true
                return
            }
            if transport.receiveEOF {
                throw VLESSError.truncated(
                    expected: 2,
                    actual: transport.inbox.readableByteCount
                )
            }
            switch try await receiveOnce() {
            case .eof, .needMore, .bytes:
                break
            }
        }
    }

    private func send(_ data: Data) async throws {
        let wire: Data
        if let realitySession {
            wire = try realitySession.sealApplication(data)
        } else {
            wire = data
        }
        try await transport.send(wire)
    }

    private func receiveOnce() async throws -> WireReceive {
        guard let chunk = try await transport.receiveRaw() else { return .eof }

        if let realitySession {
            try realitySession.feedWire(chunk)
            let plain = realitySession.drainPlaintext()
            if plain.isEmpty { return .needMore }
            transport.inbox.append(plain)
            return .bytes(plain.count)
        }

        transport.inbox.append(chunk)
        return .bytes(chunk.count)
    }
}
