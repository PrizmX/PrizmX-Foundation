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
    public let flow: String?

    public init(
        server: Endpoint,
        uuid: String,
        sni: String? = nil,
        tls: Bool = true,
        reality: REALITYConfig? = nil,
        flow: String? = nil
    ) {
        self.server = server
        self.uuid = uuid
        self.sni = sni
        self.tls = tls
        self.reality = reality
        self.flow = VLESSVision.normalized(flow)
    }

    public func connect(to endpoint: Endpoint) async throws -> any OutboundConnection {
        let connection = try VLESSOutboundConnection(
            server: server,
            uuid: uuid,
            target: endpoint,
            sni: sni,
            tls: tls,
            reality: reality,
            flow: flow
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
///
/// When `flow` is `xtls-rprx-vision` and `command` is TCP, the header carries
/// the protobuf Flow addon and the stream is Vision-padded until end/direct.
/// Uplink stays REALITY-sealed (`end` only); after a downlink `direct` frame
/// the peer splices raw inner-TLS bytes, so the record layer stops decrypting
/// and the rest of the stream is delivered untouched.
public final class VLESSOutboundConnection: OutboundConnection, @unchecked Sendable {

    public let endpoint: Endpoint
    public let server: Endpoint
    public let userID: UUID
    public let sni: String?
    public let tlsEnabled: Bool
    public let reality: REALITYConfig?
    public let flow: String?
    public let command: VLESSCommand

    public var state: OutboundConnectionState {
        transport.state
    }

    /// Downlink switched to raw passthrough after a Vision `direct` frame
    /// (tests / diagnostics).
    var downlinkIsRaw: Bool {
        realitySession?.isRawMode ?? false
    }

    private let transport: NWStreamTransport
    /// Serializes vision encode + header flush + TLS seal. The relay reads
    /// (downlink) and writes (uplink) from concurrent tasks; without this the
    /// TLS record sequence and wire order race.
    private let sendMutex = AsyncMutex()
    private var realitySession: REALITYSession?
    private var visionWriter: VLESSVisionWriter?
    private var visionReader: VLESSVisionReader?
    private var visionApp = Data()
    private var visionResponsePending = Data()
    private var unsentHeader: Data?
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
    ///   - reality: Optional REALITY handshake provider.
    ///   - flow: Optional VLESS flow (`xtls-rprx-vision`). Applied on TCP only.
    ///   - command: `tcp` (default) or `udp`.
    public init(
        server: Endpoint,
        uuid: String,
        target: Endpoint,
        sni: String? = nil,
        tls: Bool = true,
        reality: REALITYConfig? = nil,
        flow: String? = nil,
        command: VLESSCommand = .tcp
    ) throws {
        self.server = server
        self.endpoint = target
        self.userID = try VLESSUserID.parse(uuid)
        self.sni = sni
        self.tlsEnabled = tls
        self.reality = reality
        self.flow = VLESSVision.normalized(flow)
        self.command = command
        self.transport = NWStreamTransport(
            queueLabel: "prizmx.vless.outbound",
            endpoint: target,
            errorPeer: server
        )
        if command == .tcp, VLESSVision.isEnabled(self.flow) {
            self.visionWriter = VLESSVisionWriter(userID: self.userID)
            self.visionReader = VLESSVisionReader(userID: self.userID)
        }
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
            try await self.sendPayload(data)
            return data.count
        }
    }

    public func read(into buffer: UnsafeMutableRawBufferPointer) async throws -> Int {
        if buffer.isEmpty { return 0 }
        try await transport.ensureOpen { try await self.connectAndHandshake() }
        await transport.readMutex.acquire()
        defer { transport.readMutex.release() }
        try transport.ensureNotClosed()

        try await flushHeaderIfNeeded()
        if visionReader != nil {
            return try await readVision(into: buffer)
        }
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

    /// Vision downlink: decrypt one record at a time and hand plaintext to the
    /// unpadding reader. On a `command=direct` frame the peer starts splicing
    /// raw (unencrypted) inner-TLS bytes, so the record layer switches to raw
    /// mode and buffered wire bytes are delivered untouched.
    private func readVision(into buffer: UnsafeMutableRawBufferPointer) async throws -> Int {
        while true {
            if !visionApp.isEmpty {
                let take = min(buffer.count, visionApp.count)
                visionApp.withUnsafeBytes { src in
                    buffer.copyMemory(
                        from: UnsafeRawBufferPointer(rebasing: src.prefix(take))
                    )
                }
                visionApp.removeFirst(take)
                return take
            }
            if transport.receiveEOF { return 0 }

            switch try await receiveVisionOnce() {
            case .eof:
                if !visionApp.isEmpty { continue }
                return 0
            case .needMore, .bytes:
                continue
            }
        }
    }

    private func receiveVisionOnce() async throws -> WireReceive {
        guard let visionReader else { return .eof }
        guard let chunk = try await transport.receiveRaw() else { return .eof }

        guard let realitySession else {
            // Vision over Network.framework TLS: chunks are already plaintext.
            let plain = try stripVisionResponseHeader(from: chunk)
            guard !plain.isEmpty else { return .needMore }
            let out = visionReader.feed(plain)
            visionApp.append(out)
            return out.isEmpty ? .needMore : .bytes(out.count)
        }
        if realitySession.isRawMode {
            visionApp.append(chunk)
            return .bytes(chunk.count)
        }
        realitySession.appendWire(chunk)
        var produced = 0
        while let record = try realitySession.decryptNextRecord() {
            produced += record.count
            let plain = try stripVisionResponseHeader(from: record)
            if !plain.isEmpty {
                visionApp.append(visionReader.feed(plain))
            }
            if visionReader.sawDirectCommand {
                realitySession.enableRawMode()
                visionApp.append(realitySession.drainRawIncoming())
                break
            }
        }
        return produced > 0 ? .bytes(produced) : .needMore
    }

    /// Strips the 2-byte (plus addons) VLESS response header from the first
    /// decrypted records; later records pass through unchanged.
    private func stripVisionResponseHeader(from record: Data) throws -> Data {
        guard !responseHeaderConsumed else { return record }
        visionResponsePending.append(record)
        guard let parsed = try VLESSResponseHeader.consume(
            visionResponsePending.withUnsafeBytes { $0 }
        ) else {
            return Data()
        }
        responseHeaderConsumed = true
        let rest = Data(visionResponsePending.dropFirst(parsed.1))
        visionResponsePending.removeAll(keepingCapacity: false)
        return rest
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
        let addons: Data
        if visionWriter != nil, let flow {
            addons = VLESSVision.addons(flow: flow)
        } else {
            addons = Data()
        }
        let header = VLESSHeader(
            userID: userID,
            destination: endpoint,
            command: command,
            addons: addons
        )
        unsentHeader = try header.encode()
        requestHeaderSent = true
    }

    /// Vision needs the first padded frame in the same TLS record as the VLESS
    /// header (Xray reads both from the first application buffer).
    private func sendPayload(_ data: Data) async throws {
        try await sendSerialized {
            let body: Data
            if let visionWriter {
                body = visionWriter.encode(data, longPadding: unsentHeader != nil)
            } else {
                body = data
            }
            return takeHeaderPayload(extra: body)
        }
    }

    private func flushHeaderIfNeeded() async throws {
        try await sendSerialized { takeHeaderPayload(extra: nil) }
    }

    private func sendSerialized(_ buildPayload: () -> Data) async throws {
        await sendMutex.acquire()
        defer { sendMutex.release() }
        let payload = buildPayload()
        guard !payload.isEmpty else { return }
        try await sendWire(payload)
    }

    private func takeHeaderPayload(extra: Data?) -> Data {
        guard let header = unsentHeader else { return extra ?? Data() }
        unsentHeader = nil
        var payload = header
        if let extra, !extra.isEmpty {
            payload.append(extra)
        } else if let visionWriter {
            payload.append(visionWriter.camouflage())
        }
        return payload
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

    private func sendWire(_ data: Data) async throws {
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
