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
    /// Clash `skip-cert-verify`: accept any server certificate (plain TLS only).
    public let skipCertVerify: Bool
    /// Offered ALPN (`nil` = `h2`, `http/1.1`).
    public let alpn: [String]?
    /// Transport (`tcp`, `ws`, …). REALITY / Vision require `tcp`.
    public let network: StreamTransport

    public init(
        server: Endpoint,
        uuid: String,
        sni: String? = nil,
        tls: Bool = true,
        reality: REALITYConfig? = nil,
        flow: String? = nil,
        skipCertVerify: Bool = false,
        alpn: [String]? = nil,
        network: StreamTransport = .tcp
    ) {
        self.server = server
        self.uuid = uuid
        self.sni = sni
        self.tls = tls
        self.reality = reality
        self.flow = VLESSVision.normalized(flow)
        self.skipCertVerify = skipCertVerify
        self.alpn = alpn
        self.network = network
    }

    public func connect(to endpoint: Endpoint) async throws -> any OutboundConnection {
        let connection = try VLESSOutboundConnection(
            server: server,
            uuid: uuid,
            target: endpoint,
            sni: sni,
            tls: tls,
            reality: reality,
            flow: flow,
            skipCertVerify: skipCertVerify,
            alpn: alpn,
            network: network
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
/// Uplink stays TLS-sealed (`end` only); after a downlink `direct` frame
/// the peer splices raw inner-TLS bytes, so the record layer stops decrypting
/// and the rest of the stream is delivered untouched.
///
/// Vision over plain TLS (no REALITY) therefore also uses the userspace
/// TLS 1.3 client — Network.framework TLS cannot surrender the raw socket
/// after `direct` — with standard Web-PKI authentication (system trust +
/// hostname, CertificateVerify, ALPN). Xray requires TLS 1.3 for Vision,
/// which is all this client speaks.
public final class VLESSOutboundConnection: OutboundConnection, @unchecked Sendable {

    public let endpoint: Endpoint
    public let server: Endpoint
    public let userID: UUID
    public let sni: String?
    public let tlsEnabled: Bool
    public let reality: REALITYConfig?
    public let flow: String?
    public let command: VLESSCommand
    public let skipCertVerify: Bool
    public let alpn: [String]?
    public let network: StreamTransport

    public var state: OutboundConnectionState {
        transport.state
    }

    /// Downlink switched to raw passthrough after a Vision `direct` frame
    /// (tests / diagnostics).
    var downlinkIsRaw: Bool {
        userspaceTLS?.isRawMode ?? false
    }

    /// REALITY, or Vision over plain TLS: TLS 1.3 runs in userspace on a raw
    /// TCP connection instead of Network.framework TLS.
    var usesUserspaceTLS: Bool {
        reality != nil || (tlsEnabled && visionWriter != nil)
    }

    private let transport: NWStreamTransport
    /// Serializes vision encode + header flush + TLS seal. The relay reads
    /// (downlink) and writes (uplink) from concurrent tasks; without this the
    /// TLS record sequence and wire order race.
    private let sendMutex = AsyncMutex()
    /// Userspace TLS 1.3 record layer (REALITY or Vision+TLS). Set once in
    /// `connectAndHandshake` before `markEstablished`.
    private var userspaceTLS: TLS13RecordLayer?
    private var visionWriter: VLESSVisionWriter?
    private var visionReader: VLESSVisionReader?
    private var visionApp = Data()
    private var visionResponsePending = Data()
    private var unsentHeader: Data?
    private var requestHeaderSent = false
    private var responseHeaderConsumed = false

    enum WireReceive: Equatable {
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
    ///   - skipCertVerify: Accept any server certificate (explicit opt-in).
    ///   - alpn: Offered ALPN; `nil` keeps the platform / `h2,http/1.1` default.
    ///   - network: Transport above TCP/TLS. Anything but `tcp` excludes
    ///     REALITY and Vision (rejected at `open()`).
    public init(
        server: Endpoint,
        uuid: String,
        target: Endpoint,
        sni: String? = nil,
        tls: Bool = true,
        reality: REALITYConfig? = nil,
        flow: String? = nil,
        command: VLESSCommand = .tcp,
        skipCertVerify: Bool = false,
        alpn: [String]? = nil,
        network: StreamTransport = .tcp
    ) throws {
        self.server = server
        self.endpoint = target
        self.userID = try VLESSUserID.parse(uuid)
        self.sni = sni
        self.tlsEnabled = tls
        self.reality = reality
        self.flow = VLESSVision.normalized(flow)
        self.command = command
        self.skipCertVerify = skipCertVerify
        self.alpn = alpn
        self.network = network
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
        try transport.ensureReadable()

        // Lock-free check: only the very first read may need `sendMutex`,
        // so a stalled upload never blocks the download direction.
        if !transport.isHandshakeFlushed {
            try await flushHeaderIfNeeded()
        }
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

        return try ingestVisionWire(chunk, reader: visionReader)
    }

    /// Feeds one wire chunk through the Vision downlink (split out for tests).
    func ingestVisionWire(_ chunk: Data, reader visionReader: VLESSVisionReader) throws -> WireReceive {
        guard let tlsLayer = userspaceTLS else {
            // Vision without TLS: chunks are already plaintext.
            let plain = try stripVisionResponseHeader(from: chunk)
            guard !plain.isEmpty else { return .needMore }
            let out = visionReader.feed(plain)
            visionApp.append(out)
            return out.isEmpty ? .needMore : .bytes(out.count)
        }
        if tlsLayer.isRawMode {
            visionApp.append(chunk)
            return .bytes(chunk.count)
        }
        tlsLayer.appendWire(chunk)
        var produced = 0
        while let record = try tlsLayer.decryptNextRecord() {
            produced += record.count
            let plain = try stripVisionResponseHeader(from: record)
            if !plain.isEmpty {
                visionApp.append(visionReader.feed(plain))
            }
            if visionReader.sawDirectCommand {
                tlsLayer.enableRawMode()
                visionApp.append(tlsLayer.drainRawIncoming())
                break
            }
        }
        if tlsLayer.receivedCloseNotify { transport.markReceiveEOF() }
        return produced > 0 ? .bytes(produced) : .needMore
    }

    /// Test hook: installs a record layer as if the userspace TLS handshake ran.
    func installUserspaceTLSForTesting(_ layer: TLS13RecordLayer) {
        userspaceTLS = layer
    }

    /// Test hook: drains decoded Vision downlink bytes.
    func takeVisionAppForTesting() -> Data {
        defer { visionApp.removeAll() }
        return visionApp
    }

    /// Strips the 2-byte (plus addons) VLESS response header from the first
    /// decrypted records; later records pass through unchanged.
    private func stripVisionResponseHeader(from record: Data) throws -> Data {
        guard !responseHeaderConsumed else { return record }
        visionResponsePending.append(record)
        // Parse inside the closure: the buffer pointer must not escape it
        // (small `Data` is stored inline and would dangle).
        let parsed = try visionResponsePending.withUnsafeBytes { raw in
            try VLESSResponseHeader.consume(raw)
        }
        guard let parsed else {
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

    /// Half-close the uplink: flushes a still-pending request header, sends
    /// TLS `close_notify` on the userspace TLS path (Network.framework TLS
    /// emits its own), then TCP FIN. Reads keep working.
    public func closeWrite() async {
        guard state == .established else { return }
        if !transport.isHandshakeFlushed {
            try? await flushHeaderIfNeeded()
        }
        let tlsLayer = userspaceTLS
        await transport.finishWriting {
            await self.sendMutex.acquire()
            defer { self.sendMutex.release() }
            // The uplink stays TLS-sealed even after a downlink Vision
            // `direct` switch, so close_notify is always well-formed here.
            if let tlsLayer {
                try await self.transport.send(try tlsLayer.sealCloseNotify())
            }
        }
    }

    public var supportsHalfClose: Bool { true }

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
        if network != .tcp {
            try await connectOverTransport()
            return
        }
        guard server.port > 0, let nwPort = NWEndpoint.Port(rawValue: server.port) else {
            throw OutboundError.invalidEndpoint(server)
        }

        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true

        let tlsOptions: NWProtocolTLS.Options?
        if usesUserspaceTLS || !tlsEnabled {
            tlsOptions = nil
        } else {
            tlsOptions = TLSClient.options(
                serverName: tlsServerName,
                skipVerification: skipCertVerify,
                alpn: alpn
            )
        }

        let parameters = NWParameters(tls: tlsOptions, tcp: tcp)
        parameters.preferNoProxies = true

        let host = try await DNSClient.resolve(server.host, role: .proxyServer)
        let nw = NWConnection(host: host, port: nwPort, using: parameters)
        transport.attach(nw)

        do {
            try await transport.waitUntilReady(nw)
            if let reality {
                self.userspaceTLS = try await REALITYHandshaker(config: reality)
                    .handshake(on: nw, queue: transport.queue)
                    .recordLayer
            } else if usesUserspaceTLS {
                self.userspaceTLS = try await TLS13ClientHandshake.run(
                    on: nw,
                    queue: transport.queue,
                    serverName: tlsServerName,
                    verifyName: tlsServerName ?? serverIPLiteral,
                    alpn: alpn ?? TLS13.defaultALPN,
                    skipCertificateVerification: skipCertVerify
                )
            }
            try await sendRequestHeader()
        } catch {
            transport.failOpen(nw)
            throw error
        }

        transport.markEstablished()
    }

    /// WebSocket-style transports: Network.framework TLS (when on) plus the
    /// transport layer from the shared dialer, then the VLESS header.
    private func connectOverTransport() async throws {
        guard reality == nil, visionWriter == nil else {
            transport.markClosed()
            throw VLESSError.transportUnsupported(network.name)
        }
        let tls = tlsEnabled
            ? TLSSettings(serverName: tlsServerName, skipCertVerify: skipCertVerify, alpn: alpn)
            : nil
        try await transport.dial(server, settings: StreamSettings(tls: tls, transport: network))
        do {
            try await sendRequestHeader()
        } catch {
            transport.failOpen()
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

    /// IP-literal server with no SNI: the certificate must cover the IP.
    private var serverIPLiteral: String? {
        if case .domain = server.host { return nil }
        return server.host.description
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
        transport.markHandshakeFlushed()
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
        if let userspaceTLS {
            wire = try userspaceTLS.sealApplication(data)
        } else {
            wire = data
        }
        try await transport.send(wire)
    }

    private func receiveOnce() async throws -> WireReceive {
        guard let chunk = try await transport.receiveRaw() else { return .eof }

        if let userspaceTLS {
            try userspaceTLS.feedWire(chunk)
            let plain = userspaceTLS.drainPlaintext()
            if userspaceTLS.receivedCloseNotify { transport.markReceiveEOF() }
            if plain.isEmpty { return .needMore }
            transport.inbox.append(plain)
            return .bytes(plain.count)
        }

        transport.inbox.append(chunk)
        return .bytes(chunk.count)
    }
}
