import Foundation

/// ShadowsocksR options of a node besides server and password (Clash
/// `cipher` / `protocol` / `protocol-param` / `obfs` / `obfs-param`).
public struct ShadowsocksRSettings: Sendable, Hashable {
    public var cipher: SSRCipher
    public var protocolKind: SSRProtocolKind
    public var protocolParam: String
    public var obfs: SSRObfsKind
    public var obfsParam: String

    public init(
        cipher: SSRCipher,
        protocolKind: SSRProtocolKind = .origin,
        protocolParam: String = "",
        obfs: SSRObfsKind = .plain,
        obfsParam: String = ""
    ) {
        self.cipher = cipher
        self.protocolKind = protocolKind
        self.protocolParam = protocolParam
        self.obfs = obfs
        self.obfsParam = obfsParam
    }
}

/// TCP ShadowsocksR client.
///
/// Uplink: the protocol plugin frames the plaintext (address header first),
/// the stream cipher encrypts it behind the client IV, and the obfs layer
/// installed on the transport wraps the result. The downlink runs the same
/// layers in reverse: obfs, server IV + stream cipher, protocol plugin.
public final class SSROutboundConnection: OutboundConnection, @unchecked Sendable {
    /// Logical peer (the proxied destination in the address header).
    public let endpoint: Endpoint
    public let server: Endpoint
    public let settings: ShadowsocksRSettings

    public var state: OutboundConnectionState { transport.state }

    /// Plaintext bytes framed and encrypted per send.
    static let maxWriteBatch = 64 * 1024

    private let transport: NWStreamTransport
    private let key: [UInt8]
    private let clientIV: [UInt8]
    /// Plugin state: `encode` runs under `writeMutex`, `decode` under
    /// `readMutex`; decoding starts only after the header flush.
    private let codec: any SSRProtocolCodec
    /// `head_len` for http obfs: the client IV plus the address header.
    private let obfsHeadLength: Int

    // Send path (transport.writeMutex)
    private let encryptor: SSRStreamCrypter
    private var pendingHeader: [UInt8]?
    private var ivSent = false

    // Receive path (transport.readMutex)
    private var decryptor: SSRStreamCrypter?
    private var serverIV: [UInt8] = []
    private let plaintext = DirectBuffer()

    public init(server: Endpoint, password: String, settings: ShadowsocksRSettings, target: Endpoint) throws {
        self.server = server
        self.endpoint = target
        self.settings = settings
        let cipher = settings.cipher
        key = cipher.key(password: password)
        clientIV = SSRBytes.random(cipher.ivByteCount)
        encryptor = try cipher.makeCrypter(key: key, iv: clientIV, encrypt: true)
        let header = try ShadowsocksAddress.encode(target)
        pendingHeader = header
        obfsHeadLength = clientIV.count + SSRBytes.headSize(header)
        codec = SSRProtocolFactory.make(settings.protocolKind, context: SSRContext(
            key: key,
            iv: clientIV,
            protocolParam: settings.protocolParam,
            overhead: settings.protocolKind.overhead + settings.obfs.overhead
        ))
        transport = NWStreamTransport(queueLabel: "prizmx.ssr.outbound", endpoint: target, errorPeer: server)
    }

    // MARK: OutboundConnection

    public func open() async throws {
        try await transport.open { try await self.connectTCP() }
    }

    public func write(_ buffer: UnsafeRawBufferPointer) async throws -> Int {
        try await transport.write(buffer, connecting: { try await self.connectTCP() }) { buffer in
            let take = min(buffer.count, Self.maxWriteBatch)
            try await self.send(Array(buffer.prefix(take)))
            return take
        }
    }

    public func read(into buffer: UnsafeMutableRawBufferPointer) async throws -> Int {
        if buffer.isEmpty { return 0 }
        try await transport.ensureOpen { try await self.connectTCP() }
        // The server answers only after the address header (and, with
        // tls1.2_ticket_auth, the ClientHello it triggers) went out.
        if !transport.isHandshakeFlushed {
            try await flushHeader()
        }
        await transport.readMutex.acquire()
        defer { transport.readMutex.release() }
        try transport.ensureReadable()

        while plaintext.readableByteCount == 0 {
            guard let chunk = try await transport.receiveRaw() else { return 0 }
            let plain = try decrypt([UInt8](chunk))
            if !plain.isEmpty { plaintext.append(plain) }
        }
        let take = min(buffer.count, plaintext.readableByteCount)
        buffer.copyMemory(from: UnsafeRawBufferPointer(rebasing: plaintext.readableBytes.prefix(take)))
        plaintext.consume(take)
        return take
    }

    public func close() async {
        await transport.close()
    }

    /// Flushes the address header if nothing was written yet, then FIN.
    public func closeWrite() async {
        guard state == .established else { return }
        if !transport.isHandshakeFlushed {
            try? await flushHeader()
        }
        await transport.finishWriting()
    }

    public var supportsHalfClose: Bool { true }

    // MARK: Wire

    private func connectTCP() async throws {
        try await transport.dial(server, settings: StreamSettings())
        if settings.obfs != .plain {
            transport.install(SSRObfs.stream(
                settings.obfs,
                lower: transport.socketStream,
                host: server.host.description,
                port: server.port,
                param: settings.obfsParam,
                key: key,
                headLength: obfsHeadLength
            ))
        }
        transport.markEstablished()
    }

    /// Plugin → stream cipher (IV first) → obfs. The first send carries the
    /// address header ahead of `data`.
    private func send(_ data: [UInt8]) async throws {
        var plain = data
        if let header = pendingHeader {
            plain = header + plain
            pendingHeader = nil
            transport.markHandshakeFlushed()
        }
        var wire = encryptor.update(try codec.encode(plain))
        if !ivSent {
            ivSent = true
            wire = clientIV + wire
        }
        try await transport.send(Data(wire))
    }

    private func flushHeader() async throws {
        await transport.writeMutex.acquire()
        defer { transport.writeMutex.release() }
        try transport.ensureWritable()
        if pendingHeader != nil {
            try await send([])
        }
    }

    /// Server IV (first `ivByteCount` bytes), then stream cipher → plugin.
    private func decrypt(_ chunk: [UInt8]) throws -> [UInt8] {
        var bytes = chunk
        if decryptor == nil {
            let ivCount = settings.cipher.ivByteCount
            let take = min(ivCount - serverIV.count, bytes.count)
            serverIV += bytes.prefix(take)
            bytes.removeFirst(take)
            guard serverIV.count == ivCount else { return [] }
            decryptor = try settings.cipher.makeCrypter(key: key, iv: serverIV, encrypt: false)
        }
        guard let decryptor, !bytes.isEmpty else { return [] }
        return try codec.decode(decryptor.update(bytes))
    }
}
