import Foundation

/// VMess AEAD client (`alterId: 0`), as Xray / sing-box speak it today.
///
/// `open()` dials per `StreamSettings` (TCP, TLS, WebSocket, …). The sealed
/// request header goes out with the first uplink chunk (or alone, before the
/// first read). Downlink starts with the AEAD response header, then chunks.
/// Half-close sends the in-band end-of-stream chunk, so it works over any
/// transport.
///
/// Legacy MD5 auth (`alterId > 0`) is not implemented: servers since 2022
/// accept AEAD for every user.
public final class VMessOutboundConnection: OutboundConnection, @unchecked Sendable {
    public let endpoint: Endpoint
    public let server: Endpoint
    public let security: VMessSecurity
    public let command: VMessCommand

    public var state: OutboundConnectionState { transport.state }

    private let commandKey: [UInt8]
    private let settings: StreamSettings
    private let transport: NWStreamTransport
    private let session: VMessSession
    private let options: UInt8
    private let responseHeader: VMessResponseHeader

    // Uplink (transport.writeMutex)
    private var sealer: VMessChunkCipher
    private var pendingHeader: [UInt8]?
    private var header: VMessRequestHeader

    // Downlink (transport.readMutex)
    private var opener: VMessChunkCipher
    private var responseConsumed = false
    private var downlinkEnded = false
    private let wire = DirectBuffer()
    private let plain = DirectBuffer()

    /// - Parameters:
    ///   - server: VMess server.
    ///   - uuid: User id.
    ///   - security: Body security (`auto` → AES-128-GCM).
    ///   - target: Destination in the request header.
    ///   - command: TCP stream or UDP (one datagram per chunk).
    ///   - settings: TCP / TLS / transport dialing.
    public init(
        server: Endpoint,
        uuid: String,
        security: VMessSecurity = .auto,
        target: Endpoint,
        command: VMessCommand = .tcp,
        settings: StreamSettings = StreamSettings()
    ) throws {
        guard let userID = UUID(uuidString: uuid) else { throw VMessError.invalidUserID(uuid) }
        self.server = server
        self.endpoint = target
        self.security = security
        self.command = command
        self.settings = settings
        self.commandKey = VMessKDF.commandKey(userID: userID)
        let session = VMessSession.random()
        self.session = session
        let options = VMessRequestHeader.options(for: security)
        self.options = options
        self.header = VMessRequestHeader(
            session: session,
            options: options,
            security: security,
            command: command,
            target: target,
            padding: (0..<Int.random(in: 0..<16)).map { _ in UInt8.random(in: 0...255) }
        )
        self.responseHeader = VMessResponseHeader(session: session)
        self.sealer = VMessChunkCipher(security: security, key: session.requestKey, iv: session.requestIV, options: options)
        self.opener = VMessChunkCipher(security: security, key: session.responseKey, iv: session.responseIV, options: options)
        self.transport = NWStreamTransport(queueLabel: "prizmx.vmess.outbound", endpoint: target, errorPeer: server)
    }

    private var chunked: Bool { options & VMessOption.chunkStream != 0 }

    // MARK: OutboundConnection

    public func open() async throws {
        try await transport.open { try await self.connect() }
    }

    public func write(_ buffer: UnsafeRawBufferPointer) async throws -> Int {
        try await transport.write(buffer, connecting: { try await self.connect() }) { buffer in
            try await self.sendPayload(Array(buffer), splitting: true)
            return buffer.count
        }
    }

    public func read(into buffer: UnsafeMutableRawBufferPointer) async throws -> Int {
        if buffer.isEmpty { return 0 }
        try await transport.ensureOpen { try await self.connect() }
        if !transport.isHandshakeFlushed {
            try await flushHeader()
        }
        await transport.readMutex.acquire()
        defer { transport.readMutex.release() }
        try transport.ensureReadable()

        while plain.readableByteCount == 0 {
            guard let chunk = try await nextChunk() else { return 0 }
            plain.append(chunk)
        }
        let take = min(buffer.count, plain.readableByteCount)
        buffer.copyMemory(from: UnsafeRawBufferPointer(rebasing: plain.readableBytes.prefix(take)))
        plain.consume(take)
        return take
    }

    public func close() async {
        await transport.close()
    }

    /// Sends the end-of-stream chunk (chunked security), then half-closes
    /// the transport too where it can: sing-box ends the uplink only on the
    /// transport's EOF (it reads the AEAD end chunk as an empty payload).
    public func closeWrite() async {
        guard state == .established else { return }
        if chunked {
            await transport.writeMutex.acquire()
            let sent: Bool
            if (try? transport.ensureWritable()) != nil {
                sent = (try? await sendChunks([[]])) != nil
            } else {
                sent = false
            }
            transport.writeMutex.release()
            guard sent else { return }
        } else if !transport.isHandshakeFlushed {
            try? await flushHeader()
        }
        await transport.finishWriting()
    }

    public var supportsHalfClose: Bool { true }

    // MARK: Datagrams (UDP command)

    /// Sends one datagram as exactly one chunk.
    func sendPacket(_ payload: [UInt8]) async throws {
        try await transport.ensureOpen { try await self.connect() }
        await transport.writeMutex.acquire()
        defer { transport.writeMutex.release() }
        try transport.ensureWritable()
        try await sendPayload(payload, splitting: false)
    }

    /// Next downlink datagram (one chunk); `nil` at end of stream.
    func receivePacket() async throws -> [UInt8]? {
        try await transport.ensureOpen { try await self.connect() }
        if !transport.isHandshakeFlushed {
            try await flushHeader()
        }
        await transport.readMutex.acquire()
        defer { transport.readMutex.release() }
        try transport.ensureReadable()
        return try await nextChunk()
    }

    // MARK: Uplink

    private func connect() async throws {
        try await transport.dial(server, settings: settings)
        do {
            pendingHeader = try VMessRequestHeader.seal(try header.encode(), commandKey: commandKey)
        } catch {
            transport.failOpen()
            throw error
        }
        transport.markEstablished()
    }

    /// Splits `payload` into chunks (stream) or one chunk (packet) and sends
    /// them, prefixed by the request header if it has not gone out yet.
    private func sendPayload(_ payload: [UInt8], splitting: Bool) async throws {
        guard chunked else {
            try await sendWire(payload)
            return
        }
        var pieces: [[UInt8]] = []
        if splitting {
            var offset = 0
            while offset < payload.count {
                let end = min(offset + VMessChunkCipher.maxPayload, payload.count)
                pieces.append(Array(payload[offset..<end]))
                offset = end
            }
        } else {
            guard payload.count <= VMessChunkCipher.maxPayload else {
                throw VMessError.chunkTooLarge(payload.count)
            }
            pieces = [payload]
        }
        guard !pieces.isEmpty else { return }
        try await sendChunks(pieces)
    }

    private func sendChunks(_ pieces: [[UInt8]]) async throws {
        var wireBytes: [UInt8] = []
        for piece in pieces {
            wireBytes += try sealer.seal(piece)
        }
        try await sendWire(wireBytes)
    }

    /// Prepends the request header to the first send.
    private func sendWire(_ bytes: [UInt8]) async throws {
        var data = Data()
        if let header = pendingHeader {
            pendingHeader = nil
            transport.markHandshakeFlushed()
            data.append(contentsOf: header)
        }
        data.append(contentsOf: bytes)
        guard !data.isEmpty else { return }
        try await transport.send(data)
    }

    /// First read before any write: the server answers only after the header.
    private func flushHeader() async throws {
        await transport.writeMutex.acquire()
        defer { transport.writeMutex.release() }
        try transport.ensureWritable()
        try await sendWire([])
    }

    // MARK: Downlink

    /// Next chunk payload (raw bytes for `zero`); `nil` at end of stream.
    private func nextChunk() async throws -> [UInt8]? {
        if downlinkEnded { return nil }
        if !responseConsumed {
            try await consumeResponseHeader()
        }
        guard chunked else {
            if wire.readableByteCount > 0 {
                defer { wire.clear() }
                return Array(wire.readableBytes)
            }
            guard let chunk = try await transport.receiveRaw() else { return nil }
            return Array(chunk)
        }
        while true {
            // A clean close between chunks also ends the stream: Xray sends
            // no end-of-stream chunk downstream.
            guard let field = try await take(2, endOfStreamAllowed: true) else {
                downlinkEnded = true
                return nil
            }
            let (size, padding) = opener.openLength(field)
            if opener.isEndOfStream(size: size, padding: padding) {
                downlinkEnded = true
                return nil
            }
            let payload = try opener.open(try await take(size), padding: padding)
            if !payload.isEmpty { return payload }
        }
    }

    private func consumeResponseHeader() async throws {
        let length = try responseHeader.openLength(try await take(VMessResponseHeader.lengthRecordByteCount))
        let header = try responseHeader.openPayload(try await take(length + 16))
        guard header.count >= 4, header[0] == session.responseAuth else {
            throw VMessError.responseMismatch
        }
        responseConsumed = true
    }

    /// Exactly `count` downlink bytes.
    private func take(_ count: Int) async throws -> [UInt8] {
        guard let bytes = try await take(count, endOfStreamAllowed: false) else {
            throw VMessError.truncated
        }
        return bytes
    }

    /// Exactly `count` bytes, or `nil` when the stream ends cleanly before
    /// the first of them (only if `endOfStreamAllowed`).
    private func take(_ count: Int, endOfStreamAllowed: Bool) async throws -> [UInt8]? {
        while wire.readableByteCount < count {
            guard let chunk = try await transport.receiveRaw() else {
                if endOfStreamAllowed && wire.readableByteCount == 0 { return nil }
                throw VMessError.truncated
            }
            wire.append(chunk)
        }
        let bytes = Array(wire.readableBytes.prefix(count))
        wire.consume(count)
        return bytes
    }
}

/// VMess UDP: the `udp` command, one datagram per chunk.
public final class VMessDatagramOutbound: DatagramOutbound, @unchecked Sendable {
    private let connection: VMessOutboundConnection

    public init(connection: VMessOutboundConnection) {
        self.connection = connection
    }

    public func open() async throws {
        try await connection.open()
    }

    public func send(_ payload: Data, to _: Endpoint) async throws {
        try await connection.sendPacket(Array(payload))
    }

    public func receive() async throws -> Data? {
        try await connection.receivePacket().map { Data($0) }
    }

    public func close() async {
        await connection.close()
    }
}
