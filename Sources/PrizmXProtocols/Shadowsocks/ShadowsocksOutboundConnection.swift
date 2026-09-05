import Foundation
import Network
import os

// MARK: - Factory

/// Builds Shadowsocks-AEAD outbound tunnels to arbitrary targets through a
/// single SIP008 server (`server` / `password` / `method`).
public struct ShadowsocksOutboundFactory: OutboundConnectionFactory, Sendable {
    public let server: Endpoint
    public let password: String
    public let cipher: ShadowsocksCipher

    public init(server: Endpoint, password: String, cipher: ShadowsocksCipher) {
        self.server = server
        self.password = password
        self.cipher = cipher
    }

    public func connect(to endpoint: Endpoint) async throws -> any OutboundConnection {
        let connection = ShadowsocksOutboundConnection(
            server: server,
            password: password,
            cipher: cipher,
            target: endpoint
        )
        return connection
    }
}

// MARK: - Outbound connection

/// TCP Shadowsocks-AEAD client (`aes-128-gcm` / `aes-256-gcm`).
///
/// `open()` establishes the underlying `NWConnection`. The first application
/// packet is:
/// `[client salt] + AEAD(target address header [+ initial write bytes])`.
///
/// Subsequent `write`s are chunked at `0x3FFF` bytes. `read` consumes the
/// server salt on first use, then decrypts chunks with an independent nonce.
public final class ShadowsocksOutboundConnection: OutboundConnection, @unchecked Sendable {

    /// Logical peer (the proxied destination encoded in the SS address header).
    public let endpoint: Endpoint
    /// Shadowsocks server this connection dials.
    public let server: Endpoint
    public let cipher: ShadowsocksCipher

    public var state: OutboundConnectionState {
        transport.state
    }

    private let preSharedKey: [UInt8]
    private let transport: NWStreamTransport

    // Send path (transport.writeMutex)
    private var encryptor: ShadowsocksAEADContext?
    private var clientSalt: [UInt8]
    private var pendingAddressHeader: [UInt8]?
    private var saltSent = false
    private let sendPlaintext = DirectBuffer()
    private let sendCiphertext = DirectBuffer()

    // Receive path (transport.readMutex)
    private var decryptor: ShadowsocksAEADContext?
    private let recvCiphertext = DirectBuffer()
    private let recvPlaintext = DirectBuffer()

    /// - Parameters:
    ///   - server: Shadowsocks server host and port.
    ///   - password: SIP008 password; converted to a master key via EVP_BytesToKey.
    ///   - cipher: `aes-128-gcm` or `aes-256-gcm`.
    ///   - target: Destination the server should connect to (SOCKS address header).
    public init(
        server: Endpoint,
        password: String,
        cipher: ShadowsocksCipher,
        target: Endpoint
    ) {
        self.server = server
        self.endpoint = target
        self.cipher = cipher
        self.preSharedKey = cipher.masterKey(fromPassword: password)
        self.clientSalt = cipher.randomSalt()
        self.transport = NWStreamTransport(
            queueLabel: "prizmx.shadowsocks.outbound",
            endpoint: target,
            errorPeer: server
        )
    }

    /// Test/advanced initializer with an explicit master key (PSK).
    public init(
        server: Endpoint,
        preSharedKey: [UInt8],
        cipher: ShadowsocksCipher,
        target: Endpoint,
        clientSalt: [UInt8]? = nil
    ) {
        self.server = server
        self.endpoint = target
        self.cipher = cipher
        self.preSharedKey = preSharedKey
        self.clientSalt = clientSalt ?? cipher.randomSalt()
        self.transport = NWStreamTransport(
            queueLabel: "prizmx.shadowsocks.outbound",
            endpoint: target,
            errorPeer: server
        )
    }

    // MARK: OutboundConnection

    public func open() async throws {
        try await transport.open { try await self.connectTCP() }
    }

    public func write(_ buffer: UnsafeRawBufferPointer) async throws -> Int {
        try await transport.write(buffer, connecting: { try await self.connectTCP() }) { buffer in
            try self.prepareEncryptorIfNeeded()

            // First packet: [client salt] + AEAD(address header + initial data).
            if !self.saltSent {
                return try await self.sendHandshakeIfNeeded(prefixing: buffer)
            }

            let take = min(buffer.count, ShadowsocksAEAD.maxPayloadLength)
            let chunk = UnsafeRawBufferPointer(rebasing: buffer.prefix(take))
            try await self.encryptAndSend(plaintext: chunk)
            return take
        }
    }

    public func read(into buffer: UnsafeMutableRawBufferPointer) async throws -> Int {
        if buffer.isEmpty { return 0 }
        try await transport.ensureOpen { try await self.connectTCP() }
        try await flushHandshakeBeforeRead()

        await transport.readMutex.acquire()
        defer { transport.readMutex.release() }
        try transport.ensureNotClosed()

        while true {
            if recvPlaintext.readableByteCount > 0 {
                let take = min(buffer.count, recvPlaintext.readableByteCount)
                buffer.copyMemory(
                    from: UnsafeRawBufferPointer(
                        rebasing: recvPlaintext.readableBytes.prefix(take)
                    )
                )
                recvPlaintext.consume(take)
                return take
            }

            switch try await decryptNextChunk(into: buffer) {
            case .eof:
                return 0
            case .written(let count):
                if count > 0 { return count }
                continue
            case .buffered:
                continue
            }
        }
    }

    public func close() async {
        await transport.close()
    }

    /// `Data` convenience matching the requested outbound write surface.
    /// Copies into a scratch buffer before `await` so the `Data` storage is not
    /// required to remain stable across suspension.
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

    /// `Data` convenience matching the requested outbound read surface.
    public func read(maxLength: Int) async throws -> Data {
        let bytes = try await read(upTo: maxLength)
        return Data(bytes)
    }

    // MARK: TCP

    private func connectTCP() async throws {
        guard server.port > 0 else {
            throw OutboundError.invalidEndpoint(server)
        }
        guard let nwPort = NWEndpoint.Port(rawValue: server.port) else {
            throw OutboundError.invalidEndpoint(server)
        }

        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let parameters = NWParameters(tls: nil, tcp: tcp)
        parameters.preferNoProxies = true
        let host = try await DNSClient.resolve(server.host, role: .proxyServer)
        let nw = NWConnection(host: host, port: nwPort, using: parameters)
        transport.attach(nw)

        do {
            try await transport.waitUntilReady(nw)
        } catch {
            transport.failOpen(nw)
            throw error
        }

        transport.markEstablished()
    }

    // MARK: Handshake + encrypt

    private func prepareEncryptorIfNeeded() throws {
        guard encryptor == nil else { return }
        encryptor = try ShadowsocksAEADContext(
            cipher: cipher,
            preSharedKey: preSharedKey,
            salt: clientSalt
        )
        pendingAddressHeader = try ShadowsocksAddress.encode(endpoint)
    }

    /// Sends `[salt] + AEAD(address [+ prefix of first write])` once.
    /// Returns the number of caller bytes consumed from `prefixing`.
    @discardableResult
    private func sendHandshakeIfNeeded(prefixing buffer: UnsafeRawBufferPointer) async throws -> Int {
        guard !saltSent else { return 0 }
        try prepareEncryptorIfNeeded()
        let header = pendingAddressHeader ?? []
        let headerCount = header.count
        let take = min(buffer.count, ShadowsocksAEAD.maxPayloadLength - headerCount)

        sendPlaintext.clear()
        sendPlaintext.append(header)
        if take > 0 {
            sendPlaintext.append(UnsafeRawBufferPointer(rebasing: buffer.prefix(take)))
        }
        pendingAddressHeader = nil

        sendCiphertext.clear()
        sendCiphertext.append(clientSalt)
        saltSent = true
        try appendSealedChunk(plaintext: sendPlaintext.readableBytes)
        try await sendCiphertextBuffer()
        return take
    }

    private func flushHandshakeBeforeRead() async throws {
        await transport.writeMutex.acquire()
        defer { transport.writeMutex.release() }
        try transport.ensureNotClosed()
        try prepareEncryptorIfNeeded()
        if !saltSent {
            _ = try await sendHandshakeIfNeeded(prefixing: UnsafeRawBufferPointer(start: nil, count: 0))
        }
    }

    private func encryptAndSend(plaintext: UnsafeRawBufferPointer) async throws {
        sendCiphertext.clear()
        try appendSealedChunk(plaintext: plaintext)
        try await sendCiphertextBuffer()
    }

    private func appendSealedChunk(plaintext: UnsafeRawBufferPointer) throws {
        guard var encryptor else {
            throw OutboundError.alreadyClosed(endpoint)
        }
        let sealedCount = ShadowsocksAEAD.sealedChunkByteCount(plaintextCount: plaintext.count)
        let writable = sendCiphertext.prepareWritable(minimumCapacity: sealedCount)
        let written = try encryptor.sealChunk(plaintext: plaintext, into: writable)
        sendCiphertext.commitWritten(written)
        self.encryptor = encryptor
    }

    private func sendCiphertextBuffer() async throws {
        let readable = sendCiphertext.readableBytes
        guard readable.count > 0 else { return }
        let data = Data(readable)
        try await transport.send(data)
        sendCiphertext.clear()
    }

    // MARK: Decrypt

    private enum DecryptOutcome {
        case eof
        case written(Int)
        case buffered
    }

    /// Decrypts one chunk. Direct-writes into `buffer` when it can hold the
    /// whole payload; otherwise the payload is staged in `recvPlaintext`.
    private func decryptNextChunk(
        into buffer: UnsafeMutableRawBufferPointer
    ) async throws -> DecryptOutcome {
        try await consumeServerSaltIfNeeded()

        let lengthRecordCount = ShadowsocksAEAD.lengthRecordByteCount
        try await fillRecvCiphertext(atLeast: lengthRecordCount)
        if recvCiphertext.readableByteCount == 0 && transport.receiveEOF {
            return .eof
        }
        if recvCiphertext.readableByteCount < lengthRecordCount {
            throw ShadowsocksError.truncated(
                expected: lengthRecordCount,
                actual: recvCiphertext.readableByteCount
            )
        }

        guard var decryptor else {
            throw OutboundError.alreadyClosed(endpoint)
        }

        let lengthSlice = UnsafeRawBufferPointer(
            rebasing: recvCiphertext.readableBytes.prefix(lengthRecordCount)
        )
        let payloadLength = try decryptor.openLengthRecord(lengthSlice)
        recvCiphertext.consume(lengthRecordCount)
        self.decryptor = decryptor

        let payloadRecordCount = payloadLength + ShadowsocksAEAD.tagByteCount
        try await fillRecvCiphertext(atLeast: payloadRecordCount)
        if recvCiphertext.readableByteCount < payloadRecordCount {
            throw ShadowsocksError.truncated(
                expected: payloadRecordCount,
                actual: recvCiphertext.readableByteCount
            )
        }

        let payloadSlice = UnsafeRawBufferPointer(
            rebasing: recvCiphertext.readableBytes.prefix(payloadRecordCount)
        )

        if payloadLength == 0 {
            _ = try decryptor.openPayloadRecord(
                payloadSlice,
                into: UnsafeMutableRawBufferPointer(start: nil, count: 0)
            )
            recvCiphertext.consume(payloadRecordCount)
            self.decryptor = decryptor
            return .buffered
        }

        if buffer.count >= payloadLength && recvPlaintext.readableByteCount == 0 {
            let written = try decryptor.openPayloadRecord(payloadSlice, into: buffer)
            recvCiphertext.consume(payloadRecordCount)
            self.decryptor = decryptor
            return .written(written)
        }

        recvPlaintext.clear()
        let writable = recvPlaintext.prepareWritable(minimumCapacity: payloadLength)
        let written = try decryptor.openPayloadRecord(payloadSlice, into: writable)
        recvPlaintext.commitWritten(written)
        recvCiphertext.consume(payloadRecordCount)
        self.decryptor = decryptor
        return .buffered
    }

    private func consumeServerSaltIfNeeded() async throws {
        guard decryptor == nil else { return }
        let saltCount = cipher.saltByteCount
        try await fillRecvCiphertext(atLeast: saltCount)
        guard recvCiphertext.readableByteCount >= saltCount else {
            throw ShadowsocksError.truncated(
                expected: saltCount,
                actual: recvCiphertext.readableByteCount
            )
        }
        let salt = Array(recvCiphertext.readableBytes.bindMemory(to: UInt8.self).prefix(saltCount))
        recvCiphertext.consume(saltCount)
        decryptor = try ShadowsocksAEADContext(
            cipher: cipher,
            preSharedKey: preSharedKey,
            salt: salt
        )
    }

    private func fillRecvCiphertext(atLeast minimum: Int) async throws {
        while recvCiphertext.readableByteCount < minimum && !transport.receiveEOF {
            guard let chunk = try await transport.receiveRaw() else { break }
            recvCiphertext.append(chunk)
        }
    }
}

