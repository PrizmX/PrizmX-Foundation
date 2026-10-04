import CryptoKit
import Foundation
import os

// MARK: - Keys

/// Shadowsocks 2022 pre-shared keys: the `password` is base64 PSKs joined
/// by `:`. With more than one, the leading ones are server identity keys
/// (extensible identity headers, AES methods only) and the last is the
/// user's key.
public struct Shadowsocks2022Keys: Sendable, Hashable {
    public let cipher: ShadowsocksCipher
    public let pskList: [[UInt8]]

    public init(cipher: ShadowsocksCipher, password: String) throws {
        precondition(cipher.is2022)
        let parts = password.split(separator: ":", omittingEmptySubsequences: false)
        let keys = try parts.map { part -> [UInt8] in
            guard let data = Data(base64Encoded: String(part)), data.count == cipher.keyByteCount else {
                throw ShadowsocksError.invalidKeySize(expected: cipher.keyByteCount, actual: Data(base64Encoded: String(part))?.count ?? 0)
            }
            return Array(data)
        }
        guard !keys.isEmpty, cipher.usesAES || keys.count == 1 else {
            throw ShadowsocksError.invalidKeySize(expected: cipher.keyByteCount, actual: 0)
        }
        self.cipher = cipher
        self.pskList = keys
    }

    var userPSK: [UInt8] { pskList[pskList.count - 1] }

    /// `BLAKE3(psk[i + 1])[0..<16]`: what identity header `i` proves.
    func identityHash(_ index: Int) -> [UInt8] {
        Array(BLAKE3.hash(pskList[index + 1]).prefix(16))
    }

    /// `derive_key("shadowsocks 2022 session subkey", psk ‖ salt)`.
    func sessionKey(salt: some DataProtocol) -> [UInt8] {
        BLAKE3.deriveKey(context: "shadowsocks 2022 session subkey", material: userPSK + [UInt8](salt), count: cipher.keyByteCount)
    }

    /// TCP identity headers for `salt`: one AES block per identity key.
    func identityHeaders(salt: [UInt8]) -> [UInt8] {
        guard pskList.count > 1 else { return [] }
        var headers: [UInt8] = []
        for index in 0..<(pskList.count - 1) {
            let subkey = BLAKE3.deriveKey(
                context: "shadowsocks 2022 identity subkey",
                material: pskList[index] + salt,
                count: cipher.keyByteCount
            )
            headers += AESBlock.encrypt(block: identityHash(index), key: subkey)
        }
        return headers
    }
}

enum Shadowsocks2022 {
    static let headerTypeClient: UInt8 = 0
    static let headerTypeServer: UInt8 = 1
    static let maxPadding = 900
    /// Allowed clock difference to the server (seconds).
    static let maxTimeDifference: Int64 = 30

    static var now: Int64 { Int64(Date().timeIntervalSince1970) }

    static func be64(_ value: UInt64) -> [UInt8] {
        withUnsafeBytes(of: value.bigEndian) { Array($0) }
    }

    static func readBE64(_ bytes: some Collection<UInt8>) -> UInt64 {
        bytes.reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
    }
}

@frozen
public enum Shadowsocks2022Error: Error, Equatable, Sendable {
    case badHeaderType(UInt8)
    /// Server clock differs by more than 30 s.
    case badTimestamp(Int64)
    /// The response does not echo our request salt.
    case badRequestSalt
    /// A UDP reply names another client session.
    case badClientSession
}

// MARK: - TCP

/// Shadowsocks 2022 (SIP022) TCP client.
///
/// Request: `salt ‖ identity headers ‖ AEAD(type, time, length) ‖
/// AEAD(address, padding, initial payload)`, then SIP004-style chunks of up
/// to 0xFFFF bytes. Response: `salt ‖ AEAD(type, time, request salt,
/// length) ‖ AEAD(first payload)`, then chunks. Subkeys come from BLAKE3.
public final class Shadowsocks2022OutboundConnection: OutboundConnection, @unchecked Sendable {
    public let endpoint: Endpoint
    public let server: Endpoint
    public let keys: Shadowsocks2022Keys
    public let plugin: ShadowsocksPlugin?

    public var state: OutboundConnectionState { transport.state }

    private var cipher: ShadowsocksCipher { keys.cipher }
    private let transport: NWStreamTransport
    private let requestSalt: [UInt8]

    // Uplink (writeMutex)
    private var encryptor: ShadowsocksAEADContext
    private var requestSent = false
    private let sendCiphertext = DirectBuffer()

    // Downlink (readMutex)
    private var decryptor: ShadowsocksAEADContext?
    private var pendingFirstLength: Int?
    private let recvCiphertext = DirectBuffer()
    private let recvPlaintext = DirectBuffer()

    public init(
        server: Endpoint,
        keys: Shadowsocks2022Keys,
        target: Endpoint,
        plugin: ShadowsocksPlugin? = nil
    ) throws {
        self.server = server
        self.keys = keys
        self.endpoint = target
        self.plugin = plugin
        let salt = keys.cipher.randomSalt()
        self.requestSalt = salt
        self.encryptor = try ShadowsocksAEADContext(cipher: keys.cipher, subkey: keys.sessionKey(salt: salt))
        self.transport = NWStreamTransport(queueLabel: "prizmx.ss2022.outbound", endpoint: target, errorPeer: server)
    }

    public func open() async throws {
        try await transport.open { try await self.connect() }
    }

    public func write(_ buffer: UnsafeRawBufferPointer) async throws -> Int {
        try await transport.write(buffer, connecting: { try await self.connect() }) { buffer in
            try await self.sendPayload(buffer)
        }
    }

    public func read(into buffer: UnsafeMutableRawBufferPointer) async throws -> Int {
        if buffer.isEmpty { return 0 }
        try await transport.ensureOpen { try await self.connect() }
        if !transport.isHandshakeFlushed {
            try await flushRequest()
        }
        await transport.readMutex.acquire()
        defer { transport.readMutex.release() }
        try transport.ensureReadable()

        while recvPlaintext.readableByteCount == 0 {
            guard try await decryptNext() else { return 0 }
        }
        let take = min(buffer.count, recvPlaintext.readableByteCount)
        buffer.copyMemory(from: UnsafeRawBufferPointer(rebasing: recvPlaintext.readableBytes.prefix(take)))
        recvPlaintext.consume(take)
        return take
    }

    public func close() async {
        await transport.close()
    }

    public func closeWrite() async {
        guard state == .established else { return }
        if !transport.isHandshakeFlushed { try? await flushRequest() }
        await transport.finishWriting()
    }

    public var supportsHalfClose: Bool { true }

    // MARK: Uplink

    private func connect() async throws {
        try await transport.dialShadowsocks(server, plugin: plugin)
        transport.markEstablished()
    }

    /// The request (with as much of `buffer` as fits) on the first call,
    /// then whole writes sealed as consecutive chunks in one send.
    private func sendPayload(_ buffer: UnsafeRawBufferPointer) async throws -> Int {
        sendCiphertext.clear()
        var offset = 0
        if !requestSent {
            offset = try appendRequest(initial: buffer)
        }
        let limit = min(buffer.count, offset + ShadowsocksOutboundConnection.maxWriteBatch)
        while offset < limit {
            let end = min(offset + cipher.maxChunkPayload, limit)
            try appendChunk(UnsafeRawBufferPointer(rebasing: buffer[offset..<end]))
            offset = end
        }
        try await flushCiphertext()
        return offset
    }

    private func flushRequest() async throws {
        await transport.writeMutex.acquire()
        defer { transport.writeMutex.release() }
        try transport.ensureWritable()
        guard !requestSent else { return }
        sendCiphertext.clear()
        _ = try appendRequest(initial: UnsafeRawBufferPointer(start: nil, count: 0))
        try await flushCiphertext()
    }

    /// Appends salt, identity headers and both request headers; returns how
    /// many bytes of `initial` the variable header carries.
    private func appendRequest(initial: UnsafeRawBufferPointer) throws -> Int {
        requestSent = true
        transport.markHandshakeFlushed()
        let address = try ShadowsocksAddress.encode(endpoint)
        let padding = initial.count < Shadowsocks2022.maxPadding ? Int.random(in: 1...Shadowsocks2022.maxPadding) : 0
        let room = 0xFFFF - address.count - 2 - padding
        let take = min(initial.count, room)

        var variable = address
        variable += [UInt8(padding >> 8), UInt8(padding & 0xFF)]
        variable += [UInt8](repeating: 0, count: padding)
        variable += initial.prefix(take)

        var fixed = [Shadowsocks2022.headerTypeClient]
        fixed += Shadowsocks2022.be64(UInt64(Shadowsocks2022.now))
        fixed += [UInt8(variable.count >> 8), UInt8(variable.count & 0xFF)]

        sendCiphertext.append(requestSalt)
        sendCiphertext.append(keys.identityHeaders(salt: requestSalt))
        try appendSealed(fixed)
        try appendSealed(variable)
        return take
    }

    /// One AEAD record (no length prefix), as the request headers use.
    private func appendSealed(_ plaintext: [UInt8]) throws {
        let writable = sendCiphertext.prepareWritable(minimumCapacity: plaintext.count + ShadowsocksAEAD.tagByteCount)
        let written = try plaintext.withUnsafeBytes { try encryptor.seal(plaintext: $0, into: writable) }
        sendCiphertext.commitWritten(written)
    }

    private func appendChunk(_ plaintext: UnsafeRawBufferPointer) throws {
        let sealedCount = ShadowsocksAEAD.sealedChunkByteCount(plaintextCount: plaintext.count)
        let writable = sendCiphertext.prepareWritable(minimumCapacity: sealedCount)
        let written = try encryptor.sealChunk(plaintext: plaintext, into: writable)
        sendCiphertext.commitWritten(written)
    }

    private func flushCiphertext() async throws {
        guard sendCiphertext.readableByteCount > 0 else { return }
        let data = Data(sendCiphertext.readableBytes)
        sendCiphertext.clear()
        try await transport.send(data)
    }

    // MARK: Downlink

    /// Decrypts the next record into `recvPlaintext`; `false` at EOF.
    private func decryptNext() async throws -> Bool {
        if decryptor == nil {
            guard try await readResponseHeader() else { return false }
        }
        guard var decryptor else { return false }
        defer { self.decryptor = decryptor }
        let length: Int
        if let first = pendingFirstLength {
            pendingFirstLength = nil
            length = first
        } else {
            guard try await fill(ShadowsocksAEAD.lengthRecordByteCount, endOfStreamAllowed: true) else { return false }
            length = try decryptor.openLengthRecord(
                UnsafeRawBufferPointer(rebasing: recvCiphertext.readableBytes.prefix(ShadowsocksAEAD.lengthRecordByteCount))
            )
            recvCiphertext.consume(ShadowsocksAEAD.lengthRecordByteCount)
        }
        let record = length + ShadowsocksAEAD.tagByteCount
        _ = try await fill(record, endOfStreamAllowed: false)
        let writable = recvPlaintext.prepareWritable(minimumCapacity: max(length, 1))
        let written = try decryptor.openPayloadRecord(
            UnsafeRawBufferPointer(rebasing: recvCiphertext.readableBytes.prefix(record)),
            into: writable
        )
        recvPlaintext.commitWritten(written)
        recvCiphertext.consume(record)
        return true
    }

    /// Server salt and fixed response header; checks type, time and our
    /// request salt. `false` when the server closed before answering.
    private func readResponseHeader() async throws -> Bool {
        let saltCount = cipher.saltByteCount
        guard try await fill(saltCount, endOfStreamAllowed: true) else { return false }
        let salt = Array(recvCiphertext.readableBytes.prefix(saltCount))
        recvCiphertext.consume(saltCount)
        var context = try ShadowsocksAEADContext(cipher: cipher, subkey: keys.sessionKey(salt: salt))

        let headerCount = 1 + 8 + saltCount + 2
        let record = headerCount + ShadowsocksAEAD.tagByteCount
        _ = try await fill(record, endOfStreamAllowed: false)
        var header = [UInt8](repeating: 0, count: headerCount)
        try header.withUnsafeMutableBytes { output in
            _ = try context.openPayloadRecord(
                UnsafeRawBufferPointer(rebasing: recvCiphertext.readableBytes.prefix(record)),
                into: output
            )
        }
        recvCiphertext.consume(record)

        guard header[0] == Shadowsocks2022.headerTypeServer else {
            throw Shadowsocks2022Error.badHeaderType(header[0])
        }
        let time = Int64(bitPattern: Shadowsocks2022.readBE64(header[1..<9]))
        guard abs(time - Shadowsocks2022.now) <= Shadowsocks2022.maxTimeDifference else {
            throw Shadowsocks2022Error.badTimestamp(time)
        }
        guard Array(header[9..<(9 + saltCount)]) == requestSalt else {
            throw Shadowsocks2022Error.badRequestSalt
        }
        pendingFirstLength = Int(header[9 + saltCount]) << 8 | Int(header[10 + saltCount])
        decryptor = context
        return true
    }

    /// At least `count` ciphertext bytes buffered; `false` on a clean EOF
    /// before any of them (only if allowed).
    private func fill(_ count: Int, endOfStreamAllowed: Bool) async throws -> Bool {
        while recvCiphertext.readableByteCount < count {
            guard let chunk = try await transport.receiveRaw() else {
                if endOfStreamAllowed && recvCiphertext.readableByteCount == 0 { return false }
                throw ShadowsocksError.truncated(expected: count, actual: recvCiphertext.readableByteCount)
            }
            recvCiphertext.append(chunk)
        }
        return true
    }
}

// MARK: - UDP

/// Shadowsocks 2022 UDP. AES methods: an AES-ECB sealed separate header
/// (session id, packet id) whose tail is the body's nonce, identity headers,
/// then the body sealed with a per-session BLAKE3 key. ChaCha20: the whole
/// packet sealed with XChaCha20-Poly1305 under the PSK, nonce in front.
public final class Shadowsocks2022DatagramOutbound: DatagramOutbound, @unchecked Sendable {
    public let server: Endpoint
    public let keys: Shadowsocks2022Keys
    private let socket = UDPSocket(label: "prizmx.ss2022.udp")
    private let sessionID = UInt64.random(in: 1...UInt64.max)
    private let packetID = OSAllocatedUnfairLock(initialState: UInt64(0))
    private let sessionKey: [UInt8]
    /// Server session id → its body key (AES methods).
    private var serverKeys: [UInt64: [UInt8]] = [:]

    public init(server: Endpoint, keys: Shadowsocks2022Keys) {
        self.server = server
        self.keys = keys
        self.sessionKey = keys.sessionKey(salt: Shadowsocks2022.be64(sessionID))
    }

    public func open() async throws {
        try await socket.open(server)
    }

    public func send(_ payload: Data, to destination: Endpoint) async throws {
        let id = packetID.withLock { current -> UInt64 in
            current += 1
            return current
        }
        socket.send(try encode(payload, to: destination, packetID: id))
    }

    public func receive() async throws -> Data? {
        while let packet = await socket.receive() {
            // Undecryptable or foreign packets are dropped.
            if let payload = try? decode(packet) { return payload }
        }
        return nil
    }

    public func close() async {
        socket.close()
    }

    // MARK: Wire

    func encode(_ payload: Data, to destination: Endpoint, packetID: UInt64) throws -> Data {
        let header = Shadowsocks2022.be64(sessionID) + Shadowsocks2022.be64(packetID)
        let padding = destination.port == 53 && payload.count < Shadowsocks2022.maxPadding
            ? Int.random(in: 1...(Shadowsocks2022.maxPadding - payload.count))
            : 0
        var body = [Shadowsocks2022.headerTypeClient]
        body += Shadowsocks2022.be64(UInt64(Shadowsocks2022.now))
        body += [UInt8(padding >> 8), UInt8(padding & 0xFF)] + [UInt8](repeating: 0, count: padding)
        body += try ShadowsocksAddress.encode(destination)
        body += payload

        if !keys.cipher.usesAES {
            let nonce = (0..<24).map { _ in UInt8.random(in: 0...255) }
            return Data(nonce) + (try XChaCha20Poly1305.seal(header + body, key: keys.userPSK, nonce: nonce))
        }
        var packet = AESBlock.encrypt(block: header, key: keys.pskList[0])
        for index in 0..<(keys.pskList.count - 1) {
            let mixed = zip(keys.identityHash(index), header).map { $0 ^ $1 }
            packet += AESBlock.encrypt(block: mixed, key: keys.pskList[index])
        }
        let box = try AES.GCM.seal(body, using: SymmetricKey(data: sessionKey), nonce: AES.GCM.Nonce(data: header[4..<16]))
        return Data(packet) + box.ciphertext + box.tag
    }

    func decode(_ packet: Data) throws -> Data {
        let bytes = [UInt8](packet)
        var body: [UInt8]
        if keys.cipher.usesAES {
            guard bytes.count >= 16 + 16 else { throw ShadowsocksError.truncated(expected: 32, actual: bytes.count) }
            // Requests seal the header with the first (identity) key, replies
            // with the user's key; they differ only with identity headers.
            let header = AESBlock.decrypt(block: Array(bytes[0..<16]), key: keys.userPSK)
            let serverSession = Shadowsocks2022.readBE64(header[0..<8])
            let key = serverKeys[serverSession] ?? keys.sessionKey(salt: header[0..<8])
            let sealed = bytes[16...]
            do {
                let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: header[4..<16]), ciphertext: sealed.dropLast(16), tag: sealed.suffix(16))
                body = Array(try AES.GCM.open(box, using: SymmetricKey(data: key)))
            } catch {
                throw ShadowsocksError.authenticationFailed
            }
            serverKeys[serverSession] = key
        } else {
            guard bytes.count >= 24 + 16 + 16 else { throw ShadowsocksError.truncated(expected: 56, actual: bytes.count) }
            let plain = try XChaCha20Poly1305.open(Array(bytes[24...]), key: keys.userPSK, nonce: Array(bytes[0..<24]))
            body = Array(plain.dropFirst(16))
        }
        // type ‖ time ‖ client session id ‖ padding length ‖ padding ‖ address ‖ payload
        guard body.count >= 1 + 8 + 8 + 2 else { throw ShadowsocksError.truncated(expected: 19, actual: body.count) }
        guard body[0] == Shadowsocks2022.headerTypeServer else { throw Shadowsocks2022Error.badHeaderType(body[0]) }
        let time = Int64(bitPattern: Shadowsocks2022.readBE64(body[1..<9]))
        guard abs(time - Shadowsocks2022.now) <= Shadowsocks2022.maxTimeDifference else {
            throw Shadowsocks2022Error.badTimestamp(time)
        }
        guard Shadowsocks2022.readBE64(body[9..<17]) == sessionID else { throw Shadowsocks2022Error.badClientSession }
        let padding = Int(body[17]) << 8 | Int(body[18])
        guard body.count >= 19 + padding else { throw ShadowsocksError.truncated(expected: 19 + padding, actual: body.count) }
        body.removeFirst(19 + padding)
        let addressCount = try body.withUnsafeBytes { try ShadowsocksAddress.decode($0).1 }
        return Data(body.dropFirst(addressCount))
    }
}

/// XChaCha20-Poly1305 (24-byte nonce) on CryptoKit's ChaCha20-Poly1305:
/// HChaCha20 subkey from the first 16 nonce bytes, then the IETF AEAD with
/// nonce `0000 ‖ nonce[16..<24]`.
enum XChaCha20Poly1305 {
    static func seal(_ plaintext: [UInt8], key: [UInt8], nonce: [UInt8]) throws -> [UInt8] {
        let (subkey, inner) = derive(key: key, nonce: nonce)
        let box = try ChaChaPoly.seal(plaintext, using: subkey, nonce: inner)
        return Array(box.ciphertext) + Array(box.tag)
    }

    static func open(_ sealed: [UInt8], key: [UInt8], nonce: [UInt8]) throws -> [UInt8] {
        guard sealed.count >= 16 else { throw ShadowsocksError.authenticationFailed }
        let (subkey, inner) = derive(key: key, nonce: nonce)
        do {
            let box = try ChaChaPoly.SealedBox(nonce: inner, ciphertext: sealed.dropLast(16), tag: sealed.suffix(16))
            return Array(try ChaChaPoly.open(box, using: subkey))
        } catch {
            throw ShadowsocksError.authenticationFailed
        }
    }

    private static func derive(key: [UInt8], nonce: [UInt8]) -> (SymmetricKey, ChaChaPoly.Nonce) {
        precondition(nonce.count == 24)
        let subkey = ChaCha20.hchacha20(key: key, nonce: Array(nonce.prefix(16)))
        let inner = try! ChaChaPoly.Nonce(data: [0, 0, 0, 0] + nonce[16..<24])
        return (SymmetricKey(data: subkey), inner)
    }
}
