import CryptoKit
import Foundation

// MARK: - SIP004 / SIP007 AEAD constants

/// Shadowsocks AEAD (SIP004, amended by SIP007) TCP record parameters.
///
/// Wire format after the session salt:
/// `[encrypted 2-byte BE length][16-byte tag][encrypted payload][16-byte tag]`
///
/// Each of the two AEAD operations consumes a distinct nonce. The nonce is a
/// 12-byte little-endian counter starting at 0.
public enum ShadowsocksAEAD {
    /// Maximum plaintext bytes in a single TCP chunk (`0x3FFF`).
    /// The high two bits of the length field are reserved and must be zero.
    public static let maxPayloadLength = 0x3FFF
    /// AES-GCM authentication tag size (bytes).
    public static let tagByteCount = 16
    /// Counting nonce size for AES-GCM (bytes).
    public static let nonceByteCount = 12
    /// Plaintext length field size (bytes).
    public static let lengthFieldByteCount = 2
    /// Encrypted length record: 2-byte ciphertext + tag.
    public static let lengthRecordByteCount = lengthFieldByteCount + tagByteCount
    /// HKDF info string that binds the subkey to Shadowsocks (no quotes).
    public static let subkeyInfo = "ss-subkey"

    /// Total ciphertext bytes of a sealed chunk with `plaintextCount` payload bytes.
    @inlinable
    public static func sealedChunkByteCount(plaintextCount: Int) -> Int {
        lengthRecordByteCount + plaintextCount + tagByteCount
    }
}

// MARK: - Cipher

/// SIP008 `method` identifiers for the AEAD ciphers implemented here.
@frozen
public enum ShadowsocksCipher: String, Hashable, Sendable, Codable, CaseIterable {
    case aes128GCM = "aes-128-gcm"
    case aes256GCM = "aes-256-gcm"

    /// Master-key / subkey size in bytes. Equal to the salt size for these ciphers.
    public var keyByteCount: Int {
        switch self {
        case .aes128GCM: return 16
        case .aes256GCM: return 32
        }
    }

    /// Per-session salt size in bytes (SIP004: same as the key size).
    public var saltByteCount: Int { keyByteCount }

    /// Derives the pre-shared master key from a password using OpenSSL
    /// `EVP_BytesToKey` with MD5 and an empty salt (Shadowsocks convention).
    public func masterKey(fromPassword password: String) -> [UInt8] {
        ShadowsocksKeyDerivation.evpBytesToKey(password: password, keyByteCount: keyByteCount)
    }

    /// Cryptographically random salt of `saltByteCount` bytes.
    public func randomSalt() -> [UInt8] {
        let material = SymmetricKey(size: SymmetricKeySize(bitCount: saltByteCount * 8))
        return material.withUnsafeBytes { Array($0) }
    }
}

// MARK: - Errors

@frozen
public enum ShadowsocksError: Error, Equatable, Sendable {
    /// AEAD tag verification failed (wrong key, nonce desync, or tampered bytes).
    case authenticationFailed
    /// Plaintext or decoded length exceeds `ShadowsocksAEAD.maxPayloadLength`.
    case payloadTooLarge(Int)
    /// A record or output buffer was shorter than the AEAD layer requires.
    case truncated(expected: Int, actual: Int)
    /// SOCKS-style address cannot be encoded (empty / overlong domain).
    case invalidAddress(Endpoint)
    /// Master key or subkey length does not match the selected cipher.
    case invalidKeySize(expected: Int, actual: Int)
}

// MARK: - Nonce

/// 12-byte Shadowsocks AEAD counting nonce.
///
/// Incremented after **every** AEAD seal/open as an unsigned little-endian
/// integer. One TCP chunk therefore advances the counter twice.
@frozen
public struct ShadowsocksNonce: Sendable, Equatable {
    public static let size = ShadowsocksAEAD.nonceByteCount

    public static func == (lhs: ShadowsocksNonce, rhs: ShadowsocksNonce) -> Bool {
        lhs.withUnsafeBytes { left in
            rhs.withUnsafeBytes { right in
                left.elementsEqual(right)
            }
        }
    }

    /// Packed 12-byte little-endian counter (no heap allocation, no padding).
    @usableFromInline
    var storage: (
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
    )

    @inlinable
    public init() {
        storage = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    }

    /// Current nonce as a 12-byte array (test / debug helper).
    public var bytes: [UInt8] {
        withUnsafeBytes { Array($0) }
    }

    /// Increments the nonce by one (little-endian unsigned integer).
    public mutating func increment() {
        withUnsafeMutableBytes { raw in
            let bytes = raw.bindMemory(to: UInt8.self)
            for index in 0..<Self.size {
                bytes[index] &+= 1
                if bytes[index] != 0 { return }
            }
        }
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        var copy = storage
        return try Swift.withUnsafeBytes(of: &copy) { try body($0) }
    }

    mutating func withUnsafeMutableBytes<R>(
        _ body: (UnsafeMutableRawBufferPointer) throws -> R
    ) rethrows -> R {
        try Swift.withUnsafeMutableBytes(of: &storage, body)
    }

    func makeGCMNonce() throws -> AES.GCM.Nonce {
        try withUnsafeBytes { raw in
            try AES.GCM.Nonce(data: Data(raw))
        }
    }
}

// MARK: - HKDF-SHA1 / EVP_BytesToKey

/// Key-derivation primitives used by Shadowsocks AEAD.
///
/// - Password → master key: `EVP_BytesToKey(MD5, password, salt="")`.
/// - Master key + salt → session subkey: HKDF-SHA1 with info `"ss-subkey"`.
public enum ShadowsocksKeyDerivation {
    /// RFC 5869 HKDF-Extract with HMAC-SHA1: `PRK = HMAC-SHA1(salt, ikm)`.
    public static func extract<Salt: DataProtocol, IKM: DataProtocol>(
        salt: Salt,
        inputKeyMaterial ikm: IKM
    ) -> [UInt8] {
        let saltKey: SymmetricKey
        if salt.isEmpty {
            // RFC 5869: a missing salt is HashLen zeros. SS always supplies a salt.
            saltKey = SymmetricKey(data: Data(repeating: 0, count: Insecure.SHA1.byteCount))
        } else {
            saltKey = SymmetricKey(data: Data(salt))
        }
        let prk = HMAC<Insecure.SHA1>.authenticationCode(for: ikm, using: saltKey)
        return prk.withUnsafeBytes { Array($0) }
    }

    /// RFC 5869 HKDF-Expand with HMAC-SHA1.
    public static func expand<Info: DataProtocol>(
        prk: some DataProtocol,
        info: Info,
        outputByteCount: Int
    ) -> [UInt8] {
        precondition(outputByteCount > 0)
        let hashByteCount = Insecure.SHA1.byteCount
        let blockCount = (outputByteCount + hashByteCount - 1) / hashByteCount
        precondition(blockCount <= 255, "HKDF-Expand output too large")

        let prkKey = SymmetricKey(data: Data(prk))
        var previous: [UInt8] = []
        var okm: [UInt8] = []
        okm.reserveCapacity(blockCount * hashByteCount)

        for counter in 1...blockCount {
            var hmac = HMAC<Insecure.SHA1>(key: prkKey)
            if !previous.isEmpty {
                hmac.update(data: previous)
            }
            hmac.update(data: info)
            hmac.update(data: [UInt8(counter)])
            previous = hmac.finalize().withUnsafeBytes { Array($0) }
            okm.append(contentsOf: previous)
        }
        return Array(okm.prefix(outputByteCount))
    }

    /// Full HKDF-SHA1: Extract then Expand.
    public static func derive<Salt: DataProtocol, IKM: DataProtocol, Info: DataProtocol>(
        inputKeyMaterial: IKM,
        salt: Salt,
        info: Info,
        outputByteCount: Int
    ) -> [UInt8] {
        let prk = extract(salt: salt, inputKeyMaterial: inputKeyMaterial)
        return expand(prk: prk, info: info, outputByteCount: outputByteCount)
    }

    /// Shadowsocks session subkey: `HKDF-SHA1(psk, salt, "ss-subkey")`.
    public static func deriveSubkey<PSK: DataProtocol, Salt: DataProtocol>(
        preSharedKey: PSK,
        salt: Salt,
        byteCount: Int
    ) -> [UInt8] {
        derive(
            inputKeyMaterial: preSharedKey,
            salt: salt,
            info: Array(ShadowsocksAEAD.subkeyInfo.utf8),
            outputByteCount: byteCount
        )
    }

    /// OpenSSL `EVP_BytesToKey` with MD5, empty salt, iteration count 1.
    ///
    /// `D_0 = ""`; `D_i = MD5(D_{i-1} || password)`; key is the prefix of
    /// `D_1 || D_2 || …` of length `keyByteCount`.
    public static func evpBytesToKey(password: String, keyByteCount: Int) -> [UInt8] {
        precondition(keyByteCount > 0)
        let passwordBytes = Array(password.utf8)
        var previous: [UInt8] = []
        var derived: [UInt8] = []
        derived.reserveCapacity(keyByteCount + Insecure.MD5.byteCount)

        while derived.count < keyByteCount {
            var hasher = Insecure.MD5()
            if !previous.isEmpty {
                hasher.update(data: previous)
            }
            hasher.update(data: passwordBytes)
            previous = hasher.finalize().withUnsafeBytes { Array($0) }
            derived.append(contentsOf: previous)
        }
        return Array(derived.prefix(keyByteCount))
    }
}

// MARK: - AEAD context (chunk seal / open + nonce)

/// One direction of a Shadowsocks AEAD TCP session (encrypt **or** decrypt).
///
/// Client and server use independent salts, so a connection holds two contexts.
/// All seal/open entry points operate on caller-owned buffers; CryptoKit still
/// allocates temporary `Data` for the AES-GCM primitive, which is copied into
/// the destination slice and discarded.
public struct ShadowsocksAEADContext: Sendable {
    public let cipher: ShadowsocksCipher
    public private(set) var nonce: ShadowsocksNonce

    private let subkey: SymmetricKey

    /// Builds a context from an already-derived session subkey.
    public init(cipher: ShadowsocksCipher, subkey: some DataProtocol) throws {
        let count = subkey.count
        guard count == cipher.keyByteCount else {
            throw ShadowsocksError.invalidKeySize(expected: cipher.keyByteCount, actual: count)
        }
        self.cipher = cipher
        self.subkey = SymmetricKey(data: Data(subkey))
        self.nonce = ShadowsocksNonce()
    }

    /// Derives the session subkey from the pre-shared master key and salt.
    public init(
        cipher: ShadowsocksCipher,
        preSharedKey: some DataProtocol,
        salt: some DataProtocol
    ) throws {
        guard preSharedKey.count == cipher.keyByteCount else {
            throw ShadowsocksError.invalidKeySize(
                expected: cipher.keyByteCount,
                actual: preSharedKey.count
            )
        }
        guard salt.count == cipher.saltByteCount else {
            throw ShadowsocksError.truncated(
                expected: cipher.saltByteCount,
                actual: salt.count
            )
        }
        let derived = ShadowsocksKeyDerivation.deriveSubkey(
            preSharedKey: preSharedKey,
            salt: salt,
            byteCount: cipher.keyByteCount
        )
        try self.init(cipher: cipher, subkey: derived)
    }

    // MARK: Chunk seal

    /// Encrypts one TCP chunk into `output`.
    ///
    /// Layout written: `[len ciphertext (2)][len tag (16)][payload ciphertext][payload tag (16)]`.
    /// Returns the number of bytes written. Advances the nonce twice on success.
    @discardableResult
    public mutating func sealChunk(
        plaintext: UnsafeRawBufferPointer,
        into output: UnsafeMutableRawBufferPointer
    ) throws -> Int {
        let payloadCount = plaintext.count
        guard payloadCount <= ShadowsocksAEAD.maxPayloadLength else {
            throw ShadowsocksError.payloadTooLarge(payloadCount)
        }
        let sealedCount = ShadowsocksAEAD.sealedChunkByteCount(plaintextCount: payloadCount)
        guard output.count >= sealedCount else {
            throw ShadowsocksError.truncated(expected: sealedCount, actual: output.count)
        }

        var lengthField: (UInt8, UInt8) = (
            UInt8(truncatingIfNeeded: payloadCount >> 8),
            UInt8(truncatingIfNeeded: payloadCount)
        )
        _ = try Swift.withUnsafeBytes(of: &lengthField) { raw in
            try seal(
                plaintext: raw,
                into: UnsafeMutableRawBufferPointer(
                    rebasing: output.prefix(ShadowsocksAEAD.lengthRecordByteCount)
                )
            )
        }
        _ = try seal(
            plaintext: plaintext,
            into: UnsafeMutableRawBufferPointer(
                rebasing: output[ShadowsocksAEAD.lengthRecordByteCount..<sealedCount]
            )
        )
        return sealedCount
    }

    /// Allocating convenience used by tests.
    public mutating func sealChunk(_ plaintext: [UInt8]) throws -> [UInt8] {
        let sealedCount = ShadowsocksAEAD.sealedChunkByteCount(plaintextCount: plaintext.count)
        let output = UnsafeMutableRawBufferPointer.allocate(
            byteCount: sealedCount,
            alignment: MemoryLayout<UInt64>.alignment
        )
        defer { output.deallocate() }
        let written = try plaintext.withUnsafeBytes { raw in
            try sealChunk(plaintext: raw, into: output)
        }
        return Array(UnsafeRawBufferPointer(rebasing: output.prefix(written)))
    }

    // MARK: Chunk open

    /// Decrypts an 18-byte length record and returns the payload length.
    /// Advances the nonce once on success.
    public mutating func openLengthRecord(_ record: UnsafeRawBufferPointer) throws -> Int {
        guard record.count == ShadowsocksAEAD.lengthRecordByteCount else {
            throw ShadowsocksError.truncated(
                expected: ShadowsocksAEAD.lengthRecordByteCount,
                actual: record.count
            )
        }
        var lengthField = (UInt8(0), UInt8(0))
        _ = try Swift.withUnsafeMutableBytes(of: &lengthField) { raw in
            try open(ciphertextAndTag: record, into: raw)
        }
        let length = Int(lengthField.0) << 8 | Int(lengthField.1)
        guard length <= ShadowsocksAEAD.maxPayloadLength else {
            throw ShadowsocksError.payloadTooLarge(length)
        }
        return length
    }

    /// Decrypts a payload record (`payloadLength + 16` bytes) into `output`.
    /// Advances the nonce once on success.
    @discardableResult
    public mutating func openPayloadRecord(
        _ record: UnsafeRawBufferPointer,
        into output: UnsafeMutableRawBufferPointer
    ) throws -> Int {
        try open(ciphertextAndTag: record, into: output)
    }

    /// Decrypts one complete sealed chunk (no salt) into `output`.
    @discardableResult
    public mutating func openChunk(
        sealed: UnsafeRawBufferPointer,
        into output: UnsafeMutableRawBufferPointer
    ) throws -> Int {
        guard sealed.count >= ShadowsocksAEAD.lengthRecordByteCount else {
            throw ShadowsocksError.truncated(
                expected: ShadowsocksAEAD.lengthRecordByteCount,
                actual: sealed.count
            )
        }
        let lengthRecord = UnsafeRawBufferPointer(
            rebasing: sealed.prefix(ShadowsocksAEAD.lengthRecordByteCount)
        )
        let payloadLength = try openLengthRecord(lengthRecord)
        let payloadRecordByteCount = payloadLength + ShadowsocksAEAD.tagByteCount
        let expected = ShadowsocksAEAD.lengthRecordByteCount + payloadRecordByteCount
        guard sealed.count >= expected else {
            throw ShadowsocksError.truncated(expected: expected, actual: sealed.count)
        }
        let payloadRecord = UnsafeRawBufferPointer(
            rebasing: sealed[
                ShadowsocksAEAD.lengthRecordByteCount
                    ..< (ShadowsocksAEAD.lengthRecordByteCount + payloadRecordByteCount)
            ]
        )
        return try openPayloadRecord(payloadRecord, into: output)
    }

    /// Allocating convenience used by tests. Consumes exactly one sealed chunk.
    public mutating func openChunk(_ sealed: [UInt8]) throws -> [UInt8] {
        try sealed.withUnsafeBytes { raw in
            guard raw.count >= ShadowsocksAEAD.lengthRecordByteCount else {
                throw ShadowsocksError.truncated(
                    expected: ShadowsocksAEAD.lengthRecordByteCount,
                    actual: raw.count
                )
            }
            let lengthRecord = UnsafeRawBufferPointer(
                rebasing: raw.prefix(ShadowsocksAEAD.lengthRecordByteCount)
            )
            let payloadLength = try openLengthRecord(lengthRecord)
            let payloadRecordByteCount = payloadLength + ShadowsocksAEAD.tagByteCount
            let expected = ShadowsocksAEAD.lengthRecordByteCount + payloadRecordByteCount
            guard raw.count >= expected else {
                throw ShadowsocksError.truncated(expected: expected, actual: raw.count)
            }
            let payloadRecord = UnsafeRawBufferPointer(
                rebasing: raw[
                    ShadowsocksAEAD.lengthRecordByteCount
                        ..< (ShadowsocksAEAD.lengthRecordByteCount + payloadRecordByteCount)
                ]
            )
            guard payloadLength > 0 else {
                _ = try openPayloadRecord(
                    payloadRecord,
                    into: UnsafeMutableRawBufferPointer(start: nil, count: 0)
                )
                return []
            }
            let output = UnsafeMutableRawBufferPointer.allocate(
                byteCount: payloadLength,
                alignment: MemoryLayout<UInt64>.alignment
            )
            defer { output.deallocate() }
            let written = try openPayloadRecord(payloadRecord, into: output)
            return Array(UnsafeRawBufferPointer(rebasing: output.prefix(written)))
        }
    }

    // MARK: Primitive seal / open (one AEAD op, then increment nonce)

    /// Encrypts `plaintext` as ciphertext‖tag into `output`. Empty AAD.
    @discardableResult
    mutating func seal(
        plaintext: UnsafeRawBufferPointer,
        into output: UnsafeMutableRawBufferPointer
    ) throws -> Int {
        let gcmNonce = try nonce.makeGCMNonce()
        let box: AES.GCM.SealedBox
        if plaintext.isEmpty {
            box = try AES.GCM.seal(Data(), using: subkey, nonce: gcmNonce)
        } else {
            box = try withUnownedData(plaintext) { data in
                try AES.GCM.seal(data, using: subkey, nonce: gcmNonce)
            }
        }

        let combinedCount = box.ciphertext.count + box.tag.count
        guard output.count >= combinedCount else {
            throw ShadowsocksError.truncated(expected: combinedCount, actual: output.count)
        }
        if box.ciphertext.count > 0 {
            box.ciphertext.copyBytes(
                to: UnsafeMutableRawBufferPointer(rebasing: output.prefix(box.ciphertext.count))
            )
        }
        box.tag.copyBytes(
            to: UnsafeMutableRawBufferPointer(
                rebasing: output[box.ciphertext.count..<combinedCount]
            )
        )
        nonce.increment()
        return combinedCount
    }

    /// Decrypts ciphertext‖tag in `record` into `output`. Empty AAD.
    @discardableResult
    mutating func open(
        ciphertextAndTag record: UnsafeRawBufferPointer,
        into output: UnsafeMutableRawBufferPointer
    ) throws -> Int {
        let tagByteCount = ShadowsocksAEAD.tagByteCount
        guard record.count >= tagByteCount else {
            throw ShadowsocksError.truncated(expected: tagByteCount, actual: record.count)
        }
        let ciphertextCount = record.count - tagByteCount
        guard output.count >= ciphertextCount else {
            throw ShadowsocksError.truncated(expected: ciphertextCount, actual: output.count)
        }

        let gcmNonce = try nonce.makeGCMNonce()
        let ciphertext = UnsafeRawBufferPointer(rebasing: record.prefix(ciphertextCount))
        let tag = UnsafeRawBufferPointer(rebasing: record.suffix(tagByteCount))

        let plaintext: Data
        do {
            let box = try AES.GCM.SealedBox(
                nonce: gcmNonce,
                ciphertext: ciphertextCount == 0 ? Data() : unownedData(ciphertext),
                tag: unownedData(tag)
            )
            plaintext = try AES.GCM.open(box, using: subkey)
        } catch {
            throw ShadowsocksError.authenticationFailed
        }

        if ciphertextCount > 0 {
            plaintext.copyBytes(
                to: UnsafeMutableRawBufferPointer(rebasing: output.prefix(ciphertextCount))
            )
        }
        nonce.increment()
        return ciphertextCount
    }
}

// MARK: - SOCKS-style destination address (first payload of the client stream)

/// Encodes the proxy target as a SOCKS5-style address header (ATYP + ADDR + PORT).
/// This is the plaintext prefix of the client's first AEAD payload.
public enum ShadowsocksAddress {
    public static let maxEncodedByteCount = 1 + 1 + 255 + 2

    public static func encodedByteCount(of endpoint: Endpoint) throws -> Int {
        switch endpoint.host {
        case .ipv4: return 1 + 4 + 2
        case .ipv6: return 1 + 16 + 2
        case .domain(let domain):
            let utf8Count = domain.utf8.count
            guard (1...255).contains(utf8Count) else {
                throw ShadowsocksError.invalidAddress(endpoint)
            }
            return 1 + 1 + utf8Count + 2
        }
    }

    /// Writes the address header into `output` and returns the byte count used.
    @discardableResult
    public static func encode(
        _ endpoint: Endpoint,
        into output: UnsafeMutableRawBufferPointer
    ) throws -> Int {
        let count = try encodedByteCount(of: endpoint)
        guard output.count >= count else {
            throw ShadowsocksError.truncated(expected: count, actual: output.count)
        }
        switch endpoint.host {
        case .ipv4(let address):
            output[0] = 0x01
            output[1] = UInt8(truncatingIfNeeded: address.rawValue >> 24)
            output[2] = UInt8(truncatingIfNeeded: address.rawValue >> 16)
            output[3] = UInt8(truncatingIfNeeded: address.rawValue >> 8)
            output[4] = UInt8(truncatingIfNeeded: address.rawValue)
            storePort(endpoint.port, at: 5, in: output)
        case .ipv6(let address):
            output[0] = 0x04
            output.storeBytes(of: address.high.bigEndian, toByteOffset: 1, as: UInt64.self)
            output.storeBytes(of: address.low.bigEndian, toByteOffset: 9, as: UInt64.self)
            storePort(endpoint.port, at: 17, in: output)
        case .domain(let domain):
            let utf8 = Array(domain.utf8)
            output[0] = 0x03
            output[1] = UInt8(utf8.count)
            for (index, byte) in utf8.enumerated() {
                output[2 + index] = byte
            }
            storePort(endpoint.port, at: 2 + utf8.count, in: output)
        }
        return count
    }

    public static func encode(_ endpoint: Endpoint) throws -> [UInt8] {
        let count = try encodedByteCount(of: endpoint)
        var bytes = [UInt8](repeating: 0, count: count)
        _ = try bytes.withUnsafeMutableBytes { try encode(endpoint, into: $0) }
        return bytes
    }

    /// Parses a SOCKS5 address header. Returns the endpoint and bytes consumed.
    public static func decode(_ buffer: UnsafeRawBufferPointer) throws -> (Endpoint, Int) {
        guard buffer.count >= 1 else {
            throw ShadowsocksError.truncated(expected: 1, actual: buffer.count)
        }
        switch buffer[0] {
        case 0x01:
            guard buffer.count >= 7 else {
                throw ShadowsocksError.truncated(expected: 7, actual: buffer.count)
            }
            let address = IPv4Address(buffer[1], buffer[2], buffer[3], buffer[4])
            let port = UInt16(buffer[5]) << 8 | UInt16(buffer[6])
            return (Endpoint(host: .ipv4(address), port: port), 7)
        case 0x03:
            guard buffer.count >= 2 else {
                throw ShadowsocksError.truncated(expected: 2, actual: buffer.count)
            }
            let length = Int(buffer[1])
            let total = 2 + length + 2
            guard buffer.count >= total, length > 0 else {
                throw ShadowsocksError.truncated(expected: total, actual: buffer.count)
            }
            let domain = String(decoding: buffer[2..<(2 + length)], as: UTF8.self)
            let port = UInt16(buffer[2 + length]) << 8 | UInt16(buffer[3 + length])
            return (Endpoint(domain: domain, port: port), total)
        case 0x04:
            guard buffer.count >= 19 else {
                throw ShadowsocksError.truncated(expected: 19, actual: buffer.count)
            }
            let high = loadUInt64BE(buffer, offset: 1)
            let low = loadUInt64BE(buffer, offset: 9)
            let port = UInt16(buffer[17]) << 8 | UInt16(buffer[18])
            return (Endpoint(host: .ipv6(IPv6Address(high: high, low: low)), port: port), 19)
        default:
            throw ShadowsocksError.invalidAddress(
                Endpoint(host: .ipv4(.any), port: 0)
            )
        }
    }

    @inline(__always)
    private static func storePort(
        _ port: UInt16,
        at offset: Int,
        in output: UnsafeMutableRawBufferPointer
    ) {
        output[offset] = UInt8(truncatingIfNeeded: port >> 8)
        output[offset + 1] = UInt8(truncatingIfNeeded: port)
    }
}

/// Independent AEAD UDP packets (`[salt][AES-GCM(address‖payload)]`).
public enum ShadowsocksUDP {
    public static func encode(
        cipher: ShadowsocksCipher,
        preSharedKey: [UInt8],
        destination: Endpoint,
        payload: Data
    ) throws -> Data {
        let header = try ShadowsocksAddress.encode(destination)
        let salt = cipher.randomSalt()
        var context = try ShadowsocksAEADContext(
            cipher: cipher,
            preSharedKey: preSharedKey,
            salt: salt
        )
        var plaintext = Data(header)
        plaintext.append(payload)
        let sealedCount = plaintext.count + ShadowsocksAEAD.tagByteCount
        var packet = Data(salt)
        packet.append(Data(count: sealedCount))
        try packet.withUnsafeMutableBytes { raw in
            let output = UnsafeMutableRawBufferPointer(
                rebasing: raw[salt.count..<salt.count + sealedCount]
            )
            _ = try plaintext.withUnsafeBytes { plain in
                try context.seal(plaintext: plain, into: output)
            }
        }
        return packet
    }

    public static func decode(
        cipher: ShadowsocksCipher,
        preSharedKey: [UInt8],
        packet: Data
    ) throws -> (destination: Endpoint, payload: Data) {
        let saltCount = cipher.saltByteCount
        guard packet.count > saltCount + ShadowsocksAEAD.tagByteCount else {
            throw ShadowsocksError.truncated(
                expected: saltCount + ShadowsocksAEAD.tagByteCount + 1,
                actual: packet.count
            )
        }
        let salt = Array(packet.prefix(saltCount))
        var context = try ShadowsocksAEADContext(
            cipher: cipher,
            preSharedKey: preSharedKey,
            salt: salt
        )
        let sealed = packet.dropFirst(saltCount)
        let plainCount = sealed.count - ShadowsocksAEAD.tagByteCount
        let output = UnsafeMutableRawBufferPointer.allocate(
            byteCount: max(plainCount, 1),
            alignment: MemoryLayout<UInt64>.alignment
        )
        defer { output.deallocate() }
        let written = try sealed.withUnsafeBytes { raw in
            try context.open(ciphertextAndTag: raw, into: output)
        }
        let view = UnsafeRawBufferPointer(rebasing: output.prefix(written))
        let (endpoint, headerCount) = try ShadowsocksAddress.decode(view)
        let payload = Data(view.dropFirst(headerCount))
        return (endpoint, payload)
    }
}

// MARK: - Unowned Data wrappers (zero-copy input into CryptoKit)

/// Wraps caller memory as `Data` without copying. The returned value must not
/// outlive `buffer`; CryptoKit AES-GCM APIs copy what they need synchronously.
private func unownedData(_ buffer: UnsafeRawBufferPointer) -> Data {
    guard let base = buffer.baseAddress, buffer.count > 0 else { return Data() }
    return Data(
        bytesNoCopy: UnsafeMutableRawPointer(mutating: base),
        count: buffer.count,
        deallocator: .none
    )
}

private func withUnownedData<R>(
    _ buffer: UnsafeRawBufferPointer,
    _ body: (Data) throws -> R
) rethrows -> R {
    try body(unownedData(buffer))
}
