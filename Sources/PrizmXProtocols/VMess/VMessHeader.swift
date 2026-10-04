import CryptoKit
import Foundation

/// VMess request command.
@frozen
public enum VMessCommand: UInt8, Sendable, Hashable {
    case tcp = 0x01
    case udp = 0x02
}

/// Request option bits (`RequestOption*`).
enum VMessOption {
    static let chunkStream: UInt8 = 0x01
    static let chunkMasking: UInt8 = 0x04
    static let globalPadding: UInt8 = 0x08
}

/// Per-connection secrets the client picks (Xray `ClientSession`).
struct VMessSession: Sendable {
    let requestKey: [UInt8]
    let requestIV: [UInt8]
    let responseKey: [UInt8]
    let responseIV: [UInt8]
    /// Echoed by the server as the first response header byte.
    let responseAuth: UInt8

    init(requestKey: [UInt8], requestIV: [UInt8], responseAuth: UInt8) {
        self.requestKey = requestKey
        self.requestIV = requestIV
        self.responseKey = Array(SHA256.hash(data: requestKey).prefix(16))
        self.responseIV = Array(SHA256.hash(data: requestIV).prefix(16))
        self.responseAuth = responseAuth
    }

    static func random() -> VMessSession {
        let bytes = (0..<33).map { _ in UInt8.random(in: 0...255) }
        return VMessSession(
            requestKey: Array(bytes[0..<16]),
            requestIV: Array(bytes[16..<32]),
            responseAuth: bytes[32]
        )
    }
}

/// The VMess request header: plaintext layout, then AEAD sealing.
struct VMessRequestHeader {
    var session: VMessSession
    var options: UInt8
    var security: VMessSecurity
    var command: VMessCommand
    var target: Endpoint
    var padding: [UInt8]

    /// Option bits Xray's client sets for `security`.
    static func options(for security: VMessSecurity) -> UInt8 {
        switch security.resolved {
        case .zero: 0
        case .none: VMessOption.chunkStream | VMessOption.chunkMasking
        default: VMessOption.chunkStream | VMessOption.chunkMasking | VMessOption.globalPadding
        }
    }

    /// `[ver 1][IV 16][key 16][V][opt][P<<4|sec][0][cmd][port][atyp][addr][pad][fnv1a32]`
    func encode() throws -> [UInt8] {
        var bytes: [UInt8] = [0x01]
        bytes += session.requestIV
        bytes += session.requestKey
        bytes.append(session.responseAuth)
        bytes.append(options)
        bytes.append(UInt8(padding.count) << 4 | security.headerValue)
        bytes.append(0x00)
        bytes.append(command.rawValue)
        bytes += try Self.address(target)
        bytes += padding
        let checksum = FNV1a32.hash(bytes)
        bytes += [
            UInt8(truncatingIfNeeded: checksum >> 24), UInt8(truncatingIfNeeded: checksum >> 16),
            UInt8(truncatingIfNeeded: checksum >> 8), UInt8(truncatingIfNeeded: checksum),
        ]
        return bytes
    }

    /// Port first, then `1` IPv4 / `2` domain / `3` IPv6.
    static func address(_ target: Endpoint) throws -> [UInt8] {
        var bytes = [UInt8(target.port >> 8), UInt8(target.port & 0xFF)]
        switch target.host {
        case .ipv4(let address):
            bytes.append(0x01)
            bytes += withUnsafeBytes(of: address.rawValue.bigEndian) { Array($0) }
        case .domain(let domain):
            let utf8 = Array(domain.utf8)
            guard (1...255).contains(utf8.count) else { throw VMessError.invalidAddress(target) }
            bytes.append(0x02)
            bytes.append(UInt8(utf8.count))
            bytes += utf8
        case .ipv6(let address):
            bytes.append(0x03)
            bytes += withUnsafeBytes(of: address.high.bigEndian) { Array($0) }
            bytes += withUnsafeBytes(of: address.low.bigEndian) { Array($0) }
        }
        return bytes
    }

    /// `authID ‖ AEAD(len) ‖ nonce ‖ AEAD(header)` (Xray `SealVMessAEADHeader`).
    static func seal(
        _ plaintext: [UInt8],
        commandKey: [UInt8],
        timestamp: Int64 = Int64(Date().timeIntervalSince1970),
        connectionNonce: [UInt8] = (0..<8).map { _ in UInt8.random(in: 0...255) },
        authRandom: [UInt8] = (0..<4).map { _ in UInt8.random(in: 0...255) }
    ) throws -> [UInt8] {
        let authID = authenticationID(commandKey: commandKey, timestamp: timestamp, random: authRandom)
        let lengthKey = VMessKDF.derive16(commandKey, [Array("VMess Header AEAD Key_Length".utf8), authID, connectionNonce])
        let lengthNonce = Array(VMessKDF.derive(commandKey, [Array("VMess Header AEAD Nonce_Length".utf8), authID, connectionNonce]).prefix(12))
        let headerKey = VMessKDF.derive16(commandKey, [Array("VMess Header AEAD Key".utf8), authID, connectionNonce])
        let headerNonce = Array(VMessKDF.derive(commandKey, [Array("VMess Header AEAD Nonce".utf8), authID, connectionNonce]).prefix(12))

        let length = [UInt8(plaintext.count >> 8), UInt8(plaintext.count & 0xFF)]
        return authID
            + (try VMessAEAD.seal(length, key: lengthKey, nonce: lengthNonce, aad: authID))
            + connectionNonce
            + (try VMessAEAD.seal(plaintext, key: headerKey, nonce: headerNonce, aad: authID))
    }

    /// `AES-ECB(KDF16(cmdKey, "AES Auth ID Encryption"), time ‖ rand ‖ crc32)`.
    static func authenticationID(commandKey: [UInt8], timestamp: Int64, random: [UInt8]) -> [UInt8] {
        var block = withUnsafeBytes(of: timestamp.bigEndian) { Array($0) } + random
        let crc = CRC32.checksum(block)
        block += withUnsafeBytes(of: crc.bigEndian) { Array($0) }
        let key = VMessKDF.derive16(commandKey, [Array("AES Auth ID Encryption".utf8)])
        return AESBlock.encrypt(block: block, key: key)
    }
}

/// The AEAD response header: `AEAD(len)` (18 bytes) then `AEAD(header)`.
struct VMessResponseHeader {
    let lengthKey: [UInt8]
    let lengthNonce: [UInt8]
    let payloadKey: [UInt8]
    let payloadNonce: [UInt8]

    init(session: VMessSession) {
        lengthKey = VMessKDF.derive16(session.responseKey, [Array("AEAD Resp Header Len Key".utf8)])
        lengthNonce = Array(VMessKDF.derive(session.responseIV, "AEAD Resp Header Len IV").prefix(12))
        payloadKey = VMessKDF.derive16(session.responseKey, [Array("AEAD Resp Header Key".utf8)])
        payloadNonce = Array(VMessKDF.derive(session.responseIV, "AEAD Resp Header IV").prefix(12))
    }

    static let lengthRecordByteCount = 2 + 16

    func openLength(_ record: [UInt8]) throws -> Int {
        let plain = try VMessAEAD.open(record, key: lengthKey, nonce: lengthNonce, aad: [])
        return Int(plain[0]) << 8 | Int(plain[1])
    }

    /// Opens the header and returns its bytes (`[V][opt][cmd][cmdLen]…`).
    func openPayload(_ record: [UInt8]) throws -> [UInt8] {
        try VMessAEAD.open(record, key: payloadKey, nonce: payloadNonce, aad: [])
    }
}

// MARK: - Body chunks

/// One direction of the VMess chunk stream: masked 2-byte length, AEAD (or
/// plain for `none`) payload, optional random padding.
struct VMessChunkCipher {
    /// Largest payload per uplink chunk so the whole chunk stays within
    /// Xray's 8 KiB buffer (length 2 + tag 16 + padding up to 64).
    static let maxPayload = 8192 - 2 - 16 - 64

    private let security: VMessSecurity
    private let key: SymmetricKey?
    private var nonce: [UInt8]
    private var counter: UInt16 = 0
    private var shake: SHAKE128?
    private let padding: Bool

    init(security: VMessSecurity, key: [UInt8], iv: [UInt8], options: UInt8) {
        self.security = security.resolved
        switch security.resolved {
        case .aes128GCM: self.key = SymmetricKey(data: key)
        case .chacha20Poly1305: self.key = SymmetricKey(data: VMessKDF.chachaKey(key))
        default: self.key = nil
        }
        self.nonce = Array(iv.prefix(12))
        self.shake = options & VMessOption.chunkMasking != 0 ? SHAKE128(absorbing: iv) : nil
        self.padding = options & VMessOption.globalPadding != 0 && shake != nil
    }

    var overhead: Int { key == nil ? 0 : 16 }

    private mutating func nextPadding() -> Int {
        guard padding, var shake else { return 0 }
        defer { self.shake = shake }
        return Int(shake.nextUInt16() % 64)
    }

    private mutating func nextMask() -> UInt16 {
        guard var shake else { return 0 }
        defer { self.shake = shake }
        return shake.nextUInt16()
    }

    private mutating func nextNonce() -> [UInt8] {
        nonce[0] = UInt8(counter >> 8)
        nonce[1] = UInt8(counter & 0xFF)
        counter &+= 1
        return nonce
    }

    /// One wire chunk for `payload` (empty payload = end-of-stream marker).
    mutating func seal(_ payload: [UInt8]) throws -> [UInt8] {
        let paddingCount = nextPadding()
        let size = payload.count + overhead + paddingCount
        guard size <= 0xFFFF else { throw VMessError.chunkTooLarge(size) }
        let field = UInt16(size) ^ nextMask()
        var chunk = [UInt8(field >> 8), UInt8(field & 0xFF)]
        chunk += try encrypt(payload)
        if paddingCount > 0 {
            chunk += (0..<paddingCount).map { _ in UInt8.random(in: 0...255) }
        }
        return chunk
    }

    /// Decodes a 2-byte length field: (chunk size, padding inside it).
    mutating func openLength(_ field: [UInt8]) -> (size: Int, padding: Int) {
        let paddingCount = nextPadding()
        let size = Int((UInt16(field[0]) << 8 | UInt16(field[1])) ^ nextMask())
        return (size, paddingCount)
    }

    /// `true` when a chunk of this size is the end-of-stream marker.
    func isEndOfStream(size: Int, padding: Int) -> Bool {
        size == overhead + padding
    }

    /// Decrypts a whole chunk body (`size` bytes, padding at the end).
    mutating func open(_ body: [UInt8], padding: Int) throws -> [UInt8] {
        guard body.count >= overhead + padding else { throw VMessError.truncated }
        let sealed = Array(body.prefix(body.count - padding))
        guard let key else { return sealed }
        let nonce = nextNonce()
        do {
            switch security {
            case .chacha20Poly1305:
                let box = try ChaChaPoly.SealedBox(
                    nonce: ChaChaPoly.Nonce(data: nonce),
                    ciphertext: sealed.dropLast(16),
                    tag: sealed.suffix(16)
                )
                return Array(try ChaChaPoly.open(box, using: key))
            default:
                let box = try AES.GCM.SealedBox(
                    nonce: AES.GCM.Nonce(data: nonce),
                    ciphertext: sealed.dropLast(16),
                    tag: sealed.suffix(16)
                )
                return Array(try AES.GCM.open(box, using: key))
            }
        } catch {
            throw VMessError.authenticationFailed
        }
    }

    private mutating func encrypt(_ payload: [UInt8]) throws -> [UInt8] {
        guard let key else { return payload }
        let nonce = nextNonce()
        switch security {
        case .chacha20Poly1305:
            let box = try ChaChaPoly.seal(payload, using: key, nonce: ChaChaPoly.Nonce(data: nonce))
            return Array(box.ciphertext) + Array(box.tag)
        default:
            let box = try AES.GCM.seal(payload, using: key, nonce: AES.GCM.Nonce(data: nonce))
            return Array(box.ciphertext) + Array(box.tag)
        }
    }
}
