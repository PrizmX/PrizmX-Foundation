import CryptoKit
import Foundation
import os

/// ShadowsocksR protocol plugins (`protocol`).
@frozen
public enum SSRProtocolKind: String, Sendable, Hashable, CaseIterable {
    case origin
    case authSHA1V4 = "auth_sha1_v4"
    case authAES128MD5 = "auth_aes128_md5"
    case authAES128SHA1 = "auth_aes128_sha1"
    case authChainA = "auth_chain_a"

    /// Bytes the plugin adds per frame (sent to the server by auth_chain).
    var overhead: Int {
        switch self {
        case .origin: 0
        case .authSHA1V4: 7
        case .authAES128MD5, .authAES128SHA1: 9
        case .authChainA: 4
        }
    }
}

/// What the plugins know about the connection (SSR `server_info`).
struct SSRContext {
    /// `EVP_BytesToKey(password)` for the stream cipher.
    var key: [UInt8]
    /// Client IV of the stream cipher (empty for `none`).
    var iv: [UInt8]
    /// `protocol-param`, e.g. `uid:password` for multi-user servers.
    var protocolParam: String
    /// Protocol + obfs overhead (auth_chain reports it to the server).
    var overhead: Int
}

/// Client side of a protocol plugin: frames plaintext before the stream
/// cipher, unframes after it.
protocol SSRProtocolCodec: AnyObject {
    func encode(_ plain: [UInt8]) throws -> [UInt8]
    func decode(_ data: [UInt8]) throws -> [UInt8]
}

enum SSRProtocolFactory {
    static func make(_ kind: SSRProtocolKind, context: SSRContext) -> any SSRProtocolCodec {
        switch kind {
        case .origin: SSROrigin()
        case .authSHA1V4: SSRAuthSHA1V4(context: context)
        case .authAES128MD5: SSRAuthAES128(context: context, sha1: false)
        case .authAES128SHA1: SSRAuthAES128(context: context, sha1: true)
        case .authChainA: SSRAuthChainA(context: context)
        }
    }
}

/// Process-wide client id / connection counter the auth plugins send
/// (`obfs_auth_*_data`): servers use them for replay protection.
enum SSRClientIdentity {
    private static let state = OSAllocatedUnfairLock(initialState: (clientID: [UInt8](), connectionID: UInt32(0)))

    /// `[utc time LE][client id 4][connection id LE]`.
    static func authData() -> [UInt8] {
        let (clientID, connectionID) = state.withLock { current -> ([UInt8], UInt32) in
            if current.connectionID > 0xFF00_0000 || current.clientID.isEmpty {
                current.clientID = SSRBytes.random(4)
                current.connectionID = UInt32.random(in: 0...UInt32.max) & 0xFF_FFFF
            }
            current.connectionID &+= 1
            return (current.clientID, current.connectionID)
        }
        let now = UInt32(truncatingIfNeeded: Int(Date().timeIntervalSince1970))
        return SSRBytes.le32(now) + clientID + SSRBytes.le32(connectionID)
    }
}

enum SSRBytes {
    static func random(_ count: Int) -> [UInt8] {
        (0..<count).map { _ in UInt8.random(in: 0...255) }
    }

    static func le16(_ value: Int) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value), UInt8(truncatingIfNeeded: value >> 8)]
    }

    static func be16(_ value: Int) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]
    }

    static func le32(_ value: UInt32) -> [UInt8] {
        (0..<4).map { UInt8(truncatingIfNeeded: value >> UInt32($0 * 8)) }
    }

    static func readLE16(_ bytes: [UInt8], _ offset: Int) -> Int {
        Int(bytes[offset]) | Int(bytes[offset + 1]) << 8
    }

    static func readBE16(_ bytes: [UInt8], _ offset: Int) -> Int {
        Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
    }

    static func hmac(_ key: [UInt8], _ data: [UInt8], sha1: Bool) -> [UInt8] {
        let symmetric = SymmetricKey(data: key)
        return sha1
            ? Array(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: symmetric))
            : Array(HMAC<Insecure.MD5>.authenticationCode(for: data, using: symmetric))
    }

    /// SOCKS address header size at the start of `buf` (SSR `get_head_size`).
    static func headSize(_ buf: [UInt8], default value: Int = 30) -> Int {
        guard buf.count >= 2 else { return value }
        switch buf[0] & 0x07 {
        case 1: return 7
        case 4: return 19
        case 3: return 4 + Int(buf[1])
        default: return value
        }
    }

    /// zlib Adler-32.
    static func adler32(_ bytes: [UInt8]) -> UInt32 {
        var a: UInt32 = 1
        var b: UInt32 = 0
        for byte in bytes {
            a = (a + UInt32(byte)) % 65521
            b = (b + a) % 65521
        }
        return b << 16 | a
    }
}

// MARK: - origin

/// Plain Shadowsocks stream: no framing.
final class SSROrigin: SSRProtocolCodec {
    func encode(_ plain: [UInt8]) throws -> [UInt8] { plain }
    func decode(_ data: [UInt8]) throws -> [UInt8] { data }
}

// MARK: - auth_sha1_v4

/// `[len BE][crc16][rnd][data][adler32]` frames; the first frame carries
/// the auth data, a CRC32 over the key and an HMAC-SHA1 tag.
final class SSRAuthSHA1V4: SSRProtocolCodec {
    private static let unit = 8100
    private static let salt = Array("auth_sha1_v4".utf8)
    private let context: SSRContext
    private var sentHeader = false
    private var pending: [UInt8] = []

    init(context: SSRContext) {
        self.context = context
    }

    func encode(_ plain: [UInt8]) throws -> [UInt8] {
        var buf = plain[...]
        var out: [UInt8] = []
        if !sentHeader {
            sentHeader = true
            let take = min(buf.count, Int.random(in: 0...31) + SSRBytes.headSize(Array(buf)))
            out += authFrame(SSRClientIdentity.authData() + buf.prefix(take))
            buf = buf.dropFirst(take)
        }
        while buf.count > Self.unit {
            out += frame(Array(buf.prefix(Self.unit)))
            buf = buf.dropFirst(Self.unit)
        }
        out += frame(Array(buf))
        return out
    }

    /// One-byte padding marker plus a little random padding.
    private func padding(for count: Int) -> [UInt8] {
        guard count <= 1200 else { return [0x01] }
        let length = Int.random(in: 0..<min(count > 400 ? 256 : 512, 127))
        return [UInt8(length + 1)] + SSRBytes.random(length)
    }

    private func frame(_ data: [UInt8]) -> [UInt8] {
        let body = padding(for: data.count) + data
        let length = body.count + 8
        let crc = CRC32.checksum(SSRBytes.be16(length)) & 0xFFFF
        var out = SSRBytes.be16(length) + SSRBytes.le16(Int(crc)) + body
        out += SSRBytes.le32(SSRBytes.adler32(out))
        return out
    }

    private func authFrame(_ data: [UInt8]) -> [UInt8] {
        let body = padding(for: data.count) + data
        let length = body.count + 16
        let crc = CRC32.checksum(SSRBytes.be16(length) + Self.salt + context.key)
        var out = SSRBytes.be16(length) + SSRBytes.le32(crc) + body
        out += SSRBytes.hmac(context.iv + context.key, out, sha1: true).prefix(10)
        return out
    }

    func decode(_ data: [UInt8]) throws -> [UInt8] {
        pending += data
        var out: [UInt8] = []
        while pending.count > 4 {
            let crc = CRC32.checksum(pending.prefix(2)) & 0xFFFF
            guard SSRBytes.le16(Int(crc)) == Array(pending[2..<4]) else { throw SSRError.authenticationFailed }
            let length = SSRBytes.readBE16(pending, 0)
            guard length >= 7, length < 8192 else { throw SSRError.malformedFrame }
            guard pending.count >= length else { break }
            guard SSRBytes.le32(SSRBytes.adler32(Array(pending.prefix(length - 4)))) == Array(pending[(length - 4)..<length]) else {
                throw SSRError.authenticationFailed
            }
            var position = Int(pending[4])
            position = position < 255 ? position + 4 : SSRBytes.readBE16(pending, 5) + 4
            // The padding length comes off the wire: it must stay in the frame.
            guard position <= length - 4 else { throw SSRError.malformedFrame }
            out += pending[position..<(length - 4)]
            pending.removeFirst(length)
        }
        return out
    }
}

// MARK: - auth_aes128_md5 / auth_aes128_sha1

/// HMAC-authenticated frames keyed per packet id; the first frame carries an
/// AES-sealed auth block and the (optional) user id.
final class SSRAuthAES128: SSRProtocolCodec {
    private static let unit = 8100
    private let context: SSRContext
    private let sha1: Bool
    private let salt: String
    private var userKey: [UInt8]
    private var userID: [UInt8]
    private var sentHeader = false
    private var packID: UInt32 = 1
    private var recvID: UInt32 = 1
    private var pending: [UInt8] = []

    init(context: SSRContext, sha1: Bool) {
        self.context = context
        self.sha1 = sha1
        self.salt = sha1 ? "auth_aes128_sha1" : "auth_aes128_md5"
        self.userKey = context.key
        self.userID = SSRBytes.random(4)
        let items = context.protocolParam.split(separator: ":", maxSplits: 1)
        if items.count == 2, let id = UInt32(items[0]) {
            let password = Array(items[1].utf8)
            self.userKey = sha1 ? Array(Insecure.SHA1.hash(data: password)) : Array(Insecure.MD5.hash(data: password))
            self.userID = SSRBytes.le32(id)
        }
    }

    func encode(_ plain: [UInt8]) throws -> [UInt8] {
        var buf = plain[...]
        var out: [UInt8] = []
        if !sentHeader {
            sentHeader = true
            let take = min(buf.count, Int.random(in: 0...31) + SSRBytes.headSize(Array(buf)))
            out += authFrame(Array(buf.prefix(take)))
            buf = buf.dropFirst(take)
        }
        while buf.count > Self.unit {
            out += frame(Array(buf.prefix(Self.unit)))
            buf = buf.dropFirst(Self.unit)
        }
        out += frame(Array(buf))
        return out
    }

    private func padding(for count: Int) -> [UInt8] {
        let length = count > 1300 ? 0 : Int.random(in: 0..<(count > 900 ? 32 : 127))
        return [UInt8(length + 1)] + SSRBytes.random(length)
    }

    private func frame(_ data: [UInt8]) -> [UInt8] {
        let body = padding(for: data.count) + data
        let length = body.count + 8
        let macKey = userKey + SSRBytes.le32(packID)
        var out = SSRBytes.le16(length)
        out += SSRBytes.hmac(macKey, out, sha1: sha1).prefix(2)
        out += body
        out += SSRBytes.hmac(macKey, out, sha1: sha1).prefix(4)
        packID &+= 1
        return out
    }

    private func authFrame(_ data: [UInt8]) -> [UInt8] {
        guard !data.isEmpty else { return [] }
        let padding = Int.random(in: 0..<(data.count > 400 ? 512 : 1024))
        let length = 7 + 4 + 16 + 4 + data.count + padding + 4
        let block = SSRClientIdentity.authData() + SSRBytes.le16(length) + SSRBytes.le16(padding)
        let macKey = context.iv + context.key
        let sealed = SSRAuthBlock.encrypt(block, password: Data(userKey).base64EncodedString() + salt)
        var identity = userID + sealed
        identity += SSRBytes.hmac(macKey, identity, sha1: sha1).prefix(4)
        let check = SSRBytes.random(1)
        var out = check + SSRBytes.hmac(macKey, check, sha1: sha1).prefix(6)
        out += identity + SSRBytes.random(padding) + data
        out += SSRBytes.hmac(userKey, out, sha1: sha1).prefix(4)
        return out
    }

    func decode(_ data: [UInt8]) throws -> [UInt8] {
        pending += data
        var out: [UInt8] = []
        while pending.count > 4 {
            let macKey = userKey + SSRBytes.le32(recvID)
            guard Array(SSRBytes.hmac(macKey, Array(pending.prefix(2)), sha1: sha1).prefix(2)) == Array(pending[2..<4]) else {
                throw SSRError.authenticationFailed
            }
            let length = SSRBytes.readLE16(pending, 0)
            guard length >= 7, length < 8192 else { throw SSRError.malformedFrame }
            guard pending.count >= length else { break }
            guard Array(SSRBytes.hmac(macKey, Array(pending.prefix(length - 4)), sha1: sha1).prefix(4)) == Array(pending[(length - 4)..<length]) else {
                throw SSRError.authenticationFailed
            }
            recvID &+= 1
            var position = Int(pending[4])
            position = position < 255 ? position + 4 : SSRBytes.readLE16(pending, 5) + 4
            guard position <= length - 4 else { throw SSRError.malformedFrame }
            out += pending[position..<(length - 4)]
            pending.removeFirst(length)
        }
        return out
    }
}

// MARK: - auth_chain_a

/// xorshift128+ as auth_chain seeds it from the previous frame's hash.
struct SSRXorShift128Plus {
    private var v0: UInt64 = 0
    private var v1: UInt64 = 0

    mutating func next() -> UInt64 {
        var x = v0
        let y = v1
        v0 = y
        x ^= x << 23
        x ^= y ^ (x >> 17) ^ (y >> 26)
        v1 = x
        return x &+ y
    }

    /// `init_from_bin_len`: the first two bytes replaced by `length`, then
    /// four rounds discarded.
    mutating func seed(hash: [UInt8], length: Int) {
        var first = SSRBytes.le16(length) + hash[2..<8]
        v0 = Self.le64(&first)
        var second = Array(hash[8..<16])
        v1 = Self.le64(&second)
        for _ in 0..<4 { _ = next() }
    }

    private static func le64(_ bytes: inout [UInt8]) -> UInt64 {
        bytes.enumerated().reduce(UInt64(0)) { $0 | UInt64($1.element) << UInt64($1.offset * 8) }
    }
}

/// Frames chained by HMAC-MD5: each frame's length is XOR-masked with the
/// previous hash, its payload RC4-encrypted and hidden at a pseudo-random
/// offset inside pseudo-random padding.
final class SSRAuthChainA: SSRProtocolCodec {
    private static let unit = 2800
    private static let salt = "auth_chain_a"
    private let context: SSRContext
    private var userKey: [UInt8]
    private var userID: [UInt8]
    private var sentHeader = false
    private var packID: UInt32 = 1
    private var recvID: UInt32 = 1
    private var lastClientHash: [UInt8] = []
    private var lastServerHash: [UInt8] = []
    private var randomClient = SSRXorShift128Plus()
    private var randomServer = SSRXorShift128Plus()
    private var encryptor: SSRStreamCrypter?
    private var decryptor: SSRStreamCrypter?
    private var pending: [UInt8] = []
    private var sawMSS = false

    init(context: SSRContext) {
        self.context = context
        self.userKey = context.key
        self.userID = SSRBytes.random(4)
        let items = context.protocolParam.split(separator: ":", maxSplits: 1)
        if items.count == 2, let id = UInt32(items[0]) {
            self.userKey = Array(items[1].utf8)
            self.userID = SSRBytes.le32(id)
        }
    }

    static func randomLength(_ size: Int, hash: [UInt8], random: inout SSRXorShift128Plus) -> Int {
        guard size <= 1440 else { return 0 }
        random.seed(hash: hash, length: size)
        let modulus: UInt64 = size > 1300 ? 31 : size > 900 ? 127 : size > 400 ? 521 : 1021
        return Int(random.next() % modulus)
    }

    static func startPosition(_ randomLength: Int, random: inout SSRXorShift128Plus) -> Int {
        guard randomLength > 0 else { return 0 }
        return Int(random.next() % 8_589_934_609 % UInt64(randomLength))
    }

    func encode(_ plain: [UInt8]) throws -> [UInt8] {
        var buf = plain[...]
        var out: [UInt8] = []
        if !sentHeader {
            sentHeader = true
            let take = min(buf.count, Int.random(in: 0...31) + SSRBytes.headSize(Array(buf)))
            out += try authFrame(Array(buf.prefix(take)))
            buf = buf.dropFirst(take)
        }
        while buf.count > Self.unit {
            out += frame(Array(buf.prefix(Self.unit)))
            buf = buf.dropFirst(Self.unit)
        }
        out += frame(Array(buf))
        return out
    }

    private func frame(_ data: [UInt8]) -> [UInt8] {
        let sealed = encryptor?.update(data) ?? data
        let randomLength = Self.randomLength(sealed.count, hash: lastClientHash, random: &randomClient)
        let padding = SSRBytes.random(randomLength)
        var body: [UInt8]
        if sealed.isEmpty {
            body = padding
        } else if randomLength > 0 {
            let start = Self.startPosition(randomLength, random: &randomClient)
            body = Array(padding[..<start]) + sealed + Array(padding[start...])
        } else {
            body = sealed
        }
        let macKey = userKey + SSRBytes.le32(packID)
        let length = sealed.count ^ SSRBytes.readLE16(lastClientHash, 14)
        body = SSRBytes.le16(length) + body
        lastClientHash = SSRBytes.hmac(macKey, body, sha1: false)
        packID &+= 1
        return body + lastClientHash.prefix(2)
    }

    private func authFrame(_ data: [UInt8]) throws -> [UInt8] {
        let block = SSRClientIdentity.authData() + SSRBytes.le16(context.overhead) + SSRBytes.le16(0)
        let macKey = context.iv + context.key
        var check = SSRBytes.random(4)
        lastClientHash = SSRBytes.hmac(macKey, check, sha1: false)
        check += lastClientHash.prefix(8)

        var uid = userID
        for index in 0..<4 {
            uid[index] ^= lastClientHash[8 + index]
        }
        let sealed = SSRAuthBlock.encrypt(block, password: Data(userKey).base64EncodedString() + Self.salt)
        let identity = uid + sealed
        lastServerHash = SSRBytes.hmac(userKey, identity, sha1: false)

        let rc4Password = Data(userKey).base64EncodedString() + Data(lastClientHash).base64EncodedString()
        let rc4Key = ShadowsocksKeyDerivation.evpBytesToKey(password: rc4Password, keyByteCount: 16)
        encryptor = try SSRStreamCrypter.rc4(key: rc4Key, encrypt: true)
        decryptor = try SSRStreamCrypter.rc4(key: rc4Key, encrypt: false)
        return check + identity + lastServerHash.prefix(4) + frame(data)
    }

    func decode(_ data: [UInt8]) throws -> [UInt8] {
        // The server hash chain starts from our auth frame.
        guard lastServerHash.count >= 16 else { throw SSRError.malformedFrame }
        pending += data
        var out: [UInt8] = []
        while pending.count > 4 {
            let macKey = userKey + SSRBytes.le32(recvID)
            let dataLength = SSRBytes.readLE16(pending, 0) ^ SSRBytes.readLE16(lastServerHash, 14)
            let randomLength = Self.randomLength(dataLength, hash: lastServerHash, random: &randomServer)
            let length = dataLength + randomLength
            guard length < 4096 else { throw SSRError.malformedFrame }
            guard pending.count >= length + 4 else { break }
            let serverHash = SSRBytes.hmac(macKey, Array(pending.prefix(length + 2)), sha1: false)
            guard Array(serverHash.prefix(2)) == Array(pending[(length + 2)..<(length + 4)]) else {
                throw SSRError.authenticationFailed
            }
            var position = 2
            if dataLength > 0, randomLength > 0 {
                position += Self.startPosition(randomLength, random: &randomServer)
            }
            var plain = decryptor?.update(Array(pending[position..<(position + dataLength)])) ?? []
            lastServerHash = serverHash
            if recvID == 1, !sawMSS {
                // The server's first frame starts with its TCP MSS.
                sawMSS = true
                plain = Array(plain.dropFirst(2))
            }
            out += plain
            recvID &+= 1
            pending.removeFirst(length + 4)
        }
        return out
    }
}
