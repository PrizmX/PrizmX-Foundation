import CryptoKit
import Foundation
import Network

// MARK: - TLS 1.3 constants

/// Minimal userspace TLS 1.3 client used by REALITY.
///
/// Network.framework cannot inject a custom ClientHello Session ID, so REALITY
/// must speak TLS 1.3 on a raw TCP `NWConnection`. Cipher suites:
/// `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`.
enum TLS13 {
    static let recordHeaderByteCount = 5
    static let maxPlaintext = 1 << 14
    static let handshakeClientHello: UInt8 = 1
    static let handshakeServerHello: UInt8 = 2
    static let handshakeEncryptedExtensions: UInt8 = 8
    static let handshakeCertificate: UInt8 = 11
    static let handshakeCertificateVerify: UInt8 = 15
    static let handshakeFinished: UInt8 = 20
    static let handshakeNewSessionTicket: UInt8 = 4
    static let contentChangeCipherSpec: UInt8 = 20
    static let contentAlert: UInt8 = 21
    static let contentHandshake: UInt8 = 22
    static let contentApplicationData: UInt8 = 23
    static let versionTLS10: UInt16 = 0x0301
    static let versionTLS12: UInt16 = 0x0303
    static let versionTLS13: UInt16 = 0x0304
    static let namedGroupX25519: UInt16 = 0x001D
    static let signatureEd25519: UInt16 = 0x0807
    static let extServerName: UInt16 = 0
    static let extSupportedGroups: UInt16 = 10
    static let extECPointFormats: UInt16 = 11
    static let extSignatureAlgorithms: UInt16 = 13
    static let extALPN: UInt16 = 16
    static let extSupportedVersions: UInt16 = 43
    static let extPSKModes: UInt16 = 45
    static let extKeyShare: UInt16 = 51
    static let extRenegotiationInfo: UInt16 = 0xFF01

    static let aes128GCMSha256: UInt16 = 0x1301
    static let aes256GCMSha384: UInt16 = 0x1302
    static let chacha20Poly1305Sha256: UInt16 = 0x1303

    /// HelloRetryRequest.random (RFC 8446).
    static let helloRetryRequestRandom: [UInt8] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ]
}

// MARK: - Byte writer / reader

struct TLS13ByteWriter {
    private(set) var bytes: [UInt8] = []

    mutating func u8(_ value: UInt8) { bytes.append(value) }

    mutating func u16(_ value: UInt16) {
        bytes.append(UInt8(value >> 8))
        bytes.append(UInt8(value & 0xFF))
    }

    mutating func append(_ data: [UInt8]) { bytes.append(contentsOf: data) }

    mutating func withU8Length(_ body: (inout TLS13ByteWriter) -> Void) {
        let index = bytes.count
        u8(0)
        let start = bytes.count
        body(&self)
        bytes[index] = UInt8(bytes.count - start)
    }

    mutating func withU16Length(_ body: (inout TLS13ByteWriter) -> Void) {
        let index = bytes.count
        u16(0)
        let start = bytes.count
        body(&self)
        let length = bytes.count - start
        bytes[index] = UInt8(length >> 8)
        bytes[index + 1] = UInt8(length & 0xFF)
    }

    mutating func withU24Length(_ body: (inout TLS13ByteWriter) -> Void) {
        let index = bytes.count
        bytes.append(contentsOf: [0, 0, 0])
        let start = bytes.count
        body(&self)
        let length = bytes.count - start
        bytes[index] = UInt8((length >> 16) & 0xFF)
        bytes[index + 1] = UInt8((length >> 8) & 0xFF)
        bytes[index + 2] = UInt8(length & 0xFF)
    }
}

struct TLS13ByteReader {
    let bytes: [UInt8]
    var offset = 0

    var remaining: Int { bytes.count - offset }

    mutating func u8() throws -> UInt8 {
        guard remaining >= 1 else {
            throw REALITYError.truncated(expected: 1, actual: remaining)
        }
        defer { offset += 1 }
        return bytes[offset]
    }

    mutating func u16() throws -> UInt16 {
        let high = try u8()
        let low = try u8()
        return (UInt16(high) << 8) | UInt16(low)
    }

    mutating func u24() throws -> Int {
        let a = try u8()
        let b = try u8()
        let c = try u8()
        return (Int(a) << 16) | (Int(b) << 8) | Int(c)
    }

    mutating func take(_ count: Int) throws -> [UInt8] {
        guard remaining >= count else {
            throw REALITYError.truncated(expected: count, actual: remaining)
        }
        let slice = Array(bytes[offset..<(offset + count)])
        offset += count
        return slice
    }

    mutating func vec8() throws -> [UInt8] {
        let length = Int(try u8())
        return try take(length)
    }

    mutating func vec16() throws -> [UInt8] {
        let length = Int(try u16())
        return try take(length)
    }

    mutating func vec24() throws -> [UInt8] {
        let length = try u24()
        return try take(length)
    }
}

// MARK: - Random

enum TLS13Random {
    static func bytes(_ count: Int) -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        return (0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) }
    }
}

// MARK: - ClientHello

struct TLS13ClientHelloBuilt {
    /// Handshake message (type + uint24 + ClientHello), no record header.
    var handshake: [UInt8]
    /// 32-byte `legacy_random`.
    var random: [UInt8]
    var ephemeral: Curve25519.KeyAgreement.PrivateKey
    var publicKeyBytes: [UInt8]
}

enum TLS13ClientHelloBuilder {
    /// Builds a TLS 1.3 ClientHello with a 32-byte Session ID (REALITY offset 39).
    static func build(
        serverName: String,
        ephemeral: Curve25519.KeyAgreement.PrivateKey,
        sessionID: [UInt8] = [UInt8](repeating: 0, count: REALITY.sessionIDByteCount),
        random: [UInt8]? = nil
    ) -> TLS13ClientHelloBuilt {
        precondition(sessionID.count == REALITY.sessionIDByteCount)
        let random = random ?? TLS13Random.bytes(32)
        precondition(random.count == 32, "ClientHello.Random must be 32 bytes")
        let publicKey = Array(ephemeral.publicKey.rawRepresentation)

        var body = TLS13ByteWriter()
        body.u16(TLS13.versionTLS12)
        body.append(random)
        body.u8(UInt8(sessionID.count))
        body.append(sessionID)

        body.withU16Length { suites in
            suites.u16(TLS13.aes128GCMSha256)
            suites.u16(TLS13.aes256GCMSha384)
            suites.u16(TLS13.chacha20Poly1305Sha256)
        }
        body.u8(1)
        body.u8(0)

        body.withU16Length { extensions in
            writeServerName(&extensions, serverName)
            writeSupportedGroups(&extensions)
            writeECPointFormats(&extensions)
            writeSignatureAlgorithms(&extensions)
            writeALPN(&extensions)
            writeSupportedVersions(&extensions)
            writePSKModes(&extensions)
            writeKeyShare(&extensions, publicKey)
            writeRenegotiationInfo(&extensions)
        }

        var handshake = TLS13ByteWriter()
        handshake.u8(TLS13.handshakeClientHello)
        handshake.withU24Length { $0.append(body.bytes) }

        return TLS13ClientHelloBuilt(
            handshake: handshake.bytes,
            random: random,
            ephemeral: ephemeral,
            publicKeyBytes: publicKey
        )
    }

    static func wrapRecord(_ handshake: [UInt8]) -> [UInt8] {
        var record = TLS13ByteWriter()
        record.u8(TLS13.contentHandshake)
        record.u16(TLS13.versionTLS10)
        record.u16(UInt16(handshake.count))
        record.append(handshake)
        return record.bytes
    }

    private static func writeServerName(_ writer: inout TLS13ByteWriter, _ name: String) {
        let host = Array(name.utf8)
        writer.u16(TLS13.extServerName)
        writer.withU16Length { body in
            body.withU16Length { list in
                list.u8(0) // host_name
                list.withU16Length { $0.append(host) }
            }
        }
    }

    private static func writeSupportedGroups(_ writer: inout TLS13ByteWriter) {
        writer.u16(TLS13.extSupportedGroups)
        writer.withU16Length { body in
            body.withU16Length { list in
                list.u16(TLS13.namedGroupX25519)
                list.u16(0x0017) // secp256r1
                list.u16(0x0018) // secp384r1
            }
        }
    }

    private static func writeECPointFormats(_ writer: inout TLS13ByteWriter) {
        writer.u16(TLS13.extECPointFormats)
        writer.withU16Length { body in
            body.u8(1)
            body.u8(0)
        }
    }

    private static func writeSignatureAlgorithms(_ writer: inout TLS13ByteWriter) {
        writer.u16(TLS13.extSignatureAlgorithms)
        writer.withU16Length { body in
            body.withU16Length { list in
                list.u16(0x0403) // ecdsa_secp256r1_sha256
                list.u16(0x0804) // rsa_pss_rsae_sha256
                list.u16(0x0401) // rsa_pkcs1_sha256
                list.u16(0x0503) // ecdsa_secp384r1_sha384
                list.u16(0x0805) // rsa_pss_rsae_sha384
                list.u16(TLS13.signatureEd25519)
                list.u16(0x0806) // rsa_pss_rsae_sha512
                list.u16(0x0601) // rsa_pkcs1_sha512
            }
        }
    }

    private static func writeALPN(_ writer: inout TLS13ByteWriter) {
        writer.u16(TLS13.extALPN)
        writer.withU16Length { body in
            body.withU16Length { list in
                list.withU8Length { $0.append(Array("h2".utf8)) }
                list.withU8Length { $0.append(Array("http/1.1".utf8)) }
            }
        }
    }

    private static func writeSupportedVersions(_ writer: inout TLS13ByteWriter) {
        writer.u16(TLS13.extSupportedVersions)
        writer.withU16Length { body in
            body.withU8Length { $0.u16(TLS13.versionTLS13) }
        }
    }

    private static func writePSKModes(_ writer: inout TLS13ByteWriter) {
        writer.u16(TLS13.extPSKModes)
        writer.withU16Length { body in
            body.u8(1)
            body.u8(1) // psk_dhe_ke
        }
    }

    private static func writeKeyShare(_ writer: inout TLS13ByteWriter, _ publicKey: [UInt8]) {
        writer.u16(TLS13.extKeyShare)
        writer.withU16Length { body in
            body.withU16Length { list in
                list.u16(TLS13.namedGroupX25519)
                list.withU16Length { $0.append(publicKey) }
            }
        }
    }

    private static func writeRenegotiationInfo(_ writer: inout TLS13ByteWriter) {
        writer.u16(TLS13.extRenegotiationInfo)
        writer.withU16Length { body in
            body.u8(0)
        }
    }
}

// MARK: - Hash / HKDF / traffic keys

enum TLS13HashKind {
    case sha256
    case sha384

    var byteCount: Int {
        switch self {
        case .sha256: return 32
        case .sha384: return 48
        }
    }

    func hash(_ data: Data) -> Data {
        switch self {
        case .sha256: return Data(SHA256.hash(data: data))
        case .sha384: return Data(SHA384.hash(data: data))
        }
    }

    func hmac(key: Data, data: Data) -> Data {
        let symmetric = SymmetricKey(data: key)
        switch self {
        case .sha256:
            let mac = HMAC<SHA256>.authenticationCode(for: data, using: symmetric)
            return mac.withUnsafeBytes { Data($0) }
        case .sha384:
            let mac = HMAC<SHA384>.authenticationCode(for: data, using: symmetric)
            return mac.withUnsafeBytes { Data($0) }
        }
    }

    func extract(salt: Data, ikm: Data) -> Data {
        let saltKey: Data
        if salt.isEmpty {
            saltKey = Data(count: byteCount)
        } else {
            saltKey = salt
        }
        return hmac(key: saltKey, data: ikm)
    }

    func expand(prk: Data, info: Data, length: Int) -> Data {
        let prkKey = SymmetricKey(data: prk)
        var previous = Data()
        var okm = Data()
        okm.reserveCapacity(length)
        var counter: UInt8 = 1
        while okm.count < length {
            switch self {
            case .sha256:
                var inner = HMAC<SHA256>(key: prkKey)
                if !previous.isEmpty { inner.update(data: previous) }
                inner.update(data: info)
                inner.update(data: [counter])
                previous = inner.finalize().withUnsafeBytes { Data($0) }
            case .sha384:
                var inner = HMAC<SHA384>(key: prkKey)
                if !previous.isEmpty { inner.update(data: previous) }
                inner.update(data: info)
                inner.update(data: [counter])
                previous = inner.finalize().withUnsafeBytes { Data($0) }
            }
            okm.append(previous)
            counter += 1
        }
        return Data(okm.prefix(length))
    }

    func expandLabel(secret: Data, label: String, context: Data, length: Int) -> Data {
        let fullLabel = Array(("tls13 " + label).utf8)
        var hkdfLabel = Data()
        hkdfLabel.append(UInt8(length >> 8))
        hkdfLabel.append(UInt8(length & 0xFF))
        hkdfLabel.append(UInt8(fullLabel.count))
        hkdfLabel.append(contentsOf: fullLabel)
        hkdfLabel.append(UInt8(context.count))
        hkdfLabel.append(context)
        return expand(prk: secret, info: hkdfLabel, length: length)
    }

    func deriveSecret(secret: Data, label: String, transcript: Data) -> Data {
        expandLabel(secret: secret, label: label, context: hash(transcript), length: byteCount)
    }
}

struct TLS13CipherSuite {
    let rawValue: UInt16
    let hash: TLS13HashKind
    let keyByteCount: Int
    let aead: TLS13AEADKind

    static func parse(_ value: UInt16) throws -> TLS13CipherSuite {
        switch value {
        case TLS13.aes128GCMSha256:
            return TLS13CipherSuite(rawValue: value, hash: .sha256, keyByteCount: 16, aead: .aesGCM)
        case TLS13.aes256GCMSha384:
            return TLS13CipherSuite(rawValue: value, hash: .sha384, keyByteCount: 32, aead: .aesGCM)
        case TLS13.chacha20Poly1305Sha256:
            return TLS13CipherSuite(rawValue: value, hash: .sha256, keyByteCount: 32, aead: .chachaPoly)
        default:
            throw REALITYError.unsupportedCipherSuite(value)
        }
    }
}

enum TLS13AEADKind {
    case aesGCM
    case chachaPoly
}

struct TLS13TrafficKeys {
    var key: SymmetricKey
    var iv: [UInt8]
    var sequence: UInt64 = 0
    let aead: TLS13AEADKind
}

struct TLS13TrafficPair {
    var client: TLS13TrafficKeys
    var server: TLS13TrafficKeys
}

enum TLS13AEAD {
    static func seal(
        plaintext: Data,
        keys: inout TLS13TrafficKeys,
        contentType: UInt8
    ) throws -> Data {
        var inner = plaintext
        inner.append(contentType)
        let nonce = xorNonce(keys.iv, keys.sequence)
        keys.sequence += 1
        let ciphertextLength = inner.count + 16
        var header: [UInt8] = [
            TLS13.contentApplicationData,
            0x03, 0x03,
            UInt8(ciphertextLength >> 8),
            UInt8(ciphertextLength & 0xFF),
        ]
        let aad = Data(header)
        let (ciphertext, tag) = try sealInner(
            plaintext: inner,
            key: keys.key,
            nonce: nonce,
            aad: aad,
            kind: keys.aead
        )
        header.append(contentsOf: ciphertext)
        header.append(contentsOf: tag)
        return Data(header)
    }

    static func open(
        recordHeader: [UInt8],
        fragment: [UInt8],
        keys: inout TLS13TrafficKeys
    ) throws -> (contentType: UInt8, plaintext: Data) {
        guard fragment.count >= 16 else {
            throw REALITYError.truncated(expected: 16, actual: fragment.count)
        }
        let ciphertext = Array(fragment.dropLast(16))
        let tag = Array(fragment.suffix(16))
        let nonce = xorNonce(keys.iv, keys.sequence)
        keys.sequence += 1
        let inner = try openInner(
            ciphertext: Data(ciphertext),
            tag: Data(tag),
            key: keys.key,
            nonce: nonce,
            aad: Data(recordHeader),
            kind: keys.aead
        )
        guard let typeIndex = inner.lastIndex(where: { $0 != 0 }) else {
            throw REALITYError.handshakeFailed("empty TLS inner plaintext")
        }
        let type = inner[typeIndex]
        return (type, Data(inner[..<typeIndex]))
    }

    private static func sealInner(
        plaintext: Data,
        key: SymmetricKey,
        nonce: [UInt8],
        aad: Data,
        kind: TLS13AEADKind
    ) throws -> (Data, [UInt8]) {
        switch kind {
        case .aesGCM:
            let box = try AES.GCM.seal(
                plaintext,
                using: key,
                nonce: try AES.GCM.Nonce(data: Data(nonce)),
                authenticating: aad
            )
            return (box.ciphertext, Array(box.tag))
        case .chachaPoly:
            let box = try ChaChaPoly.seal(
                plaintext,
                using: key,
                nonce: try ChaChaPoly.Nonce(data: Data(nonce)),
                authenticating: aad
            )
            return (box.ciphertext, Array(box.tag))
        }
    }

    private static func openInner(
        ciphertext: Data,
        tag: Data,
        key: SymmetricKey,
        nonce: [UInt8],
        aad: Data,
        kind: TLS13AEADKind
    ) throws -> Data {
        do {
            switch kind {
            case .aesGCM:
                let box = try AES.GCM.SealedBox(
                    nonce: try AES.GCM.Nonce(data: Data(nonce)),
                    ciphertext: ciphertext,
                    tag: tag
                )
                return try AES.GCM.open(box, using: key, authenticating: aad)
            case .chachaPoly:
                let box = try ChaChaPoly.SealedBox(
                    nonce: try ChaChaPoly.Nonce(data: Data(nonce)),
                    ciphertext: ciphertext,
                    tag: tag
                )
                return try ChaChaPoly.open(box, using: key, authenticating: aad)
            }
        } catch {
            throw REALITYError.handshakeFailed("TLS record authentication failed")
        }
    }

    static func xorNonce(_ iv: [UInt8], _ sequence: UInt64) -> [UInt8] {
        var nonce = iv
        for index in 0..<8 {
            let shift = (7 - index) * 8
            nonce[nonce.count - 8 + index] ^= UInt8((sequence >> shift) & 0xFF)
        }
        return nonce
    }
}

struct TLS13HandshakeSecrets {
    var pair: TLS13TrafficPair
    var master: Data
    var clientHSTrafficSecret: Data
    var serverHSTrafficSecret: Data
}

enum TLS13KeySchedule {
    static func handshakeSecrets(
        suite: TLS13CipherSuite,
        sharedSecret: Data,
        transcript: Data
    ) -> TLS13HandshakeSecrets {
        let hash = suite.hash
        let zeros = Data(count: hash.byteCount)
        let early = hash.extract(salt: zeros, ikm: zeros)
        let emptyHash = hash.hash(Data())
        let derived = hash.expandLabel(secret: early, label: "derived", context: emptyHash, length: hash.byteCount)
        let handshakeSecret = hash.extract(salt: derived, ikm: sharedSecret)
        let clientHS = hash.deriveSecret(secret: handshakeSecret, label: "c hs traffic", transcript: transcript)
        let serverHS = hash.deriveSecret(secret: handshakeSecret, label: "s hs traffic", transcript: transcript)
        let derived2 = hash.expandLabel(
            secret: handshakeSecret,
            label: "derived",
            context: emptyHash,
            length: hash.byteCount
        )
        let master = hash.extract(salt: derived2, ikm: zeros)
        return TLS13HandshakeSecrets(
            pair: TLS13TrafficPair(
                client: trafficKeys(secret: clientHS, suite: suite),
                server: trafficKeys(secret: serverHS, suite: suite)
            ),
            master: master,
            clientHSTrafficSecret: clientHS,
            serverHSTrafficSecret: serverHS
        )
    }

    static func applicationSecrets(
        suite: TLS13CipherSuite,
        master: Data,
        transcript: Data
    ) -> TLS13TrafficPair {
        let hash = suite.hash
        let client = hash.deriveSecret(secret: master, label: "c ap traffic", transcript: transcript)
        let server = hash.deriveSecret(secret: master, label: "s ap traffic", transcript: transcript)
        return TLS13TrafficPair(
            client: trafficKeys(secret: client, suite: suite),
            server: trafficKeys(secret: server, suite: suite)
        )
    }

    static func finishedVerifyData(trafficSecret: Data, suite: TLS13CipherSuite, transcript: Data) -> Data {
        let hash = suite.hash
        let finishedKey = hash.expandLabel(
            secret: trafficSecret,
            label: "finished",
            context: Data(),
            length: hash.byteCount
        )
        return hash.hmac(key: finishedKey, data: hash.hash(transcript))
    }

    private static func trafficKeys(secret: Data, suite: TLS13CipherSuite) -> TLS13TrafficKeys {
        let key = suite.hash.expandLabel(secret: secret, label: "key", context: Data(), length: suite.keyByteCount)
        let iv = suite.hash.expandLabel(secret: secret, label: "iv", context: Data(), length: 12)
        return TLS13TrafficKeys(
            key: SymmetricKey(data: key),
            iv: Array(iv),
            aead: suite.aead
        )
    }

}

// MARK: - X.509 (Ed25519 leaf)

struct TLS13Certificate {
    let der: [UInt8]
    let publicKey: [UInt8]
    let signature: [UInt8]
    let isEd25519: Bool
}

enum TLS13X509 {
    static func parse(_ der: [UInt8]) throws -> TLS13Certificate {
        var reader = DERReader(bytes: der)
        var cert = try reader.sequence()
        var tbs = try cert.sequence()
        let tbsBytes = Array(der[tbs.sourceRange])
        _ = tbsBytes
        if tbs.peekTag() == 0xA0 { try tbs.skipTLV() }
        try tbs.skipTLV() // serial
        try tbs.skipTLV() // signature algorithm
        try tbs.skipTLV() // issuer
        try tbs.skipTLV() // validity
        try tbs.skipTLV() // subject
        var spki = try tbs.sequence()
        var algorithm = try spki.sequence()
        let oid = try algorithm.oid()
        let isEd25519 = oid == [0x2B, 0x65, 0x70]
        let bitString = try spki.bitString()
        try cert.skipTLV() // signatureAlgorithm
        let signature = try cert.bitString()

        var publicKey: [UInt8] = []
        if isEd25519, bitString.count == 32 {
            publicKey = bitString
        } else if isEd25519, bitString.count > 32 {
            publicKey = Array(bitString.suffix(32))
        }

        return TLS13Certificate(
            der: der,
            publicKey: publicKey,
            signature: signature,
            isEd25519: isEd25519
        )
    }
}

struct DERReader {
    let bytes: [UInt8]
    var offset = 0
    let base: Int

    var sourceRange: Range<Int> { base..<(base + bytes.count) }

    init(bytes: [UInt8], base: Int = 0) {
        self.bytes = bytes
        self.base = base
    }

    func peekTag() -> UInt8? {
        guard offset < bytes.count else { return nil }
        return bytes[offset]
    }

    mutating func sequence() throws -> DERReader {
        let (tag, content, contentBase) = try readTLV()
        guard tag == 0x30 else {
            throw REALITYError.handshakeFailed("DER expected SEQUENCE")
        }
        return DERReader(bytes: content, base: contentBase)
    }

    mutating func oid() throws -> [UInt8] {
        let (tag, content, _) = try readTLV()
        guard tag == 0x06 else {
            throw REALITYError.handshakeFailed("DER expected OID")
        }
        return content
    }

    mutating func bitString() throws -> [UInt8] {
        let (tag, content, _) = try readTLV()
        guard tag == 0x03, !content.isEmpty else {
            throw REALITYError.handshakeFailed("DER expected BIT STRING")
        }
        return Array(content.dropFirst())
    }

    mutating func skipTLV() throws {
        _ = try readTLV()
    }

    mutating func readTLV() throws -> (UInt8, [UInt8], Int) {
        guard offset < bytes.count else {
            throw REALITYError.truncated(expected: 2, actual: 0)
        }
        let tag = bytes[offset]
        offset += 1
        let (length, header) = try readLength()
        _ = header
        // Subtraction form: `length` alone may be near Int.max.
        guard length <= bytes.count - offset else {
            throw REALITYError.truncated(expected: length, actual: bytes.count - offset)
        }
        let contentBase = base + offset
        let content = Array(bytes[offset..<(offset + length)])
        offset += length
        return (tag, content, contentBase)
    }

    private mutating func readLength() throws -> (Int, Int) {
        guard offset < bytes.count else {
            throw REALITYError.truncated(expected: 1, actual: 0)
        }
        let first = bytes[offset]
        offset += 1
        if first & 0x80 == 0 {
            return (Int(first), 1)
        }
        let count = Int(first & 0x7F)
        // Cap the long-form width at 8 bytes: wider lengths can only come
        // from a hostile or broken peer and would overflow Int below.
        guard count > 0, count <= MemoryLayout<UInt64>.size, offset + count <= bytes.count else {
            throw REALITYError.truncated(expected: count, actual: bytes.count - offset)
        }
        var wide: UInt64 = 0
        for _ in 0..<count {
            wide = (wide << 8) | UInt64(bytes[offset])
            offset += 1
        }
        guard let length = Int(exactly: wide) else {
            throw REALITYError.truncated(expected: Int.max, actual: bytes.count)
        }
        return (length, 1 + count)
    }
}

// MARK: - Record layer (post-handshake)

final class TLS13RecordLayer: @unchecked Sendable {
    private var application: TLS13TrafficPair
    private var incoming = DirectBuffer()
    private var pendingPlaintext = DirectBuffer()

    init(application: TLS13TrafficPair) {
        self.application = application
    }

    func sealApplication(_ plaintext: Data) throws -> Data {
        var output = Data()
        var offset = 0
        while offset < plaintext.count {
            let end = min(offset + TLS13.maxPlaintext, plaintext.count)
            let chunk = plaintext.subdata(in: offset..<end)
            output.append(try TLS13AEAD.seal(
                plaintext: chunk,
                keys: &application.client,
                contentType: TLS13.contentApplicationData
            ))
            offset = end
        }
        return output
    }

    func feedWire(_ chunk: Data) throws {
        incoming.append(chunk)
        try drainRecords()
    }

    func drainPlaintext() -> Data {
        let count = pendingPlaintext.readableByteCount
        guard count > 0 else { return Data() }
        let data = Data(pendingPlaintext.readableBytes)
        pendingPlaintext.consume(count)
        return data
    }

    private func drainRecords() throws {
        while incoming.readableByteCount >= TLS13.recordHeaderByteCount {
            let headerView = incoming.readableBytes
            let length = (Int(headerView[3]) << 8) | Int(headerView[4])
            let total = TLS13.recordHeaderByteCount + length
            guard incoming.readableByteCount >= total else { return }
            let raw = Array(headerView)
            let header = Array(raw.prefix(TLS13.recordHeaderByteCount))
            let fragment = Array(raw[TLS13.recordHeaderByteCount..<total])
            incoming.consume(total)

            let recordType = header[0]
            if recordType == TLS13.contentChangeCipherSpec {
                continue
            }
            if recordType == TLS13.contentAlert {
                if fragment.count >= 2 {
                    throw REALITYError.alert(fragment[0], fragment[1])
                }
                throw REALITYError.alert(0, 0)
            }

            let (innerType, plaintext) = try TLS13AEAD.open(
                recordHeader: header,
                fragment: fragment,
                keys: &application.server
            )
            switch innerType {
            case TLS13.contentApplicationData:
                pendingPlaintext.append(Array(plaintext))
            case TLS13.contentHandshake:
                continue
            case TLS13.contentAlert:
                let bytes = Array(plaintext)
                if bytes.count >= 2 {
                    throw REALITYError.alert(bytes[0], bytes[1])
                }
                throw REALITYError.alert(0, 0)
            default:
                break
            }
        }
    }
}

// MARK: - Handshake

enum TLS13Handshake {
    static func run(
        connection: NWConnection,
        queue _: DispatchQueue,
        clientHello: TLS13ClientHelloBuilt,
        verifyCertificate: (TLS13Certificate) throws -> Void
    ) async throws -> TLS13RecordLayer {
        let incoming = DirectBuffer()

        func send(_ data: Data) async throws {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                connection.send(
                    content: data,
                    completion: .contentProcessed { error in
                        if let error {
                            continuation.resume(throwing: error)
                        } else {
                            continuation.resume()
                        }
                    }
                )
            }
        }

        func receiveMore() async throws {
            let chunk: Data = try await withCheckedThrowingContinuation { continuation in
                connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, isComplete, error in
                    if let error {
                        continuation.resume(throwing: error)
                        return
                    }
                    if isComplete && (data == nil || data?.isEmpty == true) {
                        continuation.resume(returning: Data())
                        return
                    }
                    continuation.resume(returning: data ?? Data())
                }
            }
            guard !chunk.isEmpty else {
                throw REALITYError.handshakeFailed("peer closed during TLS handshake")
            }
            incoming.append(chunk)
        }

        func readRecord() async throws -> (type: UInt8, header: [UInt8], fragment: [UInt8]) {
            while incoming.readableByteCount < TLS13.recordHeaderByteCount {
                try await receiveMore()
            }
            let view = incoming.readableBytes
            let length = (Int(view[3]) << 8) | Int(view[4])
            let total = TLS13.recordHeaderByteCount + length
            while incoming.readableByteCount < total {
                try await receiveMore()
            }
            let raw = Array(incoming.readableBytes)
            let header = Array(raw.prefix(TLS13.recordHeaderByteCount))
            let fragment = Array(raw[TLS13.recordHeaderByteCount..<total])
            incoming.consume(total)
            return (header[0], header, fragment)
        }

        try await send(Data(TLS13ClientHelloBuilder.wrapRecord(clientHello.handshake)))

        var transcript = Data(clientHello.handshake)
        var suite: TLS13CipherSuite?
        var serverShare: [UInt8]?
        var handshakeKeys: TLS13TrafficPair?
        var masterSecret: Data?
        var clientHSSecret: Data?
        var serverHSSecret: Data?
        var hsBuffer: [UInt8] = []
        var sawEncryptedExtensions = false
        var sawCertificate = false
        var sawCertificateVerify = false
        var sawFinished = false
        var leaf: TLS13Certificate?

        func popHandshake() throws -> (UInt8, [UInt8], Data)? {
            guard hsBuffer.count >= 4 else { return nil }
            let type = hsBuffer[0]
            let length = (Int(hsBuffer[1]) << 16) | (Int(hsBuffer[2]) << 8) | Int(hsBuffer[3])
            guard hsBuffer.count >= 4 + length else { return nil }
            let raw = Data(hsBuffer[0..<(4 + length)])
            let body = Array(hsBuffer[4..<(4 + length)])
            hsBuffer.removeFirst(4 + length)
            return (type, body, raw)
        }

        func parseServerHello(_ body: [UInt8]) throws {
            var reader = TLS13ByteReader(bytes: body)
            _ = try reader.u16()
            let random = try reader.take(32)
            if random == TLS13.helloRetryRequestRandom {
                throw REALITYError.handshakeFailed("HelloRetryRequest is not supported")
            }
            _ = try reader.vec8()
            let cipher = try reader.u16()
            _ = try reader.u8()
            suite = try TLS13CipherSuite.parse(cipher)
            let extensions = try reader.vec16()
            var extReader = TLS13ByteReader(bytes: extensions)
            var sawTLS13 = false
            while extReader.remaining > 0 {
                let extType = try extReader.u16()
                let extData = try extReader.vec16()
                if extType == TLS13.extSupportedVersions {
                    var inner = TLS13ByteReader(bytes: extData)
                    if try inner.u16() == TLS13.versionTLS13 { sawTLS13 = true }
                } else if extType == TLS13.extKeyShare {
                    var inner = TLS13ByteReader(bytes: extData)
                    let group = try inner.u16()
                    let key = try inner.vec16()
                    if group == TLS13.namedGroupX25519, key.count == 32 {
                        serverShare = key
                    }
                }
            }
            guard sawTLS13 else {
                throw REALITYError.handshakeFailed("ServerHello is not TLS 1.3")
            }
            guard serverShare != nil else {
                throw REALITYError.handshakeFailed("ServerHello missing X25519 key_share")
            }
        }

        func parseCertificate(_ body: [UInt8]) throws -> TLS13Certificate {
            var reader = TLS13ByteReader(bytes: body)
            _ = try reader.vec8()
            let list = try reader.vec24()
            var listReader = TLS13ByteReader(bytes: list)
            let certDER = try listReader.vec24()
            _ = try listReader.vec16()
            return try TLS13X509.parse(certDER)
        }

        func parseCertificateVerify(_ body: [UInt8], certificate: TLS13Certificate, transcriptBefore: Data) throws {
            var reader = TLS13ByteReader(bytes: body)
            let scheme = try reader.u16()
            let signature = try reader.vec16()
            guard scheme == TLS13.signatureEd25519 else {
                throw REALITYError.handshakeFailed("CertificateVerify scheme \(scheme) is not ed25519")
            }
            guard certificate.isEd25519, certificate.publicKey.count == 32 else {
                throw REALITYError.unverifiedCertificate
            }
            var signed = Data(repeating: 0x20, count: 64)
            signed.append(contentsOf: Array("TLS 1.3, server CertificateVerify".utf8))
            signed.append(0)
            signed.append(suite!.hash.hash(transcriptBefore))
            let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: Data(certificate.publicKey))
            guard publicKey.isValidSignature(Data(signature), for: signed) else {
                throw REALITYError.handshakeFailed("CertificateVerify Ed25519 failed")
            }
        }

        while !sawFinished {
            let record = try await readRecord()
            if record.type == TLS13.contentChangeCipherSpec {
                continue
            }
            if record.type == TLS13.contentAlert {
                if record.fragment.count >= 2 {
                    throw REALITYError.alert(record.fragment[0], record.fragment[1])
                }
                throw REALITYError.alert(0, 0)
            }

            if record.type == TLS13.contentHandshake {
                hsBuffer.append(contentsOf: record.fragment)
                while let (type, body, raw) = try popHandshake() {
                    if type == TLS13.handshakeServerHello {
                        try parseServerHello(body)
                        transcript.append(raw)
                        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(serverShare!))
                        let shared = try clientHello.ephemeral.sharedSecretFromKeyAgreement(with: peer)
                        let sharedBytes = shared.withUnsafeBytes { Data($0) }
                        let secrets = TLS13KeySchedule.handshakeSecrets(
                            suite: suite!,
                            sharedSecret: sharedBytes,
                            transcript: transcript
                        )
                        handshakeKeys = secrets.pair
                        masterSecret = secrets.master
                        clientHSSecret = secrets.clientHSTrafficSecret
                        serverHSSecret = secrets.serverHSTrafficSecret
                    } else {
                        throw REALITYError.unexpectedMessage(type)
                    }
                }
                continue
            }

            guard record.type == TLS13.contentApplicationData, var hsKeys = handshakeKeys, let currentSuite = suite else {
                throw REALITYError.unexpectedMessage(record.type)
            }
            let opened = try TLS13AEAD.open(
                recordHeader: record.header,
                fragment: record.fragment,
                keys: &hsKeys.server
            )
            handshakeKeys = hsKeys
            if opened.contentType == TLS13.contentAlert {
                let bytes = Array(opened.plaintext)
                if bytes.count >= 2 { throw REALITYError.alert(bytes[0], bytes[1]) }
                throw REALITYError.alert(0, 0)
            }
            guard opened.contentType == TLS13.contentHandshake else {
                throw REALITYError.unexpectedMessage(opened.contentType)
            }
            hsBuffer.append(contentsOf: opened.plaintext)

            while let (type, body, raw) = try popHandshake() {
                switch type {
                case TLS13.handshakeEncryptedExtensions:
                    sawEncryptedExtensions = true
                    transcript.append(raw)
                case TLS13.handshakeCertificate:
                    sawCertificate = true
                    leaf = try parseCertificate(body)
                    try verifyCertificate(leaf!)
                    transcript.append(raw)
                case TLS13.handshakeCertificateVerify:
                    guard let leaf else {
                        throw REALITYError.unexpectedMessage(type)
                    }
                    try parseCertificateVerify(body, certificate: leaf, transcriptBefore: transcript)
                    sawCertificateVerify = true
                    transcript.append(raw)
                case TLS13.handshakeFinished:
                    guard let serverHS = serverHSSecret else {
                        throw REALITYError.handshakeFailed("Finished before ServerHello")
                    }
                    let expected = TLS13KeySchedule.finishedVerifyData(
                        trafficSecret: serverHS,
                        suite: currentSuite,
                        transcript: transcript
                    )
                    guard Data(body) == expected else {
                        throw REALITYError.handshakeFailed("server Finished verify_data mismatch")
                    }
                    transcript.append(raw)
                    sawFinished = true
                default:
                    throw REALITYError.unexpectedMessage(type)
                }
            }
            _ = (sawEncryptedExtensions, sawCertificate, sawCertificateVerify)
        }

        guard sawEncryptedExtensions, sawCertificate, sawCertificateVerify, sawFinished,
              let currentSuite = suite,
              let master = masterSecret,
              let clientHS = clientHSSecret,
              var hsKeys = handshakeKeys else {
            throw REALITYError.handshakeFailed("incomplete TLS 1.3 handshake")
        }

        let clientFinished = TLS13KeySchedule.finishedVerifyData(
            trafficSecret: clientHS,
            suite: currentSuite,
            transcript: transcript
        )
        var finishedMsg = TLS13ByteWriter()
        finishedMsg.u8(TLS13.handshakeFinished)
        finishedMsg.withU24Length { $0.append(Array(clientFinished)) }

        var ccs = TLS13ByteWriter()
        ccs.u8(TLS13.contentChangeCipherSpec)
        ccs.u16(TLS13.versionTLS12)
        ccs.u16(1)
        ccs.u8(1)

        let finishedRecord = try TLS13AEAD.seal(
            plaintext: Data(finishedMsg.bytes),
            keys: &hsKeys.client,
            contentType: TLS13.contentHandshake
        )
        try await send(Data(ccs.bytes) + finishedRecord)

        let application = TLS13KeySchedule.applicationSecrets(
            suite: currentSuite,
            master: master,
            transcript: transcript
        )
        let layer = TLS13RecordLayer(application: application)
        if incoming.readableByteCount > 0 {
            let leftover = Data(incoming.readableBytes)
            try layer.feedWire(leftover)
        }
        return layer
    }
}
