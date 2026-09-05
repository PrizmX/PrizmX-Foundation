import CryptoKit
import Foundation

// MARK: - Constants

/// Xray-core Vision / REALITY (XTLS) camouflage handshake.
///
/// Wire layout of the 32-byte ClientHello Session ID (handshake offset 39):
///
/// ```
/// [0]     Version_x
/// [1]     Version_y
/// [2]     Version_z
/// [3]     reserved (0)
/// [4..<8] Unix timestamp, big-endian uint32
/// [8..<16] Short ID (zero-padded to 8 bytes)
/// ```
///
/// The first 16 bytes are AES-256-GCM sealed in place; ciphertext ‖ tag
/// overwrite the full 32-byte field. AAD is the ClientHello handshake
/// message with a **zeroed** Session ID (Xray copies zeros into `Raw[39:]`
/// before `Seal`, and the server zeros `sessionId` before `Open`).
public enum REALITY {
    /// Xray-core version bytes written into Session ID `[0..<3]`.
    /// Compatibility only; the server does not require a specific triple
    /// unless `MinClientVer` / `MaxClientVer` is configured.
    public static let clientVersion: (UInt8, UInt8, UInt8) = (25, 8, 3)

    /// HKDF-SHA256 info string (no quotes).
    public static let hkdfInfo = "REALITY"

    /// Session ID / encrypted blob size.
    public static let sessionIDByteCount = 32

    /// Offset of the Session ID body inside the handshake ClientHello
    /// (`msg_type` + `uint24 length` + `legacy_version` + `random` + `sid_len`).
    public static let handshakeSessionIDOffset = 39

    /// Short ID is at most 8 bytes (16 hex characters).
    public static let shortIDByteCount = 8

    /// Server X25519 public key size.
    public static let publicKeyByteCount = 32
}

// MARK: - Errors

@frozen
public enum REALITYError: Error, Equatable, Sendable {
    /// `publicKey` is not 32-byte Curve25519 (hex / Base64 / Base64URL / Base45).
    case invalidPublicKey(String)
    /// `shortId` is not even-length hex of at most 8 bytes.
    case invalidShortID(String)
    /// `serverName` (SNI) is empty.
    case invalidServerName
    /// TLS 1.3 record or handshake was truncated.
    case truncated(expected: Int, actual: Int)
    /// Peer selected a cipher suite this client does not implement.
    case unsupportedCipherSuite(UInt16)
    /// Handshake message type was not expected at this point.
    case unexpectedMessage(UInt8)
    /// Fatal TLS alert (`level`, `description`).
    case alert(UInt8, UInt8)
    /// Ed25519 certificate HMAC-SHA512 did not match `AuthKey` (dest cert / MITM).
    case unverifiedCertificate
    /// CertificateVerify or Finished MAC failed.
    case handshakeFailed(String)
}

// MARK: - Configuration

/// REALITY transport parameters for a VLESS outbound.
///
/// When present on `VLESSOutboundConnection`, Network.framework TLS is skipped
/// and a userspace TLS 1.3 ClientHello carries the encrypted Session ID.
public struct REALITYConfig: Hashable, Sendable {
    /// Original public-key encoding (hex, Base64, Base64URL, or Base45).
    public let publicKey: String
    /// Original Short ID hex string (may be empty).
    public let shortId: String
    /// SNI / camouflage domain (e.g. `www.apple.com`).
    public let serverName: String
    /// Optional spider path used by Xray when verification fails. This client
    /// fails closed (`unverifiedCertificate`) instead of spidering dest.
    public let spiderX: String

    /// Decoded 32-byte X25519 public key.
    public let publicKeyBytes: [UInt8]
    /// Decoded Short ID, 0…8 bytes (not yet padded).
    public let shortIdBytes: [UInt8]

    /// - Parameters:
    ///   - publicKey: Server X25519 public key.
    ///   - shortId: Hex Short ID (empty is 8 zero bytes on the wire).
    ///   - serverName: TLS SNI borrowed from the dest site.
    ///   - spiderX: Optional path stored for diagnostics; unused on success.
    public init(
        publicKey: String,
        shortId: String = "",
        serverName: String,
        spiderX: String = ""
    ) throws {
        let name = serverName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { throw REALITYError.invalidServerName }

        self.publicKey = publicKey
        self.shortId = shortId
        self.serverName = name
        self.spiderX = spiderX
        self.publicKeyBytes = try REALITYKeyEncoding.decode32(publicKey)
        self.shortIdBytes = try REALITYKeyEncoding.decodeShortID(shortId)
    }

    /// Curve25519 public key for ECDH with the client's ephemeral share.
    public var serverPublicKey: Curve25519.KeyAgreement.PublicKey {
        try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(publicKeyBytes))
    }

    /// Short ID padded with trailing zeros to 8 bytes (Session ID `[8..<16]`).
    public var paddedShortID: [UInt8] {
        var bytes = shortIdBytes
        if bytes.count < REALITY.shortIDByteCount {
            bytes.append(contentsOf: repeatElement(0, count: REALITY.shortIDByteCount - bytes.count))
        }
        return Array(bytes.prefix(REALITY.shortIDByteCount))
    }
}

// MARK: - Key / Short ID encoding

/// Decodes REALITY public keys and Short IDs from the encodings Xray and
/// Clash Meta accept.
public enum REALITYKeyEncoding: Sendable {
    /// 32-byte Curve25519 public key from hex, standard Base64, Base64URL, or Base45.
    public static func decode32(_ string: String) throws -> [UInt8] {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw REALITYError.invalidPublicKey(string) }

        if trimmed.count == 64, let hex = decodeHex(trimmed), hex.count == REALITY.publicKeyByteCount {
            return hex
        }
        if let url = decodeBase64URL(trimmed), url.count == REALITY.publicKeyByteCount {
            return url
        }
        if let std = decodeBase64(trimmed), std.count == REALITY.publicKeyByteCount {
            return std
        }
        if let b45 = try? decodeBase45(trimmed), b45.count == REALITY.publicKeyByteCount {
            return b45
        }
        throw REALITYError.invalidPublicKey(string)
    }

    /// Even-length hex, at most 8 bytes. Empty string → empty (padded later).
    public static func decodeShortID(_ string: String) throws -> [UInt8] {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return [] }
        guard trimmed.count.isMultiple(of: 2), trimmed.count <= REALITY.shortIDByteCount * 2 else {
            throw REALITYError.invalidShortID(string)
        }
        guard let hex = decodeHex(trimmed) else {
            throw REALITYError.invalidShortID(string)
        }
        return hex
    }

    static func decodeHex(_ string: String) -> [UInt8]? {
        let hex = string.filter { !$0.isWhitespace }
        guard hex.count.isMultiple(of: 2), !hex.isEmpty else { return hex.isEmpty ? [] : nil }
        var result: [UInt8] = []
        result.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            result.append(byte)
            index = next
        }
        return result
    }

    private static func decodeBase64(_ string: String) -> [UInt8]? {
        guard let data = Data(base64Encoded: paddedBase64(string, urlSafe: false)) else { return nil }
        return Array(data)
    }

    private static func decodeBase64URL(_ string: String) -> [UInt8]? {
        let mapped = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        guard let data = Data(base64Encoded: paddedBase64(mapped, urlSafe: false)) else { return nil }
        return Array(data)
    }

    private static func paddedBase64(_ string: String, urlSafe: Bool) -> String {
        var value = string
        if urlSafe {
            value = value.replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")
        }
        let pad = (4 - value.count % 4) % 4
        if pad > 0 { value.append(String(repeating: "=", count: pad)) }
        return value
    }

    /// RFC 9285 Base45. Alphabet: `0-9 A-Z` and ` $%*+-./:`.
    static func decodeBase45(_ string: String) throws -> [UInt8] {
        let alphabet = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:")
        var values: [Int] = []
        values.reserveCapacity(string.count)
        for scalar in string.unicodeScalars {
            if scalar == "\n" || scalar == "\r" { continue }
            guard let index = alphabet.firstIndex(of: Character(scalar)) else {
                throw REALITYError.invalidPublicKey(string)
            }
            values.append(index)
        }
        guard !values.isEmpty else { throw REALITYError.invalidPublicKey(string) }

        var output: [UInt8] = []
        var i = 0
        while i < values.count {
            let remaining = values.count - i
            if remaining >= 3 {
                let value = values[i] + values[i + 1] * 45 + values[i + 2] * 45 * 45
                guard value <= 0xFFFF else { throw REALITYError.invalidPublicKey(string) }
                output.append(UInt8(value / 256))
                output.append(UInt8(value % 256))
                i += 3
            } else if remaining == 2 {
                let value = values[i] + values[i + 1] * 45
                guard value <= 0xFF else { throw REALITYError.invalidPublicKey(string) }
                output.append(UInt8(value))
                i += 2
            } else {
                throw REALITYError.invalidPublicKey(string)
            }
        }
        return output
    }

    /// RFC 9285 Base45 encoder (tests / round-trip).
    static func encodeBase45(_ bytes: [UInt8]) -> String {
        let alphabet = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:")
        var output = ""
        var i = 0
        while i < bytes.count {
            if i + 1 < bytes.count {
                let value = Int(bytes[i]) * 256 + Int(bytes[i + 1])
                let c0 = value % 45
                let c1 = (value / 45) % 45
                let c2 = value / (45 * 45)
                output.append(alphabet[c0])
                output.append(alphabet[c1])
                output.append(alphabet[c2])
                i += 2
            } else {
                let value = Int(bytes[i])
                output.append(alphabet[value % 45])
                output.append(alphabet[value / 45])
                i += 1
            }
        }
        return output
    }
}
