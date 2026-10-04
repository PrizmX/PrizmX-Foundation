import CryptoKit
import Foundation

/// VMess body security (Clash `cipher`, sing-box / Xray `security`).
@frozen
public enum VMessSecurity: String, Sendable, Hashable, CaseIterable {
    /// AES-128-GCM on hardware with AES (all Apple silicon / x86-64).
    case auto
    case aes128GCM = "aes-128-gcm"
    case chacha20Poly1305 = "chacha20-poly1305"
    /// Length-masked chunks without encryption (deprecated upstream).
    case none
    /// No chunking at all: the body is the raw stream.
    case zero

    /// `auto` resolved the way Xray does on arm64 / amd64.
    var resolved: VMessSecurity {
        self == .auto ? .aes128GCM : self
    }

    /// Request header security nibble (`SecurityType`).
    var headerValue: UInt8 {
        switch resolved {
        case .aes128GCM: 3
        case .chacha20Poly1305: 4
        case .none, .zero, .auto: 5
        }
    }

    var isAEAD: Bool {
        resolved == .aes128GCM || resolved == .chacha20Poly1305
    }
}

@frozen
public enum VMessError: Error, Equatable, Sendable {
    /// `uuid` is not a valid UUID.
    case invalidUserID(String)
    /// Target cannot be encoded (empty / overlong domain).
    case invalidAddress(Endpoint)
    /// The response header or a body chunk failed to authenticate.
    case authenticationFailed
    /// The response header echoes a different auth byte.
    case responseMismatch
    /// A chunk exceeds the size its framing allows.
    case chunkTooLarge(Int)
    /// The stream ended inside a header or chunk.
    case truncated
}

/// VMess AEAD key schedule (Xray `proxy/vmess/aead`).
enum VMessKDF {
    private static let root = Array("VMess AEAD KDF".utf8)
    private static let blockSize = 64

    /// `KDF(key, path…)`: HMAC-SHA256 keyed with "VMess AEAD KDF", then one
    /// HMAC layer per path element, each using the previous layer as its
    /// hash function.
    static func derive(_ key: [UInt8], _ path: [[UInt8]]) -> [UInt8] {
        var hash: ([UInt8]) -> [UInt8] = { data in
            Array(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: root)))
        }
        for element in path {
            let parent = hash
            hash = { data in hmac(key: element, data: data, hash: parent) }
        }
        return hash(key)
    }

    static func derive(_ key: [UInt8], _ path: String...) -> [UInt8] {
        derive(key, path.map { Array($0.utf8) })
    }

    static func derive16(_ key: [UInt8], _ path: [[UInt8]]) -> [UInt8] {
        Array(derive(key, path).prefix(16))
    }

    /// RFC 2104 HMAC over an arbitrary 64-byte-block hash.
    private static func hmac(key: [UInt8], data: [UInt8], hash: ([UInt8]) -> [UInt8]) -> [UInt8] {
        var block = key.count > blockSize ? hash(key) : key
        block += [UInt8](repeating: 0, count: blockSize - block.count)
        let inner = hash(block.map { $0 ^ 0x36 } + data)
        return hash(block.map { $0 ^ 0x5C } + inner)
    }

    /// `MD5(uuid ‖ "c48619fe-8f02-49e0-b9e9-edf763e17e21")`.
    static func commandKey(userID: UUID) -> [UInt8] {
        var hasher = Insecure.MD5()
        hasher.update(data: withUnsafeBytes(of: userID.uuid) { Array($0) })
        hasher.update(data: Array("c48619fe-8f02-49e0-b9e9-edf763e17e21".utf8))
        return Array(hasher.finalize())
    }

    /// 32-byte ChaCha20-Poly1305 body key from a 16-byte VMess key:
    /// `MD5(key) ‖ MD5(MD5(key))`.
    static func chachaKey(_ key: [UInt8]) -> [UInt8] {
        let first = Array(Insecure.MD5.hash(data: key))
        return first + Array(Insecure.MD5.hash(data: first))
    }
}

/// AES-GCM with associated data over byte arrays (header sealing).
enum VMessAEAD {
    static func seal(_ plaintext: [UInt8], key: [UInt8], nonce: [UInt8], aad: [UInt8]) throws -> [UInt8] {
        let box = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: key),
            nonce: AES.GCM.Nonce(data: nonce),
            authenticating: aad
        )
        return Array(box.ciphertext) + Array(box.tag)
    }

    static func open(_ sealed: [UInt8], key: [UInt8], nonce: [UInt8], aad: [UInt8]) throws -> [UInt8] {
        guard sealed.count >= 16 else { throw VMessError.truncated }
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: nonce),
                ciphertext: sealed.dropLast(16),
                tag: sealed.suffix(16)
            )
            return Array(try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad))
        } catch {
            throw VMessError.authenticationFailed
        }
    }
}
