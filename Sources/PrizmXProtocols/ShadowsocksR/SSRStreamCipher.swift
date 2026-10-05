import CommonCrypto
import CryptoKit
import Foundation

/// ShadowsocksR stream ciphers (`method`). These are the pre-AEAD
/// Shadowsocks ciphers: no integrity of their own, kept for SSR servers.
@frozen
public enum SSRCipher: String, Sendable, Hashable, CaseIterable {
    case none
    case rc4MD5 = "rc4-md5"
    case aes128CFB = "aes-128-cfb"
    case aes192CFB = "aes-192-cfb"
    case aes256CFB = "aes-256-cfb"
    case aes128CTR = "aes-128-ctr"
    case aes192CTR = "aes-192-ctr"
    case aes256CTR = "aes-256-ctr"
    case chacha20
    case chacha20IETF = "chacha20-ietf"

    /// `EVP_BytesToKey` output size (SSR uses 16 for `none` too: the key
    /// still feeds the protocol plugins).
    var keyByteCount: Int {
        switch self {
        case .none, .rc4MD5, .aes128CFB, .aes128CTR: 16
        case .aes192CFB, .aes192CTR: 24
        case .aes256CFB, .aes256CTR, .chacha20, .chacha20IETF: 32
        }
    }

    /// IV prefixed to each direction's stream.
    var ivByteCount: Int {
        switch self {
        case .none: 0
        case .chacha20: 8
        case .chacha20IETF: 12
        default: 16
        }
    }

    func key(password: String) -> [UInt8] {
        ShadowsocksKeyDerivation.evpBytesToKey(password: password, keyByteCount: keyByteCount)
    }

    func makeCrypter(key: [UInt8], iv: [UInt8], encrypt: Bool) throws -> SSRStreamCrypter {
        try SSRStreamCrypter(cipher: self, key: key, iv: iv, encrypt: encrypt)
    }
}

/// One direction of an SSR stream cipher: XORs (or CFB-transforms) bytes
/// continuously across calls.
final class SSRStreamCrypter: @unchecked Sendable {
    private enum Engine {
        case passthrough
        case commonCrypto(CCCryptorRef)
        case chacha(ChaCha20)
    }

    private var engine: Engine

    init(cipher: SSRCipher, key: [UInt8], iv: [UInt8], encrypt: Bool) throws {
        let operation = CCOperation(encrypt ? kCCEncrypt : kCCDecrypt)
        switch cipher {
        case .none:
            engine = .passthrough
        case .chacha20, .chacha20IETF:
            engine = .chacha(ChaCha20(key: key, nonce: iv))
        case .rc4MD5:
            var hasher = Insecure.MD5()
            hasher.update(data: key)
            hasher.update(data: iv)
            let rc4Key = Array(hasher.finalize())
            engine = .commonCrypto(try Self.create(operation, mode: CCMode(kCCModeRC4), algorithm: CCAlgorithm(kCCAlgorithmRC4), key: rc4Key, iv: nil))
        case .aes128CFB, .aes192CFB, .aes256CFB:
            engine = .commonCrypto(try Self.create(operation, mode: CCMode(kCCModeCFB), algorithm: CCAlgorithm(kCCAlgorithmAES), key: key, iv: iv))
        case .aes128CTR, .aes192CTR, .aes256CTR:
            engine = .commonCrypto(try Self.create(
                operation,
                mode: CCMode(kCCModeCTR),
                algorithm: CCAlgorithm(kCCAlgorithmAES),
                key: key,
                iv: iv,
                options: CCModeOptions(kCCModeOptionCTR_BE)
            ))
        }
    }

    deinit {
        if case .commonCrypto(let ref) = engine {
            CCCryptorRelease(ref)
        }
    }

    /// RC4 keys run through `rc4-md5` as a plain 16-byte RC4 key.
    static func rc4(key: [UInt8], encrypt: Bool) throws -> SSRStreamCrypter {
        try SSRStreamCrypter(rc4Key: key, encrypt: encrypt)
    }

    private init(rc4Key: [UInt8], encrypt: Bool) throws {
        engine = .commonCrypto(try Self.create(
            CCOperation(encrypt ? kCCEncrypt : kCCDecrypt),
            mode: CCMode(kCCModeRC4),
            algorithm: CCAlgorithm(kCCAlgorithmRC4),
            key: rc4Key,
            iv: nil
        ))
    }

    func update(_ input: [UInt8]) -> [UInt8] {
        guard !input.isEmpty else { return [] }
        switch engine {
        case .passthrough:
            return input
        case .chacha(var chacha):
            var output = input
            chacha.apply(&output)
            engine = .chacha(chacha)
            return output
        case .commonCrypto(let ref):
            var output = [UInt8](repeating: 0, count: input.count)
            var moved = 0
            let status = CCCryptorUpdate(ref, input, input.count, &output, output.count, &moved)
            precondition(status == kCCSuccess && moved == input.count, "stream cipher update failed (\(status))")
            return output
        }
    }

    private static func create(
        _ operation: CCOperation,
        mode: CCMode,
        algorithm: CCAlgorithm,
        key: [UInt8],
        iv: [UInt8]?,
        options: CCModeOptions = 0
    ) throws -> CCCryptorRef {
        var ref: CCCryptorRef?
        let status = CCCryptorCreateWithMode(
            operation, mode, algorithm, CCPadding(ccNoPadding),
            iv, key, key.count, nil, 0, 0, options, &ref
        )
        guard status == kCCSuccess, let ref else { throw SSRError.cipherUnavailable }
        return ref
    }
}

/// Single-block AES-128-CBC with a zero IV, as SSR's auth plugins use it to
/// seal their 16-byte auth block (equivalent to ECB for one block).
enum SSRAuthBlock {
    static func encrypt(_ block: [UInt8], password: String) -> [UInt8] {
        let key = ShadowsocksKeyDerivation.evpBytesToKey(password: password, keyByteCount: 16)
        return AESBlock.encrypt(block: block, key: key)
    }
}

@frozen
public enum SSRError: Error, Equatable, Sendable {
    /// CommonCrypto refused the cipher configuration.
    case cipherUnavailable
    /// A protocol frame failed its checksum / MAC.
    case authenticationFailed
    /// A protocol frame has an impossible length.
    case malformedFrame
    /// The obfs handshake reply does not verify.
    case obfsRejected
}
