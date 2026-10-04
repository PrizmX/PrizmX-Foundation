import Foundation

/// Raw ChaCha20 keystream (RFC 8439 block function). CryptoKit only offers
/// the ChaCha20-Poly1305 AEAD; ShadowsocksR's `chacha20` / `chacha20-ietf`
/// stream ciphers and XChaCha20's HChaCha20 need the bare cipher.
struct ChaCha20 {
    /// `djb`: 64-bit counter + 8-byte nonce; `ietf`: 32-bit counter +
    /// 12-byte nonce.
    enum Variant {
        case djb
        case ietf
    }

    private var input: [UInt32]
    private let variant: Variant
    private var keystream = [UInt8](repeating: 0, count: 64)
    private var offset = 64

    init(key: [UInt8], nonce: [UInt8], counter: UInt64 = 0) {
        precondition(key.count == 32, "ChaCha20 key must be 32 bytes")
        precondition(nonce.count == 8 || nonce.count == 12, "ChaCha20 nonce must be 8 or 12 bytes")
        variant = nonce.count == 8 ? .djb : .ietf
        input = Self.constants + Self.words(key)
        switch variant {
        case .djb:
            input += [UInt32(truncatingIfNeeded: counter), UInt32(truncatingIfNeeded: counter >> 32)]
            input += Self.words(nonce)
        case .ietf:
            input += [UInt32(truncatingIfNeeded: counter)]
            input += Self.words(nonce)
        }
    }

    /// XORs the keystream into `bytes` (continuous across calls).
    mutating func apply(_ bytes: inout [UInt8]) {
        for index in bytes.indices {
            if offset == 64 {
                Self.block(input, into: &keystream)
                advanceCounter()
                offset = 0
            }
            bytes[index] ^= keystream[offset]
            offset += 1
        }
    }

    private mutating func advanceCounter() {
        input[12] &+= 1
        if variant == .djb, input[12] == 0 {
            input[13] &+= 1
        }
    }

    /// HChaCha20 (XChaCha20 draft §2.2): 32-byte subkey from a key and the
    /// first 16 nonce bytes.
    static func hchacha20(key: [UInt8], nonce: [UInt8]) -> [UInt8] {
        precondition(key.count == 32 && nonce.count == 16)
        var state = constants + words(key) + words(nonce)
        rounds(&state)
        let selected = Array(state[0..<4]) + Array(state[12..<16])
        return selected.flatMap { word in
            (0..<4).map { UInt8(truncatingIfNeeded: word >> UInt32($0 * 8)) }
        }
    }

    // MARK: Core

    private static let constants: [UInt32] = [0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574]

    private static func words(_ bytes: [UInt8]) -> [UInt32] {
        stride(from: 0, to: bytes.count, by: 4).map { index in
            UInt32(bytes[index]) | UInt32(bytes[index + 1]) << 8
                | UInt32(bytes[index + 2]) << 16 | UInt32(bytes[index + 3]) << 24
        }
    }

    private static func block(_ input: [UInt32], into output: inout [UInt8]) {
        var state = input
        rounds(&state)
        for index in 0..<16 {
            let word = state[index] &+ input[index]
            output[index * 4] = UInt8(truncatingIfNeeded: word)
            output[index * 4 + 1] = UInt8(truncatingIfNeeded: word >> 8)
            output[index * 4 + 2] = UInt8(truncatingIfNeeded: word >> 16)
            output[index * 4 + 3] = UInt8(truncatingIfNeeded: word >> 24)
        }
    }

    private static func rounds(_ s: inout [UInt32]) {
        for _ in 0..<10 {
            quarter(&s, 0, 4, 8, 12)
            quarter(&s, 1, 5, 9, 13)
            quarter(&s, 2, 6, 10, 14)
            quarter(&s, 3, 7, 11, 15)
            quarter(&s, 0, 5, 10, 15)
            quarter(&s, 1, 6, 11, 12)
            quarter(&s, 2, 7, 8, 13)
            quarter(&s, 3, 4, 9, 14)
        }
    }

    @inline(__always)
    private static func quarter(_ s: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        s[a] &+= s[b]; s[d] ^= s[a]; s[d] = s[d] << 16 | s[d] >> 16
        s[c] &+= s[d]; s[b] ^= s[c]; s[b] = s[b] << 12 | s[b] >> 20
        s[a] &+= s[b]; s[d] ^= s[a]; s[d] = s[d] << 8 | s[d] >> 24
        s[c] &+= s[d]; s[b] ^= s[c]; s[b] = s[b] << 7 | s[b] >> 25
    }
}
