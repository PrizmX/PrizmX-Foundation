import Foundation

/// SHA-224 (FIPS 180-4): SHA-256 compression with distinct IVs, truncated to
/// 28 bytes. CryptoKit does not expose SHA-224; this is the algorithm Trojan
/// uses for `hex(SHA224(password))`.
public enum SHA224: Sendable {
    /// Digest size in bytes (224 bits).
    public static let digestByteCount = 28
    /// Lowercase hex encoding of the digest (what Trojan puts on the wire).
    public static let hexDigestByteCount = 56

    /// 28-byte raw digest of `data`.
    public static func hash(_ data: some DataProtocol) -> [UInt8] {
        var hasher = Hasher()
        hasher.update(data)
        return hasher.finalize()
    }

    /// 56 ASCII bytes: lowercase hex of `hash(_:)`.
    public static func hexDigest(_ data: some DataProtocol) -> [UInt8] {
        hexEncode(hash(data))
    }

    /// Lowercase hex string of `hash(_:)`.
    public static func hexString(_ data: some DataProtocol) -> String {
        String(decoding: hexDigest(data), as: UTF8.self)
    }

    public static func hexEncode(_ digest: [UInt8]) -> [UInt8] {
        let alphabet: [UInt8] = [
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        ]
        var hex = [UInt8](repeating: 0, count: digest.count * 2)
        for (index, byte) in digest.enumerated() {
            hex[index * 2] = alphabet[Int(byte >> 4)]
            hex[index * 2 + 1] = alphabet[Int(byte & 0x0F)]
        }
        return hex
    }

    struct Hasher {
        private var h0: UInt32 = 0xC105_9ED8
        private var h1: UInt32 = 0x367C_D507
        private var h2: UInt32 = 0x3070_DD17
        private var h3: UInt32 = 0xF70E_5939
        private var h4: UInt32 = 0xFFC0_0B31
        private var h5: UInt32 = 0x6858_1511
        private var h6: UInt32 = 0x64F9_8FA7
        private var h7: UInt32 = 0xBEFA_4FA4
        private var bitCount: UInt64 = 0
        private var leftover = [UInt8]()

        mutating func update(_ data: some DataProtocol) {
            let consumed: Void? = data.withContiguousStorageIfAvailable { buffer in
                process(UnsafeRawBufferPointer(buffer))
            }
            if consumed != nil { return }
            Array(data).withUnsafeBytes { process($0) }
        }

        mutating func finalize() -> [UInt8] {
            var block = leftover
            let totalBits = bitCount + UInt64(block.count) * 8
            block.append(0x80)
            let remainder = block.count % 64
            let pad = remainder <= 56 ? 56 - remainder : 120 - remainder
            if pad > 0 {
                block.append(contentsOf: repeatElement(0, count: pad))
            }
            var length = totalBits.bigEndian
            withUnsafeBytes(of: &length) { block.append(contentsOf: $0) }
            leftover.removeAll(keepingCapacity: true)
            block.withUnsafeBytes { process($0) }

            var digest = [UInt8](repeating: 0, count: SHA224.digestByteCount)
            let words: [UInt32] = [h0, h1, h2, h3, h4, h5, h6]
            for (index, word) in words.enumerated() {
                let be = word.bigEndian
                withUnsafeBytes(of: be) { raw in
                    for offset in 0..<4 {
                        let out = index * 4 + offset
                        if out < digest.count {
                            digest[out] = raw[offset]
                        }
                    }
                }
            }
            return digest
        }

        private mutating func process(_ bytes: UnsafeRawBufferPointer) {
            var offset = 0
            if !leftover.isEmpty {
                let need = 64 - leftover.count
                if bytes.count < need {
                    leftover.append(contentsOf: bytes)
                    return
                }
                leftover.append(contentsOf: bytes.prefix(need))
                leftover.withUnsafeBytes { compress($0) }
                bitCount += 512
                leftover.removeAll(keepingCapacity: true)
                offset = need
            }
            while offset + 64 <= bytes.count {
                compress(UnsafeRawBufferPointer(rebasing: bytes[offset..<(offset + 64)]))
                bitCount += 512
                offset += 64
            }
            if offset < bytes.count {
                leftover.append(contentsOf: bytes[offset...])
            }
        }

        private mutating func compress(_ block: UnsafeRawBufferPointer) {
            precondition(block.count == 64)
            var w = [UInt32](repeating: 0, count: 64)
            for i in 0..<16 {
                w[i] = UInt32(block[i * 4]) << 24
                    | UInt32(block[i * 4 + 1]) << 16
                    | UInt32(block[i * 4 + 2]) << 8
                    | UInt32(block[i * 4 + 3])
            }
            for i in 16..<64 {
                let s0 = rotateRight(w[i - 15], 7) ^ rotateRight(w[i - 15], 18) ^ (w[i - 15] >> 3)
                let s1 = rotateRight(w[i - 2], 17) ^ rotateRight(w[i - 2], 19) ^ (w[i - 2] >> 10)
                w[i] = w[i - 16] &+ s0 &+ w[i - 7] &+ s1
            }

            var a = h0, b = h1, c = h2, d = h3
            var e = h4, f = h5, g = h6, h = h7
            for i in 0..<64 {
                let s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25)
                let ch = (e & f) ^ (~e & g)
                let temp1 = h &+ s1 &+ ch &+ K[i] &+ w[i]
                let s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22)
                let maj = (a & b) ^ (a & c) ^ (b & c)
                let temp2 = s0 &+ maj
                h = g
                g = f
                f = e
                e = d &+ temp1
                d = c
                c = b
                b = a
                a = temp1 &+ temp2
            }
            h0 = h0 &+ a
            h1 = h1 &+ b
            h2 = h2 &+ c
            h3 = h3 &+ d
            h4 = h4 &+ e
            h5 = h5 &+ f
            h6 = h6 &+ g
            h7 = h7 &+ h
        }
    }
}

@inline(__always)
private func rotateRight(_ value: UInt32, _ amount: UInt32) -> UInt32 {
    (value >> amount) | (value << (32 - amount))
}

private let K: [UInt32] = [
    0x428A_2F98, 0x7137_4491, 0xB5C0_FBCF, 0xE9B5_DBA5, 0x3956_C25B, 0x59F1_11F1, 0x923F_82A4, 0xAB1C_5ED5,
    0xD807_AA98, 0x1283_5B01, 0x2431_85BE, 0x550C_7DC3, 0x72BE_5D74, 0x80DE_B1FE, 0x9BDC_06A7, 0xC19B_F174,
    0xE49B_69C1, 0xEFBE_4786, 0x0FC1_9DC6, 0x240C_A1CC, 0x2DE9_2C6F, 0x4A74_84AA, 0x5CB0_A9DC, 0x76F9_88DA,
    0x983E_5152, 0xA831_C66D, 0xB003_27C8, 0xBF59_7FC7, 0xC6E0_0BF3, 0xD5A7_9147, 0x06CA_6351, 0x1429_2967,
    0x27B7_0A85, 0x2E1B_2138, 0x4D2C_6DFC, 0x5338_0D13, 0x650A_7354, 0x766A_0ABB, 0x81C2_C92E, 0x9272_2C85,
    0xA2BF_E8A1, 0xA81A_664B, 0xC24B_8B70, 0xC76C_51A3, 0xD192_E819, 0xD699_0624, 0xF40E_3585, 0x106A_A070,
    0x19A4_C116, 0x1E37_6C08, 0x2748_774C, 0x34B0_BCB5, 0x391C_0CB3, 0x4ED8_AA4A, 0x5B9C_CA4F, 0x682E_6FF3,
    0x748F_82EE, 0x78A5_636F, 0x84C8_7814, 0x8CC7_0208, 0x90BE_FFFA, 0xA450_6CEB, 0xBEF9_A3F7, 0xC671_78F2,
]
