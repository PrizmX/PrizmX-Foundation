import Foundation

/// SHAKE128 extendable-output function (FIPS 202). CryptoKit has no SHA-3;
/// VMess uses SHAKE128 to mask chunk lengths and pick padding sizes.
///
/// Absorb everything with `init(absorbing:)`, then `squeeze` any number of
/// bytes in as many calls as needed (the output stream is continuous).
struct SHAKE128 {
    private static let rate = 168
    private var state = [UInt64](repeating: 0, count: 25)
    private var block = [UInt8](repeating: 0, count: rate)
    private var offset = rate

    init(absorbing input: some DataProtocol) {
        let bytes = [UInt8](input)
        var position = 0
        while bytes.count - position >= Self.rate {
            absorbBlock(bytes[position..<(position + Self.rate)])
            position += Self.rate
        }
        var last = [UInt8](repeating: 0, count: Self.rate)
        let tail = bytes.count - position
        for index in 0..<tail {
            last[index] = bytes[position + index]
        }
        last[tail] ^= 0x1F
        last[Self.rate - 1] ^= 0x80
        absorbBlock(last[...])
    }

    /// Next `count` bytes of the output stream.
    mutating func squeeze(_ count: Int) -> [UInt8] {
        var output: [UInt8] = []
        output.reserveCapacity(count)
        while output.count < count {
            if offset == Self.rate {
                for lane in 0..<(Self.rate / 8) {
                    var value = state[lane]
                    for byte in 0..<8 {
                        block[lane * 8 + byte] = UInt8(truncatingIfNeeded: value)
                        value >>= 8
                    }
                }
                offset = 0
            }
            let take = min(count - output.count, Self.rate - offset)
            output.append(contentsOf: block[offset..<(offset + take)])
            offset += take
            if offset == Self.rate {
                Keccak.permute(&state)
            }
        }
        return output
    }

    /// Next big-endian `UInt16` of the output stream.
    mutating func nextUInt16() -> UInt16 {
        let bytes = squeeze(2)
        return UInt16(bytes[0]) << 8 | UInt16(bytes[1])
    }

    private mutating func absorbBlock(_ bytes: ArraySlice<UInt8>) {
        let base = bytes.startIndex
        for lane in 0..<(Self.rate / 8) {
            var value: UInt64 = 0
            for byte in 0..<8 {
                value |= UInt64(bytes[base + lane * 8 + byte]) << UInt64(byte * 8)
            }
            state[lane] ^= value
        }
        Keccak.permute(&state)
    }
}

/// Keccak-f[1600] permutation.
enum Keccak {
    private static let roundConstants: [UInt64] = [
        0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808A, 0x8000_0000_8000_8000,
        0x0000_0000_0000_808B, 0x0000_0000_8000_0001, 0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
        0x0000_0000_0000_008A, 0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000A,
        0x0000_0000_8000_808B, 0x8000_0000_0000_008B, 0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
        0x8000_0000_0000_8002, 0x8000_0000_0000_0080, 0x0000_0000_0000_800A, 0x8000_0000_8000_000A,
        0x8000_0000_8000_8081, 0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
    ]
    private static let rotations: [UInt64] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
    ]

    static func permute(_ a: inout [UInt64]) {
        var c = [UInt64](repeating: 0, count: 5)
        var b = [UInt64](repeating: 0, count: 25)
        for round in 0..<24 {
            // θ
            for x in 0..<5 {
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]
            }
            for x in 0..<5 {
                let d = c[(x + 4) % 5] ^ rotate(c[(x + 1) % 5], 1)
                for y in stride(from: 0, to: 25, by: 5) {
                    a[y + x] ^= d
                }
            }
            // ρ and π
            for x in 0..<5 {
                for y in 0..<5 {
                    let index = x + 5 * y
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = rotate(a[index], rotations[index])
                }
            }
            // χ
            for y in stride(from: 0, to: 25, by: 5) {
                for x in 0..<5 {
                    a[y + x] = b[y + x] ^ (~b[y + (x + 1) % 5] & b[y + (x + 2) % 5])
                }
            }
            // ι
            a[0] ^= roundConstants[round]
        }
    }

    @inline(__always)
    private static func rotate(_ value: UInt64, _ count: UInt64) -> UInt64 {
        count == 0 ? value : (value << count) | (value >> (64 - count))
    }
}
