import Foundation

/// The deterministic byte stream `Interop/target` serves and verifies:
/// xorshift64* seeded with `seed ^ 0x9E3779B97F4A7C15`, eight little-endian
/// bytes per step. Both sides generate it on the fly, so payloads of any
/// size are checked while streaming.
///
/// Generation works a 64-bit word at a time and checks compare with
/// `memcmp`, so the client is not the bottleneck under load (also in debug
/// builds).
struct PayloadPattern {
    private var state: UInt64
    /// Unused tail of the current word (little-endian), `pending` bytes.
    private var word: UInt64 = 0
    private var pending = 0

    init(seed: UInt64) {
        let mixed = seed ^ 0x9E37_79B9_7F4A_7C15
        state = mixed == 0 ? 1 : mixed
    }

    mutating func next(_ count: Int) -> Data {
        var data = Data(count: count)
        data.withUnsafeMutableBytes { fill($0) }
        return data
    }

    /// Advances over `chunk` and returns the offset of the first mismatch.
    mutating func firstMismatch(in chunk: Data) -> Int? {
        guard !chunk.isEmpty else { return nil }
        let expected = next(chunk.count)
        let equal = chunk.withUnsafeBytes { got in
            expected.withUnsafeBytes { want in
                memcmp(got.baseAddress!, want.baseAddress!, chunk.count) == 0
            }
        }
        if equal { return nil }
        for (offset, pair) in zip(chunk, expected).enumerated() where pair.0 != pair.1 {
            return offset
        }
        return nil
    }

    private mutating func fill(_ buffer: UnsafeMutableRawBufferPointer) {
        var offset = 0
        // Drain the partial word first.
        while pending > 0, offset < buffer.count {
            buffer[offset] = UInt8(truncatingIfNeeded: word)
            word >>= 8
            pending -= 1
            offset += 1
        }
        // Whole words.
        while buffer.count - offset >= 8 {
            buffer.storeBytes(of: nextWord().littleEndian, toByteOffset: offset, as: UInt64.self)
            offset += 8
        }
        // Tail: keep the rest of the word for the next call.
        if offset < buffer.count {
            word = nextWord()
            pending = 8
            while offset < buffer.count {
                buffer[offset] = UInt8(truncatingIfNeeded: word)
                word >>= 8
                pending -= 1
                offset += 1
            }
        }
    }

    @inline(__always)
    private mutating func nextWord() -> UInt64 {
        var x = state
        x ^= x >> 12
        x ^= x << 25
        x ^= x >> 27
        state = x
        return x &* 0x2545_F491_4F6C_DD1D
    }
}
