import Foundation

/// BLAKE3 hash and key derivation (reference algorithm, 32-byte output).
/// Shadowsocks 2022 derives its session and identity subkeys with
/// `deriveKey`; CryptoKit has no BLAKE3.
enum BLAKE3 {
    private static let iv: [UInt32] = [
        0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
        0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
    ]
    private static let permutation = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
    private static let blockLength = 64
    private static let chunkLength = 1024

    private static let chunkStart: UInt32 = 1 << 0
    private static let chunkEnd: UInt32 = 1 << 1
    private static let parent: UInt32 = 1 << 2
    private static let root: UInt32 = 1 << 3
    private static let deriveKeyContext: UInt32 = 1 << 5
    private static let deriveKeyMaterial: UInt32 = 1 << 6

    /// 32-byte BLAKE3 hash.
    static func hash(_ input: some DataProtocol) -> [UInt8] {
        digest([UInt8](input), key: iv, flags: 0)
    }

    /// `derive_key(context, material)`, truncated to `count` (≤ 32) bytes.
    static func deriveKey(context: String, material: some DataProtocol, count: Int = 32) -> [UInt8] {
        precondition(count <= 32, "only 32-byte outputs are implemented")
        let contextKey = words(digest(Array(context.utf8), key: iv, flags: deriveKeyContext))
        return Array(digest([UInt8](material), key: contextKey, flags: deriveKeyMaterial).prefix(count))
    }

    // MARK: Tree

    private static func digest(_ input: [UInt8], key: [UInt32], flags: UInt32) -> [UInt8] {
        // Chaining values of completed subtrees, merged like binary carry.
        var stack: [[UInt32]] = []
        var chunkCounter: UInt64 = 0
        var offset = 0
        // Every chunk but the last is hashed and merged; the last one (maybe
        // empty) produces the root output, after merging what remains.
        while input.count - offset > chunkLength {
            let chunk = Array(input[offset..<(offset + chunkLength)])
            var cv = chunkOutput(chunk, key: key, counter: chunkCounter, flags: flags).chainingValue
            chunkCounter += 1
            var total = chunkCounter
            while total & 1 == 0 {
                cv = parentOutput(left: stack.removeLast(), right: cv, key: key, flags: flags).chainingValue
                total >>= 1
            }
            stack.append(cv)
            offset += chunkLength
        }
        var output = chunkOutput(Array(input[offset...]), key: key, counter: chunkCounter, flags: flags)
        while let left = stack.popLast() {
            output = parentOutput(left: left, right: output.chainingValue, key: key, flags: flags)
        }
        return output.rootBytes()
    }

    /// Inputs of the last compression of a node, kept so the root can be
    /// finished with the ROOT flag.
    private struct Output {
        var cv: [UInt32]
        var block: [UInt32]
        var counter: UInt64
        var blockLength: UInt32
        var flags: UInt32

        var chainingValue: [UInt32] {
            Array(BLAKE3.compress(cv: cv, block: block, counter: counter, blockLength: blockLength, flags: flags).prefix(8))
        }

        func rootBytes() -> [UInt8] {
            let state = BLAKE3.compress(cv: cv, block: block, counter: 0, blockLength: blockLength, flags: flags | BLAKE3.root)
            return state.prefix(8).flatMap { word in (0..<4).map { UInt8(truncatingIfNeeded: word >> UInt32($0 * 8)) } }
        }
    }

    private static func chunkOutput(_ chunk: [UInt8], key: [UInt32], counter: UInt64, flags: UInt32) -> Output {
        var cv = key
        let blockCount = max(1, (chunk.count + blockLength - 1) / blockLength)
        for index in 0..<blockCount {
            let start = index * blockLength
            let end = min(start + blockLength, chunk.count)
            var block = [UInt8](chunk[start..<end])
            let length = UInt32(block.count)
            block += [UInt8](repeating: 0, count: blockLength - block.count)
            var blockFlags = flags
            if index == 0 { blockFlags |= chunkStart }
            if index == blockCount - 1 {
                return Output(cv: cv, block: words(block), counter: counter, blockLength: length, flags: blockFlags | chunkEnd)
            }
            cv = Array(compress(cv: cv, block: words(block), counter: counter, blockLength: length, flags: blockFlags).prefix(8))
        }
        preconditionFailure("unreachable")
    }

    private static func parentOutput(left: [UInt32], right: [UInt32], key: [UInt32], flags: UInt32) -> Output {
        Output(cv: key, block: left + right, counter: 0, blockLength: UInt32(blockLength), flags: flags | parent)
    }

    // MARK: Compression

    fileprivate static func compress(cv: [UInt32], block: [UInt32], counter: UInt64, blockLength: UInt32, flags: UInt32) -> [UInt32] {
        var state = cv + Array(iv.prefix(4)) + [
            UInt32(truncatingIfNeeded: counter), UInt32(truncatingIfNeeded: counter >> 32), blockLength, flags,
        ]
        var message = block
        for round in 0..<7 {
            g(&state, 0, 4, 8, 12, message[0], message[1])
            g(&state, 1, 5, 9, 13, message[2], message[3])
            g(&state, 2, 6, 10, 14, message[4], message[5])
            g(&state, 3, 7, 11, 15, message[6], message[7])
            g(&state, 0, 5, 10, 15, message[8], message[9])
            g(&state, 1, 6, 11, 12, message[10], message[11])
            g(&state, 2, 7, 8, 13, message[12], message[13])
            g(&state, 3, 4, 9, 14, message[14], message[15])
            if round < 6 {
                message = permutation.map { message[$0] }
            }
        }
        for index in 0..<8 {
            state[index] ^= state[index + 8]
            state[index + 8] ^= cv[index]
        }
        return state
    }

    @inline(__always)
    private static func g(_ s: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt32, _ y: UInt32) {
        s[a] = s[a] &+ s[b] &+ x
        s[d] = rotate(s[d] ^ s[a], 16)
        s[c] = s[c] &+ s[d]
        s[b] = rotate(s[b] ^ s[c], 12)
        s[a] = s[a] &+ s[b] &+ y
        s[d] = rotate(s[d] ^ s[a], 8)
        s[c] = s[c] &+ s[d]
        s[b] = rotate(s[b] ^ s[c], 7)
    }

    @inline(__always)
    private static func rotate(_ value: UInt32, _ count: UInt32) -> UInt32 {
        value >> count | value << (32 - count)
    }

    private static func words(_ bytes: [UInt8]) -> [UInt32] {
        stride(from: 0, to: bytes.count, by: 4).map { (index: Int) -> UInt32 in
            UInt32(bytes[index]) | UInt32(bytes[index + 1]) << 8
                | UInt32(bytes[index + 2]) << 16 | UInt32(bytes[index + 3]) << 24
        }
    }
}
