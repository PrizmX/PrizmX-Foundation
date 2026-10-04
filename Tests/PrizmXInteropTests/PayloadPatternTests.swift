import Foundation
import Testing

/// The Swift pattern must match `Interop/target`'s Go implementation.
@Suite("Interop payload pattern")
struct PayloadPatternTests {
    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    /// Golden bytes from `newPattern(seed).Read` in Interop/target/main.go.
    @Test(arguments: [
        (UInt64(0), "7a48219ae2b3830d679dfef1794cc454780e7a0042"),
        (42, "1aecbc037f8d3208cdb67ae179727e079eb01b548f"),
    ])
    func matchesGoTarget(seed: UInt64, golden: String) {
        var pattern = PayloadPattern(seed: seed)
        #expect(hex(pattern.next(21)) == golden)
    }

    @Test func chunkingDoesNotChangeTheStream() {
        var whole = PayloadPattern(seed: 7)
        let expected = whole.next(1000)
        var pieces = PayloadPattern(seed: 7)
        var joined = Data()
        for size in [1, 3, 8, 13, 64, 7, 904] {
            joined += pieces.next(size)
        }
        #expect(joined == expected)
    }

    @Test func reportsTheFirstMismatch() {
        var source = PayloadPattern(seed: 9)
        var corrupted = source.next(100)
        corrupted[57] ^= 0xFF
        var check = PayloadPattern(seed: 9)
        #expect(check.firstMismatch(in: corrupted.prefix(50)) == nil)
        #expect(check.firstMismatch(in: corrupted.dropFirst(50)) == 7)
    }
}
