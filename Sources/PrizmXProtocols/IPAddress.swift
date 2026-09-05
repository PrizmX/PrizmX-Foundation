/// An IPv4 address stored as a single `UInt32` with no heap allocation.
///
/// `rawValue` is endian-independent: for an address `a.b.c.d`,
/// `rawValue == a << 24 | b << 16 | c << 8 | d` always holds.
@frozen
public struct IPv4Address: Hashable, Sendable, CustomStringConvertible, Codable {

    /// Numeric representation of the address (`a << 24 | b << 16 | c << 8 | d`).
    public let rawValue: UInt32

    @inlinable
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// Constructs from the four octets.
    @inlinable
    public init(_ octet1: UInt8, _ octet2: UInt8, _ octet3: UInt8, _ octet4: UInt8) {
        self.rawValue = UInt32(octet1) << 24 | UInt32(octet2) << 16
            | UInt32(octet3) << 8 | UInt32(octet4)
    }

    /// Constructs from network byte order: `value` is the result of loading
    /// big-endian memory natively (i.e. the return value of `load(as: UInt32.self)`).
    @inlinable
    public init(networkOrder value: UInt32) {
        self.rawValue = UInt32(bigEndian: value)
    }

    /// Returns the value in network byte order (big-endian): when written back
    /// to memory via `storeBytes(of:as:)`, it produces the byte sequence a.b.c.d.
    @inlinable
    public var networkOrder: UInt32 { UInt32(bigEndian: rawValue) }

    /// Parses a dotted-decimal literal such as `"192.168.1.100"`.
    /// Returns `nil` for invalid input.
    public init?(parsing text: some StringProtocol) {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var octets: [UInt8] = []
        octets.reserveCapacity(4)
        for part in parts {
            guard let value = UInt8(part) else { return nil }
            octets.append(value)
        }
        self.init(octets[0], octets[1], octets[2], octets[3])
    }

    public var description: String {
        let octet1 = (rawValue >> 24) & 0xFF
        let octet2 = (rawValue >> 16) & 0xFF
        let octet3 = (rawValue >> 8) & 0xFF
        let octet4 = rawValue & 0xFF
        return "\(octet1).\(octet2).\(octet3).\(octet4)"
    }

    public static let loopback = IPv4Address(127, 0, 0, 1)
    public static let any = IPv4Address(0, 0, 0, 0)
}

/// An IPv6 address stored as two `UInt64`s (16 bytes total) with no heap
/// allocation.
///
/// `high` packs segments 0–3 and `low` packs segments 4–7 (both in network
/// order); e.g. `::1` has `low == 1`.
@frozen
public struct IPv6Address: Hashable, Sendable, CustomStringConvertible, Codable {

    /// Fixed-size representation of the 8 16-bit segments (network order),
    /// no heap allocation.
    @frozen
    public struct Segments: Hashable, Sendable {
        public var s0: UInt16
        public var s1: UInt16
        public var s2: UInt16
        public var s3: UInt16
        public var s4: UInt16
        public var s5: UInt16
        public var s6: UInt16
        public var s7: UInt16

        public init(
            _ s0: UInt16, _ s1: UInt16, _ s2: UInt16, _ s3: UInt16,
            _ s4: UInt16, _ s5: UInt16, _ s6: UInt16, _ s7: UInt16
        ) {
            self.s0 = s0; self.s1 = s1; self.s2 = s2; self.s3 = s3
            self.s4 = s4; self.s5 = s5; self.s6 = s6; self.s7 = s7
        }

        /// Visits each segment in network order; returning `false` from `body`
        /// stops iteration early.
        public func forEach(_ body: (UInt16) throws -> Bool) rethrows {
            for value in [s0, s1, s2, s3, s4, s5, s6, s7] {
                if try !body(value) { return }
            }
        }
    }

    /// Segments 0–3 (high 64 bits), packed in network order.
    public let high: UInt64
    /// Segments 4–7 (low 64 bits), packed in network order.
    public let low: UInt64

    public init(segments: Segments) {
        func pack(_ s1: UInt16, _ s2: UInt16, _ s3: UInt16, _ s4: UInt16) -> UInt64 {
            UInt64(s1) << 48 | UInt64(s2) << 32 | UInt64(s3) << 16 | UInt64(s4)
        }
        self.high = pack(segments.s0, segments.s1, segments.s2, segments.s3)
        self.low = pack(segments.s4, segments.s5, segments.s6, segments.s7)
    }

    public init(high: UInt64, low: UInt64) {
        self.high = high
        self.low = low
    }

    /// The 8 16-bit segments (network order).
    public var segments: Segments {
        func segment(_ value: UInt64, _ index: Int) -> UInt16 {
            UInt16(truncatingIfNeeded: value >> (48 - 16 * index))
        }
        return Segments(
            segment(high, 0), segment(high, 1), segment(high, 2), segment(high, 3),
            segment(low, 0), segment(low, 1), segment(low, 2), segment(low, 3)
        )
    }

    /// Parses an IPv6 literal, supporting `::` compression and a trailing
    /// embedded IPv4 (e.g. `::ffff:192.168.0.1`).
    public init?(parsing text: some StringProtocol) {
        // Reject illegal lone leading/trailing colons (":a", "a:") while
        // allowing "::".
        guard !(text.hasPrefix(":") && !text.hasPrefix("::")),
              !(text.hasSuffix(":") && !text.hasSuffix("::"))
        else { return nil }

        var head: [UInt16] = []
        var tail: [UInt16] = []
        var isAfterCompress = false
        var hasCompress = false

        var parts = text.split(separator: ":", omittingEmptySubsequences: false)[...]
        // Drop the empty parts produced by "::" at either end (the prefix
        // checks above guarantee no valid input is wrongly stripped).
        if parts.first?.isEmpty == true { parts = parts.dropFirst() }
        if parts.last?.isEmpty == true { parts = parts.dropLast() }

        for (index, part) in parts.enumerated() {
            if part.isEmpty {
                // An empty part in the middle marks the "::" compression;
                // it may appear at most once.
                guard !hasCompress else { return nil }
                hasCompress = true
                isAfterCompress = true
                continue
            }
            if part.contains(".") {
                // Trailing embedded IPv4, must be the last part; expand it
                // into two 16-bit segments.
                guard index == parts.count - 1,
                      let v4 = IPv4Address(parsing: part)
                else { return nil }
                let hi = UInt16(truncatingIfNeeded: v4.rawValue >> 16)
                let lo = UInt16(truncatingIfNeeded: v4.rawValue)
                if isAfterCompress {
                    tail.append(hi); tail.append(lo)
                } else {
                    head.append(hi); head.append(lo)
                }
                continue
            }
            guard let value = UInt16(part, radix: 16) else { return nil }
            if isAfterCompress {
                tail.append(value)
            } else {
                head.append(value)
            }
        }

        let total = head.count + tail.count
        if hasCompress {
            guard total <= 7 else { return nil }
        } else {
            guard total == 8 else { return nil }
        }

        var segments = head
        segments.append(contentsOf: repeatElement(0, count: 8 - total))
        segments.append(contentsOf: tail)
        self.init(
            segments: Segments(
                segments[0], segments[1], segments[2], segments[3],
                segments[4], segments[5], segments[6], segments[7]
            )
        )
    }

    public var description: String {
        let values: [UInt16] = [
            segments.s0, segments.s1, segments.s2, segments.s3,
            segments.s4, segments.s5, segments.s6, segments.s7,
        ]

        // Find the longest run of zero segments (compressed to "::" only when
        // the run length is >= 2).
        var bestStart = -1
        var bestLength = 0
        var runStart = -1
        var runLength = 0
        for (index, value) in values.enumerated() {
            if value == 0 {
                if runLength == 0 { runStart = index }
                runLength += 1
                if runLength > bestLength {
                    bestLength = runLength
                    bestStart = runStart
                }
            } else {
                runLength = 0
            }
        }

        func hex(_ value: UInt16) -> String { String(value, radix: 16) }

        guard bestLength >= 2 else {
            return values.map(hex).joined(separator: ":")
        }
        let head = values[..<bestStart].map(hex).joined(separator: ":")
        let tail = values[(bestStart + bestLength)...].map(hex).joined(separator: ":")
        return head + "::" + tail
    }

    public static let loopback = IPv6Address(
        segments: Segments(0, 0, 0, 0, 0, 0, 0, 1)
    )
    public static let any = IPv6Address(
        segments: Segments(0, 0, 0, 0, 0, 0, 0, 0)
    )
}
