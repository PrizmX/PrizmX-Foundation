import Foundation
import PrizmXProtocols

/// What is known about a connection besides its destination, for rules such
/// as NETWORK, SRC-IP-CIDR, IN-PORT and PROCESS-NAME.
///
/// At FakeDNS time only the name is known (`isComplete == false`): a rule
/// that needs more leaves the match undecided, and the dial decides later.
public struct RouteContext: Sendable, Equatable {
    public enum Network: String, Sendable, Equatable {
        case tcp
        case udp
    }

    public var network: Network?
    public var sourceHost: Endpoint.Host?
    public var sourcePort: UInt16?
    /// Local listener port (mixed-port); nil for TUN flows.
    public var inboundPort: UInt16?
    public var processName: String?
    public var processPath: String?
    /// The IP the client dialed when the destination is a name sniffed from
    /// its first bytes (TLS SNI, HTTP Host). As in mihomo, IP rules match
    /// this address, `no-resolve` or not, and the name is not looked up.
    public var destinationAddress: Endpoint.Host?
    /// False while only the destination name is known (FakeDNS).
    public var isComplete: Bool

    public init(
        network: Network? = nil,
        sourceHost: Endpoint.Host? = nil,
        sourcePort: UInt16? = nil,
        inboundPort: UInt16? = nil,
        processName: String? = nil,
        processPath: String? = nil,
        destinationAddress: Endpoint.Host? = nil,
        isComplete: Bool = true
    ) {
        self.network = network
        self.sourceHost = sourceHost
        self.sourcePort = sourcePort
        self.inboundPort = inboundPort
        self.processName = processName
        self.processPath = processPath
        self.destinationAddress = destinationAddress
        self.isComplete = isComplete
    }

    /// Nothing known; context rules do not match.
    public static let none = RouteContext()
    /// FakeDNS: context rules are undecided.
    public static let nameOnly = RouteContext(isComplete: false)
}

/// Ports and ranges as Clash writes them: `443`, `8000-9000`, `80/443`,
/// `80,443`.
public struct PortSet: Sendable, Hashable, CustomStringConvertible {
    public let ranges: [ClosedRange<UInt16>]

    public init?(parsing text: String) {
        var ranges: [ClosedRange<UInt16>] = []
        for part in text.split(whereSeparator: { $0 == "/" || $0 == "," }) {
            let bounds = part.split(separator: "-", maxSplits: 1).map {
                $0.trimmingCharacters(in: .whitespaces)
            }
            guard let low = bounds.first.flatMap({ UInt16($0) }) else { return nil }
            let high = bounds.count == 2 ? UInt16(bounds[1]) : low
            guard let high, low <= high else { return nil }
            ranges.append(low...high)
        }
        guard !ranges.isEmpty else { return nil }
        self.ranges = ranges
    }

    public func contains(_ port: UInt16) -> Bool {
        ranges.contains { $0.contains(port) }
    }

    public var description: String {
        ranges.map { $0.lowerBound == $0.upperBound ? "\($0.lowerBound)" : "\($0.lowerBound)-\($0.upperBound)" }
            .joined(separator: "/")
    }
}

/// `IP-SUFFIX` as mihomo reads it: `8.8.8.8/24` matches every address whose
/// last 24 bits are those of 8.8.8.8 (`*.8.8.8`). An address of the other
/// family never matches.
public struct IPSuffix: Sendable, Hashable, CustomStringConvertible {
    /// `.ipv4` or `.ipv6`.
    public let address: Endpoint.Host
    /// Trailing bits compared, up to the family's width.
    public let bits: UInt8

    init(address: Endpoint.Host, bits: UInt8) {
        self.address = address
        self.bits = bits
    }

    public func matches(_ host: Endpoint.Host) -> Bool {
        func low<T: FixedWidthInteger & UnsignedInteger>(_ count: Int) -> T {
            count >= T.bitWidth ? ~0 : (1 << count) - 1
        }
        switch (address, host) {
        case (.ipv4(let suffix), .ipv4(let candidate)):
            return (suffix.rawValue ^ candidate.rawValue) & low(Int(bits)) == 0
        case (.ipv6(let suffix), .ipv6(let candidate)):
            let lowBits = min(Int(bits), 64)
            return (suffix.low ^ candidate.low) & low(lowBits) == 0
                && (suffix.high ^ candidate.high) & low(Int(bits) - lowBits) == 0
        default:
            return false
        }
    }

    public var description: String { "\(address)/\(bits)" }
}

/// A compiled `NSRegularExpression` that can live in Sendable rule values.
/// The regex is immutable after compilation and safe to use concurrently.
public struct RulePattern: @unchecked Sendable, Hashable, CustomStringConvertible {
    public let pattern: String
    private let regex: NSRegularExpression

    public init?(_ pattern: String, caseInsensitive: Bool = false) {
        guard let regex = try? NSRegularExpression(
            pattern: pattern,
            options: caseInsensitive ? [.caseInsensitive] : []
        ) else { return nil }
        self.pattern = pattern
        self.regex = regex
    }

    /// A `*` / `?` glob. `DOMAIN-WILDCARD` lets `*` span dots
    /// (`*.google.com` matches `a.b.google.com`); rule-set domain entries
    /// keep it within one label.
    public init?(wildcard: String, crossesLabels: Bool = false) {
        var pattern = "^"
        for character in wildcard.lowercased() {
            switch character {
            case "*": pattern += crossesLabels ? ".*" : "[^.]*"
            case "?": pattern += "[^.]"
            default: pattern += NSRegularExpression.escapedPattern(for: String(character))
            }
        }
        self.init(pattern + "$")
    }

    public func matches(_ text: String) -> Bool {
        regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil
    }

    public var description: String { pattern }

    public static func == (lhs: Self, rhs: Self) -> Bool { lhs.pattern == rhs.pattern }
    public func hash(into hasher: inout Hasher) { hasher.combine(pattern) }
}
