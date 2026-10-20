import Foundation
import PrizmXProtocols

/// One condition inside AND / OR / NOT or a classical rule set: a matcher
/// plus its own `no-resolve`.
public struct RuleCondition: Hashable, Sendable {
    public var matcher: RouteRule.HostMatcher
    public var noResolve: Bool

    public init(_ matcher: RouteRule.HostMatcher, noResolve: Bool = false) {
        self.matcher = matcher
        self.noResolve = noResolve
    }
}

/// A Clash rule provider's payload (`RULE-SET`), indexed for lookup: a
/// domain set answers in a few hash probes per name label and a CIDR set in
/// one probe per prefix length, however many entries it holds.
public final class RuleSet: Sendable, Hashable, CustomStringConvertible {
    public enum Behavior: String, Sendable, Hashable {
        case domain
        case ipcidr
        case classical
    }

    public let name: String
    public let behavior: Behavior
    /// Entries kept after parsing.
    public let count: Int

    private let exact: Set<String>
    /// `+.example.com`: the name and every subdomain.
    private let suffixes: Set<String>
    /// `.example.com`: subdomains only.
    private let subdomains: Set<String>
    private let wildcards: [RulePattern]
    private let ipv4: [UInt8: Set<UInt32>]
    private let ipv6: [UInt8: Set<IPv6Key>]
    /// Classical sets: full conditions, evaluated by `Router`.
    public let conditions: [RuleCondition]

    private struct IPv6Key: Hashable, Sendable {
        var high: UInt64
        var low: UInt64
    }

    /// `behavior: domain` payload: `example.com`, `+.example.com`,
    /// `.example.com`, `*.example.com`.
    public init(name: String, domains: [String]) {
        var exact = Set<String>()
        var suffixes = Set<String>()
        var subdomains = Set<String>()
        var wildcards: [RulePattern] = []
        for raw in domains {
            let entry = raw.trimmingCharacters(in: .whitespaces).lowercased()
            guard !entry.isEmpty else { continue }
            if entry.hasPrefix("+.") {
                suffixes.insert(String(entry.dropFirst(2)))
            } else if entry.hasPrefix(".") {
                subdomains.insert(String(entry.dropFirst()))
            } else if entry.contains("*") || entry.contains("?") {
                if let pattern = RulePattern(wildcard: entry) { wildcards.append(pattern) }
            } else {
                exact.insert(entry)
            }
        }
        self.name = name
        self.behavior = .domain
        self.exact = exact
        self.suffixes = suffixes
        self.subdomains = subdomains
        self.wildcards = wildcards
        self.ipv4 = [:]
        self.ipv6 = [:]
        self.conditions = []
        self.count = exact.count + suffixes.count + subdomains.count + wildcards.count
    }

    /// `behavior: ipcidr` payload. Malformed lines are skipped.
    public init(name: String, cidrs: [String]) {
        var ipv4: [UInt8: Set<UInt32>] = [:]
        var ipv6: [UInt8: Set<IPv6Key>] = [:]
        var count = 0
        for raw in cidrs {
            guard let matcher = try? RouteRule.compile(.ipCIDR(raw)) else { continue }
            switch matcher {
            case .ipv4(let address):
                ipv4[32, default: []].insert(address.rawValue)
            case .ipv4CIDR(let network, let prefix):
                ipv4[prefix, default: []].insert(network.rawValue & Self.mask4(prefix))
            case .ipv6(let address):
                ipv6[128, default: []].insert(IPv6Key(high: address.high, low: address.low))
            case .ipv6CIDR(let network, let prefix):
                ipv6[prefix, default: []].insert(Self.masked6(network, prefix))
            default:
                continue
            }
            count += 1
        }
        self.name = name
        self.behavior = .ipcidr
        self.exact = []
        self.suffixes = []
        self.subdomains = []
        self.wildcards = []
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.conditions = []
        self.count = count
    }

    /// `behavior: classical` payload, already compiled.
    public init(name: String, conditions: [RuleCondition]) {
        self.name = name
        self.behavior = .classical
        self.exact = []
        self.suffixes = []
        self.subdomains = []
        self.wildcards = []
        self.ipv4 = [:]
        self.ipv6 = [:]
        self.conditions = conditions
        self.count = conditions.count
    }

    public func contains(domain host: String) -> Bool {
        if exact.contains(host) || suffixes.contains(host) { return true }
        var rest = Substring(host)
        while let dot = rest.firstIndex(of: ".") {
            rest = rest[rest.index(after: dot)...]
            if rest.isEmpty { break }
            let parent = String(rest)
            if suffixes.contains(parent) || subdomains.contains(parent) { return true }
        }
        return wildcards.contains { $0.matches(host) }
    }

    public func contains(ipv4 address: IPv4Address) -> Bool {
        for (prefix, networks) in ipv4 where networks.contains(address.rawValue & Self.mask4(prefix)) {
            return true
        }
        return false
    }

    public func contains(ipv6 address: IPv6Address) -> Bool {
        for (prefix, networks) in ipv6 where networks.contains(Self.masked6(address, prefix)) {
            return true
        }
        return false
    }

    private static func mask4(_ prefix: UInt8) -> UInt32 {
        let length = min(prefix, 32)
        return length == 0 ? 0 : ~UInt32(0) << (32 - UInt32(length))
    }

    private static func masked6(_ address: IPv6Address, _ prefix: UInt8) -> IPv6Key {
        let bits = Int(min(prefix, 128))
        if bits <= 64 {
            let mask: UInt64 = bits == 0 ? 0 : ~UInt64(0) << (64 - UInt64(bits))
            return IPv6Key(high: address.high & mask, low: 0)
        }
        let rest = bits - 64
        let mask: UInt64 = rest == 64 ? ~0 : ~UInt64(0) << (64 - UInt64(rest))
        return IPv6Key(high: address.high, low: address.low & mask)
    }

    public var description: String { name }

    public static func == (lhs: RuleSet, rhs: RuleSet) -> Bool { lhs === rhs }
    public func hash(into hasher: inout Hasher) { hasher.combine(ObjectIdentifier(self)) }
}
