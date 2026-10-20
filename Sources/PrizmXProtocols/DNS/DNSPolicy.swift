import Foundation

/// A domain test built by the config layer (patterns, geosite, rule sets),
/// carried in `DNSSettings` without this module knowing those matchers.
public struct DomainPredicate: Sendable, Hashable, CustomStringConvertible {
    private let id = UUID()
    public let description: String
    private let test: @Sendable (String) -> Bool

    public init(_ description: String, _ test: @escaping @Sendable (String) -> Bool) {
        self.description = description
        self.test = test
    }

    public func matches(_ domain: String) -> Bool { test(domain.lowercased()) }

    public static func == (lhs: Self, rhs: Self) -> Bool { lhs.id == rhs.id }
    public func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

/// An address test (Clash `fallback-filter` geoip / ipcidr).
public struct AddressPredicate: Sendable, Hashable, CustomStringConvertible {
    private let id = UUID()
    public let description: String
    private let test: @Sendable (IPv4Address) -> Bool

    public init(_ description: String, _ test: @escaping @Sendable (IPv4Address) -> Bool) {
        self.description = description
        self.test = test
    }

    public func matches(_ address: IPv4Address) -> Bool { test(address) }

    public static func == (lhs: Self, rhs: Self) -> Bool { lhs.id == rhs.id }
    public func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

/// One Clash `nameserver-policy` entry: names it covers → their upstreams.
public struct NameserverPolicy: Sendable, Hashable {
    public var domains: DomainPredicate
    public var nameservers: [NameserverEndpoint]

    public init(domains: DomainPredicate, nameservers: [NameserverEndpoint]) {
        self.domains = domains
        self.nameservers = nameservers
    }
}

/// Clash `fallback-filter`: when the `nameserver` answer is replaced by the
/// `fallback` one.
public struct FallbackFilter: Sendable, Hashable {
    /// Names that go to `fallback` only (`domain` / `geosite`).
    public var domains: DomainPredicate?
    /// True for an address the `nameserver` answer must not contain
    /// (outside `geoip-code`, or inside `ipcidr`).
    public var rejectsAddress: AddressPredicate?

    public init(domains: DomainPredicate? = nil, rejectsAddress: AddressPredicate? = nil) {
        self.domains = domains
        self.rejectsAddress = rejectsAddress
    }
}

/// Clash top-level `hosts`: exact names, `*.x` (one label) and `+.x` (the
/// name and every subdomain). Checked before `/etc/hosts`.
public struct ProfileHosts: Sendable, Hashable {
    private var exact: [String: SystemHosts.Mapping] = [:]
    private var wildcards: [(pattern: String, mapping: SystemHosts.Mapping)] = []

    public static let empty = ProfileHosts()

    public init() {}

    /// `entries`: name → addresses as the profile writes them. Values that
    /// are not IP literals (Clash allows a domain alias) are skipped.
    public init(_ entries: [String: [String]]) {
        for (rawName, values) in entries {
            var mapping = SystemHosts.Mapping()
            for value in values {
                if let v4 = IPv4Address(parsing: value) {
                    mapping.addresses.append(.ipv4(v4))
                    mapping.ipv4.append(v4)
                } else if let v6 = IPv6Address(parsing: value) {
                    mapping.addresses.append(.ipv6(v6))
                    mapping.ipv6.append(v6)
                }
            }
            guard !mapping.isEmpty else { continue }
            let name = rawName.lowercased()
            if name.hasPrefix("*.") || name.hasPrefix("+.") || name.hasPrefix(".") {
                wildcards.append((name, mapping))
            } else {
                exact[name] = mapping
            }
        }
        // Most specific first (longer suffix), so overlapping patterns pick
        // the same entry on every launch.
        wildcards.sort { lhs, rhs in
            lhs.pattern.count != rhs.pattern.count ? lhs.pattern.count > rhs.pattern.count : lhs.pattern < rhs.pattern
        }
    }

    public var isEmpty: Bool { exact.isEmpty && wildcards.isEmpty }

    public func lookup(_ name: String) -> SystemHosts.Mapping? {
        var key = name.lowercased()
        while key.hasSuffix(".") { key.removeLast() }
        if let hit = exact[key] { return hit }
        for entry in wildcards {
            if entry.pattern.hasPrefix("+.") {
                let suffix = String(entry.pattern.dropFirst(2))
                if key == suffix || key.hasSuffix("." + suffix) { return entry.mapping }
            } else if entry.pattern.hasPrefix("*.") {
                let suffix = String(entry.pattern.dropFirst(2))
                guard key.hasSuffix("." + suffix) else { continue }
                let label = key.dropLast(suffix.count + 1)
                if !label.isEmpty, !label.contains(".") { return entry.mapping }
            } else if key.hasSuffix(entry.pattern) {
                return entry.mapping
            }
        }
        return nil
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.exact == rhs.exact
            && lhs.wildcards.map(\.pattern) == rhs.wildcards.map(\.pattern)
            && lhs.wildcards.map(\.mapping) == rhs.wildcards.map(\.mapping)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(exact.keys.sorted())
        hasher.combine(wildcards.map(\.pattern))
    }
}
