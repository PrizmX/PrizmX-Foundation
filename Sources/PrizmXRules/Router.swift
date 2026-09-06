import Foundation
import PrizmXProtocols

// MARK: - Policy / rule type

/// The action taken when a rule matches.
@frozen
public enum Policy: Sendable, Hashable {
    /// Connect directly (bypass any proxy group).
    case direct
    /// Block the connection.
    case reject
    /// Forward through a named policy group in `NodeManager`.
    case proxy(targetGroup: String)
}

/// User-facing matcher kinds (Clash / Surge style).
///
/// Converted to `RouteRule.HostMatcher` when a `RouteRule` is built.
@frozen
public enum RuleType: Hashable, Sendable {
    /// Exact domain (`google.com` does not match `www.google.com`).
    case domain(String)
    /// Domain suffix (`google.com` matches `google.com` and `www.google.com`).
    case domainSuffix(String)
    /// Substring of the domain (`google` matches `www.google.co.jp`).
    case domainKeyword(String)
    /// IPv4/IPv6 literal or CIDR (`10.0.0.0/8`, `192.168.1.1`, `2001:db8::/32`).
    case ipCIDR(String)
    /// GeoIP country code (`GEOIP,CN,DIRECT`). Evaluated when a `GeoIPMatcher` is supplied.
    case geoIP(code: String)
    /// Geosite category (`GEOSITE,cn,DIRECT`). Evaluated when a `GeositeMatcher` is supplied.
    case geosite(tag: String)
    /// Matches every remaining request (typically used as FINAL).
    case matchAll
}

/// A single routing rule.
public struct RouteRule: Hashable, Sendable {

    /// Compiled host matcher used by the engine.
    @frozen
    public enum HostMatcher: Hashable, Sendable {
        /// Exact domain name (case-insensitive, normalized to lowercase at
        /// build time).
        case domain(String)
        /// Domain suffix: matches the domain itself and all its subdomains.
        case domainSuffix(String)
        /// Case-insensitive substring of the domain.
        case domainKeyword(String)
        /// Exact IPv4 address.
        case ipv4(IPv4Address)
        /// IPv4 CIDR block, `prefixLength` in 0...32.
        case ipv4CIDR(IPv4Address, prefixLength: UInt8)
        /// Exact IPv6 address.
        case ipv6(IPv6Address)
        /// IPv6 CIDR block, `prefixLength` in 0...128.
        case ipv6CIDR(IPv6Address, prefixLength: UInt8)
        /// GeoIP country code (`CN`). Evaluated when `Router` is given a `GeoIPMatcher`.
        case geoIP(code: String)
        /// Geosite category (`cn`). Evaluated when `Router` is given a `GeositeMatcher`.
        case geosite(tag: String)
        /// Catch-all.
        case matchAll
    }

    /// The host matcher.
    public let matcher: HostMatcher
    /// Applies to this port only; `nil` means all ports.
    public let port: UInt16?
    /// The policy applied when matched.
    public let policy: Policy

    public init(_ matcher: HostMatcher, port: UInt16? = nil, policy: Policy) {
        self.matcher = matcher
        self.port = port
        self.policy = policy
    }

    /// Builds a rule from a `RuleType` (parses CIDR strings).
    public init(type: RuleType, port: UInt16? = nil, policy: Policy) {
        self.init(Self.compile(type), port: port, policy: policy)
    }

    public static func compile(_ type: RuleType) -> HostMatcher {
        switch type {
        case .domain(let domain):
            return .domain(domain.lowercased())
        case .domainSuffix(let suffix):
            return .domainSuffix(Self.normalizeSuffix(suffix))
        case .domainKeyword(let keyword):
            return .domainKeyword(keyword.lowercased())
        case .matchAll:
            return .matchAll
        case .ipCIDR(let text):
            return compileCIDR(text)
        case .geoIP(code: let code):
            return .geoIP(code: code.uppercased())
        case .geosite(tag: let tag):
            return .geosite(tag: tag.lowercased())
        }
    }

    private static func compileCIDR(_ text: String) -> HostMatcher {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmed.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let host = String(parts[0])
        let prefixText = parts.count == 2 ? String(parts[1]) : nil

        if let v4 = IPv4Address(parsing: host) {
            let prefix = prefixText.flatMap { UInt8($0) } ?? 32
            precondition(prefix <= 32, "IPv4 CIDR prefix must be 0...32, got \(prefix)")
            return prefix == 32 ? .ipv4(v4) : .ipv4CIDR(v4, prefixLength: prefix)
        }
        if let v6 = IPv6Address(parsing: host) {
            let prefix = prefixText.flatMap { UInt8($0) } ?? 128
            precondition(prefix <= 128, "IPv6 CIDR prefix must be 0...128, got \(prefix)")
            return prefix == 128 ? .ipv6(v6) : .ipv6CIDR(v6, prefixLength: prefix)
        }
        preconditionFailure("invalid ipCIDR literal: \(text)")
    }

    fileprivate static func normalizeSuffix(_ suffix: String) -> String {
        var key = suffix.lowercased()
        if key.hasPrefix("*.") { key.removeFirst(2) }
        while key.hasPrefix(".") { key.removeFirst() }
        while key.hasSuffix(".") { key.removeLast() }
        return key
    }
}

/// Clash / sing-box style routing: rules are tried **in list order**, first
/// match wins. Port-scoped rules that do not match the port are skipped.
public final class Router: Sendable {

    public let rules: [RouteRule]
    public let defaultPolicy: Policy
    private let geoIP: GeoIPMatcher?
    private let geosite: GeositeMatcher?

    public init(
        rules: [RouteRule] = [],
        default defaultPolicy: Policy = .direct,
        geoIP: GeoIPMatcher? = nil,
        geosite: GeositeMatcher? = nil
    ) {
        self.rules = rules
        self.defaultPolicy = defaultPolicy
        self.geoIP = geoIP
        self.geosite = geosite
    }

    /// Primary API: policy for a destination endpoint.
    public func match(endpoint: Endpoint) -> Policy {
        for rule in rules {
            if matches(rule, endpoint: endpoint) {
                return rule.policy
            }
        }
        return defaultPolicy
    }

    /// Queries a policy given a host name (domain or IP literal) and a port.
    public func match(host: some StringProtocol, port: UInt16) -> Policy {
        if let address = IPv4Address(parsing: host) {
            return match(endpoint: Endpoint(host: .ipv4(address), port: port))
        }
        if let address = IPv6Address(parsing: host) {
            return match(endpoint: Endpoint(host: .ipv6(address), port: port))
        }
        return match(endpoint: Endpoint(domain: String(host), port: port))
    }

    /// Queries a policy given a URL. Returns `nil` when the URL has no host.
    public func match(url: URL, defaultPort: UInt16) -> Policy? {
        guard let host = url.host else { return nil }
        let port = UInt16(clamping: url.port ?? Int(defaultPort))
        return match(host: host, port: port)
    }

    private func matches(_ rule: RouteRule, endpoint: Endpoint) -> Bool {
        if let port = rule.port, port != endpoint.port { return false }
        switch rule.matcher {
        case .domain(let domain):
            guard case .domain(let host) = endpoint.host else { return false }
            return host == domain.lowercased()
        case .domainSuffix(let suffix):
            guard case .domain(let host) = endpoint.host else { return false }
            let key = RouteRule.normalizeSuffix(suffix)
            guard !key.isEmpty else { return false }
            return host == key || host.hasSuffix("." + key)
        case .domainKeyword(let keyword):
            guard case .domain(let host) = endpoint.host else { return false }
            return host.contains(keyword.lowercased())
        case .ipv4(let address):
            guard case .ipv4(let host) = endpoint.host else { return false }
            return host == address
        case .ipv4CIDR(let network, let prefixLength):
            guard case .ipv4(let host) = endpoint.host else { return false }
            return Self.ipv4(host, in: network, prefix: prefixLength)
        case .ipv6(let address):
            guard case .ipv6(let host) = endpoint.host else { return false }
            return host == address
        case .ipv6CIDR(let network, let prefixLength):
            guard case .ipv6(let host) = endpoint.host else { return false }
            return Self.ipv6(host, in: network, prefix: prefixLength)
        case .geoIP(code: let code):
            switch endpoint.host {
            case .ipv4(let address):
                return geoIP?.lookup(ipv4: address) == code
            case .ipv6(let address):
                return geoIP?.lookup(ipv6: address) == code
            case .domain:
                return false
            }
        case .geosite(tag: let tag):
            guard case .domain(let host) = endpoint.host, let geosite else { return false }
            return geosite.match(domain: host, group: tag)
        case .matchAll:
            return true
        }
    }

    private static func ipv4(_ address: IPv4Address, in network: IPv4Address, prefix: UInt8) -> Bool {
        let length = min(prefix, 32)
        let mask = length == 0 ? UInt32(0) : ~UInt32(0) << (32 - UInt32(length))
        return address.rawValue & mask == network.rawValue & mask
    }

    private static func ipv6(
        _ address: IPv6Address,
        in network: IPv6Address,
        prefix: UInt8
    ) -> Bool {
        let bits = Int(prefix)
        if bits == 0 { return true }
        if bits <= 64 {
            let shift = 64 - bits
            let mask = shift == 64 ? 0 : ~UInt64(0) << shift
            return (address.high & mask) == (network.high & mask)
        }
        let rest = bits - 64
        let shift = 64 - rest
        let mask = shift == 64 ? 0 : ~UInt64(0) << shift
        return address.high == network.high && (address.low & mask) == (network.low & mask)
    }
}
