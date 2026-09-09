import Foundation
#if os(macOS)
import SystemConfiguration
#endif

/// Which outbound plane is asking for a real A record.
///
/// Mirrors Clash Meta's split: node hostnames vs DIRECT destinations.
/// App queries never use this type — those stay on FakeIP.
public enum DNSRole: Sendable, Hashable, CustomStringConvertible {
    /// Clash `proxy-server-nameserver` — resolve a proxy node's hostname.
    case proxyServer
    /// Clash `direct-nameserver` — resolve a DIRECT destination (and the real
    /// answer for fake-ip-filtered App queries).

    case direct

    public var description: String {
        switch self {
        case .proxyServer: "proxy-server"
        case .direct: "direct"
        }
    }
}

/// A nameserver the outbound DNS plane may query.
///
/// Addresses for `.udp` must be IP literals (Clash `default-nameserver`
/// rule). `.doh` hosts are resolved via the bootstrap nameservers.
public enum NameserverEndpoint: Sendable, Hashable, Codable, CustomStringConvertible {
    case udp(address: String, port: UInt16)
    case doh(url: String)

    public var description: String {
        switch self {
        case .udp(let address, let port): "udp://\(address):\(port)"
        case .doh(let url): "doh://\(url)"
        }
    }

    /// UDP nameserver at `ip:port`. Returns nil when `ip` is not a usable
    /// IPv4 literal (loopback, FakeIP range, non-IP).
    public static func udp(ip: String, port: UInt16 = 53) -> NameserverEndpoint? {
        guard NameserverAddress.isUsableIPv4(ip) else { return nil }
        return .udp(address: ip, port: port)
    }

    /// Clash `nameserver`-style value: `223.5.5.5`, `udp://1.1.1.1:53`,
    /// `https://dns.example/dns-query`. Unsupported transports
    /// (`tls://`, `quic://`, `dhcp://`, `system`) return nil.
    public static func parse(_ raw: String) -> NameserverEndpoint? {
        let value = raw.trimmingCharacters(in: .whitespaces)
        guard !value.isEmpty else { return nil }
        if value.hasPrefix("https://") {
            guard URL(string: value) != nil else { return nil }
            return .doh(url: value)
        }
        if value.hasPrefix("udp://") {
            let rest = String(value.dropFirst("udp://".count))
            let (host, port) = splitHostPort(rest, defaultPort: 53)
            return udp(ip: host, port: port)
        }
        if value.hasPrefix("tcp://") || value.hasPrefix("tls://") || value.hasPrefix("quic://")
            || value.hasPrefix("dhcp://") || value == "system" || value.hasPrefix("system://") {
            return nil
        }
        return udp(ip: value)
    }

    private static func splitHostPort(_ text: String, defaultPort: UInt16) -> (String, UInt16) {
        guard let colon = text.lastIndex(of: ":"), text[text.index(after: colon)...].allSatisfy(\.isNumber),
              let port = UInt16(text[text.index(after: colon)...]) else {
            return (text, defaultPort)
        }
        return (String(text[..<colon]), port)
    }
}

/// Clash-shaped outbound DNS configuration.
///
/// Empty role lists fall back the same way Mihomo does: proxy-server →
/// `nameservers` → `defaultNameservers`; direct → `defaultNameservers`.
public struct DNSSettings: Sendable, Hashable {
    /// Clash `default-nameserver`. IP-only bootstrap / default upstreams.
    public var defaultNameservers: [NameserverEndpoint]
    /// Clash `nameserver` — general upstreams (often DoH).
    public var nameservers: [NameserverEndpoint]
    /// Clash `proxy-server-nameserver`. Empty → `nameservers`.
    public var proxyServerNameservers: [NameserverEndpoint]
    /// Clash `direct-nameserver`. Empty → `systemNameservers`.
    public var directNameservers: [NameserverEndpoint]
    /// The machine's effective resolver captured before FakeDNS is installed.
    /// Tracks fast-flux DNS generations fastest (mDNSResponder re-queries on
    /// short TTLs); appended as a tail source to both roles.
    public var systemNameservers: [NameserverEndpoint]
    /// Clash `fake-ip-filter` — these domains never receive fake IPs.
    public var fakeIPFilter: [String]
    /// Clash `dns.ipv6`. When false (default), FakeDNS answers AAAA with
    /// NODATA so clients use IPv4 FakeIP. When true, PROXY and DIRECT names
    /// get FakeIPv6 (`fd11:4514:1919:6472::/64`); filter / node hosts still
    /// get a real AAAA.
    public var ipv6: Bool
    /// Fallback positive-cache lifetime when the answer carries no TTL.
    public var cacheTTL: TimeInterval

    public init(
        defaultNameservers: [NameserverEndpoint],
        nameservers: [NameserverEndpoint] = [],
        proxyServerNameservers: [NameserverEndpoint] = [],
        directNameservers: [NameserverEndpoint] = [],
        systemNameservers: [NameserverEndpoint] = [],
        fakeIPFilter: [String] = [],
        ipv6: Bool = false,
        cacheTTL: TimeInterval = 60
    ) {
        self.defaultNameservers = defaultNameservers
        self.nameservers = nameservers
        self.proxyServerNameservers = proxyServerNameservers
        self.directNameservers = directNameservers
        self.systemNameservers = systemNameservers
        self.fakeIPFilter = fakeIPFilter
        self.ipv6 = ipv6
        self.cacheTTL = cacheTTL
    }

    /// Freeze effective DNS IPs captured **before** tunnel settings apply.
    /// Public resolvers are used only when that list is empty — they are not
    /// raced against the local resolver (different CDNs, poisoned edges).
    public static func bootstrap(
        physicalIPs: [String],
        fallbackIPs: [String] = ["223.5.5.5"]
    ) -> DNSSettings {
        let physical = physicalIPs.compactMap { NameserverEndpoint.udp(ip: $0) }
        let fallback = fallbackIPs.compactMap { NameserverEndpoint.udp(ip: $0) }
        return DNSSettings(
            defaultNameservers: physical.isEmpty ? fallback : physical,
            systemNameservers: physical
        )
    }

    public func endpoints(for role: DNSRole) -> [NameserverEndpoint] {
        switch role {
        case .proxyServer:
            // Clash: proxy-server-nameserver → nameserver → default. We
            // additionally append bootstrap + system as tail sources: answers
            // are merged, and a dead CDN edge from the provider's DoH must not
            // starve the dial when another resolver already has a live one.
            let primary = !proxyServerNameservers.isEmpty ? proxyServerNameservers : nameservers
            return Self.deduplicate(primary + defaultNameservers + systemNameservers)
        case .direct:
            let primary = !directNameservers.isEmpty ? directNameservers : systemNameservers
            return Self.deduplicate(primary + defaultNameservers)
        }
    }

    private static func deduplicate(_ endpoints: [NameserverEndpoint]) -> [NameserverEndpoint] {
        var seen = Set<NameserverEndpoint>()
        return endpoints.filter { seen.insert($0).inserted }
    }
}

public enum DNSError: Error, Sendable, Equatable, LocalizedError {
    case notConfigured
    case noNameserver
    case noRecord(String)
    case timeout
    case nameserverMustBeIP(String)
    case transportNotImplemented(NameserverKind)

    public enum NameserverKind: Sendable, Equatable {
        case doh
    }

    public var errorDescription: String? {
        switch self {
        case .notConfigured: "outbound DNS is not configured"
        case .noNameserver: "no usable nameserver"
        case .noRecord(let domain): "no A record: \(domain)"
        case .timeout: "DNS query timed out"
        case .nameserverMustBeIP(let value): "nameserver must be an IP: \(value)"
        case .transportNotImplemented(let kind): "DNS transport not implemented: \(kind)"
        }
    }
}

/// Snapshot of the effective DNS **before** FakeDNS is installed. Reading
/// SCDynamicStore after `setTunnelNetworkSettings` returns the tunnel's
/// FakeDNS (198.18.0.2) and must not be used for outbound dials.
public enum PhysicalDNSSnapshot: Sendable {
    /// Precedence matches mDNSResponder: manual DNS on the primary service
    /// (Setup scope) beats the DHCP-provided State lists.
    public static func capture() -> [String] {
        #if os(macOS)
        guard let store = SCDynamicStoreCreate(nil, "PrizmX.DNS" as CFString, nil, nil) else {
            return []
        }
        let primary = (SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any])?["PrimaryService"] as? String
        if let primary,
           let dns = SCDynamicStoreCopyValue(store, "Setup:/Network/Service/\(primary)/DNS" as CFString) as? [String: Any],
           let addresses = dns["ServerAddresses"] as? [String] {
            let usable = addresses.filter { NameserverAddress.isUsableIPv4($0) }
            TunnelLog.write(.debug, "dns snapshot Setup service=\(addresses)")
            if !usable.isEmpty { return usable }
        }
        if let global = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString) as? [String: Any],
           let addresses = global["ServerAddresses"] as? [String] {
            let usable = addresses.filter { NameserverAddress.isUsableIPv4($0) }
            TunnelLog.write(.debug, "dns snapshot Global/DNS=\(addresses)")
            if !usable.isEmpty { return usable }
        }
        if let primary,
           let dns = SCDynamicStoreCopyValue(store, "State:/Network/Service/\(primary)/DNS" as CFString) as? [String: Any],
           let addresses = dns["ServerAddresses"] as? [String] {
            let usable = addresses.filter { NameserverAddress.isUsableIPv4($0) }
            TunnelLog.write(.debug, "dns snapshot State service=\(addresses)")
            if !usable.isEmpty { return usable }
        }
        TunnelLog.write(.debug, "dns snapshot empty")
        return []
        #else
        return []
        #endif
    }
}

public enum NameserverAddress: Sendable {
    /// 198.18.0.0/16 — FakeIP pool / tunnel subnet. Never a nameserver.
    static let fakeIPNetwork = IPv4Address(198, 18, 0, 0).rawValue
    static let fakeIPMask: UInt32 = 0xFFFF_0000

    public static func isUsableIPv4(_ text: String) -> Bool {
        guard let address = IPv4Address(parsing: text) else { return false }
        if address.rawValue == 0 { return false }
        if (address.rawValue >> 24) == 127 { return false }
        if (address.rawValue & fakeIPMask) == fakeIPNetwork { return false }
        return true
    }
}

/// Clash `fake-ip-filter` matching: exact, `*.suffix`, `+.suffix`, and
/// general `*` wildcards (ordered parts, e.g. `time.*.com`).
public enum FakeIPFilter: Sendable {
    public static func matches(_ domain: String, patterns: [String]) -> Bool {
        let lower = domain.lowercased()
        return patterns.contains { match(lower, pattern: $0.lowercased()) }
    }

    static func match(_ domain: String, pattern: String) -> Bool {
        var pattern = pattern
        if pattern.hasPrefix("+.") { pattern = "*." + pattern.dropFirst(2) }
        guard pattern.contains("*") else { return domain == pattern }
        if pattern.hasPrefix("*.") && pattern.components(separatedBy: "*").count == 2 {
            let suffix = String(pattern.dropFirst(2))
            return domain == suffix || domain.hasSuffix("." + suffix)
        }
        let parts = pattern.components(separatedBy: "*")
        var cursor = domain.startIndex
        for (index, part) in parts.enumerated() {
            guard !part.isEmpty else { continue }
            guard let range = domain.range(of: part, range: cursor..<domain.endIndex) else { return false }
            if index == 0, !pattern.hasPrefix("*"), range.lowerBound != domain.startIndex { return false }
            if index == parts.count - 1, !pattern.hasSuffix("*"), range.upperBound != domain.endIndex { return false }
            cursor = range.upperBound
        }
        return true
    }
}
