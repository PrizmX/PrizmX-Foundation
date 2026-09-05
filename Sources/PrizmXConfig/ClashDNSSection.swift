import Foundation
import PrizmXProtocols

/// The `dns:` section of a Clash YAML config (Mihomo naming).
///
/// Only the fields the outbound DNS plane consumes are extracted; `listen`,
/// `enhanced-mode`, etc. belong to the local responder, not outbound lookups.
public struct ClashDNSSection: Sendable, Equatable {
    public var defaultNameservers: [String] = []
    public var nameservers: [String] = []
    public var proxyServerNameservers: [String] = []
    public var directNameservers: [String] = []
    public var fakeIPFilter: [String] = []

    public init() {}

    /// Extracts `dns:` from a Clash YAML document. Returns nil for sing-box
    /// JSON / Surge INI / missing section.
    public static func parse(from rawString: String) -> ClashDNSSection? {
        let trimmed = rawString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let first = trimmed.first, first != "{", first != "[" else { return nil }
        guard let root = try? YAMLParser.parse(trimmed), let dns = root.mapping?["dns"] else { return nil }
        var section = ClashDNSSection()
        section.defaultNameservers = strings(dns, "default-nameserver")
        section.nameservers = strings(dns, "nameserver")
        section.proxyServerNameservers = strings(dns, "proxy-server-nameserver")
        section.directNameservers = strings(dns, "direct-nameserver")
        section.fallback = strings(dns, "fallback")
        section.fakeIPFilter = strings(dns, "fake-ip-filter")
        return section
    }

    /// Reserved for a later slice (Mihomo `fallback` upstreams).
    public var fallback: [String] = []

    private static func strings(_ node: YAMLNode, _ key: String) -> [String] {
        guard let value = node.mapping?[key] else { return [] }
        if let sequence = value.sequence {
            return sequence.compactMap(\.string).filter { !$0.isEmpty }
        }
        if let scalar = value.string, !scalar.isEmpty {
            return [scalar]
        }
        return []
    }
}

extension DNSSettings {
    /// Clash semantics:
    /// - `default-nameserver` → bootstrap (plain IPs; also resolves DoH hosts)
    /// - `proxy-server-nameserver` pointing at Clash's own listener
    ///   (`udp://127.0.0.1:<listen>`) collapses to `nameservers`
    /// - `direct-nameserver` empty → the machine's effective resolver
    ///   (captured before FakeDNS is installed)
    public static func fromClash(section: ClashDNSSection?, systemDNS: [String]) -> DNSSettings {
        let system = systemDNS.compactMap { NameserverEndpoint.udp(ip: $0) }
        let bootstrap = (section?.defaultNameservers ?? []).compactMap(NameserverEndpoint.parse)
        let general = (section?.nameservers ?? []).compactMap(NameserverEndpoint.parse)
        // Loopback (Clash's own DNS listener) is dropped by `parse` via the
        // IP-literal rule, leaving an empty list → role falls back to
        // `nameservers`, matching how Clash resolves node domains internally.
        let proxy = (section?.proxyServerNameservers ?? []).compactMap(NameserverEndpoint.parse)
        let direct = (section?.directNameservers ?? []).compactMap(NameserverEndpoint.parse)
        let fallback = ["223.5.5.5", "119.29.29.29"].compactMap { NameserverEndpoint.udp(ip: $0) }
        return DNSSettings(
            defaultNameservers: bootstrap.isEmpty ? (system.isEmpty ? fallback : system) : bootstrap,
            nameservers: general,
            proxyServerNameservers: proxy,
            directNameservers: direct,
            systemNameservers: system,
            fakeIPFilter: (section?.fakeIPFilter ?? []) + ["*.lan", "*.local", "*.localhost"],
            cacheTTL: 60
        )
    }
}
