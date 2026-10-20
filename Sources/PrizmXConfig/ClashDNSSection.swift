import Foundation
import PrizmXProtocols
import PrizmXRules

/// The `dns:` section of a Clash YAML config (Mihomo naming).
///
/// Only the fields the outbound DNS plane consumes are extracted; `listen`,
/// `enhanced-mode`, etc. belong to the local responder, not outbound lookups.
public struct ClashDNSSection: Sendable, Equatable {
    /// Clash `dns.enable`. Mihomo defaults to false and then ignores the
    /// section's nameservers (node hostnames use the system resolver).
    public var enable: Bool = false
    public var defaultNameservers: [String] = []
    public var nameservers: [String] = []
    public var proxyServerNameservers: [String] = []
    public var directNameservers: [String] = []
    public var fakeIPFilter: [String] = []
    /// Clash `dns.ipv6`. Default false — FakeIP stays IPv4-only.
    public var ipv6: Bool = false
    /// Clash `nameserver-policy`: patterns (`+.x`, `geosite:cn`,
    /// `rule-set:name`, comma-separated in one key) → upstreams.
    public var nameserverPolicy: [(patterns: [String], nameservers: [String])] = []
    public var fallbackFilter = FallbackFilterSection()
    /// Top-level `hosts`, applied unless `dns.use-hosts: false`.
    public var hosts: [String: [String]] = [:]
    public var useHosts = true

    /// Clash `dns.fallback-filter`.
    public struct FallbackFilterSection: Sendable, Equatable {
        /// Replace `nameserver` answers outside `geoipCode`. Clash default on.
        public var geoip = true
        public var geoipCode = "CN"
        public var ipcidr: [String] = []
        public var domain: [String] = []
        public var geosite: [String] = []
    }

    public init() {}

    public static func == (lhs: ClashDNSSection, rhs: ClashDNSSection) -> Bool {
        lhs.enable == rhs.enable
            && lhs.defaultNameservers == rhs.defaultNameservers
            && lhs.nameservers == rhs.nameservers
            && lhs.proxyServerNameservers == rhs.proxyServerNameservers
            && lhs.directNameservers == rhs.directNameservers
            && lhs.fakeIPFilter == rhs.fakeIPFilter
            && lhs.ipv6 == rhs.ipv6
            && lhs.fallback == rhs.fallback
            && lhs.fallbackFilter == rhs.fallbackFilter
            && lhs.hosts == rhs.hosts
            && lhs.useHosts == rhs.useHosts
            && lhs.nameserverPolicy.map(\.patterns) == rhs.nameserverPolicy.map(\.patterns)
            && lhs.nameserverPolicy.map(\.nameservers) == rhs.nameserverPolicy.map(\.nameservers)
    }

    /// The fallback filter needs the GeoIP database.
    public var usesGeoIP: Bool {
        enable && !fallback.isEmpty && fallbackFilter.geoip
    }

    /// Geosite categories the DNS section names (policy keys and filter).
    public var geositeTags: [String] {
        guard enable else { return [] }
        let fromPolicy = nameserverPolicy.flatMap(\.patterns).compactMap { pattern -> String? in
            guard pattern.lowercased().hasPrefix("geosite:") else { return nil }
            return String(pattern.dropFirst("geosite:".count)).lowercased()
        }
        return fromPolicy + fallbackFilter.geosite.map { $0.lowercased() }
    }

    /// Rule providers the DNS section names (`rule-set:name` policy keys).
    public var ruleSetNames: [String] {
        guard enable else { return [] }
        return nameserverPolicy.flatMap(\.patterns).compactMap { pattern in
            pattern.lowercased().hasPrefix("rule-set:") ? String(pattern.dropFirst("rule-set:".count)) : nil
        }
    }

    /// Extracts `dns:` from a Clash YAML document. Returns nil for sing-box
    /// JSON / Surge INI / missing section.
    public static func parse(from rawString: String) -> ClashDNSSection? {
        let trimmed = ConfigText.normalized(rawString)
        guard let first = trimmed.first, first != "{", first != "[" else { return nil }
        guard let root = try? YAMLParser.parse(trimmed) else { return nil }
        return parse(root: root)
    }

    static func parse(root: YAMLNode) -> ClashDNSSection? {
        let hosts = root.mapping?["hosts"]?.mapping ?? [:]
        guard let dns = root.mapping?["dns"] ?? (hosts.isEmpty ? nil : .mapping([:])) else { return nil }
        var section = ClashDNSSection()
        for (name, value) in hosts {
            let addresses = value.sequence?.compactMap(\.string) ?? value.string.map { [$0] } ?? []
            if !addresses.isEmpty { section.hosts[name] = addresses }
        }
        section.useHosts = dns.bool(for: "use-hosts", default: true)
        // YAML mappings carry no order: specific name patterns go before
        // categories (geosite / rule-set), then alphabetically.
        let policy = dns.mapping?["nameserver-policy"]?.mapping ?? [:]
        section.nameserverPolicy = policy.keys.sorted { lhs, rhs in
            let lhsCategory = lhs.contains(":"), rhsCategory = rhs.contains(":")
            return lhsCategory == rhsCategory ? lhs < rhs : !lhsCategory
        }.compactMap { key in
            guard let value = policy[key] else { return nil }
            let servers = value.sequence?.compactMap(\.string) ?? value.string.map {
                $0.split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) }
            } ?? []
            return (Self.policyPatterns(key), servers.filter { !$0.isEmpty })
        }
        if let filter = dns.mapping?["fallback-filter"] {
            section.fallbackFilter.geoip = filter.bool(for: "geoip", default: true)
            section.fallbackFilter.geoipCode = filter.string(for: "geoip-code") ?? "CN"
            section.fallbackFilter.ipcidr = strings(filter, "ipcidr")
            section.fallbackFilter.domain = strings(filter, "domain")
            section.fallbackFilter.geosite = strings(filter, "geosite")
        }
        section.enable = dns.bool(for: "enable", default: false)
        section.defaultNameservers = strings(dns, "default-nameserver")
        section.nameservers = strings(dns, "nameserver")
        section.proxyServerNameservers = strings(dns, "proxy-server-nameserver")
        section.directNameservers = strings(dns, "direct-nameserver")
        section.fallback = strings(dns, "fallback")
        section.fakeIPFilter = strings(dns, "fake-ip-filter")
        section.ipv6 = dns.bool(for: "ipv6", default: false)
        return section
    }

    /// `geosite:cn,private` names two categories (mihomo carries the prefix
    /// over); `+.a.com,+.b.com` two name patterns.
    static func policyPatterns(_ key: String) -> [String] {
        var prefix = ""
        return key.split(separator: ",").map { raw in
            let part = raw.trimmingCharacters(in: .whitespaces)
            if let colon = part.firstIndex(of: ":"),
               ["geosite", "rule-set"].contains(part[..<colon].lowercased()) {
                prefix = String(part[...colon])
                return part
            }
            return prefix + part
        }
    }

    /// Clash `fallback` upstreams (see `fallback-filter`).
    public var fallback: [String] = []

    /// DNS keys the profile sets that PrizmX does not honor, as import
    /// warnings (the DNS answers would differ from mihomo's).
    static func importWarnings(root: YAMLNode) -> [ConfigWarning] {
        guard let dns = root.mapping?["dns"], dns.bool(for: "enable", default: false) else { return [] }
        var warnings: [ConfigWarning] = []
        func warn(_ key: String, _ reason: String) {
            warnings.append(ConfigWarning(kind: .dns, text: key, reason: reason))
        }
        if let mode = dns.string(for: "enhanced-mode"), mode.lowercased() != "fake-ip" {
            warn("enhanced-mode", "\(mode) is not supported; TUN always answers with fake IPs")
        }
        if dns.mapping?["fake-ip-range"] != nil {
            warn("fake-ip-range", "ignored; fake IPs come from 198.18.0.0/16")
        }
        if let mode = dns.string(for: "fake-ip-filter-mode"), mode.lowercased() != "blacklist" {
            warn("fake-ip-filter-mode", "\(mode) is not supported; fake-ip-filter lists names that skip fake IPs")
        }
        if dns.bool(for: "respect-rules", default: false) {
            warn("respect-rules", "not supported; DNS queries do not go through the proxy rules")
        }
        if dns.mapping?["use-system-hosts"] != nil, !dns.bool(for: "use-system-hosts", default: true) {
            warn("use-system-hosts", "ignored; /etc/hosts always applies")
        }
        let keys = ["default-nameserver", "nameserver", "fallback", "proxy-server-nameserver", "direct-nameserver"]
        for key in keys {
            for server in strings(dns, key) where NameserverEndpoint.parse(server) == nil && !Self.isLoopbackListener(server) {
                warn(key, "\(Self.redacted(server)) skipped: only plain UDP and DoH (https://) upstreams are supported")
            }
        }
        for (pattern, value) in dns.mapping?["nameserver-policy"]?.mapping ?? [:] {
            let servers = value.sequence?.compactMap(\.string) ?? value.string.map { [$0] } ?? []
            for server in servers where NameserverEndpoint.parse(server) == nil {
                warn("nameserver-policy \(pattern)", "\(Self.redacted(server)) skipped: only plain UDP and DoH upstreams are supported")
            }
        }
        return warnings
    }

    /// Clash's own listener (`127.0.0.1:1053`), dropped on purpose.
    private static func isLoopbackListener(_ server: String) -> Bool {
        let host = server.replacingOccurrences(of: "udp://", with: "").split(separator: ":").first.map(String.init) ?? ""
        return host.hasPrefix("127.") || host == "localhost"
    }

    /// Scheme and host only: DoH paths often carry an access token.
    private static func redacted(_ server: String) -> String {
        guard let url = URL(string: server), let scheme = url.scheme, let host = url.host else { return server }
        return "\(scheme)://\(host)"
    }

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

/// Matchers the DNS section borrows from the rule engine.
public struct DNSMatchers: Sendable {
    public var geoIP: GeoIPMatcher?
    public var geosite: GeositeMatcher?
    /// Rule providers named by `rule-set:` policy keys.
    public var ruleSets: [String: RuleSet]

    public init(geoIP: GeoIPMatcher? = nil, geosite: GeositeMatcher? = nil, ruleSets: [String: RuleSet] = [:]) {
        self.geoIP = geoIP
        self.geosite = geosite
        self.ruleSets = ruleSets
    }

    public static let none = DNSMatchers()

    /// Names covered by Clash domain patterns, `geosite:` and `rule-set:`.
    func domains(_ patterns: [String], label: String) -> DomainPredicate {
        var plain: [String] = []
        var tags: [String] = []
        var sets: [RuleSet] = []
        for pattern in patterns {
            let lower = pattern.lowercased()
            if lower.hasPrefix("geosite:") {
                tags.append(String(lower.dropFirst("geosite:".count)))
            } else if lower.hasPrefix("rule-set:") {
                if let set = ruleSets[String(pattern.dropFirst("rule-set:".count))] { sets.append(set) }
            } else {
                plain.append(lower)
            }
        }
        let geosite = self.geosite
        let (names, categories, providers) = (plain, tags, sets)
        return DomainPredicate(label) { domain in
            if !names.isEmpty, FakeIPFilter.matches(domain, patterns: names) { return true }
            if let geosite, categories.contains(where: { geosite.match(domain: domain, group: $0) }) { return true }
            return providers.contains { $0.behavior == .domain && $0.contains(domain: domain) }
        }
    }
}

extension DNSSettings {
    /// Clash semantics:
    /// - `default-nameserver` → bootstrap (plain IPs; also resolves DoH hosts)
    /// - `proxy-server-nameserver` pointing at Clash's own listener
    ///   (`udp://127.0.0.1:<listen>`) collapses to `nameservers`
    /// - `direct-nameserver` empty → the machine's effective resolver
    ///   (captured before FakeDNS is installed)
    ///
    /// `overrideDNS` false (default) lets the profile's nameservers alone
    /// resolve node hostnames when `dns.enable` is on; true restores
    /// PrizmX's merged resolvers.
    public static func fromClash(
        section: ClashDNSSection?,
        systemDNS: [String],
        overrideDNS: Bool = false,
        matchers: DNSMatchers = .none
    ) -> DNSSettings {
        let system = systemDNS.compactMap { NameserverEndpoint.udp(ip: $0) }
        let bootstrap = (section?.defaultNameservers ?? []).compactMap(NameserverEndpoint.parse)
        let general = (section?.nameservers ?? []).compactMap(NameserverEndpoint.parse)
        // Loopback (Clash's own DNS listener) is dropped by `parse` via the
        // IP-literal rule, leaving an empty list → role falls back to
        // `nameservers`, matching how Clash resolves node domains internally.
        let proxy = (section?.proxyServerNameservers ?? []).compactMap(NameserverEndpoint.parse)
        let direct = (section?.directNameservers ?? []).compactMap(NameserverEndpoint.parse)
        let fallback = ["223.5.5.5", "119.29.29.29"].compactMap { NameserverEndpoint.udp(ip: $0) }
        let enabled = section?.enable ?? false
        let policies: [NameserverPolicy] = enabled ? (section?.nameserverPolicy ?? []).compactMap { entry in
            let servers = entry.nameservers.compactMap(NameserverEndpoint.parse)
            guard !servers.isEmpty else { return nil }
            let label = entry.patterns.joined(separator: ",")
            return NameserverPolicy(domains: matchers.domains(entry.patterns, label: label), nameservers: servers)
        } : []
        var fallbackFilter = FallbackFilter()
        if let filter = section?.fallbackFilter, enabled {
            let names = filter.domain + filter.geosite.map { "geosite:\($0)" }
            if !names.isEmpty {
                fallbackFilter.domains = matchers.domains(names, label: "fallback-filter")
            }
            let blocked = filter.ipcidr.isEmpty ? nil : RuleSet(name: "fallback-filter", cidrs: filter.ipcidr)
            let geoIP = filter.geoip ? matchers.geoIP : nil
            let code = filter.geoipCode.uppercased()
            if blocked != nil || geoIP != nil {
                fallbackFilter.rejectsAddress = AddressPredicate("fallback-filter") { address in
                    if let blocked, blocked.contains(ipv4: address) { return true }
                    if let geoIP { return !geoIP.matches(ipv4: address, code: code) }
                    return false
                }
            }
        }
        let hosts = (section?.useHosts ?? true) ? ProfileHosts(section?.hosts ?? [:]) : .empty
        return DNSSettings(
            defaultNameservers: bootstrap.isEmpty ? (system.isEmpty ? fallback : system) : bootstrap,
            nameservers: general,
            proxyServerNameservers: proxy,
            directNameservers: direct,
            systemNameservers: system,
            fakeIPFilter: (section?.fakeIPFilter ?? []) + ["*.lan", "*.local", "*.localhost"],
            ipv6: section?.ipv6 ?? false,
            cacheTTL: 60,
            nodeDNSFromProfile: !overrideDNS && enabled,
            appDNSFromProfile: enabled,
            nameserverPolicies: policies,
            fallbackNameservers: enabled ? (section?.fallback ?? []).compactMap(NameserverEndpoint.parse) : [],
            fallbackFilter: fallbackFilter,
            hosts: hosts
        )
    }
}
