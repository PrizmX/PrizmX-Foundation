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
    /// `DOMAIN-REGEX`: regular expression on the domain.
    case domainRegex(String)
    /// `DOMAIN-WILDCARD`: `*` / `?` glob on the domain.
    case domainWildcard(String)
    /// `DST-PORT` / `SRC-PORT` / `IN-PORT`: `443`, `8000-9000`, `80/443`.
    case dstPort(String)
    case srcPort(String)
    case inPort(String)
    /// `SRC-IP-CIDR`: the client's address.
    case srcIPCIDR(String)
    /// `SRC-GEOIP`: the country of the client's address.
    case srcGeoIP(code: String)
    /// `IP-ASN` / `SRC-IP-ASN`: the autonomous system number (`13335`) of
    /// the destination or client address. Evaluated when an `ASNMatcher`
    /// is supplied.
    case ipASN(String)
    case srcIPASN(String)
    /// `IP-SUFFIX` / `SRC-IP-SUFFIX`: `8.8.8.8/24` matches addresses that
    /// end in the same 24 bits.
    case ipSuffix(String)
    case srcIPSuffix(String)
    /// `NETWORK`: `tcp` or `udp`.
    case network(String)
    /// `PROCESS-NAME` / `PROCESS-PATH` and their `-REGEX` forms.
    case processName(String)
    case processPath(String)
    case processNameRegex(String)
    case processPathRegex(String)
}

/// Failure to compile a user-facing `RuleType` into a matcher.
public enum RuleCompileError: Error, Equatable, Sendable {
    /// The `ipCIDR` payload is not a valid IP literal or CIDR block.
    case invalidCIDR(String)
    /// A port, network or regular expression payload that does not parse.
    case invalidPayload(String)
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
        case domainRegex(RulePattern)
        case domainWildcard(RulePattern)
        case dstPort(PortSet)
        case srcPort(PortSet)
        case inPort(PortSet)
        case srcIPv4CIDR(IPv4Address, prefixLength: UInt8)
        case srcIPv6CIDR(IPv6Address, prefixLength: UInt8)
        /// GeoIP country code of the client's address.
        case srcGeoIP(code: String)
        /// Autonomous system number. Evaluated when `Router` is given an `ASNMatcher`.
        case ipASN(UInt32)
        case srcIPASN(UInt32)
        case ipSuffix(IPSuffix)
        case srcIPSuffix(IPSuffix)
        case network(RouteContext.Network)
        /// Executable name, case-insensitive (`Telegram`, `curl`).
        case processName(String)
        /// Full executable path.
        case processPath(String)
        case processNameRegex(RulePattern)
        case processPathRegex(RulePattern)
        /// `AND,((…),(…))`: every condition holds.
        case and([RuleCondition])
        /// `OR,((…),(…))`: any condition holds.
        case or([RuleCondition])
        /// `NOT,((…))`.
        indirect case not(RuleCondition)
        /// `RULE-SET`: a rule provider's payload.
        case ruleSet(RuleSet)
    }

    /// The host matcher.
    public let matcher: HostMatcher
    /// Applies to this port only; `nil` means all ports.
    public let port: UInt16?
    /// The policy applied when matched.
    public let policy: Policy
    /// Clash `no-resolve`: skip IP lookup for GEOIP / IP-CIDR.
    public let noResolve: Bool

    public init(
        _ matcher: HostMatcher,
        port: UInt16? = nil,
        policy: Policy,
        noResolve: Bool = false
    ) {
        self.matcher = matcher
        self.port = port
        self.policy = policy
        self.noResolve = noResolve
    }

    /// Builds a rule from a `RuleType` (parses CIDR strings).
    ///
    /// Throws `RuleCompileError.invalidCIDR` for malformed `ipCIDR` payloads
    /// instead of trapping: rule text is user/config-controlled input.
    public init(type: RuleType, port: UInt16? = nil, policy: Policy, noResolve: Bool = false) throws {
        self.init(try Self.compile(type), port: port, policy: policy, noResolve: noResolve)
    }

    public var inspectorLabel: String {
        "\(displayType),\(displayPayload),\(displayPolicy)"
    }

    public var displayType: String { matcher.typeName }

    public var displayPayload: String { matcher.payloadText }

    public var displayPolicy: String {
        switch policy {
        case .direct: "DIRECT"
        case .reject: "REJECT"
        case .proxy(let group): group
        }
    }

    public static func compile(_ type: RuleType) throws -> HostMatcher {
        func ports(_ text: String) throws -> PortSet {
            guard let set = PortSet(parsing: text) else { throw RuleCompileError.invalidPayload(text) }
            return set
        }
        func regex(_ text: String, caseInsensitive: Bool = false) throws -> RulePattern {
            guard let pattern = RulePattern(text, caseInsensitive: caseInsensitive) else {
                throw RuleCompileError.invalidPayload(text)
            }
            return pattern
        }
        func asn(_ text: String) throws -> UInt32 {
            guard let number = UInt32(text.trimmingCharacters(in: .whitespaces)) else {
                throw RuleCompileError.invalidPayload(text)
            }
            return number
        }
        switch type {
        case .domainRegex(let pattern):
            return .domainRegex(try regex(pattern, caseInsensitive: true))
        case .domainWildcard(let glob):
            guard let pattern = RulePattern(wildcard: glob, crossesLabels: true) else {
                throw RuleCompileError.invalidPayload(glob)
            }
            return .domainWildcard(pattern)
        case .dstPort(let text):
            return .dstPort(try ports(text))
        case .srcPort(let text):
            return .srcPort(try ports(text))
        case .inPort(let text):
            return .inPort(try ports(text))
        case .srcIPCIDR(let text):
            switch try parseCIDR(text) {
            case .ipv4(let address): return .srcIPv4CIDR(address, prefixLength: 32)
            case .ipv4CIDR(let network, let prefix): return .srcIPv4CIDR(network, prefixLength: prefix)
            case .ipv6(let address): return .srcIPv6CIDR(address, prefixLength: 128)
            case .ipv6CIDR(let network, let prefix): return .srcIPv6CIDR(network, prefixLength: prefix)
            default: throw RuleCompileError.invalidCIDR(text)
            }
        case .srcGeoIP(code: let code):
            return .srcGeoIP(code: code.uppercased())
        case .ipASN(let text):
            return .ipASN(try asn(text))
        case .srcIPASN(let text):
            return .srcIPASN(try asn(text))
        case .ipSuffix(let text):
            return .ipSuffix(try parseSuffix(text))
        case .srcIPSuffix(let text):
            return .srcIPSuffix(try parseSuffix(text))
        case .network(let text):
            guard let network = RouteContext.Network(rawValue: text.lowercased()) else {
                throw RuleCompileError.invalidPayload(text)
            }
            return .network(network)
        case .processName(let name):
            return .processName(name)
        case .processPath(let path):
            return .processPath(path)
        case .processNameRegex(let pattern):
            return .processNameRegex(try regex(pattern, caseInsensitive: true))
        case .processPathRegex(let pattern):
            return .processPathRegex(try regex(pattern))
        case .domain(let domain):
            return .domain(domain.lowercased())
        case .domainSuffix(let suffix):
            return .domainSuffix(Self.normalizeSuffix(suffix))
        case .domainKeyword(let keyword):
            return .domainKeyword(keyword.lowercased())
        case .matchAll:
            return .matchAll
        case .ipCIDR(let text):
            return try parseCIDR(text)
        case .geoIP(code: let code):
            return .geoIP(code: code.uppercased())
        case .geosite(tag: let tag):
            return .geosite(tag: tag.lowercased())
        }
    }

    private static func parseCIDR(_ text: String) throws -> HostMatcher {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmed.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let host = String(parts[0])
        // A present-but-malformed prefix (`/`, `/abc`, `/-1`) is an error, not a host route.
        var prefix: UInt8?
        if parts.count == 2 {
            let digits = parts[1]
            guard !digits.isEmpty, digits.allSatisfy({ $0 >= "0" && $0 <= "9" }),
                  let parsed = UInt8(digits) else {
                throw RuleCompileError.invalidCIDR(text)
            }
            prefix = parsed
        }

        if let v4 = IPv4Address(parsing: host) {
            let length = prefix ?? 32
            guard length <= 32 else { throw RuleCompileError.invalidCIDR(text) }
            return length == 32 ? .ipv4(v4) : .ipv4CIDR(v4, prefixLength: length)
        }
        if let v6 = IPv6Address(parsing: host) {
            let length = prefix ?? 128
            guard length <= 128 else { throw RuleCompileError.invalidCIDR(text) }
            return length == 128 ? .ipv6(v6) : .ipv6CIDR(v6, prefixLength: length)
        }
        throw RuleCompileError.invalidCIDR(text)
    }

    /// `IP-SUFFIX` payloads are written like CIDRs, host bits kept.
    private static func parseSuffix(_ text: String) throws -> IPSuffix {
        switch try parseCIDR(text) {
        case .ipv4(let address): return IPSuffix(address: .ipv4(address), bits: 32)
        case .ipv4CIDR(let address, let bits): return IPSuffix(address: .ipv4(address), bits: bits)
        case .ipv6(let address): return IPSuffix(address: .ipv6(address), bits: 128)
        case .ipv6CIDR(let address, let bits): return IPSuffix(address: .ipv6(address), bits: bits)
        default: throw RuleCompileError.invalidCIDR(text)
        }
    }

    fileprivate static func normalizeSuffix(_ suffix: String) -> String {
        var key = suffix.lowercased()
        if key.hasPrefix("*.") { key.removeFirst(2) }
        while key.hasPrefix(".") { key.removeFirst() }
        while key.hasSuffix(".") { key.removeLast() }
        return key
    }
}

extension RouteRule.HostMatcher {
    /// Clash rule type as written in a profile.
    public var typeName: String {
        switch self {
        case .domain: "DOMAIN"
        case .domainSuffix: "DOMAIN-SUFFIX"
        case .domainKeyword: "DOMAIN-KEYWORD"
        case .ipv4, .ipv4CIDR: "IP-CIDR"
        case .ipv6, .ipv6CIDR: "IP-CIDR6"
        case .geoIP: "GEOIP"
        case .geosite: "GEOSITE"
        case .matchAll: "MATCH"
        case .domainRegex: "DOMAIN-REGEX"
        case .domainWildcard: "DOMAIN-WILDCARD"
        case .dstPort: "DST-PORT"
        case .srcPort: "SRC-PORT"
        case .inPort: "IN-PORT"
        case .srcIPv4CIDR, .srcIPv6CIDR: "SRC-IP-CIDR"
        case .srcGeoIP: "SRC-GEOIP"
        case .ipASN: "IP-ASN"
        case .srcIPASN: "SRC-IP-ASN"
        case .ipSuffix: "IP-SUFFIX"
        case .srcIPSuffix: "SRC-IP-SUFFIX"
        case .network: "NETWORK"
        case .processName: "PROCESS-NAME"
        case .processPath: "PROCESS-PATH"
        case .processNameRegex: "PROCESS-NAME-REGEX"
        case .processPathRegex: "PROCESS-PATH-REGEX"
        case .and: "AND"
        case .or: "OR"
        case .not: "NOT"
        case .ruleSet: "RULE-SET"
        }
    }

    public var payloadText: String {
        switch self {
        case .domain(let value), .domainSuffix(let value), .domainKeyword(let value):
            return value
        case .ipv4(let address):
            return address.description
        case .ipv4CIDR(let address, let prefix), .srcIPv4CIDR(let address, let prefix):
            return "\(address)/\(prefix)"
        case .ipv6(let address):
            return address.description
        case .ipv6CIDR(let address, let prefix), .srcIPv6CIDR(let address, let prefix):
            return "\(address)/\(prefix)"
        case .geoIP(let code), .srcGeoIP(let code):
            return code
        case .ipASN(let number), .srcIPASN(let number):
            return String(number)
        case .ipSuffix(let suffix), .srcIPSuffix(let suffix):
            return suffix.description
        case .geosite(let tag):
            return tag
        case .matchAll:
            return "*"
        case .domainRegex(let pattern), .domainWildcard(let pattern),
             .processNameRegex(let pattern), .processPathRegex(let pattern):
            return pattern.pattern
        case .dstPort(let ports), .srcPort(let ports), .inPort(let ports):
            return ports.description
        case .network(let network):
            return network.rawValue.uppercased()
        case .processName(let value), .processPath(let value):
            return value
        case .and(let conditions), .or(let conditions):
            return "(" + conditions.map { "(\($0.matcher.typeName),\($0.matcher.payloadText))" }.joined(separator: ",") + ")"
        case .not(let condition):
            return "((\(condition.matcher.typeName),\(condition.matcher.payloadText)))"
        case .ruleSet(let set):
            return set.name
        }
    }

    /// This matcher and every one nested in it (AND / OR / NOT, classical
    /// rule sets), for callers that look for GEOIP / GEOSITE anywhere.
    public var flattened: [RouteRule.HostMatcher] {
        switch self {
        case .and(let conditions), .or(let conditions):
            return [self] + conditions.flatMap(\.matcher.flattened)
        case .not(let condition):
            return [self] + condition.matcher.flattened
        case .ruleSet(let set):
            return [self] + set.conditions.flatMap(\.matcher.flattened)
        default:
            return [self]
        }
    }

    /// A domain destination needs a real address before this can match.
    func needsResolution(noResolve: Bool) -> Bool {
        if noResolve { return false }
        switch self {
        case .geoIP, .ipv4, .ipv4CIDR, .ipv6, .ipv6CIDR, .ipASN, .ipSuffix:
            return true
        case .and(let conditions), .or(let conditions):
            return conditions.contains { $0.matcher.needsResolution(noResolve: $0.noResolve) }
        case .not(let condition):
            return condition.matcher.needsResolution(noResolve: condition.noResolve)
        case .ruleSet(let set):
            switch set.behavior {
            case .domain: return false
            case .ipcidr: return true
            case .classical: return set.conditions.contains { $0.matcher.needsResolution(noResolve: $0.noResolve) }
            }
        default:
            return false
        }
    }
}

/// Real addresses for a domain destination, looked up at most once per match.
public struct ResolvedAddresses: Sendable, Equatable {
    public var ipv4: IPv4Address?
    public var ipv6: IPv6Address?

    public init(ipv4: IPv4Address? = nil, ipv6: IPv6Address? = nil) {
        self.ipv4 = ipv4
        self.ipv6 = ipv6
    }
}

/// Clash / sing-box style routing: rules are tried **in list order**, first
/// match wins. Port-scoped rules that do not match the port are skipped.
///
/// Runs of consecutive DOMAIN / DOMAIN-SUFFIX rules, and of IP-CIDR /
/// IP-CIDR6 rules, are indexed: a name is looked up once per label and an
/// address once per prefix length instead of compared with every rule, and
/// the earliest matching rule of the run still wins.
public final class Router: Sendable {

    public let rules: [RouteRule]
    public let defaultPolicy: Policy
    /// True when any rule needs a real IP (GEOIP / CIDR) unless `no-resolve`.
    public let needsIPResolution: Bool
    /// True when any rule reads the connection's process.
    public let needsProcess: Bool
    private let geoIP: GeoIPMatcher?
    private let geosite: GeositeMatcher?
    private let asn: ASNMatcher?
    /// `rules` with host payloads normalized once (not per match).
    private let compiled: [CompiledRule]
    /// Index of the run starting at each rule (nil elsewhere).
    private let runs: [Run?]

    private struct CompiledRule: Sendable {
        var rule: RouteRule
        var matcher: RouteRule.HostMatcher
        /// `"." + suffix` for `.domainSuffix`, precomputed.
        var dottedSuffix: String
        /// Domain destinations need a DNS answer before this rule can match.
        var needsResolution: Bool
    }

    /// An indexed stretch of rules.
    private enum Run: Sendable {
        case domains(DomainRun)
        case addresses(AddressRun)

        /// One past the run's last rule.
        var end: Int {
            switch self {
            case .domains(let run): run.end
            case .addresses(let run): run.end
            }
        }

        /// Some rule of the run matches a domain destination by its lookup.
        var needsResolution: Bool {
            guard case .addresses(let run) = self else { return false }
            return run.needsResolution
        }

        /// The earliest rule of the run that matches.
        func firstMatch(_ endpoint: Endpoint, _ destination: Destination) -> Int? {
            switch self {
            case .domains(let run):
                guard case .domain(let host) = endpoint.host else { return nil }
                return run.firstMatch(host)
            case .addresses(let run):
                return run.firstMatch(destination)
            }
        }
    }

    private enum RunKind {
        case domains
        case addresses
    }

    /// Consecutive DOMAIN / DOMAIN-SUFFIX rules `start..<end`, keyed to the
    /// earliest rule index for each name.
    private struct DomainRun: Sendable {
        var end: Int
        var exact: [String: Int]
        var suffix: [String: Int]

        func firstMatch(_ host: String) -> Int? {
            var best = exact[host]
            if let index = suffix[host] { best = min(best ?? index, index) }
            var rest = Substring(host)
            while let dot = rest.firstIndex(of: ".") {
                rest = rest[rest.index(after: dot)...]
                guard !rest.isEmpty else { break }
                if let index = suffix[String(rest)] { best = min(best ?? index, index) }
            }
            return best
        }
    }

    /// Consecutive IP-CIDR / IP-CIDR6 rules `start..<end`, keyed by prefix
    /// length and network to the earliest rule index.
    private struct AddressRun: Sendable {
        /// The earliest rule for a network, and the earliest one without
        /// `no-resolve`: the only kind a looked-up address can match.
        struct Hit: Sendable {
            var first: Int
            var resolvable: Int?
        }

        var end: Int
        var ipv4: [UInt8: [UInt32: Hit]] = [:]
        var ipv6: [UInt8: [RuleSet.IPv6Key: Hit]] = [:]
        /// Some rule lacks `no-resolve`.
        var needsResolution = false

        func firstMatch(_ destination: Destination) -> Int? {
            var best: Int?
            func consider(_ hit: Hit?) {
                guard let hit, let index = destination.dialed ? hit.first : hit.resolvable else { return }
                best = min(best ?? index, index)
            }
            if let address = destination.ipv4 {
                for (prefix, networks) in ipv4 {
                    consider(networks[address.rawValue & RuleSet.mask4(prefix)])
                }
            }
            if let address = destination.ipv6 {
                for (prefix, networks) in ipv6 {
                    consider(networks[RuleSet.masked6(address, prefix)])
                }
            }
            return best
        }
    }

    /// The addresses IP rules compare for a destination.
    private struct Destination {
        var ipv4: IPv4Address?
        var ipv6: IPv6Address?
        /// The destination's own address (an IP endpoint, or the one a
        /// sniffed client dialed), which `no-resolve` rules match too.
        /// Otherwise the addresses come from a lookup of the name.
        var dialed: Bool
    }

    /// Shorter runs are cheaper to walk than to look up.
    private static let minimumRunLength = 8
    /// An address is looked up once per prefix length in the run, so IP
    /// runs pay off later than domain runs.
    private static let minimumAddressRunLength = 32

    public init(
        rules: [RouteRule] = [],
        default defaultPolicy: Policy = .direct,
        geoIP: GeoIPMatcher? = nil,
        geosite: GeositeMatcher? = nil,
        asn: ASNMatcher? = nil
    ) {
        self.rules = rules
        self.defaultPolicy = defaultPolicy
        self.geoIP = geoIP
        self.geosite = geosite
        self.asn = asn
        let compiled = rules.map(Self.compile)
        self.compiled = compiled
        self.runs = Self.indexRuns(compiled)
        self.needsIPResolution = compiled.contains(where: \.needsResolution)
        self.needsProcess = rules.contains { rule in
            rule.matcher.flattened.contains { matcher in
                switch matcher {
                case .processName, .processPath, .processNameRegex, .processPathRegex: true
                default: false
                }
            }
        }
    }

    private static func compile(_ rule: RouteRule) -> CompiledRule {
        var matcher = rule.matcher
        var dotted = ""
        switch rule.matcher {
        case .domain(let value):
            matcher = .domain(value.lowercased())
        case .domainSuffix(let value):
            let key = RouteRule.normalizeSuffix(value)
            matcher = .domainSuffix(key)
            dotted = "." + key
        case .domainKeyword(let value):
            matcher = .domainKeyword(value.lowercased())
        case .geoIP(let code):
            matcher = .geoIP(code: code.uppercased())
        case .srcGeoIP(let code):
            matcher = .srcGeoIP(code: code.uppercased())
        default:
            break
        }
        return CompiledRule(
            rule: rule,
            matcher: matcher,
            dottedSuffix: dotted,
            needsResolution: matcher.needsResolution(noResolve: rule.noResolve)
        )
    }

    private static func indexRuns(_ compiled: [CompiledRule]) -> [Run?] {
        var runs = [Run?](repeating: nil, count: compiled.count)
        var start = 0
        while start < compiled.count {
            guard let kind = runKind(compiled[start]) else {
                start += 1
                continue
            }
            var end = start
            while end < compiled.count, runKind(compiled[end]) == kind { end += 1 }
            switch kind {
            case .domains where end - start >= minimumRunLength:
                runs[start] = .domains(domainRun(compiled, start..<end))
            case .addresses where end - start >= minimumAddressRunLength:
                runs[start] = .addresses(addressRun(compiled, start..<end))
            default:
                break
            }
            start = end
        }
        return runs
    }

    /// The index a rule can join. Port-scoped rules join none.
    private static func runKind(_ entry: CompiledRule) -> RunKind? {
        guard entry.rule.port == nil else { return nil }
        switch entry.matcher {
        case .domain, .domainSuffix:
            return .domains
        case .ipv4, .ipv6:
            return .addresses
        case .ipv4CIDR(_, let prefix) where prefix <= 32:
            return .addresses
        case .ipv6CIDR(_, let prefix) where prefix <= 128:
            return .addresses
        default:
            return nil
        }
    }

    private static func domainRun(_ compiled: [CompiledRule], _ range: Range<Int>) -> DomainRun {
        var run = DomainRun(end: range.upperBound, exact: [:], suffix: [:])
        for index in range {
            switch compiled[index].matcher {
            case .domain(let name):
                if run.exact[name] == nil { run.exact[name] = index }
            case .domainSuffix(let key) where !key.isEmpty:
                if run.suffix[key] == nil { run.suffix[key] = index }
            default:
                break
            }
        }
        return run
    }

    private static func addressRun(_ compiled: [CompiledRule], _ range: Range<Int>) -> AddressRun {
        var run = AddressRun(end: range.upperBound)
        for index in range {
            let resolvable = !compiled[index].rule.noResolve
            run.needsResolution = run.needsResolution || resolvable
            func record(_ hit: inout AddressRun.Hit?) {
                if hit == nil { hit = AddressRun.Hit(first: index, resolvable: nil) }
                if resolvable, hit?.resolvable == nil { hit?.resolvable = index }
            }
            switch compiled[index].matcher {
            case .ipv4(let address):
                record(&run.ipv4[32, default: [:]][address.rawValue])
            case .ipv4CIDR(let network, let prefix):
                record(&run.ipv4[prefix, default: [:]][network.rawValue & RuleSet.mask4(prefix)])
            case .ipv6(let address):
                record(&run.ipv6[128, default: [:]][RuleSet.masked6(address, 128)])
            case .ipv6CIDR(let network, let prefix):
                record(&run.ipv6[prefix, default: [:]][RuleSet.masked6(network, prefix)])
            default:
                break
            }
        }
        return run
    }

    private static func destination(
        of endpoint: Endpoint,
        resolvedIPv4: IPv4Address?,
        resolvedIPv6: IPv6Address?,
        context: RouteContext
    ) -> Destination {
        switch (endpoint.host, context.destinationAddress) {
        case (.ipv4(let address), _), (.domain, .ipv4(let address)?):
            return Destination(ipv4: address, ipv6: nil, dialed: true)
        case (.ipv6(let address), _), (.domain, .ipv6(let address)?):
            return Destination(ipv4: nil, ipv6: address, dialed: true)
        default:
            return Destination(ipv4: resolvedIPv4, ipv6: resolvedIPv6, dialed: false)
        }
    }

    /// Primary API: policy for a destination endpoint.
    public func match(
        endpoint: Endpoint,
        resolvedIPv4: IPv4Address? = nil,
        resolvedIPv6: IPv6Address? = nil,
        context: RouteContext = .none
    ) -> Policy {
        matchResult(endpoint: endpoint, resolvedIPv4: resolvedIPv4, resolvedIPv6: resolvedIPv6, context: context).policy
    }

    public func matchResult(
        endpoint: Endpoint,
        resolvedIPv4: IPv4Address? = nil,
        resolvedIPv6: IPv6Address? = nil,
        context: RouteContext = .none
    ) -> (policy: Policy, rule: RouteRule?) {
        let destination = Self.destination(
            of: endpoint,
            resolvedIPv4: resolvedIPv4,
            resolvedIPv6: resolvedIPv6,
            context: context
        )
        var index = 0
        while index < compiled.count {
            if let run = runs[index] {
                if let hit = run.firstMatch(endpoint, destination) {
                    return (compiled[hit].rule.policy, compiled[hit].rule)
                }
                index = run.end
                continue
            }
            let entry = compiled[index]
            if matches(entry, endpoint: endpoint, destination: destination, context: context) == true {
                return (entry.rule.policy, entry.rule)
            }
            index += 1
        }
        return (defaultPolicy, nil)
    }

    /// Lazy variant: rules run in order and `resolve` is called at most once,
    /// only when a domain destination first reaches a rule that needs a real
    /// IP (GEOIP / IP-CIDR without `no-resolve`). A domain rule that matches
    /// earlier never triggers a lookup, and neither does a sniffed name
    /// whose dialed address is known. Returns the addresses if one happened.
    public func matchResult(
        endpoint: Endpoint,
        context: RouteContext = .none,
        resolve: () async -> ResolvedAddresses
    ) async -> (policy: Policy, rule: RouteRule?, resolved: ResolvedAddresses?) {
        var resolved: ResolvedAddresses?
        var destination = Self.destination(of: endpoint, resolvedIPv4: nil, resolvedIPv6: nil, context: context)
        let canResolve = !destination.dialed
        func lookUp() async {
            guard canResolve, resolved == nil else { return }
            let addresses = await resolve()
            resolved = addresses
            destination = Self.destination(
                of: endpoint,
                resolvedIPv4: addresses.ipv4,
                resolvedIPv6: addresses.ipv6,
                context: context
            )
        }
        var index = 0
        while index < compiled.count {
            if let run = runs[index] {
                if run.needsResolution { await lookUp() }
                if let hit = run.firstMatch(endpoint, destination) {
                    return (compiled[hit].rule.policy, compiled[hit].rule, resolved)
                }
                index = run.end
                continue
            }
            let entry = compiled[index]
            index += 1
            if let port = entry.rule.port, port != endpoint.port { continue }
            if entry.needsResolution { await lookUp() }
            if matches(entry, endpoint: endpoint, destination: destination, context: context) == true {
                return (entry.rule.policy, entry.rule, resolved)
            }
        }
        return (defaultPolicy, nil, resolved)
    }

    /// Non-resolving variant for FakeDNS time, when only the name is known:
    /// a domain destination that reaches a rule needing a real IP, or a rule
    /// needing the connection (process, network, ports), returns `nil`,
    /// since the outcome depends on what the dial will know.
    /// `resolvedIPv4` / `resolvedIPv6`: addresses already known without a
    /// lookup (a hosts entry), so IP rules can decide.
    public func matchWithoutResolving(
        endpoint: Endpoint,
        resolvedIPv4: IPv4Address? = nil,
        resolvedIPv6: IPv6Address? = nil
    ) -> (policy: Policy, rule: RouteRule?)? {
        let haveAddresses = resolvedIPv4 != nil || resolvedIPv6 != nil
        let isDomain: Bool
        if case .domain = endpoint.host { isDomain = true } else { isDomain = false }
        let destination = Self.destination(
            of: endpoint,
            resolvedIPv4: resolvedIPv4,
            resolvedIPv6: resolvedIPv6,
            context: .nameOnly
        )
        var index = 0
        while index < compiled.count {
            if let run = runs[index] {
                if isDomain, run.needsResolution, !haveAddresses { return nil }
                if let hit = run.firstMatch(endpoint, destination) {
                    return (compiled[hit].rule.policy, compiled[hit].rule)
                }
                index = run.end
                continue
            }
            let entry = compiled[index]
            index += 1
            if let port = entry.rule.port, port != endpoint.port { continue }
            if isDomain, entry.needsResolution, !haveAddresses { return nil }
            switch matches(entry, endpoint: endpoint, destination: destination, context: .nameOnly) {
            case true?: return (entry.rule.policy, entry.rule)
            case nil: return nil
            case false?: continue
            }
        }
        return (defaultPolicy, nil)
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

    /// `nil`: the rule needs connection details `context` does not have.
    private func matches(
        _ entry: CompiledRule,
        endpoint: Endpoint,
        destination: Destination,
        context: RouteContext
    ) -> Bool? {
        let rule = entry.rule
        if let port = rule.port, port != endpoint.port { return false }
        switch entry.matcher {
        case .domainSuffix(let key):
            guard case .domain(let host) = endpoint.host, !key.isEmpty else { return false }
            return host == key || host.hasSuffix(entry.dottedSuffix)
        default:
            return evaluate(
                entry.matcher,
                noResolve: rule.noResolve,
                endpoint: endpoint,
                destination: destination,
                context: context
            )
        }
    }

    // swiftlint:disable:next cyclomatic_complexity function_body_length
    private func evaluate(
        _ matcher: RouteRule.HostMatcher,
        noResolve: Bool,
        endpoint: Endpoint,
        destination: Destination,
        context: RouteContext
    ) -> Bool? {
        func sub(_ condition: RuleCondition) -> Bool? {
            evaluate(
                condition.matcher,
                noResolve: noResolve || condition.noResolve,
                endpoint: endpoint,
                destination: destination,
                context: context
            )
        }
        /// Context rules are undecided until the connection is known.
        func known<T>(_ value: T?) -> T?? {
            context.isComplete ? .some(value) : nil
        }
        /// `no-resolve` hides looked-up addresses only.
        let addressVisible = destination.dialed || !noResolve
        switch matcher {
        case .domain(let domain):
            guard case .domain(let host) = endpoint.host else { return false }
            return host == domain.lowercased()
        case .domainSuffix(let raw):
            guard case .domain(let host) = endpoint.host else { return false }
            let key = RouteRule.normalizeSuffix(raw)
            return !key.isEmpty && (host == key || host.hasSuffix("." + key))
        case .domainKeyword(let keyword):
            guard case .domain(let host) = endpoint.host else { return false }
            return host.contains(keyword.lowercased())
        case .domainRegex(let pattern), .domainWildcard(let pattern):
            guard case .domain(let host) = endpoint.host else { return false }
            return pattern.matches(host)
        case .ipv4(let address):
            return addressVisible && destination.ipv4 == address
        case .ipv4CIDR(let network, let prefixLength):
            guard addressVisible, let host = destination.ipv4 else { return false }
            return Self.ipv4(host, in: network, prefix: prefixLength)
        case .ipv6(let address):
            return addressVisible && destination.ipv6 == address
        case .ipv6CIDR(let network, let prefixLength):
            guard addressVisible, let host = destination.ipv6 else { return false }
            return Self.ipv6(host, in: network, prefix: prefixLength)
        case .geoIP(code: let code):
            guard addressVisible, let geoIP else { return false }
            if let address = destination.ipv4, geoIP.matches(ipv4: address, code: code) { return true }
            if let address = destination.ipv6, geoIP.matches(ipv6: address, code: code) { return true }
            return false
        case .ipASN(let number):
            guard addressVisible, let asn else { return false }
            if let address = destination.ipv4, asn.lookup(ipv4: address) == number { return true }
            if let address = destination.ipv6, asn.lookup(ipv6: address) == number { return true }
            return false
        case .ipSuffix(let suffix):
            guard addressVisible else { return false }
            if let address = destination.ipv4, suffix.matches(.ipv4(address)) { return true }
            if let address = destination.ipv6, suffix.matches(.ipv6(address)) { return true }
            return false
        case .geosite(tag: let tag):
            guard case .domain(let host) = endpoint.host, let geosite else { return false }
            return geosite.match(domain: host, group: tag)
        case .matchAll:
            return true
        case .dstPort(let ports):
            // FakeDNS sees no port yet.
            guard context.isComplete else { return nil }
            return ports.contains(endpoint.port)
        case .srcPort(let ports):
            guard let port = known(context.sourcePort) else { return nil }
            return port.map(ports.contains) ?? false
        case .inPort(let ports):
            guard let port = known(context.inboundPort) else { return nil }
            return port.map(ports.contains) ?? false
        case .srcIPv4CIDR(let network, let prefix):
            guard let source = known(context.sourceHost) else { return nil }
            guard case .ipv4(let address)? = source else { return false }
            return Self.ipv4(address, in: network, prefix: prefix)
        case .srcIPv6CIDR(let network, let prefix):
            guard let source = known(context.sourceHost) else { return nil }
            guard case .ipv6(let address)? = source else { return false }
            return Self.ipv6(address, in: network, prefix: prefix)
        case .srcGeoIP(code: let code):
            guard let source = known(context.sourceHost) else { return nil }
            switch source {
            case .ipv4(let address)?: return geoIP?.matches(ipv4: address, code: code) ?? false
            case .ipv6(let address)?: return geoIP?.matches(ipv6: address, code: code) ?? false
            default: return false
            }
        case .srcIPASN(let number):
            guard let source = known(context.sourceHost) else { return nil }
            switch source {
            case .ipv4(let address)?: return asn?.lookup(ipv4: address) == number
            case .ipv6(let address)?: return asn?.lookup(ipv6: address) == number
            default: return false
            }
        case .srcIPSuffix(let suffix):
            guard let source = known(context.sourceHost) else { return nil }
            return source.map(suffix.matches) ?? false
        case .network(let network):
            guard let actual = known(context.network) else { return nil }
            return actual == network
        case .processName(let name):
            guard let process = known(context.processName) else { return nil }
            if let process, process.caseInsensitiveCompare(name) == .orderedSame { return true }
            guard let path = context.processPath else { return false }
            return (path as NSString).lastPathComponent.caseInsensitiveCompare(name) == .orderedSame
        case .processPath(let path):
            guard let actual = known(context.processPath) else { return nil }
            return actual == path
        case .processNameRegex(let pattern):
            guard let process = known(context.processName) else { return nil }
            return process.map(pattern.matches) ?? false
        case .processPathRegex(let pattern):
            guard let path = known(context.processPath) else { return nil }
            return path.map(pattern.matches) ?? false
        case .and(let conditions):
            var undecided = false
            for condition in conditions {
                switch sub(condition) {
                case false?: return false
                case nil: undecided = true
                case true?: continue
                }
            }
            return undecided ? nil : true
        case .or(let conditions):
            var undecided = false
            for condition in conditions {
                switch sub(condition) {
                case true?: return true
                case nil: undecided = true
                case false?: continue
                }
            }
            return undecided ? nil : false
        case .not(let condition):
            return sub(condition).map { !$0 }
        case .ruleSet(let set):
            switch set.behavior {
            case .domain:
                guard case .domain(let host) = endpoint.host else { return false }
                return set.contains(domain: host)
            case .ipcidr:
                guard addressVisible else { return false }
                if let address = destination.ipv4, set.contains(ipv4: address) { return true }
                if let address = destination.ipv6, set.contains(ipv6: address) { return true }
                return false
            case .classical:
                var undecided = false
                for condition in set.conditions {
                    switch sub(condition) {
                    case true?: return true
                    case nil: undecided = true
                    case false?: continue
                    }
                }
                return undecided ? nil : false
            }
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
