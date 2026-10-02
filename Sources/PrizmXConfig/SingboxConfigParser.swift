import Foundation
import PrizmXNodes
import PrizmXProtocols
import PrizmXRules

/// sing-box JSON importer (`outbounds` + `route.rules` / `route.final`).
public struct SingboxConfigParser: ConfigParserProtocol, Sendable {
    public init() {}

    public func parse(rawString: String) throws -> (Router, NodeManager) {
        try parseWithWarnings(rawString: rawString).tuple
    }

    /// Rules with fields we cannot evaluate (`invert`, `port`, `network`,
    /// `rule_set`, logical rules, unknown keys or actions) are skipped whole
    /// and reported, never imported in a broadened form.
    public func parseWithWarnings(rawString: String) throws -> ConfigParseResult {
        let trimmed = ConfigText.normalized(rawString)
        guard !trimmed.isEmpty else { throw ConfigError.emptyInput }
        let data = Data(trimmed.utf8)
        let file: SingboxFile
        do {
            file = try JSONDecoder().decode(SingboxFile.self, from: data)
        } catch {
            throw ConfigError.jsonSyntax(String(describing: error))
        }

        var nodes: [OutboundNode] = []
        var groups: [PolicyGroup] = []
        var warnings: [ConfigWarning] = []
        // Tags of built-in outbounds map to DIRECT / REJECT, in rules and as
        // group members (which may list them before they are declared).
        var builtins: [String: Policy] = [:]
        for outbound in file.outbounds ?? [] {
            guard let tag = outbound.tag else { continue }
            switch outbound.type.lowercased() {
            case "direct": builtins[tag] = .direct
            case "block": builtins[tag] = .reject
            default: break
            }
        }

        for outbound in file.outbounds ?? [] {
            do {
                switch outbound.type.lowercased() {
                case "shadowsocks":
                    nodes.append(try makeShadowsocks(outbound))
                case "vless":
                    nodes.append(try makeVLESS(outbound))
                case "trojan":
                    nodes.append(try makeTrojan(outbound))
                case "anytls":
                    nodes.append(try makeAnyTLS(outbound))
                case "selector":
                    groups.append(makeGroup(outbound, mode: .select, builtins: builtins))
                case "urltest":
                    groups.append(makeGroup(outbound, mode: .urlTest, builtins: builtins))
                case "loadbalance", "load-balance":
                    groups.append(makeGroup(outbound, mode: .loadBalance, builtins: builtins))
                case "direct", "block", "dns":
                    continue
                default:
                    warnings.append(ConfigWarning(
                        kind: .proxy,
                        text: outbound.tag ?? "?",
                        reason: "unsupported outbound type \(outbound.type)"
                    ))
                }
            } catch {
                warnings.append(ConfigWarning(
                    kind: .proxy,
                    text: outbound.tag ?? "?",
                    reason: "invalid outbound: \(error)"
                ))
            }
        }

        var allGroups = ConfigMapping.implicitGroups(for: nodes)
        for group in groups {
            allGroups.removeAll { $0.name == group.name }
            allGroups.append(group)
        }
        allGroups = ConfigMapping.pruningUndefinedMembers(allGroups, nodes: nodes, warnings: &warnings)

        func policy(_ tag: String) -> Policy {
            builtins[tag] ?? ConfigMapping.policy(named: tag)
        }

        var rules: [RouteRule] = []
        for rule in file.route?.rules ?? [] {
            do {
                rules.append(contentsOf: try expand(rule, policy: policy))
            } catch let skip as RuleSkip {
                warnings.append(ConfigWarning(kind: .rule, text: rule.summary, reason: skip.reason))
            }
        }

        let defaultPolicy = file.route?.final.map(policy) ?? .direct
        let manager = NodeManager(nodes: nodes, groups: allGroups)
        warnings += ConfigMapping.missingTargetWarnings(rules: rules, manager: manager)
        return ConfigParseResult(
            router: Router(rules: rules, default: defaultPolicy),
            nodeManager: manager,
            warnings: warnings
        )
    }

    private func makeShadowsocks(_ outbound: SingboxOutbound) throws -> OutboundNode {
        let tag = try outbound.requireTag()
        let server = try outbound.requireServer()
        let port = try outbound.requirePort()
        let method = outbound.method ?? ""
        let password = outbound.password ?? ""
        return OutboundNode(
            id: tag,
            name: tag,
            protocolConfig: .shadowsocks(
                server: try ConfigMapping.endpoint(host: server, port: port, field: "server_port"),
                password: password,
                cipher: try ConfigMapping.cipher(method)
            )
        )
    }

    private func makeVLESS(_ outbound: SingboxOutbound) throws -> OutboundNode {
        let tag = try outbound.requireTag()
        let server = try outbound.requireServer()
        let port = try outbound.requirePort()
        let uuid = outbound.uuid ?? ""
        let tls = outbound.tls?.enabled ?? false
        let sni = outbound.tls?.serverName
        let flow = VLESSVision.normalized(outbound.flow)
        var reality: REALITYConfig?
        if let settings = outbound.tls?.reality, settings.enabled != false,
           let publicKey = settings.publicKey, !publicKey.isEmpty {
            let name = (sni?.isEmpty == false) ? sni! : server
            reality = try REALITYConfig(
                publicKey: publicKey,
                shortId: settings.shortID ?? "",
                serverName: name,
                spiderX: ""
            )
        }
        return OutboundNode(
            id: tag,
            name: tag,
            protocolConfig: .vless(
                server: try ConfigMapping.endpoint(host: server, port: port, field: "server_port"),
                uuid: uuid,
                sni: sni,
                tls: tls || sni != nil || reality != nil,
                reality: reality,
                flow: flow,
                skipCertVerify: outbound.tls?.insecure ?? false,
                alpn: outbound.tls?.alpn.flatMap { $0.values.isEmpty ? nil : $0.values }
            )
        )
    }

    private func makeTrojan(_ outbound: SingboxOutbound) throws -> OutboundNode {
        let tag = try outbound.requireTag()
        let server = try outbound.requireServer()
        let port = try outbound.requirePort()
        let password = outbound.password ?? ""
        let sni = outbound.tls?.serverName
        return OutboundNode(
            id: tag,
            name: tag,
            protocolConfig: .trojan(
                server: try ConfigMapping.endpoint(host: server, port: port, field: "server_port"),
                password: password,
                sni: sni,
                skipCertVerify: outbound.tls?.insecure ?? false
            )
        )
    }

    private func makeAnyTLS(_ outbound: SingboxOutbound) throws -> OutboundNode {
        let tag = try outbound.requireTag()
        let server = try outbound.requireServer()
        let port = try outbound.requirePort()
        let password = outbound.password ?? ""
        let sni = outbound.tls?.serverName ?? server
        return OutboundNode(
            id: tag,
            name: tag,
            protocolConfig: .anytls(
                server: try ConfigMapping.endpoint(host: server, port: port, field: "server_port"),
                password: password,
                sni: sni,
                skipCertVerify: outbound.tls?.insecure ?? false,
                session: AnyTLSSessionConfig()
            )
        )
    }

    private func makeGroup(
        _ outbound: SingboxOutbound,
        mode: PolicyGroup.Mode,
        builtins: [String: Policy]
    ) -> PolicyGroup {
        let name = outbound.tag ?? "proxy"
        let members = (outbound.outbounds ?? []).map { tag in
            switch builtins[tag] {
            case .direct: "DIRECT"
            case .reject: "REJECT"
            default: tag
            }
        }
        return PolicyGroup(
            name: name,
            mode: mode,
            nodeIDs: members,
            selectedNodeID: members.first,
            testURL: outbound.url ?? PolicyGroup.defaultTestURL,
            interval: outbound.interval?.duration ?? .seconds(300),
            tolerance: ConfigMapping.toleranceMilliseconds(outbound.tolerance),
            loadBalanceStrategy: ConfigMapping.loadBalanceStrategy(outbound.strategy)
        )
    }

    private func expand(_ rule: SingboxRouteRule, policy tagPolicy: (String) -> Policy) throws -> [RouteRule] {
        let unsupported = rule.keys.subtracting(SingboxRouteRule.supportedKeys).sorted()
        guard unsupported.isEmpty else {
            throw RuleSkip("unsupported fields \(unsupported.joined(separator: ", "))")
        }
        if let type = rule.type, type != "default" {
            throw RuleSkip("unsupported rule type \(type)")
        }
        if rule.invert == true {
            throw RuleSkip("invert is not supported")
        }
        let policy: Policy
        switch rule.action ?? "route" {
        case "route":
            guard let outbound = rule.outbound, !outbound.isEmpty else {
                throw RuleSkip("route rule without outbound")
            }
            policy = tagPolicy(outbound)
        case "reject":
            policy = .reject
        default:
            throw RuleSkip("unsupported action \(rule.action ?? "")")
        }
        do {
            var result: [RouteRule] = []
            for domain in rule.domain.values {
                result.append(try RouteRule(type: .domain(domain), policy: policy))
            }
            for suffix in rule.domainSuffix.values {
                result.append(try RouteRule(type: .domainSuffix(suffix), policy: policy))
            }
            for keyword in rule.domainKeyword.values {
                result.append(try RouteRule(type: .domainKeyword(keyword), policy: policy))
            }
            for cidr in rule.ipCIDR.values {
                result.append(try RouteRule(type: .ipCIDR(cidr), policy: policy))
            }
            if rule.ipIsPrivate == true {
                for cidr in ConfigMapping.privateCIDRs {
                    result.append(try RouteRule(type: .ipCIDR(cidr), policy: policy))
                }
            }
            for site in rule.geosite.values {
                result.append(try RouteRule(type: .geosite(tag: site), policy: policy))
            }
            for country in rule.geoip.values {
                result.append(try RouteRule(type: .geoIP(code: country), policy: policy))
            }
            // A rule with no matcher we understand must not become match-all
            // or vanish silently.
            guard !result.isEmpty else { throw RuleSkip("no supported matcher") }
            return result
        } catch is RuleCompileError {
            throw RuleSkip("invalid ip_cidr")
        }
    }
}

// MARK: - Codable document

struct SingboxFile: Decodable, Sendable {
    var outbounds: [SingboxOutbound]?
    var route: SingboxRoute?
}

struct SingboxOutbound: Codable, Sendable {
    var type: String
    var tag: String?
    var server: String?
    var serverPort: Int?
    var method: String?
    var password: String?
    var uuid: String?
    var flow: String?
    var tls: SingboxTLS?
    var outbounds: [String]?
    var url: String?
    var interval: SingboxInterval?
    var tolerance: Int?
    var strategy: String?

    enum CodingKeys: String, CodingKey {
        case type, tag, server, method, password, uuid, flow, tls, outbounds, url, interval, tolerance, strategy
        case serverPort = "server_port"
    }

    func requireTag() throws -> String {
        guard let tag, !tag.isEmpty else { throw ConfigError.missingField("tag") }
        return tag
    }

    func requireServer() throws -> String {
        guard let server, !server.isEmpty else { throw ConfigError.missingField("server") }
        return server
    }

    func requirePort() throws -> Int {
        guard let serverPort else { throw ConfigError.missingField("server_port") }
        return serverPort
    }
}

struct SingboxInterval: Codable, Sendable {
    var duration: Duration

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let seconds = try? container.decode(Int.self) {
            duration = ConfigMapping.interval(String(seconds))
            return
        }
        if let seconds = try? container.decode(Double.self) {
            // Guard the Int conversion: NaN / huge values would trap.
            let whole = seconds.isFinite && seconds >= 1 && seconds < 1e9 ? Int(seconds) : 0
            duration = ConfigMapping.interval(String(whole))
            return
        }
        duration = ConfigMapping.interval(try container.decode(String.self))
    }
}

struct SingboxTLS: Codable, Sendable {
    var enabled: Bool?
    var serverName: String?
    var insecure: Bool?
    var alpn: StringOrArray?
    var reality: SingboxReality?

    enum CodingKeys: String, CodingKey {
        case enabled
        case serverName = "server_name"
        case insecure
        case alpn
        case reality
    }
}

struct SingboxReality: Codable, Sendable {
    var enabled: Bool?
    var publicKey: String?
    var shortID: String?

    enum CodingKeys: String, CodingKey {
        case enabled
        case publicKey = "public_key"
        case shortID = "short_id"
    }
}

struct SingboxRoute: Decodable, Sendable {
    var rules: [SingboxRouteRule]?
    var final: String?
}

struct SingboxRouteRule: Decodable, Sendable {
    var domain: StringOrArray
    var domainSuffix: StringOrArray
    var domainKeyword: StringOrArray
    var ipCIDR: StringOrArray
    var geosite: StringOrArray
    var geoip: StringOrArray
    var ipIsPrivate: Bool?
    var outbound: String?
    var action: String?
    var type: String?
    var invert: Bool?
    /// Every key present, to reject rules with fields we would ignore.
    var keys: Set<String>

    /// `invert: false` is harmless; `method` / `no_drop` only tune `reject`.
    static let supportedKeys: Set<String> = [
        "domain", "domain_suffix", "domain_keyword", "ip_cidr", "geosite", "geoip",
        "ip_is_private", "outbound", "action", "type", "invert", "method", "no_drop",
    ]

    private struct AnyKey: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }
        init(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { nil }
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyKey.self)
        func list(_ key: String) throws -> StringOrArray {
            try container.decodeIfPresent(StringOrArray.self, forKey: AnyKey(stringValue: key)) ?? .empty
        }
        keys = Set(container.allKeys.map(\.stringValue))
        domain = try list("domain")
        domainSuffix = try list("domain_suffix")
        domainKeyword = try list("domain_keyword")
        ipCIDR = try list("ip_cidr")
        geosite = try list("geosite")
        geoip = try list("geoip")
        ipIsPrivate = try? container.decodeIfPresent(Bool.self, forKey: AnyKey(stringValue: "ip_is_private"))
        outbound = try? container.decodeIfPresent(String.self, forKey: AnyKey(stringValue: "outbound"))
        action = try? container.decodeIfPresent(String.self, forKey: AnyKey(stringValue: "action"))
        type = try? container.decodeIfPresent(String.self, forKey: AnyKey(stringValue: "type"))
        invert = try? container.decodeIfPresent(Bool.self, forKey: AnyKey(stringValue: "invert"))
    }

    /// Compact text for warnings.
    var summary: String {
        var parts: [String] = []
        for (key, value) in [
            ("domain", domain), ("domain_suffix", domainSuffix), ("domain_keyword", domainKeyword),
            ("ip_cidr", ipCIDR), ("geosite", geosite), ("geoip", geoip),
        ] where !value.values.isEmpty {
            parts.append("\(key)=\(value.values.prefix(3).joined(separator: "|"))")
        }
        let others = keys.subtracting(Self.supportedKeys).sorted()
        if !others.isEmpty { parts.append(others.joined(separator: ",")) }
        parts.append("-> \(action == "reject" ? "reject" : (outbound ?? action ?? "?"))")
        return parts.joined(separator: " ")
    }
}

/// sing-box accepts either a string or an array of strings for most matchers.
enum StringOrArray: Codable, Sendable {
    case empty
    case values([String])

    var values: [String] {
        switch self {
        case .empty: return []
        case .values(let list): return list
        }
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .empty
        } else if let value = try? container.decode(String.self) {
            self = .values([value])
        } else {
            self = .values(try container.decode([String].self))
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .empty:
            try container.encodeNil()
        case .values(let list):
            if list.count == 1 {
                try container.encode(list[0])
            } else {
                try container.encode(list)
            }
        }
    }
}
