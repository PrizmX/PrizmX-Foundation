import Foundation
import PrizmXNodes
import PrizmXProtocols
import PrizmXRules

/// sing-box JSON importer (`outbounds` + `route.rules` / `route.final`).
public struct SingboxConfigParser: ConfigParserProtocol, Sendable {
    public init() {}

    public func parse(rawString: String) throws -> (Router, NodeManager) {
        let trimmed = rawString.trimmingCharacters(in: .whitespacesAndNewlines)
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

        for outbound in file.outbounds ?? [] {
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
                groups.append(makeGroup(outbound, mode: .select))
            case "urltest":
                groups.append(makeGroup(outbound, mode: .urlTest))
            default:
                continue
            }
        }

        var allGroups = ConfigMapping.implicitGroups(for: nodes)
        for group in groups {
            allGroups.removeAll { $0.name == group.name }
            allGroups.append(group)
        }

        var rules: [RouteRule] = []
        for rule in file.route?.rules ?? [] {
            rules.append(contentsOf: expand(rule))
        }

        let defaultPolicy = file.route?.final.map(ConfigMapping.policy(named:)) ?? .direct
        let router = Router(rules: rules, default: defaultPolicy)
        return (router, NodeManager(nodes: nodes, groups: allGroups))
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
                reality: reality
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
                sni: sni
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

    private func makeGroup(_ outbound: SingboxOutbound, mode: PolicyGroup.Mode) -> PolicyGroup {
        let name = outbound.tag ?? "proxy"
        let members = outbound.outbounds ?? []
        return PolicyGroup(
            name: name,
            mode: mode,
            nodeIDs: members,
            selectedNodeID: members.first
        )
    }

    private func expand(_ rule: SingboxRouteRule) -> [RouteRule] {
        let policy = ConfigMapping.policy(named: rule.outbound ?? "direct")
        var result: [RouteRule] = []
        for domain in rule.domain.values {
            result.append(RouteRule(type: .domain(domain), policy: policy))
        }
        for suffix in rule.domainSuffix.values {
            result.append(RouteRule(type: .domainSuffix(suffix), policy: policy))
        }
        for keyword in rule.domainKeyword.values {
            result.append(RouteRule(type: .domainKeyword(keyword), policy: policy))
        }
        for cidr in rule.ipCIDR.values {
            result.append(RouteRule(type: .ipCIDR(cidr), policy: policy))
        }
        for site in rule.geosite.values {
            result.append(RouteRule(type: .geosite(tag: site), policy: policy))
        }
        for country in rule.geoip.values {
            result.append(RouteRule(type: .geoIP(code: country), policy: policy))
        }
        return result
    }
}

// MARK: - Codable document

struct SingboxFile: Codable, Sendable {
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
    var tls: SingboxTLS?
    var outbounds: [String]?

    enum CodingKeys: String, CodingKey {
        case type, tag, server, method, password, uuid, tls, outbounds
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

struct SingboxTLS: Codable, Sendable {
    var enabled: Bool?
    var serverName: String?
    var insecure: Bool?
    var reality: SingboxReality?

    enum CodingKeys: String, CodingKey {
        case enabled
        case serverName = "server_name"
        case insecure
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

struct SingboxRoute: Codable, Sendable {
    var rules: [SingboxRouteRule]?
    var final: String?
}

struct SingboxRouteRule: Codable, Sendable {
    var domain: StringOrArray
    var domainSuffix: StringOrArray
    var domainKeyword: StringOrArray
    var ipCIDR: StringOrArray
    var geosite: StringOrArray
    var geoip: StringOrArray
    var outbound: String?

    enum CodingKeys: String, CodingKey {
        case domain, geosite, geoip, outbound
        case domainSuffix = "domain_suffix"
        case domainKeyword = "domain_keyword"
        case ipCIDR = "ip_cidr"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        domain = try container.decodeIfPresent(StringOrArray.self, forKey: .domain) ?? .empty
        domainSuffix = try container.decodeIfPresent(StringOrArray.self, forKey: .domainSuffix) ?? .empty
        domainKeyword = try container.decodeIfPresent(StringOrArray.self, forKey: .domainKeyword) ?? .empty
        ipCIDR = try container.decodeIfPresent(StringOrArray.self, forKey: .ipCIDR) ?? .empty
        geosite = try container.decodeIfPresent(StringOrArray.self, forKey: .geosite) ?? .empty
        geoip = try container.decodeIfPresent(StringOrArray.self, forKey: .geoip) ?? .empty
        outbound = try container.decodeIfPresent(String.self, forKey: .outbound)
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
