import Foundation
import PrizmXNodes
import PrizmXProtocols
import PrizmXRules

/// Clash YAML and Surge-style INI (`[Proxy]` / `[Rule]`) importer.
public struct ClashConfigParser: ConfigParserProtocol, Sendable {
    public init() {}

    public func parse(rawString: String) throws -> (Router, NodeManager) {
        let trimmed = rawString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw ConfigError.emptyInput }
        if isSurgeINI(trimmed) {
            return try parseSurge(trimmed)
        }
        return try parseClashYAML(trimmed)
    }

    private func isSurgeINI(_ text: String) -> Bool {
        let upper = text.uppercased()
        return upper.contains("[PROXY]") || upper.contains("[RULE]") || upper.contains("[PROXY GROUP]")
    }

    // MARK: Clash YAML

    private func parseClashYAML(_ text: String) throws -> (Router, NodeManager) {
        let root = try YAMLParser.parse(text)
        guard let mapping = root.mapping else {
            throw ConfigError.yamlSyntax("root document must be a mapping")
        }

        var nodes: [OutboundNode] = []
        if let proxies = mapping["proxies"]?.sequence {
            for item in proxies {
                if let node = try? parseClashProxy(item) {
                    nodes.append(node)
                }
            }
        }

        var groups = ConfigMapping.implicitGroups(for: nodes)
        if let proxyGroups = mapping["proxy-groups"]?.sequence ?? mapping["proxy_groups"]?.sequence {
            for item in proxyGroups {
                if let group = try? parseClashGroup(item) {
                    groups.removeAll { $0.name == group.name }
                    groups.append(group)
                }
            }
        }

        var rules: [RouteRule] = []
        if let ruleList = mapping["rules"]?.sequence {
            for item in ruleList {
                guard let line = item.string, !line.isEmpty else { continue }
                if let rule = try? parseRuleLine(line) {
                    rules.append(rule)
                }
            }
        }

        let router = Router(rules: rules, default: .direct)
        let manager = NodeManager(nodes: nodes, groups: groups)
        return (router, manager)
    }

    private func parseClashProxy(_ node: YAMLNode) throws -> OutboundNode? {
        guard let type = node.string(for: "type")?.lowercased() else {
            throw ConfigError.missingField("type")
        }
        let name = try node.requiredString("name")
        switch type {
        case "ss", "shadowsocks":
            let server = try node.requiredString("server")
            let port = try node.int(for: "port")
            let cipher = try ConfigMapping.cipher(try node.requiredString("cipher"))
            let password = try node.requiredString("password")
            let endpoint = try ConfigMapping.endpoint(host: server, port: port, field: "port")
            return OutboundNode(
                id: name,
                name: name,
                protocolConfig: .shadowsocks(server: endpoint, password: password, cipher: cipher)
            )
        case "vless":
            return try makeClashVLESS(node, name: name)
        case "trojan":
            let server = try node.requiredString("server")
            let port = try node.int(for: "port")
            let password = try node.requiredString("password")
            let endpoint = try ConfigMapping.endpoint(host: server, port: port, field: "port")
            let sni = node.string(for: "sni") ?? node.string(for: "servername")
            return OutboundNode(
                id: name,
                name: name,
                protocolConfig: .trojan(server: endpoint, password: password, sni: sni)
            )
        case "anytls":
            let server = try node.requiredString("server")
            let port = try node.int(for: "port")
            let password = try node.requiredString("password")
            let endpoint = try ConfigMapping.endpoint(host: server, port: port, field: "port")
            let sni = node.string(for: "sni") ?? node.string(for: "servername") ?? server
            let skipCertVerify = node.bool(for: "skip-cert-verify", default: false)
            let session = AnyTLSSessionConfig(
                checkInterval: TimeInterval(node.int(for: "idle-session-check-interval", default: 30)),
                idleTimeout: TimeInterval(node.int(for: "idle-session-timeout", default: 30)),
                minIdleSession: node.int(for: "min-idle-session", default: 1)
            )
            return OutboundNode(
                id: name,
                name: name,
                protocolConfig: .anytls(
                    server: endpoint,
                    password: password,
                    sni: sni,
                    skipCertVerify: skipCertVerify,
                    session: session
                )
            )
        default:
            return nil
        }
    }

    private func makeClashVLESS(_ node: YAMLNode, name: String) throws -> OutboundNode {
        let server = try node.requiredString("server")
        let port = try node.int(for: "port")
        let uuid = try node.requiredString("uuid")
        let endpoint = try ConfigMapping.endpoint(host: server, port: port, field: "port")
        let sni = node.string(for: "servername") ?? node.string(for: "sni")
        let tls = node.bool(for: "tls", default: sni != nil)
        let reality = try parseREALITY(from: node, sni: sni)
        let flow = VLESSVision.normalized(node.string(for: "flow"))
        return OutboundNode(
            id: name,
            name: name,
            protocolConfig: .vless(
                server: endpoint,
                uuid: uuid,
                sni: sni,
                tls: tls || reality != nil,
                reality: reality,
                flow: flow
            )
        )
    }

    private func parseREALITY(from node: YAMLNode, sni: String?) throws -> REALITYConfig? {
        guard let opts = node.mapping?["reality-opts"]?.mapping else { return nil }
        let publicKey = opts["public-key"]?.string ?? opts["public_key"]?.string
        guard let publicKey, !publicKey.isEmpty else { return nil }
        let shortId = opts["short-id"]?.string ?? opts["short_id"]?.string ?? ""
        let serverName = sni ?? node.string(for: "servername") ?? node.string(for: "sni") ?? ""
        let spiderX = opts["spider-x"]?.string ?? node.string(for: "spider-x") ?? ""
        return try REALITYConfig(
            publicKey: publicKey,
            shortId: shortId,
            serverName: serverName,
            spiderX: spiderX
        )
    }

    private func parseSurgeREALITY(
        named: (String) -> String?,
        sni: String?
    ) throws -> REALITYConfig? {
        guard let publicKey = named("public-key") ?? named("public_key") else { return nil }
        let shortId = named("short-id") ?? named("short_id") ?? ""
        let serverName = sni ?? ""
        let spiderX = named("spider-x") ?? ""
        return try REALITYConfig(
            publicKey: publicKey,
            shortId: shortId,
            serverName: serverName,
            spiderX: spiderX
        )
    }

    private func parseClashGroup(_ node: YAMLNode) throws -> PolicyGroup? {
        let name = try node.requiredString("name")
        let type = node.string(for: "type") ?? "select"
        var members: [String] = []
        if let list = node.mapping?["proxies"]?.sequence {
            members = list.compactMap(\.string)
        }
        guard !members.isEmpty else { return nil }
        let icon = node.string(for: "icon")
        return PolicyGroup(
            name: name,
            mode: ConfigMapping.groupMode(clashType: type),
            nodeIDs: members,
            selectedNodeID: members.first,
            iconURL: icon.flatMap(URL.init(string:)),
            testURL: node.string(for: "url") ?? PolicyGroup.defaultTestURL,
            interval: ConfigMapping.interval(node.string(for: "interval")),
            tolerance: ConfigMapping.toleranceMilliseconds(
                node.int(for: "tolerance", default: 50)
            ),
            loadBalanceStrategy: ConfigMapping.loadBalanceStrategy(node.string(for: "strategy"))
        )
    }

    // MARK: Surge INI

    private func parseSurge(_ text: String) throws -> (Router, NodeManager) {
        var section = ""
        var proxyLines: [String] = []
        var groupLines: [String] = []
        var ruleLines: [String] = []

        for raw in text.components(separatedBy: .newlines) {
            let line = stripInlineComment(raw).trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            if line.hasPrefix("[") && line.hasSuffix("]") {
                section = String(line.dropFirst().dropLast()).uppercased()
                continue
            }
            switch section {
            case "PROXY": proxyLines.append(line)
            case "PROXY GROUP", "PROXY-GROUP": groupLines.append(line)
            case "RULE": ruleLines.append(line)
            default: break
            }
        }

        var nodes: [OutboundNode] = []
        for line in proxyLines {
            if let node = try parseSurgeProxy(line) {
                nodes.append(node)
            }
        }

        var groups = ConfigMapping.implicitGroups(for: nodes)
        for line in groupLines {
            if let group = parseSurgeGroup(line) {
                groups.removeAll { $0.name == group.name }
                groups.append(group)
            }
        }

        let rules = try ruleLines.map { try parseRuleLine($0) }
        return (Router(rules: rules, default: .direct), NodeManager(nodes: nodes, groups: groups))
    }

    private func parseSurgeProxy(_ line: String) throws -> OutboundNode? {
        guard let eq = line.firstIndex(of: "=") else { return nil }
        let name = line[..<eq].trimmingCharacters(in: .whitespaces)
        let parts = line[line.index(after: eq)...]
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
        guard let type = parts.first?.lowercased() else { return nil }
        func named(_ key: String) -> String? {
            for part in parts {
                let pair = part.split(separator: "=", maxSplits: 1).map(String.init)
                if pair.count == 2, pair[0].lowercased() == key { return pair[1] }
            }
            return nil
        }
        switch type {
        case "ss", "shadowsocks", "custom":
            guard parts.count >= 3 else { throw ConfigError.malformedRule(line) }
            let host = parts[1]
            guard let port = Int(parts[2]) else { throw ConfigError.invalidPort(parts[2]) }
            let method = named("encrypt-method") ?? named("method") ?? ""
            let password = named("password") ?? ""
            let endpoint = try ConfigMapping.endpoint(host: host, port: port, field: "port")
            return OutboundNode(
                id: String(name),
                name: String(name),
                protocolConfig: .shadowsocks(
                    server: endpoint,
                    password: password,
                    cipher: try ConfigMapping.cipher(method)
                )
            )
        case "vless":
            guard parts.count >= 3 else { throw ConfigError.malformedRule(line) }
            let host = parts[1]
            guard let port = Int(parts[2]) else { throw ConfigError.invalidPort(parts[2]) }
            let uuid = named("uuid") ?? ""
            let sni = named("sni") ?? named("servername")
            let tls = named("tls").map { $0.lowercased() == "true" } ?? (sni != nil)
            let reality = try parseSurgeREALITY(named: named, sni: sni)
            let flow = VLESSVision.normalized(named("flow"))
            let endpoint = try ConfigMapping.endpoint(host: host, port: port, field: "port")
            return OutboundNode(
                id: String(name),
                name: String(name),
                protocolConfig: .vless(
                    server: endpoint,
                    uuid: uuid,
                    sni: sni,
                    tls: tls || reality != nil,
                    reality: reality,
                    flow: flow
                )
            )
        case "trojan":
            guard parts.count >= 3 else { throw ConfigError.malformedRule(line) }
            let host = parts[1]
            guard let port = Int(parts[2]) else { throw ConfigError.invalidPort(parts[2]) }
            let password = named("password") ?? ""
            let sni = named("sni") ?? named("servername")
            let endpoint = try ConfigMapping.endpoint(host: host, port: port, field: "port")
            return OutboundNode(
                id: String(name),
                name: String(name),
                protocolConfig: .trojan(server: endpoint, password: password, sni: sni)
            )
        case "anytls":
            guard parts.count >= 3 else { throw ConfigError.malformedRule(line) }
            let host = parts[1]
            guard let port = Int(parts[2]) else { throw ConfigError.invalidPort(parts[2]) }
            let password = named("password") ?? ""
            let sni = named("sni") ?? named("servername") ?? host
            let skipCertVerify = (named("skip-cert-verify") ?? "false") == "true"
            let endpoint = try ConfigMapping.endpoint(host: host, port: port, field: "port")
            return OutboundNode(
                id: String(name),
                name: String(name),
                protocolConfig: .anytls(
                    server: endpoint,
                    password: password,
                    sni: sni,
                    skipCertVerify: skipCertVerify,
                    session: AnyTLSSessionConfig()
                )
            )
        default:
            return nil
        }
    }

    private func parseSurgeGroup(_ line: String) -> PolicyGroup? {
        guard let eq = line.firstIndex(of: "=") else { return nil }
        let name = line[..<eq].trimmingCharacters(in: .whitespaces)
        let parts = line[line.index(after: eq)...]
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
        guard let type = parts.first else { return nil }
        let members = Array(parts.dropFirst()).filter { !$0.contains("=") && !$0.isEmpty }
        guard !members.isEmpty else { return nil }
        func named(_ key: String) -> String? {
            for part in parts {
                let pair = part.split(separator: "=", maxSplits: 1).map(String.init)
                if pair.count == 2, pair[0].lowercased() == key { return pair[1] }
            }
            return nil
        }
        return PolicyGroup(
            name: String(name),
            mode: ConfigMapping.groupMode(clashType: type),
            nodeIDs: members,
            selectedNodeID: members.first,
            testURL: named("url") ?? PolicyGroup.defaultTestURL,
            interval: ConfigMapping.interval(named("interval")),
            tolerance: ConfigMapping.toleranceMilliseconds(named("tolerance").flatMap(Int.init)),
            loadBalanceStrategy: ConfigMapping.loadBalanceStrategy(named("strategy"))
        )
    }

    private func stripInlineComment(_ line: String) -> String {
        guard let hash = line.firstIndex(of: "#"), !line[..<hash].contains("\"") else {
            return line
        }
        return String(line[..<hash])
    }

    // MARK: Rules

    /// `TYPE,payload,target[,no-resolve]` or `MATCH,target` / `FINAL,target`.
    func parseRuleLine(_ raw: String) throws -> RouteRule {
        let line = raw.trimmingCharacters(in: .whitespaces)
        let parts = line.split(separator: ",", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        guard let kind = parts.first?.uppercased() else {
            throw ConfigError.malformedRule(raw)
        }

        if kind == "MATCH" || kind == "FINAL" {
            guard parts.count >= 2 else { throw ConfigError.malformedRule(raw) }
            return try RouteRule(type: .matchAll, policy: ConfigMapping.policy(named: parts[1]))
        }
        guard parts.count >= 3 else { throw ConfigError.malformedRule(raw) }
        let payload = parts[1]
        let policy = ConfigMapping.policy(named: parts[2])
        let noResolve = parts.dropFirst(3).contains { $0.lowercased() == "no-resolve" }

        do {
            switch kind {
            case "DOMAIN":
                return try RouteRule(type: .domain(payload), policy: policy, noResolve: noResolve)
            case "DOMAIN-SUFFIX", "DOMAINSUFFIX":
                return try RouteRule(type: .domainSuffix(payload), policy: policy, noResolve: noResolve)
            case "DOMAIN-KEYWORD", "DOMAINKEYWORD":
                return try RouteRule(type: .domainKeyword(payload), policy: policy, noResolve: noResolve)
            case "IP-CIDR", "IP-CIDR6", "IPCIDR":
                return try RouteRule(type: .ipCIDR(payload), policy: policy, noResolve: noResolve)
            case "GEOIP":
                return try RouteRule(type: .geoIP(code: payload), policy: policy, noResolve: noResolve)
            case "GEOSITE":
                return try RouteRule(type: .geosite(tag: payload), policy: policy)
            default:
                throw ConfigError.malformedRule(raw)
            }
        } catch is RuleCompileError {
            throw ConfigError.malformedRule(raw)
        }
    }
}
