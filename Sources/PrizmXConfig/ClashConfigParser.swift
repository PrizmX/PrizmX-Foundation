import Foundation
import PrizmXNodes
import PrizmXProtocols
import PrizmXRules

/// Clash YAML and Surge-style INI (`[Proxy]` / `[Rule]`) importer.
public struct ClashConfigParser: ConfigParserProtocol, Sendable {
    public init() {}

    public func parse(rawString: String) throws -> (Router, NodeManager) {
        try parseWithWarnings(rawString: rawString).tuple
    }

    /// Unsupported / malformed proxies, groups and rules are skipped and
    /// reported in `warnings`; a rule is never imported in a broadened form.
    public func parseWithWarnings(rawString: String) throws -> ConfigParseResult {
        let trimmed = ConfigText.normalized(rawString)
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

    private func parseClashYAML(_ text: String) throws -> ConfigParseResult {
        let root = try YAMLParser.parse(text)
        guard let mapping = root.mapping else {
            throw ConfigError.yamlSyntax("root document must be a mapping")
        }
        var warnings: [ConfigWarning] = []

        var nodes: [OutboundNode] = []
        if let proxies = mapping["proxies"]?.sequence {
            for item in proxies {
                let name = item.string(for: "name") ?? "?"
                do {
                    if let node = try parseClashProxy(item) {
                        nodes.append(node)
                    } else {
                        let type = item.string(for: "type") ?? "?"
                        warnings.append(ConfigWarning(kind: .proxy, text: name, reason: "unsupported proxy type \(type)"))
                    }
                } catch {
                    warnings.append(ConfigWarning(kind: .proxy, text: name, reason: "invalid proxy: \(error)"))
                }
            }
        }

        var groups = ConfigMapping.implicitGroups(for: nodes)
        if let proxyGroups = mapping["proxy-groups"]?.sequence ?? mapping["proxy_groups"]?.sequence {
            for item in proxyGroups {
                if let group = parseClashGroup(item, nodes: nodes, warnings: &warnings) {
                    groups.removeAll { $0.name == group.name }
                    groups.append(group)
                }
            }
        }

        var rules: [RouteRule] = []
        if let ruleList = mapping["rules"]?.sequence {
            for item in ruleList {
                guard let line = item.string, !line.isEmpty else { continue }
                do {
                    rules.append(contentsOf: try parseRule(line))
                } catch let skip as RuleSkip {
                    warnings.append(ConfigWarning(kind: .rule, text: line, reason: skip.reason))
                }
            }
        }

        let manager = NodeManager(nodes: nodes, groups: groups)
        warnings += ConfigMapping.missingTargetWarnings(rules: rules, manager: manager)
        return ConfigParseResult(
            router: Router(rules: rules, default: .direct),
            nodeManager: manager,
            warnings: warnings
        )
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
                protocolConfig: .trojan(
                    server: endpoint,
                    password: password,
                    sni: sni,
                    skipCertVerify: node.bool(for: "skip-cert-verify", default: false)
                )
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
                flow: flow,
                skipCertVerify: node.bool(for: "skip-cert-verify", default: false),
                alpn: Self.alpn(node.mapping?["alpn"])
            )
        )
    }

    /// Clash `alpn`: a list, or a single comma-separated string.
    static func alpn(_ node: YAMLNode?) -> [String]? {
        let values: [String]
        if let list = node?.sequence {
            values = list.compactMap(\.string)
        } else if let raw = node?.string {
            values = raw.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        } else {
            return nil
        }
        let cleaned = values.filter { !$0.isEmpty }
        return cleaned.isEmpty ? nil : cleaned
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

    /// Members come from `proxies`, plus every parsed proxy for
    /// `include-all` / `include-all-proxies` (narrowed by `filter`,
    /// `exclude-filter`, `exclude-type` like mihomo). Proxy providers
    /// (`use`, `include-all-providers`) are not supported: they add no
    /// members and are reported. A group left without members is dropped
    /// and rules targeting it fail closed (the connection errors, never DIRECT).
    private func parseClashGroup(
        _ node: YAMLNode,
        nodes: [OutboundNode],
        warnings: inout [ConfigWarning]
    ) -> PolicyGroup? {
        guard let name = node.string(for: "name"), !name.isEmpty else {
            warnings.append(ConfigWarning(kind: .group, text: "?", reason: "group without name"))
            return nil
        }
        let type = node.string(for: "type") ?? "select"
        var members: [String] = node.mapping?["proxies"]?.sequence?.compactMap(\.string) ?? []

        let usesProviders = !(node.mapping?["use"]?.sequence ?? []).isEmpty
            || node.bool(for: "include-all-providers")
        if usesProviders {
            warnings.append(ConfigWarning(
                kind: .group,
                text: name,
                reason: "proxy providers (use / include-all-providers) are not supported; their proxies are missing"
            ))
        }
        if node.bool(for: "include-all") || node.bool(for: "include-all-proxies") {
            let included = includeAll(node, name: name, nodes: nodes, warnings: &warnings)
            for id in included where !members.contains(id) {
                members.append(id)
            }
        }
        guard !members.isEmpty else {
            warnings.append(ConfigWarning(
                kind: .group,
                text: name,
                reason: "no usable members; rules targeting it will fail closed"
            ))
            return nil
        }
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

    private func includeAll(
        _ node: YAMLNode,
        name: String,
        nodes: [OutboundNode],
        warnings: inout [ConfigWarning]
    ) -> [String] {
        // mihomo splits multiple patterns with a backtick.
        func patterns(_ key: String) -> [NSRegularExpression]? {
            guard let raw = node.string(for: key), !raw.isEmpty else { return [] }
            var result: [NSRegularExpression] = []
            for part in raw.split(separator: "`") where !part.isEmpty {
                guard let regex = try? NSRegularExpression(pattern: String(part)) else {
                    warnings.append(ConfigWarning(kind: .group, text: name, reason: "invalid \(key) \(part)"))
                    return nil
                }
                result.append(regex)
            }
            return result
        }
        // An invalid filter must narrow, not broaden, the group.
        guard let include = patterns("filter"), let exclude = patterns("exclude-filter") else { return [] }
        let excludedTypes = Set(
            (node.string(for: "exclude-type") ?? "")
                .split(separator: "|")
                .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
        )
        func matches(_ regex: NSRegularExpression, _ text: String) -> Bool {
            regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil
        }
        return nodes.compactMap { node in
            if excludedTypes.contains(Self.typeName(node.protocolConfig)) { return nil }
            if !include.isEmpty, !include.contains(where: { matches($0, node.name) }) { return nil }
            if exclude.contains(where: { matches($0, node.name) }) { return nil }
            return node.id
        }
    }

    private static func typeName(_ config: ProtocolConfig) -> String {
        switch config {
        case .shadowsocks: "shadowsocks"
        case .vless: "vless"
        case .trojan: "trojan"
        case .anytls: "anytls"
        case .direct: "direct"
        }
    }

    // MARK: Surge INI

    private func parseSurge(_ text: String) throws -> ConfigParseResult {
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

        // Surge import stays strict: any unsupported rule fails the import.
        let rules = try ruleLines.flatMap { try parseRuleLine($0) }
        return ConfigParseResult(
            router: Router(rules: rules, default: .direct),
            nodeManager: NodeManager(nodes: nodes, groups: groups)
        )
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
                    flow: flow,
                    skipCertVerify: named("skip-cert-verify")?.lowercased() == "true",
                    alpn: named("alpn").flatMap { Self.alpn(.scalar($0)) }
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
                protocolConfig: .trojan(
                    server: endpoint,
                    password: password,
                    sni: sni,
                    skipCertVerify: named("skip-cert-verify")?.lowercased() == "true"
                )
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

    /// Surge path: any skipped rule is a hard error.
    func parseRuleLine(_ raw: String) throws -> [RouteRule] {
        do {
            return try parseRule(raw)
        } catch is RuleSkip {
            throw ConfigError.malformedRule(raw)
        }
    }

    /// `TYPE,payload,target[,no-resolve]` or `MATCH,target` / `FINAL,target`.
    /// Throws `RuleSkip` for anything that cannot be imported exactly.
    func parseRule(_ raw: String) throws -> [RouteRule] {
        let line = raw.trimmingCharacters(in: .whitespaces)
        let parts = line.split(separator: ",", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        guard let kind = parts.first?.uppercased(), !kind.isEmpty else {
            throw RuleSkip("malformed rule")
        }

        if kind == "MATCH" || kind == "FINAL" {
            guard parts.count >= 2, !parts[1].isEmpty else { throw RuleSkip("missing policy") }
            return [RouteRule(.matchAll, policy: ConfigMapping.policy(named: parts[1]))]
        }
        guard Self.supportedRuleTypes.contains(kind) else {
            throw RuleSkip("unsupported rule type \(kind)")
        }
        guard parts.count >= 3, !parts[1].isEmpty, !parts[2].isEmpty else {
            throw RuleSkip("malformed rule")
        }
        let payload = parts[1]
        let policy = ConfigMapping.policy(named: parts[2])
        var noResolve = false
        for option in parts.dropFirst(3) where !option.isEmpty {
            // Other options (e.g. `src`) change what is matched.
            guard option.lowercased() == "no-resolve" else {
                throw RuleSkip("unsupported rule option \(option)")
            }
            noResolve = true
        }

        do {
            switch kind {
            case "DOMAIN":
                return [try RouteRule(type: .domain(payload), policy: policy, noResolve: noResolve)]
            case "DOMAIN-SUFFIX", "DOMAINSUFFIX":
                return [try RouteRule(type: .domainSuffix(payload), policy: policy, noResolve: noResolve)]
            case "DOMAIN-KEYWORD", "DOMAINKEYWORD":
                return [try RouteRule(type: .domainKeyword(payload), policy: policy, noResolve: noResolve)]
            case "IP-CIDR", "IP-CIDR6", "IPCIDR":
                return [try RouteRule(type: .ipCIDR(payload), policy: policy, noResolve: noResolve)]
            case "GEOIP":
                // mihomo's `LAN` pseudo-country is not in the MMDB.
                if payload.uppercased() == "LAN" {
                    return try ConfigMapping.privateCIDRs.map {
                        try RouteRule(type: .ipCIDR($0), policy: policy, noResolve: noResolve)
                    }
                }
                return [try RouteRule(type: .geoIP(code: payload), policy: policy, noResolve: noResolve)]
            case "GEOSITE":
                return [try RouteRule(type: .geosite(tag: payload), policy: policy)]
            default:
                throw RuleSkip("unsupported rule type \(kind)")
            }
        } catch is RuleCompileError {
            throw RuleSkip("invalid payload \(payload)")
        }
    }

    private static let supportedRuleTypes: Set<String> = [
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAINSUFFIX", "DOMAIN-KEYWORD", "DOMAINKEYWORD",
        "IP-CIDR", "IP-CIDR6", "IPCIDR", "GEOIP", "GEOSITE",
    ]
}

/// A rule the importer refuses to apply (unsupported or malformed).
struct RuleSkip: Error, Equatable {
    var reason: String
    init(_ reason: String) { self.reason = reason }
}
