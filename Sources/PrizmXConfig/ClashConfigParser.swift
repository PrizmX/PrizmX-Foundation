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
        for item in mapping["proxies"]?.sequence ?? [] {
            if let node = parseProxyEntry(item, warnings: &warnings) {
                nodes.append(node)
            }
        }
        let mainNodes = nodes

        // proxy-providers: their proxies join the catalog, and groups pick
        // them up through `use` / `include-all-providers`.
        var providerNodes: [String: [OutboundNode]] = [:]
        var names = Set(nodes.map(\.id))
        for definition in ProviderStore.definitions(in: root) where definition.kind == .proxy {
            let provided = loadProxyProvider(
                definition,
                node: mapping["proxy-providers"]?.mapping?[definition.name],
                names: &names,
                warnings: &warnings
            )
            providerNodes[definition.name] = provided
            nodes.append(contentsOf: provided)
        }

        var groups = ConfigMapping.implicitGroups(for: nodes)
        if let proxyGroups = mapping["proxy-groups"]?.sequence ?? mapping["proxy_groups"]?.sequence {
            for item in proxyGroups {
                if let group = parseClashGroup(
                    item,
                    nodes: mainNodes,
                    providers: providerNodes,
                    warnings: &warnings
                ) {
                    groups.removeAll { $0.name == group.name }
                    groups.append(group)
                }
            }
        }

        let ruleProviders = RuleProviderResolver(root: root, parser: self)
        var rules: [RouteRule] = []
        if let ruleList = mapping["rules"]?.sequence {
            for item in ruleList {
                guard let line = item.string, !line.isEmpty else { continue }
                do {
                    rules.append(contentsOf: try parseRule(line, providers: ruleProviders))
                } catch let skip as RuleSkip {
                    warnings.append(ConfigWarning(kind: .rule, text: line, reason: skip.reason))
                }
            }
        }
        warnings += ruleProviders.warnings
        warnings += ClashDNSSection.importWarnings(root: root)

        groups = ConfigMapping.pruningUndefinedMembers(groups, nodes: nodes, warnings: &warnings)
        let manager = NodeManager(nodes: nodes, groups: groups)
        warnings += ConfigMapping.missingTargetWarnings(rules: rules, manager: manager)
        var result = ConfigParseResult(
            router: Router(rules: rules, default: .direct),
            nodeManager: manager,
            warnings: warnings
        )
        result.allowsIPv6 = root.bool(for: "ipv6", default: true)
        return result
    }

    /// One `proxies` entry, or nil (reported) when it cannot be imported.
    private func parseProxyEntry(_ item: YAMLNode, warnings: inout [ConfigWarning]) -> OutboundNode? {
        let name = item.string(for: "name") ?? "?"
        if let hop = item.string(for: "dialer-proxy"), !hop.isEmpty {
            // Without the chain it would dial the server directly and expose
            // the client's address; leave it out instead.
            warnings.append(ConfigWarning(
                kind: .proxy,
                text: name,
                reason: "dialer-proxy (proxy chain via \(hop)) is not supported; skipped so it never connects without it"
            ))
            return nil
        }
        do {
            if let node = try parseClashProxy(item) { return node }
            let type = item.string(for: "type") ?? "?"
            warnings.append(ConfigWarning(kind: .proxy, text: name, reason: "unsupported proxy type \(type)"))
        } catch {
            warnings.append(ConfigWarning(kind: .proxy, text: name, reason: "invalid proxy: \(error)"))
        }
        return nil
    }

    /// Proxies of one `proxy-providers` entry: inline `payload`, or the
    /// downloaded body (Clash YAML `proxies`, or a share-link list). Names
    /// already taken get the provider's name appended.
    private func loadProxyProvider(
        _ definition: ProviderStore.Definition,
        node: YAMLNode?,
        names: inout Set<String>,
        warnings: inout [ConfigWarning]
    ) -> [OutboundNode] {
        func warn(_ reason: String) {
            warnings.append(ConfigWarning(kind: .proxy, text: "provider \(definition.name)", reason: reason))
        }
        if definition.unsupportedKeys.contains("dialer-proxy") {
            warn("dialer-proxy (proxy chain) is not supported; its proxies are left out")
            return []
        }
        if definition.unsupportedKeys.contains("override") {
            warn("override is not supported; proxies are imported as the provider sends them")
        }
        let entries: [YAMLNode]
        switch definition.type {
        case "inline":
            entries = node?.mapping?["payload"]?.sequence ?? []
        case "http":
            guard let body = ProviderStore.cachedBody(for: definition)?.text else {
                warn("not downloaded yet; its proxies are missing until it is")
                return []
            }
            entries = Self.providerProxies(body)
        default:
            warn("\(definition.type) providers are not supported (use http or inline)")
            return []
        }
        var provided: [OutboundNode] = []
        for entry in entries {
            guard var parsed = parseProxyEntry(entry, warnings: &warnings) else { continue }
            if names.contains(parsed.id) {
                let renamed = "\(parsed.id) (\(definition.name))"
                guard !names.contains(renamed) else {
                    warn("duplicate proxy name \(parsed.id) skipped")
                    continue
                }
                parsed = OutboundNode(id: renamed, name: renamed, protocolConfig: parsed.protocolConfig)
            }
            provided.append(parsed)
        }
        // Provider-level filters (mihomo `filter` / `exclude-filter` / `exclude-type`).
        if let node {
            let kept = Set(filtered(provided, by: node, name: "provider \(definition.name)", warnings: &warnings))
            provided = provided.filter { kept.contains($0.id) }
        }
        names.formUnion(provided.map(\.id))
        return provided
    }

    /// `proxies` of a provider body: Clash YAML, or share links (plain or
    /// base64) converted the same way subscriptions are.
    static func providerProxies(_ body: String) -> [YAMLNode] {
        let trimmed = body.trimmingCharacters(in: .whitespacesAndNewlines)
        if let root = try? YAMLParser.parse(trimmed), let proxies = root.mapping?["proxies"]?.sequence {
            return proxies
        }
        let links = ProxyURIList.clashYAML(from: trimmed)
            ?? ProxyURIList.decodeBase64(trimmed).flatMap(ProxyURIList.clashYAML(from:))
        guard let links, let root = try? YAMLParser.parse(links) else { return [] }
        return root.mapping?["proxies"]?.sequence ?? []
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
            let password = try node.requiredString("password")
            let cipher = try ConfigMapping.cipher(try node.requiredString("cipher"), password: password)
            let endpoint = try ConfigMapping.endpoint(host: server, port: port, field: "port")
            let opts = node.mapping?["plugin-opts"]
            let plugin = try ConfigMapping.shadowsocksPlugin(
                name: node.string(for: "plugin"),
                options: opts?.mapping?.compactMapValues(\.string) ?? [:],
                headers: opts?.mapping?["headers"]?.mapping?.compactMapValues(\.string) ?? [:],
                server: server
            )
            return OutboundNode(
                id: name,
                name: name,
                protocolConfig: .shadowsocks(server: endpoint, password: password, cipher: cipher, plugin: plugin)
            )
        case "vless":
            return try makeClashVLESS(node, name: name)
        case "vmess":
            let endpoint = try ConfigMapping.endpoint(
                host: try node.requiredString("server"),
                port: try node.int(for: "port"),
                field: "port"
            )
            var tls = Self.tls(node)
            if tls != nil, tls?.serverName == nil {
                tls?.serverName = node.string(for: "servername")
            }
            return OutboundNode(
                id: name,
                name: name,
                protocolConfig: .vmess(
                    server: endpoint,
                    uuid: try ConfigMapping.uuid(node.string(for: "uuid")),
                    security: try ConfigMapping.vmessSecurity(node.string(for: "cipher")),
                    tls: tls,
                    network: try Self.transport(node)
                )
            )
        case "http":
            let endpoint = try ConfigMapping.endpoint(
                host: try node.requiredString("server"),
                port: try node.int(for: "port"),
                field: "port"
            )
            return OutboundNode(
                id: name,
                name: name,
                protocolConfig: .http(
                    server: endpoint,
                    credentials: Self.credentials(node),
                    tls: Self.tls(node),
                    headers: node.mapping?["headers"]?.mapping?.compactMapValues(\.string) ?? [:]
                )
            )
        case "socks5":
            let endpoint = try ConfigMapping.endpoint(
                host: try node.requiredString("server"),
                port: try node.int(for: "port"),
                field: "port"
            )
            return OutboundNode(
                id: name,
                name: name,
                protocolConfig: .socks5(
                    server: endpoint,
                    credentials: Self.credentials(node),
                    tls: Self.tls(node),
                    udp: node.bool(for: "udp", default: false)
                )
            )
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
                    skipCertVerify: node.bool(for: "skip-cert-verify", default: false),
                    network: try Self.transport(node)
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
        case "ssr":
            let endpoint = try ConfigMapping.endpoint(
                host: try node.requiredString("server"),
                port: try node.int(for: "port"),
                field: "port"
            )
            return OutboundNode(
                id: name,
                name: name,
                protocolConfig: .shadowsocksR(
                    server: endpoint,
                    password: try node.requiredString("password"),
                    settings: try ConfigMapping.shadowsocksR(
                        cipher: try node.requiredString("cipher"),
                        protocol: node.string(for: "protocol"),
                        protocolParam: node.string(for: "protocol-param"),
                        obfs: node.string(for: "obfs"),
                        obfsParam: node.string(for: "obfs-param")
                    )
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
                alpn: Self.alpn(node.mapping?["alpn"]),
                network: try Self.transport(node)
            )
        )
    }

    /// Clash `network` + `ws-opts` / legacy `ws-path` / `ws-headers`.
    /// Unsupported transports fail the proxy so it is reported, not
    /// imported as a plain TCP node that cannot connect.
    static func transport(_ node: YAMLNode) throws -> StreamTransport {
        let network = (node.string(for: "network") ?? "tcp").lowercased()
        switch network {
        case "", "tcp":
            return .tcp
        case "ws":
            let opts = node.mapping?["ws-opts"]
            let path = opts?.string(for: "path") ?? node.string(for: "ws-path") ?? "/"
            let headers = (opts?.mapping?["headers"] ?? node.mapping?["ws-headers"])?
                .mapping?.compactMapValues(\.string) ?? [:]
            if opts?.bool(for: "v2ray-http-upgrade", default: false) == true {
                return .httpUpgrade(HTTPUpgradeSettings(path: path, headers: headers))
            }
            return .webSocket(WebSocketSettings.parsing(
                path: path,
                headers: headers,
                maxEarlyData: opts?.int(for: "max-early-data", default: 0) ?? 0,
                earlyDataHeaderName: opts?.string(for: "early-data-header-name") ?? ""
            ))
        case "grpc":
            let opts = node.mapping?["grpc-opts"]
            return .grpc(GRPCSettings(serviceName: opts?.string(for: "grpc-service-name") ?? ""))
        default:
            throw ConfigError.unsupportedValue("network \(network)")
        }
    }

    /// Clash `username` / `password` (HTTP / SOCKS5); `nil` when both are empty.
    static func credentials(_ node: YAMLNode) -> ProxyCredentials? {
        let username = node.string(for: "username") ?? ""
        let password = node.string(for: "password") ?? ""
        guard !username.isEmpty || !password.isEmpty else { return nil }
        return ProxyCredentials(username: username, password: password)
    }

    /// Clash `tls: true` with `sni` / `servername`, `skip-cert-verify`, `alpn`.
    static func tls(_ node: YAMLNode) -> TLSSettings? {
        guard node.bool(for: "tls", default: false) else { return nil }
        return TLSSettings(
            serverName: node.string(for: "sni") ?? node.string(for: "servername"),
            skipCertVerify: node.bool(for: "skip-cert-verify", default: false),
            alpn: alpn(node.mapping?["alpn"])
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
        providers: [String: [OutboundNode]] = [:],
        warnings: inout [ConfigWarning]
    ) -> PolicyGroup? {
        guard let name = node.string(for: "name"), !name.isEmpty else {
            warnings.append(ConfigWarning(kind: .group, text: "?", reason: "group without name"))
            return nil
        }
        let type = node.string(for: "type") ?? "select"
        switch type.lowercased() {
        case "relay":
            // A chain dials each hop through the previous one, which the
            // outbound stack cannot do; never let it go out on one hop.
            warnings.append(ConfigWarning(
                kind: .group,
                text: name,
                reason: "relay (proxy chain) groups are not supported; rules using it fail closed"
            ))
            return nil
        case "smart":
            warnings.append(ConfigWarning(kind: .group, text: name, reason: "smart groups are imported as url-test"))
        case "select", "url-test", "urltest", "fallback", "load-balance", "loadbalance":
            break
        default:
            warnings.append(ConfigWarning(kind: .group, text: name, reason: "unknown group type \(type), imported as select"))
        }
        var members: [String] = node.mapping?["proxies"]?.sequence?.compactMap(\.string) ?? []
        func add(_ ids: [String]) {
            for id in ids where !members.contains(id) {
                members.append(id)
            }
        }

        // mihomo applies the group's filters to provider and include-all
        // proxies, never to the ones listed by name.
        var candidates: [OutboundNode] = []
        for provider in node.mapping?["use"]?.sequence?.compactMap(\.string) ?? [] {
            guard let provided = providers[provider] else {
                warnings.append(ConfigWarning(kind: .group, text: name, reason: "proxy provider \(provider) is not defined"))
                continue
            }
            candidates += provided
        }
        let includeAll = node.bool(for: "include-all")
        if includeAll || node.bool(for: "include-all-providers") {
            candidates += providers.keys.sorted().flatMap { providers[$0] ?? [] }
        }
        if includeAll || node.bool(for: "include-all-proxies") {
            candidates += nodes
        }
        if !candidates.isEmpty {
            add(filtered(candidates, by: node, name: name, warnings: &warnings))
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
            mode: type.lowercased() == "smart" ? .urlTest : ConfigMapping.groupMode(clashType: type),
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

    /// `filter` / `exclude-filter` / `exclude-type` of `node` (a group or a
    /// proxy provider) applied to `nodes`.
    private func filtered(
        _ nodes: [OutboundNode],
        by node: YAMLNode,
        name: String,
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
            if excludedTypes.contains(node.protocolConfig.typeName) { return nil }
            if !include.isEmpty, !include.contains(where: { matches($0, node.name) }) { return nil }
            if exclude.contains(where: { matches($0, node.name) }) { return nil }
            return node.id
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

        var warnings: [ConfigWarning] = []
        groups = ConfigMapping.pruningUndefinedMembers(groups, nodes: nodes, warnings: &warnings)

        // Surge import stays strict: any unsupported rule fails the import.
        let rules = try ruleLines.flatMap { try parseRuleLine($0) }
        return ConfigParseResult(
            router: Router(rules: rules, default: .direct),
            nodeManager: NodeManager(nodes: nodes, groups: groups),
            warnings: warnings
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
            // Surge `obfs=http|tls, obfs-host=…, obfs-uri=…`.
            let plugin = try ConfigMapping.shadowsocksPlugin(
                name: named("obfs") == nil ? nil : "obfs",
                options: [
                    "mode": named("obfs") ?? "",
                    "host": named("obfs-host") ?? "bing.com",
                    "path": named("obfs-uri") ?? "/",
                ],
                server: host
            )
            return OutboundNode(
                id: String(name),
                name: String(name),
                protocolConfig: .shadowsocks(
                    server: endpoint,
                    password: password,
                    cipher: try ConfigMapping.cipher(method, password: password),
                    plugin: plugin
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
                    alpn: named("alpn").flatMap { Self.alpn(.scalar($0)) },
                    network: Self.surgeTransport(named: named)
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
                    skipCertVerify: named("skip-cert-verify")?.lowercased() == "true",
                    network: Self.surgeTransport(named: named)
                )
            )
        case "vmess":
            // `name = vmess, host, port, username=<uuid>[, tls=true, sni=…, ws=true, …]`
            guard parts.count >= 3 else { throw ConfigError.malformedRule(line) }
            guard let port = Int(parts[2]) else { throw ConfigError.invalidPort(parts[2]) }
            let endpoint = try ConfigMapping.endpoint(host: parts[1], port: port, field: "port")
            let tls: TLSSettings? = named("tls")?.lowercased() == "true"
                ? TLSSettings(
                    serverName: named("sni"),
                    skipCertVerify: named("skip-cert-verify")?.lowercased() == "true"
                )
                : nil
            return OutboundNode(
                id: String(name),
                name: String(name),
                protocolConfig: .vmess(
                    server: endpoint,
                    uuid: try ConfigMapping.uuid(named("username")),
                    security: try ConfigMapping.vmessSecurity(named("encrypt-method")),
                    tls: tls,
                    network: Self.surgeTransport(named: named)
                )
            )
        case "http", "https", "socks5", "socks5-tls":
            // `name = http, host, port[, user, pass][, key=value…]`
            guard parts.count >= 3 else { throw ConfigError.malformedRule(line) }
            let host = parts[1]
            guard let port = Int(parts[2]) else { throw ConfigError.invalidPort(parts[2]) }
            // Positional credentials come right after the port. Base64
            // padding (`cGFzcw==`) is not an option: an option has a value.
            let positional = parts.dropFirst(3).prefix { part in
                let pair = part.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                return pair.count < 2 || pair[0].isEmpty || pair[1].isEmpty || pair[1].hasPrefix("=")
            }
            let username = named("username") ?? positional.first
            let password = named("password") ?? positional.dropFirst().first
            let credentials = (username ?? "").isEmpty && (password ?? "").isEmpty
                ? nil
                : ProxyCredentials(username: username ?? "", password: password ?? "")
            let tls: TLSSettings? = type.hasSuffix("s") || type.hasSuffix("-tls")
                ? TLSSettings(
                    serverName: named("sni"),
                    skipCertVerify: named("skip-cert-verify")?.lowercased() == "true"
                )
                : nil
            let endpoint = try ConfigMapping.endpoint(host: host, port: port, field: "port")
            let config: ProtocolConfig = type.hasPrefix("http")
                ? .http(server: endpoint, credentials: credentials, tls: tls)
                : .socks5(
                    server: endpoint,
                    credentials: credentials,
                    tls: tls,
                    udp: named("udp-relay")?.lowercased() == "true"
                )
            return OutboundNode(id: String(name), name: String(name), protocolConfig: config)
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

    /// Surge `ws=true, ws-path=/p, ws-headers=Host:a.com|X-Key:v`.
    static func surgeTransport(named: (String) -> String?) -> StreamTransport {
        guard named("ws")?.lowercased() == "true" else { return .tcp }
        var headers: [String: String] = [:]
        for pair in (named("ws-headers") ?? "").split(separator: "|") {
            let parts = pair.split(separator: ":", maxSplits: 1)
            guard parts.count == 2 else { continue }
            headers[parts[0].trimmingCharacters(in: .whitespaces)] = parts[1].trimmingCharacters(in: .whitespaces)
        }
        return .webSocket(WebSocketSettings.parsing(path: named("ws-path") ?? "/", headers: headers))
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

    /// `TYPE,payload,target[,no-resolve|src]`, `MATCH,target` / `FINAL,target`,
    /// or a logical rule (`AND,((DOMAIN,a),(NETWORK,UDP)),target`).
    /// `providers` resolves `RULE-SET` names (Clash YAML only).
    /// Throws `RuleSkip` for anything that cannot be imported exactly.
    func parseRule(_ raw: String, providers: RuleProviderResolver? = nil) throws -> [RouteRule] {
        let parts = Self.splitTopLevel(raw.trimmingCharacters(in: .whitespaces))
        guard let kind = parts.first?.uppercased(), !kind.isEmpty else {
            throw RuleSkip("malformed rule")
        }

        if kind == "MATCH" || kind == "FINAL" {
            guard parts.count >= 2, !parts[1].isEmpty else { throw RuleSkip("missing policy") }
            if parts[1].uppercased() == "PASS" { return [] }
            return [RouteRule(.matchAll, policy: ConfigMapping.policy(named: parts[1]))]
        }
        guard parts.count >= 3, !parts[1].isEmpty, !parts[2].isEmpty else {
            throw RuleSkip("malformed rule")
        }
        let payload = parts[1]
        // PASS hands the connection to the next rule, which is what leaving
        // the rule out does.
        if parts[2].uppercased() == "PASS" { return [] }
        let policy = ConfigMapping.policy(named: parts[2])
        let options = try Self.options(parts.dropFirst(3))
        let ruleKind = try options.source ? Self.sourceKind(kind) : kind

        // mihomo's `LAN` pseudo-country is not in the MMDB.
        if ruleKind == "GEOIP" || ruleKind == "SRC-GEOIP", payload.uppercased() == "LAN" {
            return try ConfigMapping.privateCIDRs.map {
                let type: RuleType = ruleKind == "GEOIP" ? .ipCIDR($0) : .srcIPCIDR($0)
                return try RouteRule(type: type, policy: policy, noResolve: options.noResolve)
            }
        }
        let matcher = try compileCondition(kind: ruleKind, payload: payload, providers: providers)
        return [RouteRule(matcher, policy: policy, noResolve: options.noResolve)]
    }

    /// One condition without a target: a rule's matcher, a part of AND /
    /// OR / NOT, or a line of a classical rule set.
    func compileCondition(
        kind rawKind: String,
        payload: String,
        providers: RuleProviderResolver?
    ) throws -> RouteRule.HostMatcher {
        let kind = rawKind.uppercased()
        switch kind {
        case "AND", "OR", "NOT":
            let conditions = try Self.logicalOperands(payload).map { body in
                try parseCondition(body, providers: providers)
            }
            switch kind {
            case "AND":
                guard !conditions.isEmpty else { throw RuleSkip("AND without conditions") }
                return .and(conditions)
            case "OR":
                guard !conditions.isEmpty else { throw RuleSkip("OR without conditions") }
                return .or(conditions)
            default:
                guard conditions.count == 1 else { throw RuleSkip("NOT takes exactly one condition") }
                return .not(conditions[0])
            }
        case "RULE-SET":
            guard let providers else { throw RuleSkip("RULE-SET is only supported in Clash profiles") }
            return .ruleSet(try providers.ruleSet(named: payload))
        case "GEOIP" where payload.uppercased() == "LAN":
            return .or(try ConfigMapping.privateCIDRs.map { RuleCondition(try RouteRule.compile(.ipCIDR($0))) })
        case "SRC-GEOIP" where payload.uppercased() == "LAN":
            return .or(try ConfigMapping.privateCIDRs.map { RuleCondition(try RouteRule.compile(.srcIPCIDR($0))) })
        default:
            break
        }
        guard let type = Self.ruleType(kind: kind, payload: payload) else {
            throw RuleSkip("unsupported rule type \(kind)")
        }
        do {
            return try RouteRule.compile(type)
        } catch {
            throw RuleSkip("invalid payload \(payload)")
        }
    }

    /// `TYPE,payload[,no-resolve|src]` (a logical operand or a classical line).
    func parseCondition(_ body: String, providers: RuleProviderResolver?) throws -> RuleCondition {
        let parts = Self.splitTopLevel(body)
        guard parts.count >= 2, let kind = parts.first, !kind.isEmpty else {
            throw RuleSkip("malformed condition \(body)")
        }
        let options = try Self.options(parts.dropFirst(2))
        let conditionKind = try options.source ? Self.sourceKind(kind.uppercased()) : kind
        let matcher = try compileCondition(kind: conditionKind, payload: parts[1], providers: providers)
        return RuleCondition(matcher, noResolve: options.noResolve)
    }

    private static func ruleType(kind: String, payload: String) -> RuleType? {
        switch kind {
        case "DOMAIN": .domain(payload)
        case "DOMAIN-SUFFIX", "DOMAINSUFFIX": .domainSuffix(payload)
        case "DOMAIN-KEYWORD", "DOMAINKEYWORD": .domainKeyword(payload)
        case "DOMAIN-REGEX": .domainRegex(payload)
        case "DOMAIN-WILDCARD": .domainWildcard(payload)
        case "IP-CIDR", "IP-CIDR6", "IPCIDR": .ipCIDR(payload)
        case "SRC-IP-CIDR": .srcIPCIDR(payload)
        case "GEOIP": .geoIP(code: payload)
        case "SRC-GEOIP": .srcGeoIP(code: payload)
        case "IP-ASN": .ipASN(payload)
        case "SRC-IP-ASN": .srcIPASN(payload)
        case "IP-SUFFIX": .ipSuffix(payload)
        case "SRC-IP-SUFFIX": .srcIPSuffix(payload)
        case "GEOSITE": .geosite(tag: payload)
        case "DST-PORT": .dstPort(payload)
        case "SRC-PORT": .srcPort(payload)
        case "IN-PORT": .inPort(payload)
        case "NETWORK": .network(payload)
        case "PROCESS-NAME": .processName(payload)
        case "PROCESS-PATH": .processPath(payload)
        case "PROCESS-NAME-REGEX": .processNameRegex(payload)
        case "PROCESS-PATH-REGEX": .processPathRegex(payload)
        default: nil
        }
    }

    /// `no-resolve`, and `src`, which matches the client's address instead
    /// (`sourceKind`). A rule with any other option is skipped.
    private static func options(_ options: some Collection<String>) throws -> (noResolve: Bool, source: Bool) {
        var noResolve = false
        var source = false
        for option in options where !option.isEmpty {
            switch option.lowercased() {
            case "no-resolve": noResolve = true
            case "src": source = true
            default: throw RuleSkip("unsupported rule option \(option)")
            }
        }
        return (noResolve, source)
    }

    /// The SRC- rule that `src` makes of `kind`, which never looks anything
    /// up (mihomo's `ParseParams` adds `no-resolve`). Other kinds ignore
    /// `src`, as in mihomo, except `RULE-SET`: mihomo then matches the set
    /// with source and destination swapped, ports too, which PrizmX does not.
    private static func sourceKind(_ kind: String) throws -> String {
        switch kind {
        case "IP-CIDR", "IP-CIDR6", "IPCIDR": "SRC-IP-CIDR"
        case "GEOIP": "SRC-GEOIP"
        case "IP-ASN": "SRC-IP-ASN"
        case "IP-SUFFIX": "SRC-IP-SUFFIX"
        case "RULE-SET": throw RuleSkip("unsupported rule option src for RULE-SET")
        default: kind
        }
    }

    /// Splits on commas outside parentheses: `AND,((A,b),(C,d)),P` →
    /// `AND`, `((A,b),(C,d))`, `P`.
    static func splitTopLevel(_ text: String) -> [String] {
        var parts: [String] = []
        var current = ""
        var depth = 0
        for character in text {
            switch character {
            case "(":
                depth += 1
            case ")":
                depth = max(0, depth - 1)
            case "," where depth == 0:
                parts.append(current.trimmingCharacters(in: .whitespaces))
                current = ""
                continue
            default:
                break
            }
            current.append(character)
        }
        parts.append(current.trimmingCharacters(in: .whitespaces))
        return parts
    }

    /// `((A,b),(C,d))` → `A,b` and `C,d`.
    private static func logicalOperands(_ payload: String) throws -> [String] {
        var inner = payload.trimmingCharacters(in: .whitespaces)
        guard inner.hasPrefix("("), inner.hasSuffix(")") else { throw RuleSkip("malformed logical rule") }
        inner = String(inner.dropFirst().dropLast())
        return try splitTopLevel(inner).map { operand in
            let trimmed = operand.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("("), trimmed.hasSuffix(")") else { throw RuleSkip("malformed logical rule") }
            return String(trimmed.dropFirst().dropLast())
        }
    }
}

extension ClashConfigParser {
    /// Rule providers named outside `rules` (DNS `rule-set:` keys), built
    /// the same way RULE-SET builds them. Unknown or failing names are left out.
    static func ruleSets(named names: [String], configText: String) -> [String: RuleSet] {
        guard !names.isEmpty, let root = try? YAMLParser.parse(ConfigText.normalized(configText)) else { return [:] }
        let resolver = RuleProviderResolver(root: root, parser: ClashConfigParser())
        var sets: [String: RuleSet] = [:]
        for name in names {
            if let set = try? resolver.ruleSet(named: name) { sets[name] = set }
        }
        return sets
    }
}

/// Loads `rule-providers` payloads for `RULE-SET` while one profile is
/// parsed: inline payloads, or files `ProviderStore` downloaded. Each set is
/// built once per parse (and reused across parses while its file is
/// unchanged). Problems are collected in `warnings`.
final class RuleProviderResolver {
    private let definitions: [String: ProviderStore.Definition]
    private let inline: [String: [String]]
    private let parser: ClashConfigParser
    private var loaded: [String: RuleSet] = [:]
    private var loading: Set<String> = []
    private(set) var warnings: [ConfigWarning] = []

    init(root: YAMLNode, parser: ClashConfigParser) {
        var definitions: [String: ProviderStore.Definition] = [:]
        for definition in ProviderStore.definitions(in: root) where definition.kind == .rule {
            definitions[definition.name] = definition
        }
        var inline: [String: [String]] = [:]
        for (name, node) in root.mapping?["rule-providers"]?.mapping ?? [:] {
            if let payload = node.mapping?["payload"]?.sequence {
                inline[name] = payload.compactMap(\.string)
            }
        }
        self.definitions = definitions
        self.inline = inline
        self.parser = parser
    }

    func ruleSet(named name: String) throws -> RuleSet {
        if let set = loaded[name] { return set }
        guard let definition = definitions[name] else {
            throw RuleSkip("rule provider \(name) is not defined")
        }
        guard !loading.contains(name) else { throw RuleSkip("rule provider \(name) refers to itself") }
        loading.insert(name)
        defer { loading.remove(name) }
        if definition.format == "mrs" {
            throw RuleSkip("rule provider \(name): mrs (binary) format is not supported")
        }
        let set: RuleSet
        switch definition.type {
        case "inline":
            set = build(definition, entries: inline[name] ?? []).set
        case "http":
            guard let cached = ProviderStore.cachedBody(for: definition) else {
                warn(name, "not downloaded yet; RULE-SET matches nothing until it is")
                set = RuleSet(name: name, domains: [])
                break
            }
            if let hit = RuleSetCache.lookup(definition, modified: cached.modified) {
                set = hit.0
                if hit.1 > 0 { warn(name, "\(hit.1) entries skipped (unsupported or malformed)") }
            } else {
                let built = build(definition, entries: Self.entries(of: cached.text, format: definition.format))
                if definition.behavior != "classical" {
                    // Classical sets may name other providers; keep those per parse.
                    RuleSetCache.store(built.set, skipped: built.skipped, for: definition, modified: cached.modified)
                }
                set = built.set
            }
        default:
            throw RuleSkip("rule provider \(name): \(definition.type) providers are not supported (use http or inline)")
        }
        loaded[name] = set
        return set
    }

    private func build(_ definition: ProviderStore.Definition, entries: [String]) -> (set: RuleSet, skipped: Int) {
        let name = definition.name
        switch definition.behavior ?? "classical" {
        case "domain":
            return (RuleSet(name: name, domains: entries), 0)
        case "ipcidr":
            let set = RuleSet(name: name, cidrs: entries)
            let skipped = entries.count - set.count
            if skipped > 0 { warn(name, "\(skipped) malformed CIDR entries skipped") }
            return (set, skipped)
        default:
            var conditions: [RuleCondition] = []
            var skipped = 0
            for entry in entries {
                if let condition = try? parser.parseCondition(entry, providers: self) {
                    conditions.append(condition)
                } else {
                    skipped += 1
                }
            }
            if skipped > 0 { warn(name, "\(skipped) entries skipped (unsupported or malformed)") }
            return (RuleSet(name: name, conditions: conditions), skipped)
        }
    }

    /// Provider body lines: YAML `payload:`, or plain text, one per line.
    static func entries(of body: String, format: String) -> [String] {
        if format != "text",
           let root = try? YAMLParser.parse(body),
           let payload = root.mapping?["payload"]?.sequence {
            return payload.compactMap(\.string).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
        return body.split(whereSeparator: \.isNewline).compactMap { line in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#"), !trimmed.hasPrefix("//") else { return nil }
            // `- 'entry'` lines of a YAML body that did not parse as a whole.
            var entry = trimmed
            if entry.hasPrefix("- ") { entry.removeFirst(2) }
            return entry.trimmingCharacters(in: CharacterSet(charactersIn: "'\" "))
        }
    }

    private func warn(_ name: String, _ reason: String) {
        warnings.append(ConfigWarning(kind: .rule, text: "RULE-SET \(name)", reason: reason))
    }
}

/// A rule the importer refuses to apply (unsupported or malformed).
struct RuleSkip: Error, Equatable {
    var reason: String
    init(_ reason: String) { self.reason = reason }
}
