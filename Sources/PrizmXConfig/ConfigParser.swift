import Foundation
import PrizmXNodes
import PrizmXProtocols
import PrizmXRules

// MARK: - Errors / protocol

/// Failures while importing a third-party config file.
public enum ConfigError: Error, Equatable, Sendable {
    case emptyInput
    case yamlSyntax(String)
    case jsonSyntax(String)
    case missingField(String)
    case invalidPort(String)
    case unsupportedCipher(String)
    case malformedRule(String)
    /// A protocol option the importer cannot honor (plugin, transport, …).
    case unsupportedValue(String)
}

/// Imports a textual config into the in-memory `Router` + `NodeManager` model.
public protocol ConfigParserProtocol: Sendable {
    func parse(rawString: String) throws -> (Router, NodeManager)
}

/// An entry the importer skipped or could not map faithfully. Hosts should
/// surface these: a skipped rule means traffic falls through to later rules.
public struct ConfigWarning: Sendable, Hashable, CustomStringConvertible {
    public enum Kind: String, Sendable, Hashable {
        case rule
        case proxy
        case group
    }

    public var kind: Kind
    /// The offending entry (rule line, proxy or group name).
    public var text: String
    public var reason: String

    public init(kind: Kind, text: String, reason: String) {
        self.kind = kind
        self.text = text
        self.reason = reason
    }

    public var description: String {
        "\(kind.rawValue) \"\(text)\": \(reason)"
    }
}

/// Parse output plus the warnings collected while importing.
public struct ConfigParseResult: Sendable {
    public var router: Router
    public var nodeManager: NodeManager
    public var warnings: [ConfigWarning]

    public init(router: Router, nodeManager: NodeManager, warnings: [ConfigWarning] = []) {
        self.router = router
        self.nodeManager = nodeManager
        self.warnings = warnings
    }

    public var tuple: (Router, NodeManager) { (router, nodeManager) }
}

/// Convenience entry that picks Clash YAML vs sing-box JSON from content, not
/// the file extension. Tries the likely parser first, then the other once.
public enum ConfigAdapter: Sendable {
    public static func parse(
        rawString: String,
        overlay: ProfileOverlay = .empty
    ) throws -> (Router, NodeManager) {
        try parseWithWarnings(rawString: rawString, overlay: overlay).tuple
    }

    /// Same as `parse`, plus the entries that were skipped (unsupported
    /// rules, proxies, groups) so the host can show them.
    public static func parseWithWarnings(
        rawString: String,
        overlay: ProfileOverlay = .empty
    ) throws -> ConfigParseResult {
        let trimmed = ConfigText.normalized(rawString)
        guard !trimmed.isEmpty else { throw ConfigError.emptyInput }
        var parsed: ConfigParseResult
        // sing-box configs are JSON objects. A leading `[` is a Surge INI
        // section header (`[General]`), not a JSON array. Our YAML subset
        // does not accept JSON documents, so a failed primary parse can
        // safely fall through once; if both fail, keep the primary error.
        if trimmed.first == "{" {
            parsed = try parsePreferringJSON(trimmed)
        } else {
            parsed = try parsePreferringYAML(trimmed)
        }
        let applied = try overlay.apply(to: parsed.tuple)
        parsed.router = applied.0
        parsed.nodeManager = applied.1
        return parsed
    }

    private static func parsePreferringYAML(_ rawString: String) throws -> ConfigParseResult {
        do {
            return try ClashConfigParser().parseWithWarnings(rawString: rawString)
        } catch let yamlError {
            do {
                return try SingboxConfigParser().parseWithWarnings(rawString: rawString)
            } catch {
                throw yamlError
            }
        }
    }

    private static func parsePreferringJSON(_ rawString: String) throws -> ConfigParseResult {
        do {
            return try SingboxConfigParser().parseWithWarnings(rawString: rawString)
        } catch let jsonError {
            do {
                return try ClashConfigParser().parseWithWarnings(rawString: rawString)
            } catch {
                throw jsonError
            }
        }
    }
}

enum ConfigText {
    /// Drops a leading UTF-8 BOM (U+FEFF); `.whitespaces` does not cover it.
    static func strippingBOM(_ text: String) -> String {
        guard text.unicodeScalars.first == "\u{FEFF}" else { return text }
        return String(String.UnicodeScalarView(text.unicodeScalars.dropFirst()))
    }

    static func normalized(_ text: String) -> String {
        strippingBOM(text).trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

// MARK: - Shared mapping

enum ConfigMapping {
    static func endpoint(host: String, port: Int, field: String) throws -> Endpoint {
        guard (1...65535).contains(port), let value = UInt16(exactly: port) else {
            throw ConfigError.invalidPort("\(field)=\(port)")
        }
        if let v4 = IPv4Address(parsing: host) {
            return Endpoint(host: .ipv4(v4), port: value)
        }
        if let v6 = IPv6Address(parsing: host) {
            return Endpoint(host: .ipv6(v6), port: value)
        }
        guard !host.isEmpty else {
            throw ConfigError.missingField(field)
        }
        return Endpoint(domain: host, port: value)
    }

    /// Method plus password: Shadowsocks 2022 passwords must be base64 keys
    /// of the method's length, checked here rather than at connect time.
    static func cipher(_ raw: String, password: String) throws -> ShadowsocksCipher {
        let cipher = try cipher(raw)
        if cipher.is2022 {
            do {
                _ = try Shadowsocks2022Keys(cipher: cipher, password: password)
            } catch {
                throw ConfigError.unsupportedValue("\(raw) password must be base64 key(s) of the method's length")
            }
        }
        return cipher
    }

    static func cipher(_ raw: String) throws -> ShadowsocksCipher {
        let key = raw.lowercased()
        if let cipher = ShadowsocksCipher(rawValue: key) {
            return cipher
        }
        // mihomo / shadowsocks-rust aliases for the IETF ChaCha20-Poly1305 AEAD.
        if key == "chacha20-poly1305" || key == "aead_chacha20_poly1305" {
            return .chacha20IETFPoly1305
        }
        throw ConfigError.unsupportedCipher(raw)
    }

    /// ShadowsocksR options. Unknown methods, protocols (`auth_chain_b`…) or
    /// obfs (`random_head`…) fail the proxy so it is reported at import.
    /// `_compatible` names are server-side fallbacks; clients send the same.
    static func shadowsocksR(
        cipher: String,
        protocol: String?,
        protocolParam: String?,
        obfs: String?,
        obfsParam: String?
    ) throws -> ShadowsocksRSettings {
        func name(_ raw: String?, default value: String) -> String {
            let key = (raw ?? "").lowercased()
            guard !key.isEmpty else { return value }
            return key.hasSuffix("_compatible") ? String(key.dropLast("_compatible".count)) : key
        }
        let method = cipher.lowercased()
        // mihomo spells the null cipher `dummy`.
        guard let ssrCipher = SSRCipher(rawValue: method == "dummy" ? "none" : method) else {
            throw ConfigError.unsupportedCipher(cipher)
        }
        let protocolName = name(`protocol`, default: "origin")
        guard let protocolKind = SSRProtocolKind(rawValue: protocolName) else {
            throw ConfigError.unsupportedValue("ssr protocol \(protocolName)")
        }
        let obfsName = name(obfs, default: "plain")
        guard let obfsKind = SSRObfsKind(rawValue: obfsName) else {
            throw ConfigError.unsupportedValue("ssr obfs \(obfsName)")
        }
        return ShadowsocksRSettings(
            cipher: ssrCipher,
            protocolKind: protocolKind,
            protocolParam: protocolParam ?? "",
            obfs: obfsKind,
            obfsParam: obfsParam ?? ""
        )
    }

    /// VMess `cipher` / `security`. Legacy CFB / `aes-128-cfb` bodies (the
    /// `alterId > 0` era) are not supported.
    static func vmessSecurity(_ raw: String?) throws -> VMessSecurity {
        let key = (raw ?? "auto").lowercased()
        if key.isEmpty { return .auto }
        if let security = VMessSecurity(rawValue: key) { return security }
        if key == "chacha20-ietf-poly1305" { return .chacha20Poly1305 }
        throw ConfigError.unsupportedValue("vmess cipher \(key)")
    }

    /// A user id that parses as a UUID (fails the proxy at import, not at
    /// the first connection).
    static func uuid(_ raw: String?) throws -> String {
        guard let raw, !raw.isEmpty else { throw ConfigError.missingField("uuid") }
        guard UUID(uuidString: raw) != nil else { throw ConfigError.unsupportedValue("uuid \(raw)") }
        return raw
    }

    /// SIP003 plugin by name with flat string options (Clash `plugin-opts`,
    /// or SIP003 `plugin_opts` split by `sip003Options`). `nil` name means
    /// no plugin; anything but simple-obfs / v2ray-plugin websocket fails.
    static func shadowsocksPlugin(
        name: String?,
        options: [String: String],
        headers: [String: String] = [:],
        server: String
    ) throws -> ShadowsocksPlugin? {
        guard let name = name?.lowercased(), !name.isEmpty else { return nil }
        func flag(_ key: String) -> Bool {
            guard let value = options[key]?.lowercased() else { return false }
            return value.isEmpty || value == "true" || value == "1"
        }
        switch name {
        case "obfs", "obfs-local", "simple-obfs":
            let raw = (options["mode"] ?? options["obfs"] ?? "http").lowercased()
            guard let mode = SimpleObfsSettings.Mode(rawValue: raw) else {
                throw ConfigError.unsupportedValue("obfs mode \(raw)")
            }
            return .obfs(SimpleObfsSettings(
                mode: mode,
                host: options["host"] ?? options["obfs-host"] ?? "bing.com",
                path: options["obfs-uri"] ?? options["path"] ?? "/"
            ))
        case "v2ray-plugin":
            let mode = (options["mode"] ?? "websocket").lowercased()
            guard mode == "websocket" else {
                throw ConfigError.unsupportedValue("v2ray-plugin mode \(mode)")
            }
            let host = options["host"].flatMap { $0.isEmpty ? nil : $0 } ?? server
            let tls: TLSSettings? = flag("tls")
                ? TLSSettings(serverName: host, skipCertVerify: flag("skip-cert-verify"))
                : nil
            // `mux` defaults on, as in v2ray-plugin and Clash.
            let mux = options["mux"].map { !["false", "0"].contains($0.lowercased()) } ?? true
            return .v2ray(
                webSocket: WebSocketSettings(path: options["path"] ?? "/", host: host, headers: headers),
                tls: tls,
                mux: mux
            )
        default:
            throw ConfigError.unsupportedValue("plugin \(name)")
        }
    }

    /// SIP003 `key=value;flag;…` plugin options.
    static func sip003Options(_ raw: String?) -> [String: String] {
        var options: [String: String] = [:]
        for item in (raw ?? "").split(separator: ";") {
            let pair = item.split(separator: "=", maxSplits: 1).map {
                $0.trimmingCharacters(in: .whitespaces)
            }
            guard let key = pair.first, !key.isEmpty else { continue }
            options[key.lowercased()] = pair.count == 2 ? pair[1] : ""
        }
        return options
    }

    static func policy(named target: String) -> Policy {
        switch target.uppercased() {
        case "DIRECT", "DIRECTLY":
            return .direct
        case "REJECT", "REJECT-DROP", "BLOCK", "BLACKHOLE":
            return .reject
        default:
            return .proxy(targetGroup: target)
        }
    }

    /// One singleton group per node so a rule can point at a proxy name, not only a group.
    static func implicitGroups(for nodes: [OutboundNode]) -> [PolicyGroup] {
        nodes.map { node in
            PolicyGroup(
                name: node.id,
                mode: .select,
                nodeIDs: [node.id],
                selectedNodeID: node.id
            )
        }
    }

    static func groupMode(clashType: String) -> PolicyGroup.Mode {
        switch clashType.lowercased() {
        case "url-test", "urltest":
            return .urlTest
        case "fallback":
            return .fallback
        case "load-balance", "loadbalance":
            return .loadBalance
        default:
            return .select
        }
    }

    static func loadBalanceStrategy(_ raw: String?) -> PolicyGroup.LoadBalanceStrategy {
        switch raw?.lowercased() {
        case "round-robin", "roundrobin":
            return .roundRobin
        default:
            return .consistentHashing
        }
    }

    /// Clash `interval`. mihomo turns 0 into 300 s for groups that list their
    /// `proxies` inline (only `use:` provider groups inherit the provider's
    /// setting, where 0 disables checks), so 0 / negative / unparsable use
    /// the default here too.
    static func interval(_ raw: String?, defaultSeconds: Int = 300) -> Duration {
        guard let raw else { return .seconds(defaultSeconds) }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let parsed: Duration?
        if let seconds = Int(trimmed) {
            parsed = .seconds(seconds)
        } else if trimmed.hasSuffix("ms"), let value = Int(trimmed.dropLast(2)) {
            parsed = .milliseconds(value)
        } else if trimmed.hasSuffix("s"), let value = Int(trimmed.dropLast()) {
            parsed = .seconds(value)
        } else if trimmed.hasSuffix("m"), let value = Int(trimmed.dropLast()) {
            parsed = .seconds(min(value, Int(Int32.max)) * 60)
        } else if trimmed.hasSuffix("h"), let value = Int(trimmed.dropLast()) {
            parsed = .seconds(min(value, Int(Int32.max)) * 3_600)
        } else {
            parsed = nil
        }
        guard let parsed, parsed > .zero else { return .seconds(defaultSeconds) }
        return max(parsed, .seconds(1))
    }

    /// mihomo `GEOIP,LAN` / sing-box `ip_is_private`: private, loopback,
    /// link-local, CGNAT, multicast, unspecified and broadcast ranges.
    static let privateCIDRs = [
        "0.0.0.0/32", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
        "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
    ]

    /// Drops group members the config does not define: proxies skipped as
    /// unsupported or invalid, typos, provider-only names. Kept, such a name
    /// fails the group whenever it is picked; a `select` group starting on
    /// one fails every flow until the user switches. A group left empty is
    /// dropped as well, and the pass repeats since other groups may list it.
    static func pruningUndefinedMembers(
        _ groups: [PolicyGroup],
        nodes: [OutboundNode],
        warnings: inout [ConfigWarning]
    ) -> [PolicyGroup] {
        let nodeIDs = Set(nodes.map(\.id))
        var groups = groups
        while true {
            let groupNames = Set(groups.map(\.name))
            var changed = false
            let isDefined = { (member: String) in
                nodeIDs.contains(member) || groupNames.contains(member) || NodeManager.isBuiltinMember(member)
            }
            groups = groups.compactMap { group in
                let dropped = group.nodeIDs.filter { !isDefined($0) }
                guard !dropped.isEmpty else { return group }
                changed = true
                let kept = group.nodeIDs.filter(isDefined)
                let listed = dropped.prefix(3).joined(separator: ", ") + (dropped.count > 3 ? ", …" : "")
                warnings.append(ConfigWarning(
                    kind: .group,
                    text: group.name,
                    reason: "dropped \(dropped.count) undefined member(s): \(listed)"
                ))
                guard !kept.isEmpty else {
                    warnings.append(ConfigWarning(
                        kind: .group,
                        text: group.name,
                        reason: "no usable members; rules targeting it will fail closed"
                    ))
                    return nil
                }
                let selected = group.selectedNodeID.flatMap { kept.contains($0) ? $0 : nil } ?? kept.first
                return PolicyGroup(
                    name: group.name,
                    mode: group.mode,
                    nodeIDs: kept,
                    selectedNodeID: selected,
                    iconURL: group.iconURL,
                    testURL: group.testURL,
                    interval: group.interval,
                    tolerance: group.tolerance,
                    loadBalanceStrategy: group.loadBalanceStrategy
                )
            }
            if !changed { return groups }
        }
    }

    /// Rules whose proxy target is neither a node nor a group fail closed at
    /// connect time; report each such target once.
    static func missingTargetWarnings(rules: [RouteRule], manager: NodeManager) -> [ConfigWarning] {
        var counts: [String: Int] = [:]
        var order: [String] = []
        for rule in rules {
            guard case .proxy(let target) = rule.policy,
                  manager.nodesByID[target] == nil,
                  manager.groupsByName[target] == nil
            else { continue }
            if counts[target] == nil { order.append(target) }
            counts[target, default: 0] += 1
        }
        return order.map { target in
            ConfigWarning(
                kind: .group,
                text: target,
                reason: "referenced by \(counts[target] ?? 0) rule(s) but not defined; matching connections fail"
            )
        }
    }

    static func toleranceMilliseconds(_ raw: Int?, default defaultValue: Int = 50) -> Duration {
        .milliseconds(max(0, raw ?? defaultValue))
    }
}
