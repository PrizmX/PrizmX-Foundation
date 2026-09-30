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

    static func cipher(_ raw: String) throws -> ShadowsocksCipher {
        let key = raw.lowercased()
        if let cipher = ShadowsocksCipher(rawValue: key) {
            return cipher
        }
        throw ConfigError.unsupportedCipher(raw)
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

    /// Clash `interval`. `0` means "no periodic test" in mihomo; the engine
    /// has no off switch, so 0 / negative / unparsable use the default.
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
