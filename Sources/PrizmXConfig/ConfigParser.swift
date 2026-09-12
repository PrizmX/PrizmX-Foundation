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

/// Convenience entry that picks Clash YAML vs sing-box JSON from content, not
/// the file extension. Tries the likely parser first, then the other once.
public enum ConfigAdapter: Sendable {
    public static func parse(
        rawString: String,
        overlay: ProfileOverlay = .empty
    ) throws -> (Router, NodeManager) {
        let trimmed = rawString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw ConfigError.emptyInput }
        let parsed: (Router, NodeManager)
        // sing-box configs are JSON objects. A leading `[` is a Surge INI
        // section header (`[General]`), not a JSON array. Our YAML subset
        // does not accept JSON documents, so a failed primary parse can
        // safely fall through once; if both fail, keep the primary error.
        if trimmed.first == "{" {
            parsed = try parsePreferringJSON(rawString)
        } else {
            parsed = try parsePreferringYAML(rawString)
        }
        return try overlay.apply(to: parsed)
    }

    private static func parsePreferringYAML(_ rawString: String) throws -> (Router, NodeManager) {
        do {
            return try ClashConfigParser().parse(rawString: rawString)
        } catch let yamlError {
            do {
                return try SingboxConfigParser().parse(rawString: rawString)
            } catch {
                throw yamlError
            }
        }
    }

    private static func parsePreferringJSON(_ rawString: String) throws -> (Router, NodeManager) {
        do {
            return try SingboxConfigParser().parse(rawString: rawString)
        } catch let jsonError {
            do {
                return try ClashConfigParser().parse(rawString: rawString)
            } catch {
                throw jsonError
            }
        }
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

    static func interval(_ raw: String?, defaultSeconds: Int = 300) -> Duration {
        guard let raw, !raw.isEmpty else { return .seconds(defaultSeconds) }
        if let seconds = Int(raw) { return .seconds(max(1, seconds)) }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if trimmed.hasSuffix("ms"), let value = Int(trimmed.dropLast(2)) {
            return .milliseconds(max(1, value))
        }
        if trimmed.hasSuffix("s"), let value = Int(trimmed.dropLast()) {
            return .seconds(max(1, value))
        }
        if trimmed.hasSuffix("m"), let value = Int(trimmed.dropLast()) {
            return .seconds(max(1, value) * 60)
        }
        if trimmed.hasSuffix("h"), let value = Int(trimmed.dropLast()) {
            return .seconds(max(1, value) * 3_600)
        }
        return .seconds(defaultSeconds)
    }

    static func toleranceMilliseconds(_ raw: Int?, default defaultValue: Int = 50) -> Duration {
        .milliseconds(max(0, raw ?? defaultValue))
    }
}
