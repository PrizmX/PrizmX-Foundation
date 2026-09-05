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

/// Convenience entry that picks Clash YAML vs sing-box JSON from the first non-space character.
public enum ConfigAdapter: Sendable {
    public static func parse(rawString: String) throws -> (Router, NodeManager) {
        let trimmed = rawString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw ConfigError.emptyInput }
        if trimmed.first == "{" || trimmed.first == "[" {
            return try SingboxConfigParser().parse(rawString: rawString)
        }
        return try ClashConfigParser().parse(rawString: rawString)
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
        case "url-test", "fallback", "load-balance", "urltest":
            return .urlTest
        default:
            return .select
        }
    }
}
