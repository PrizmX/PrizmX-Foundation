import Foundation
import PrizmXNodes
import PrizmXProtocols
import PrizmXRules

/// Local overlay merged onto a profile body at parse time.
///
/// The subscription / local YAML is never rewritten. Overlay rules are
/// prepended (first match wins); overlay groups are appended and skipped
/// when a group of the same name already exists in the body.
public struct ProfileOverlay: Sendable, Hashable, Codable, Equatable {
    public static let currentVersion = 1
    public static let empty = ProfileOverlay()

    public var version: Int
    public var rules: [OverlayRule]
    public var groups: [OverlayGroup]

    public var isEmpty: Bool { rules.isEmpty && groups.isEmpty }

    public init(
        version: Int = ProfileOverlay.currentVersion,
        rules: [OverlayRule] = [],
        groups: [OverlayGroup] = []
    ) {
        self.version = version
        self.rules = rules
        self.groups = groups
    }

    /// Prepends overlay rules and appends overlay groups onto a parsed body.
    public func apply(to parsed: (Router, NodeManager)) throws -> (Router, NodeManager) {
        guard !isEmpty else { return parsed }
        let compiledRules = try rules.map { try $0.compile() }
        let nodes = Array(parsed.1.nodesByID.values)
        var groups = Array(parsed.1.groupsByName.values)
        var names = Set(groups.map(\.name))
        for item in self.groups {
            let name = item.name.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !name.isEmpty else { continue }
            switch name.uppercased() {
            case "DIRECT", "REJECT", "REJECT-DROP":
                continue
            default:
                break
            }
            guard names.insert(name).inserted else { continue }
            let group = item.compile()
            guard !group.nodeIDs.isEmpty else { continue }
            groups.append(group)
        }
        let router = Router(
            rules: compiledRules + parsed.0.rules,
            default: parsed.0.defaultPolicy
        )
        return (router, NodeManager(nodes: nodes, groups: groups))
    }
}

/// One user-owned routing rule. Compiled with the same matchers as Clash YAML.
public struct OverlayRule: Sendable, Hashable, Codable, Equatable, Identifiable {
    public enum Kind: String, Sendable, Codable, Hashable, CaseIterable, Identifiable {
        case domain
        case domainSuffix
        case domainKeyword
        case ipCIDR
        case geoIP
        case geosite
        case matchAll

        public var id: String { rawValue }

        public var clashType: String {
            switch self {
            case .domain: "DOMAIN"
            case .domainSuffix: "DOMAIN-SUFFIX"
            case .domainKeyword: "DOMAIN-KEYWORD"
            case .ipCIDR: "IP-CIDR"
            case .geoIP: "GEOIP"
            case .geosite: "GEOSITE"
            case .matchAll: "MATCH"
            }
        }
    }

    public var id: UUID
    public var type: Kind
    public var payload: String
    public var policy: String
    public var noResolve: Bool

    public init(
        id: UUID = UUID(),
        type: Kind,
        payload: String,
        policy: String,
        noResolve: Bool = false
    ) {
        self.id = id
        self.type = type
        self.payload = payload
        self.policy = policy
        self.noResolve = noResolve
    }

    public func compile() throws -> RouteRule {
        let mapped = ConfigMapping.policy(named: policy)
        let value = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        switch type {
        case .domain, .domainSuffix, .domainKeyword, .geoIP, .geosite:
            guard !value.isEmpty else { throw ConfigError.malformedRule(type.clashType) }
            fallthrough
        case .matchAll, .ipCIDR:
            do {
                return try RouteRule(type: ruleType(value), policy: mapped, noResolve: noResolve)
            } catch is RuleCompileError {
                throw ConfigError.malformedRule("\(type.clashType) \(value)")
            }
        }
    }

    /// Rebuilds the `RuleType` for the shared throwing compiler.
    private func ruleType(_ value: String) -> RuleType {
        switch type {
        case .domain: .domain(value)
        case .domainSuffix: .domainSuffix(value)
        case .domainKeyword: .domainKeyword(value)
        case .geoIP: .geoIP(code: value)
        case .geosite: .geosite(tag: value)
        case .matchAll: .matchAll
        case .ipCIDR: .ipCIDR(value)
        }
    }
}

/// One user-owned policy group. Same-name groups in the profile body win.
public struct OverlayGroup: Sendable, Hashable, Codable, Equatable, Identifiable {
    public var id: UUID
    public var name: String
    public var mode: String
    public var members: [String]
    public var selectedMember: String?
    public var testURL: String?
    public var intervalSeconds: Int?
    public var toleranceMilliseconds: Int?

    public init(
        id: UUID = UUID(),
        name: String,
        mode: String = "select",
        members: [String],
        selectedMember: String? = nil,
        testURL: String? = nil,
        intervalSeconds: Int? = nil,
        toleranceMilliseconds: Int? = nil
    ) {
        self.id = id
        self.name = name
        self.mode = mode
        self.members = members
        self.selectedMember = selectedMember
        self.testURL = testURL
        self.intervalSeconds = intervalSeconds
        self.toleranceMilliseconds = toleranceMilliseconds
    }

    public func compile() -> PolicyGroup {
        let nodeIDs = members.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        return PolicyGroup(
            name: name.trimmingCharacters(in: .whitespacesAndNewlines),
            mode: ConfigMapping.groupMode(clashType: mode),
            nodeIDs: nodeIDs,
            selectedNodeID: selectedMember ?? nodeIDs.first,
            testURL: testURL ?? PolicyGroup.defaultTestURL,
            interval: .seconds(max(1, intervalSeconds ?? 300)),
            tolerance: .milliseconds(max(0, toleranceMilliseconds ?? 50))
        )
    }
}

/// Active overlay JSON next to `tunnel/active.conf` (App Group).
public enum ProfileOverlayStore: Sendable {
    public static let activeRelativePath = "tunnel/overlay.json"

    public static func write(
        _ overlay: ProfileOverlay,
        relativePath: String = activeRelativePath,
        appGroupIdentifier: String = TunnelConfigStorage.defaultAppGroupIdentifier,
        directoryName: String = TunnelConfigStorage.defaultDirectoryName
    ) throws -> String {
        guard let root = TunnelConfigStorage.containerURL(
            appGroupIdentifier: appGroupIdentifier,
            directoryName: directoryName
        ) else {
            throw TunnelConfigStorageError.appGroupUnavailable
        }
        let url = root.appendingPathComponent(relativePath)
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try encoder.encode(overlay).write(to: url, options: .atomic)
        return relativePath
    }

    public static func read(
        relativePath: String,
        appGroupIdentifier: String = TunnelConfigStorage.defaultAppGroupIdentifier,
        directoryName: String = TunnelConfigStorage.defaultDirectoryName
    ) -> ProfileOverlay {
        guard let root = TunnelConfigStorage.containerURL(
            appGroupIdentifier: appGroupIdentifier,
            directoryName: directoryName
        ) else {
            return .empty
        }
        let url = root.appendingPathComponent(relativePath)
        guard let data = try? Data(contentsOf: url),
              let overlay = try? JSONDecoder().decode(ProfileOverlay.self, from: data)
        else {
            return .empty
        }
        return overlay
    }

    public static func load(from provider: [String: Any]) -> ProfileOverlay {
        guard let path = provider[TunnelProviderKeys.overlayPath] as? String else {
            return .empty
        }
        return read(relativePath: path)
    }
}
