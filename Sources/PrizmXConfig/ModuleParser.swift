import Foundation
import PrizmXRules

/// Format of an imported module overlay file.
public enum ModuleFormat: String, Sendable, Codable, Equatable, Hashable {
    /// Surge module (`.sgmodule`, INI sections).
    case sgmodule
    /// Stash override (`.stoverride`, YAML).
    case stoverride
}

/// Parsed representation of one Surge `.sgmodule` or Stash `.stoverride` file.
/// Non-MITM sections (rules, hosts, fake-ip-filter) are extracted cleanly;
/// MITM / URL Rewrite / HTTP Script sections are reported in `skipped`.
public struct ParsedModule: Sendable, Equatable {
    public var format: ModuleFormat
    public var name: String
    public var summary: String
    public var category: String?
    public var defaultArguments: [String: String]
    public var rules: [OverlayRule]
    public var hosts: [String: [String]]
    public var fakeIPFilters: [String]
    public var skipped: [String]

    public init(
        format: ModuleFormat,
        name: String,
        summary: String = "",
        category: String? = nil,
        defaultArguments: [String: String] = [:],
        rules: [OverlayRule] = [],
        hosts: [String: [String]] = [:],
        fakeIPFilters: [String] = [],
        skipped: [String] = []
    ) {
        self.format = format
        self.name = name
        self.summary = summary
        self.category = category
        self.defaultArguments = defaultArguments
        self.rules = rules
        self.hosts = hosts
        self.fakeIPFilters = fakeIPFilters
        self.skipped = skipped
    }

    /// Converts this module's active non-MITM sections into a `ProfileOverlay`.
    public var overlay: ProfileOverlay {
        ProfileOverlay(
            rules: rules,
            groups: [],
            hosts: hosts,
            fakeIPFilters: fakeIPFilters
        )
    }
}

public enum ModuleParseError: Error, Sendable, Equatable, LocalizedError {
    case emptyContent
    case invalidYAML(String)

    public var errorDescription: String? {
        switch self {
        case .emptyContent: "Module content is empty."
        case .invalidYAML(let detail): "Invalid module YAML: \(detail)"
        }
    }
}

/// Parses Surge `.sgmodule` (INI) and Stash `.stoverride` (YAML) modules.
public enum ModuleParser: Sendable {
    public static func parse(
        _ raw: String,
        fallbackName: String = "Untitled Module",
        argumentOverrides: [String: String] = [:]
    ) throws -> ParsedModule {
        let normalized = ConfigText.normalized(raw)
        guard !normalized.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ModuleParseError.emptyContent
        }
        if looksLikeSGModule(normalized) {
            return parseSGModule(normalized, fallbackName: fallbackName, argumentOverrides: argumentOverrides)
        }
        return try parseStOverride(normalized, fallbackName: fallbackName, argumentOverrides: argumentOverrides)
    }

    private static func looksLikeSGModule(_ text: String) -> Bool {
        for rawLine in text.split(whereSeparator: { $0.isNewline }) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            if line.hasPrefix("#!name") || line.hasPrefix("#!desc") || line.hasPrefix("#!category") || line.hasPrefix("#!arguments") {
                return true
            }
            if line.hasPrefix("[") && line.hasSuffix("]") {
                return true
            }
            if line.hasPrefix("#") || line.hasPrefix(";") { continue }
            return false
        }
        return false
    }

    // MARK: - Surge .sgmodule

    private static func parseSGModule(
        _ text: String,
        fallbackName: String,
        argumentOverrides: [String: String]
    ) -> ParsedModule {
        var name = fallbackName
        var summary = ""
        var category: String?
        var defaultArgs: [String: String] = [:]

        // First pass: extract #! metadata & default arguments.
        for rawLine in text.split(whereSeparator: { $0.isNewline }) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard line.hasPrefix("#!") else { continue }
            let body = line.dropFirst(2)
            guard let eq = body.firstIndex(of: "=") else { continue }
            let key = body[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let val = body[body.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            switch key {
            case "name":
                if !val.isEmpty { name = val }
            case "desc":
                summary = val
            case "category":
                if !val.isEmpty { category = val }
            case "arguments":
                for pair in val.split(separator: ",") {
                    guard let colon = pair.firstIndex(of: ":") else { continue }
                    let argKey = pair[..<colon].trimmingCharacters(in: .whitespaces)
                    let argVal = pair[pair.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                    if !argKey.isEmpty { defaultArgs[argKey] = argVal }
                }
            default:
                break
            }
        }

        let effectiveArgs = defaultArgs.merging(argumentOverrides) { _, override in override }
        let expanded = substituteArguments(effectiveArgs, in: text)

        var section = ""
        var rules: [OverlayRule] = []
        var hosts: [String: [String]] = [:]
        var fakeIPFilters: [String] = []
        var skipped: [String] = []
        var skippedSections = Set<String>()

        for rawLine in expanded.split(whereSeparator: { $0.isNewline }) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") || line.hasPrefix("//") {
                continue
            }
            if line.hasPrefix("[") && line.hasSuffix("]") {
                section = String(line.dropFirst().dropLast())
                    .trimmingCharacters(in: .whitespaces)
                    .lowercased()
                continue
            }

            switch section {
            case "rule":
                if let rule = parseRuleLine(line) {
                    rules.append(rule)
                } else {
                    skipped.append("[Rule] unsupported: \(line)")
                }
            case "host":
                if let (host, addrs) = parseHostLine(line) {
                    hosts[host] = addrs
                }
            case "general":
                if let eq = line.firstIndex(of: "=") {
                    let key = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
                    let val = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
                    if key == "always-real-ip" || key == "skip-proxy" || key == "fake-ip-filter" {
                        let cleaned = val.replacingOccurrences(of: "%APPEND%", with: "")
                            .replacingOccurrences(of: "%INSERT%", with: "")
                        for item in cleaned.split(separator: ",") {
                            let pattern = item.trimmingCharacters(in: .whitespaces)
                            if !pattern.isEmpty && !pattern.contains("/") && pattern.contains(".") {
                                fakeIPFilters.append(pattern)
                            }
                        }
                    }
                }
            case "mitm":
                if skippedSections.insert("mitm").inserted {
                    skipped.append("[MITM] skipped (requires MITM / PrizmX Pro)")
                }
            case "url rewrite", "header rewrite", "body rewrite", "map local":
                if skippedSections.insert(section).inserted {
                    skipped.append("[\(section)] skipped (requires MITM / PrizmX Pro)")
                }
            case "script":
                if skippedSections.insert("script").inserted {
                    skipped.append("[Script] in modules requires MITM or manual script import")
                }
            default:
                break
            }
        }

        return ParsedModule(
            format: .sgmodule,
            name: name,
            summary: summary,
            category: category,
            defaultArguments: defaultArgs,
            rules: rules,
            hosts: hosts,
            fakeIPFilters: Array(NSOrderedSet(array: fakeIPFilters)) as? [String] ?? fakeIPFilters,
            skipped: skipped
        )
    }

    // MARK: - Stash .stoverride (YAML)

    private static func parseStOverride(
        _ text: String,
        fallbackName: String,
        argumentOverrides: [String: String]
    ) throws -> ParsedModule {
        let expanded = substituteArguments(argumentOverrides, in: text)
        let root: YAMLNode
        do {
            root = try YAMLParser.parse(expanded)
        } catch {
            throw ModuleParseError.invalidYAML(error.localizedDescription)
        }
        guard let map = root.mapping else {
            throw ModuleParseError.invalidYAML("Root document must be a YAML mapping.")
        }

        let name = root.string(for: "name") ?? fallbackName
        let summary = root.string(for: "desc") ?? root.string(for: "description") ?? ""
        let category = root.string(for: "category")

        var rules: [OverlayRule] = []
        var hosts: [String: [String]] = [:]
        var fakeIPFilters: [String] = []
        var skipped: [String] = []

        if let ruleList = map["rules"]?.sequence {
            for item in ruleList {
                guard let line = item.string?.trimmingCharacters(in: .whitespaces), !line.isEmpty else { continue }
                if let rule = parseRuleLine(line) {
                    rules.append(rule)
                } else {
                    skipped.append("rules: unsupported \(line)")
                }
            }
        }

        if let hostMap = map["hosts"]?.mapping {
            for (host, value) in hostMap {
                if let single = value.string?.trimmingCharacters(in: .whitespaces), !single.isEmpty {
                    hosts[host] = [single]
                } else if let seq = value.sequence {
                    let list = seq.compactMap { $0.string?.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                    if !list.isEmpty { hosts[host] = list }
                }
            }
        }

        if let dnsMap = map["dns"]?.mapping,
           let filters = dnsMap["fake-ip-filter"]?.sequence {
            for item in filters {
                if let pattern = item.string?.trimmingCharacters(in: .whitespaces), !pattern.isEmpty {
                    fakeIPFilters.append(pattern)
                }
            }
        }

        if let httpMap = map["http"]?.mapping {
            if httpMap["mitm"] != nil {
                skipped.append("http.mitm skipped (requires MITM / PrizmX Pro)")
            }
            if httpMap["rewrite"] != nil {
                skipped.append("http.rewrite skipped (requires MITM / PrizmX Pro)")
            }
            if httpMap["script"] != nil {
                skipped.append("http.script skipped (requires MITM / PrizmX Pro)")
            }
        }
        if map["script-providers"] != nil || map["tiles"] != nil {
            skipped.append("script-providers/tiles skipped")
        }

        return ParsedModule(
            format: .stoverride,
            name: name,
            summary: summary,
            category: category,
            defaultArguments: [:],
            rules: rules,
            hosts: hosts,
            fakeIPFilters: fakeIPFilters,
            skipped: skipped
        )
    }

    // MARK: - Helpers

    private static func substituteArguments(_ args: [String: String], in text: String) -> String {
        guard !args.isEmpty else { return text }
        var result = text
        for (key, value) in args {
            result = result.replacingOccurrences(of: "{{{\(key)}}}", with: value)
        }
        return result
    }

    private static func parseRuleLine(_ line: String) -> OverlayRule? {
        let parts = line.split(separator: ",", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        guard let rawType = parts.first?.uppercased(), !rawType.isEmpty else { return nil }
        if rawType == "MATCH" || rawType == "FINAL" {
            guard parts.count >= 2, !parts[1].isEmpty else { return nil }
            return OverlayRule(type: .matchAll, payload: "", policy: parts[1])
        }
        guard parts.count >= 3 else { return nil }
        let payload = parts[1]
        let policy = parts[2]
        guard !payload.isEmpty, !policy.isEmpty else { return nil }

        let kind: OverlayRule.Kind? = switch rawType {
        case "DOMAIN": .domain
        case "DOMAIN-SUFFIX": .domainSuffix
        case "DOMAIN-KEYWORD": .domainKeyword
        case "IP-CIDR", "IP-CIDR6": .ipCIDR
        case "GEOIP": .geoIP
        case "GEOSITE": .geosite
        case "PROCESS-NAME": .processName
        default: nil
        }
        guard let kind else { return nil }
        return OverlayRule(type: kind, payload: payload, policy: policy)
    }

    private static func parseHostLine(_ line: String) -> (String, [String])? {
        guard let eq = line.firstIndex(of: "=") else { return nil }
        let host = line[..<eq].trimmingCharacters(in: .whitespaces)
        let rawVal = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
        guard !host.isEmpty, !rawVal.isEmpty else { return nil }
        // Skip Surge "server:..." DNS forwarder syntax in [Host]; keep IP/CNAME targets.
        if rawVal.lowercased().hasPrefix("server:") { return nil }
        let values = rawVal.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        return values.isEmpty ? nil : (host, values)
    }
}
