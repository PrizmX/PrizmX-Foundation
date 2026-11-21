import Foundation
import PrizmXRules

/// Format of an imported module overlay file.
public enum ModuleFormat: String, Sendable, Codable, Equatable, Hashable {
    /// Surge module (`.sgmodule`, INI sections).
    case sgmodule
    /// Stash override (`.stoverride`, YAML).
    case stoverride
}

/// Non-MITM script declared inside a module (cron or network-changed event).
public struct ModuleScript: Sendable, Equatable, Hashable, Codable {
    public enum Kind: String, Sendable, Codable, Equatable, Hashable {
        case cron
        case event
    }

    public var name: String
    public var kind: Kind
    /// Cron expression (for `.cron`) or event name (for `.event`).
    public var pattern: String
    public var scriptURL: URL
    public var argument: String
    public var timeout: TimeInterval

    public init(
        name: String,
        kind: Kind,
        pattern: String,
        scriptURL: URL,
        argument: String = "",
        timeout: TimeInterval = 10
    ) {
        self.name = name
        self.kind = kind
        self.pattern = pattern
        self.scriptURL = scriptURL
        self.argument = argument
        self.timeout = timeout
    }
}

/// Parsed representation of one Surge `.sgmodule` or Stash `.stoverride` file.
/// Non-MITM sections (rules, hosts, fake-ip-filter, cron/event scripts) are
/// extracted cleanly; MITM / URL Rewrite / HTTP Script sections are reported
/// in `skipped`.
public struct ParsedModule: Sendable, Equatable {
    public var format: ModuleFormat
    public var name: String
    public var summary: String
    public var category: String?
    public var author: String?
    public var homepage: URL?
    public var defaultArguments: [String: String]
    /// Validated Clash/Surge rule lines compiled via `ClashConfigParser.parseRule`.
    public var rawRules: [String]
    public var hosts: [String: [String]]
    public var fakeIPFilters: [String]
    public var scripts: [ModuleScript]
    public var skipped: [String]

    public init(
        format: ModuleFormat,
        name: String,
        summary: String = "",
        category: String? = nil,
        author: String? = nil,
        homepage: URL? = nil,
        defaultArguments: [String: String] = [:],
        rawRules: [String] = [],
        hosts: [String: [String]] = [:],
        fakeIPFilters: [String] = [],
        scripts: [ModuleScript] = [],
        skipped: [String] = []
    ) {
        self.format = format
        self.name = name
        self.summary = summary
        self.category = category
        self.author = author
        self.homepage = homepage
        self.defaultArguments = defaultArguments
        self.rawRules = rawRules
        self.hosts = hosts
        self.fakeIPFilters = fakeIPFilters
        self.scripts = scripts
        self.skipped = skipped
    }

    /// Converts this module's active non-MITM sections into a `ProfileOverlay`.
    public var overlay: ProfileOverlay {
        ProfileOverlay(
            rawRules: rawRules,
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
        var author: String?
        var homepage: URL?
        var defaultArgs: [String: String] = [:]

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
            case "author":
                if !val.isEmpty { author = val }
            case "homepage":
                homepage = URL(string: val)
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
        let ruleParser = ClashConfigParser()

        var section = ""
        var rawRules: [String] = []
        var hosts: [String: [String]] = [:]
        var fakeIPFilters: [String] = []
        var scripts: [ModuleScript] = []
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
                let normalizedRule = normalizeSurgeRule(line)
                if (try? ruleParser.parseRule(normalizedRule)) != nil {
                    rawRules.append(normalizedRule)
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
            case "script":
                switch parseSurgeScriptLine(line) {
                case .parsed(let script):
                    scripts.append(script)
                case .skipped(let reason):
                    skipped.append(reason)
                }
            case "mitm":
                if skippedSections.insert("mitm").inserted {
                    skipped.append("[MITM] skipped (requires MITM / PrizmX Pro)")
                }
            case "url rewrite", "header rewrite", "body rewrite", "map local":
                if skippedSections.insert(section).inserted {
                    skipped.append("[\(section)] skipped (requires MITM / PrizmX Pro)")
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
            author: author,
            homepage: homepage,
            defaultArguments: defaultArgs,
            rawRules: rawRules,
            hosts: hosts,
            fakeIPFilters: deduplicate(fakeIPFilters),
            scripts: scripts,
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
        let author = root.string(for: "author")
        let homepage = root.string(for: "homepage").flatMap(URL.init(string:))
        let ruleParser = ClashConfigParser()

        var rawRules: [String] = []
        var hosts: [String: [String]] = [:]
        var fakeIPFilters: [String] = []
        var skipped: [String] = []

        if let ruleList = map["rules"]?.sequence {
            for item in ruleList {
                guard let line = item.string?.trimmingCharacters(in: .whitespaces), !line.isEmpty else { continue }
                let normalizedRule = normalizeSurgeRule(line)
                if (try? ruleParser.parseRule(normalizedRule)) != nil {
                    rawRules.append(normalizedRule)
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
        if map["tiles"] != nil {
            skipped.append("tiles skipped")
        }

        return ParsedModule(
            format: .stoverride,
            name: name,
            summary: summary,
            category: category,
            author: author,
            homepage: homepage,
            defaultArguments: [:],
            rawRules: rawRules,
            hosts: hosts,
            fakeIPFilters: deduplicate(fakeIPFilters),
            scripts: [],
            skipped: skipped
        )
    }

    // MARK: - Helpers

    private enum ScriptLineResult {
        case parsed(ModuleScript)
        case skipped(String)
    }

    private static func parseSurgeScriptLine(_ line: String) -> ScriptLineResult {
        guard let eq = line.firstIndex(of: "=") else {
            return .skipped("[Script] malformed: \(line)")
        }
        let name = line[..<eq].trimmingCharacters(in: .whitespaces)
        let rhs = String(line[line.index(after: eq)...])
        let params = parseKeyValueList(rhs)
        let type = (params["type"] ?? "").lowercased()

        switch type {
        case "http-request", "http-response":
            return .skipped("[Script] \(name) skipped (requires MITM / PrizmX Pro)")
        case "cron":
            guard let urlStr = params["script-path"], let url = URL(string: urlStr),
                  let cronExp = params["cronexp"], !cronExp.isEmpty
            else {
                return .skipped("[Script] \(name) missing script-path or cronexp")
            }
            let timeout = params["timeout"].flatMap(TimeInterval.init) ?? 10
            return .parsed(ModuleScript(
                name: name,
                kind: .cron,
                pattern: cronExp,
                scriptURL: url,
                argument: params["argument"] ?? "",
                timeout: timeout
            ))
        case "event":
            guard let urlStr = params["script-path"], let url = URL(string: urlStr) else {
                return .skipped("[Script] \(name) missing script-path")
            }
            let eventName = params["event-name"] ?? "network-changed"
            let timeout = params["timeout"].flatMap(TimeInterval.init) ?? 10
            return .parsed(ModuleScript(
                name: name,
                kind: .event,
                pattern: eventName,
                scriptURL: url,
                argument: params["argument"] ?? "",
                timeout: timeout
            ))
        default:
            return .skipped("[Script] \(name) (type=\(type.isEmpty ? "unknown" : type)) skipped")
        }
    }

    /// Parses Surge comma-separated `key=value` attributes respecting double quotes.
    private static func parseKeyValueList(_ input: String) -> [String: String] {
        var result: [String: String] = [:]
        var current = ""
        var inQuotes = false
        var tokens: [String] = []
        let quote: Character = "\""
        for ch in input {
            if ch == quote {
                inQuotes.toggle()
            } else if ch == "," && !inQuotes {
                tokens.append(current)
                current = ""
                continue
            }
            current.append(ch)
        }
        if !current.isEmpty { tokens.append(current) }
        for token in tokens {
            guard let eq = token.firstIndex(of: "=") else { continue }
            let key = token[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            var val = token[token.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if val.first == quote && val.last == quote && val.count >= 2 {
                val = String(val.dropFirst().dropLast())
            }
            if !key.isEmpty { result[key] = val }
        }
        return result
    }

    /// Normalizes Surge rule aliases (`DEST-PORT` → `DST-PORT`) before Clash rule validation.
    private static func normalizeSurgeRule(_ line: String) -> String {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.uppercased().hasPrefix("DEST-PORT,") {
            return "DST-PORT," + trimmed.dropFirst("DEST-PORT,".count)
        }
        return trimmed
    }

    private static func substituteArguments(_ args: [String: String], in text: String) -> String {
        guard !args.isEmpty else { return text }
        var result = text
        for (key, value) in args {
            result = result.replacingOccurrences(of: "{{{\(key)}}}", with: value)
        }
        return result
    }

    private static func deduplicate(_ list: [String]) -> [String] {
        var seen = Set<String>()
        return list.filter { seen.insert($0).inserted }
    }

    private static func parseHostLine(_ line: String) -> (String, [String])? {
        guard let eq = line.firstIndex(of: "=") else { return nil }
        let host = line[..<eq].trimmingCharacters(in: .whitespaces)
        let rawVal = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
        guard !host.isEmpty, !rawVal.isEmpty else { return nil }
        if rawVal.lowercased().hasPrefix("server:") { return nil }
        let values = rawVal.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        return values.isEmpty ? nil : (host, values)
    }
}
