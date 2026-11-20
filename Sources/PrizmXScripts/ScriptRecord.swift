import Foundation

/// One user-owned script. Matching and HTTP hooks are stored here; the
/// engine still only evaluates `source` until those pipelines exist.
public struct ScriptRecord: Sendable, Hashable, Codable, Identifiable, Equatable {
    public enum Kind: String, Sendable, Codable, Hashable, CaseIterable, Identifiable {
        case httpRequest = "http-request"
        case httpResponse = "http-response"
        case cron
        case event
        case rule
        case script

        public var id: String { rawValue }

        public var title: String {
            switch self {
            case .httpRequest: "HTTP Request"
            case .httpResponse: "HTTP Response"
            case .cron: "Cron"
            case .event: "Event"
            case .rule: "Rule"
            case .script: "Script"
            }
        }

        public var showsMatch: Bool {
            switch self {
            case .httpRequest, .httpResponse, .cron, .event, .rule: true
            case .script: false
            }
        }

        public var matchPrompt: String {
            switch self {
            case .cron: "Cron (e.g. */30 * * * *)"
            case .event: "Event (e.g. network-changed)"
            default: "Match"
            }
        }

        /// HTTP request / response hooks require MITM (reserved for Pro).
        public var requiresMITM: Bool {
            switch self {
            case .httpRequest, .httpResponse: true
            default: false
            }
        }
    }

    public var id: UUID
    public var name: String
    public var enabled: Bool
    public var kind: Kind
    /// URL match, cron expression, or rule host — depending on `kind`.
    public var pattern: String
    public var source: String
    public var argument: String
    public var timeout: TimeInterval
    /// Optional remote URL when installed from a URL so it can be refreshed.
    public var sourceURL: URL?
    /// True for read-only system scripts bundled with PrizmX.
    public var isBuiltIn: Bool

    public init(
        id: UUID = UUID(),
        name: String,
        enabled: Bool = true,
        kind: Kind = .script,
        pattern: String = "",
        source: String,
        argument: String = "",
        timeout: TimeInterval = ScriptEngine.defaultTimeout,
        sourceURL: URL? = nil,
        isBuiltIn: Bool = false
    ) {
        self.id = id
        self.name = name
        self.enabled = enabled
        self.kind = kind
        self.pattern = pattern
        self.source = source
        self.argument = argument
        self.timeout = timeout
        self.sourceURL = sourceURL
        self.isBuiltIn = isBuiltIn
    }

    enum CodingKeys: String, CodingKey {
        case id, name, enabled, kind, pattern, source, argument, timeout, sourceURL, isBuiltIn
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        enabled = try c.decode(Bool.self, forKey: .enabled)
        kind = try c.decode(Kind.self, forKey: .kind)
        pattern = try c.decodeIfPresent(String.self, forKey: .pattern) ?? ""
        source = try c.decode(String.self, forKey: .source)
        argument = try c.decodeIfPresent(String.self, forKey: .argument) ?? ""
        timeout = try c.decodeIfPresent(TimeInterval.self, forKey: .timeout) ?? ScriptEngine.defaultTimeout
        sourceURL = try c.decodeIfPresent(URL.self, forKey: .sourceURL)
        isBuiltIn = try c.decodeIfPresent(Bool.self, forKey: .isBuiltIn) ?? false
    }

    public var request: ScriptRequest {
        let argument = argument.trimmingCharacters(in: .whitespacesAndNewlines)
        return ScriptRequest(
            name: name,
            source: source,
            argument: argument.isEmpty ? nil : argument,
            timeout: timeout
        )
    }

    public static let sampleSource = """
    console.log("PrizmX JSC")
    $done({ ok: true, n: 1 + 1 })
    """
}
