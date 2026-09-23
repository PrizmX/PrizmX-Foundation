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
            case .httpRequest, .httpResponse, .cron, .rule: true
            case .event, .script: false
            }
        }

        public var matchPrompt: String {
            switch self {
            case .cron: "Cron"
            default: "Match"
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

    public init(
        id: UUID = UUID(),
        name: String,
        enabled: Bool = true,
        kind: Kind = .httpRequest,
        pattern: String = "",
        source: String,
        argument: String = "",
        timeout: TimeInterval = ScriptEngine.defaultTimeout
    ) {
        self.id = id
        self.name = name
        self.enabled = enabled
        self.kind = kind
        self.pattern = pattern
        self.source = source
        self.argument = argument
        self.timeout = timeout
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
