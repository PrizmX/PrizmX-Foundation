import Foundation

/// JSON-like value returned from a script. `JSValue` stays inside the engine.
public enum ScriptValue: Sendable, Hashable {
    case undefined
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([ScriptValue])
    case object([String: ScriptValue])

    /// Compact JSON-ish dump for logs and the Scripts pane.
    public var jsonString: String {
        switch self {
        case .undefined:
            return "undefined"
        case .null:
            return "null"
        case .bool(let value):
            return value ? "true" : "false"
        case .number(let value):
            if value.isFinite, let int = Int64(exactly: value) {
                return String(int)
            }
            return String(value)
        case .string(let value):
            return Self.encodeJSONString(value)
        case .array(let items):
            return "[\(items.map(\.jsonString).joined(separator: ","))]"
        case .object(let fields):
            let body = fields.keys.sorted().map { key in
                "\(Self.encodeJSONString(key)):\(fields[key]!.jsonString)"
            }.joined(separator: ",")
            return "{\(body)}"
        }
    }

    private static func encodeJSONString(_ value: String) -> String {
        let data = try? JSONEncoder().encode(value)
        if let data, let encoded = String(data: data, encoding: .utf8) {
            return encoded
        }
        return "\"\(value)\""
    }
}
