import Foundation

/// The route a flow took, exit first like mihomo's connection `chains`:
/// `["DIRECT", "🎯Direct"]` for a rule on a group that selects DIRECT,
/// `["🇺🇸 San Jose 07", "AI"]` for a proxied one, `["DIRECT"]` for a rule
/// that names DIRECT itself.
///
/// Traffic is direct or proxied by its exit (what actually carried it), and
/// ranked per policy by the rule's choice (the outermost entry).
public struct FlowRoute: Sendable, Hashable, Codable, CustomStringConvertible {
    public static let direct = "DIRECT"

    public var chain: [String]

    public init(_ chain: [String]) {
        self.chain = chain
    }

    /// What carried the traffic: `DIRECT` or a node.
    public var exit: String { chain.first ?? "" }

    /// The policy the rule chose: the outermost group, or the exit itself.
    public var policy: String { chain.last ?? "" }

    public var isDirect: Bool { exit == Self.direct }

    /// Rule policy first: `🎯Direct → DIRECT`, `AI → 🇺🇸 San Jose 07`.
    public var description: String { chain.reversed().joined(separator: " → ") }
}
