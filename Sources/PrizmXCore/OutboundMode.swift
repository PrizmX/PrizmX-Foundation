/// Clash / Surge outbound switch: Rule follows the profile, Global pins
/// every flow to one policy group, Direct bypasses the proxy.
public enum OutboundMode: String, Sendable, Codable, CaseIterable, Equatable {
    case rule
    case global
    case direct
}
