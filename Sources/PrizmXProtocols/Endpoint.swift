/// A unified destination endpoint — the peer address + port of a proxy
/// outbound connection.
///
/// Value semantics, zero heap allocation (except for the domain case, which is
/// carried by a `String`).
@frozen
public struct Endpoint: Hashable, Sendable, CustomStringConvertible, Codable {

    /// The target host: a domain name or an IP address.
    @frozen
    public enum Host: Hashable, Sendable, CustomStringConvertible, Codable {
        /// A domain name (recommended to be normalized to lowercase;
        /// `Endpoint.init(domain:port:)` does this automatically).
        case domain(String)
        case ipv4(IPv4Address)
        case ipv6(IPv6Address)

        public var description: String {
            switch self {
            case .domain(let domain): return domain
            case .ipv4(let address): return address.description
            case .ipv6(let address): return address.description
            }
        }
    }

    /// The target host.
    public let host: Host
    /// The target port (host byte order).
    public let port: UInt16

    @inlinable
    public init(host: Host, port: UInt16) {
        self.host = host
        self.port = port
    }

    /// Convenience initializer: the domain is lowercased automatically
    /// (DNS is case-insensitive).
    @inlinable
    public init(domain: String, port: UInt16) {
        self.host = .domain(domain.lowercased())
        self.port = port
    }

    /// Parses a hostname that may be a dotted IPv4, IPv6 literal, or domain.
    /// Used by Transparent Proxy flows where the system provides host and port
    /// separately (and may already have resolved a domain to `remoteHostname`).
    public init?(hostname: String, port: UInt16) {
        guard port > 0 else { return nil }
        let trimmed = hostname.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
            let literal = trimmed.dropFirst().dropLast()
            guard let address = IPv6Address(parsing: literal) else { return nil }
            self.host = .ipv6(address)
        } else if let address = IPv4Address(parsing: trimmed) {
            self.host = .ipv4(address)
        } else if let address = IPv6Address(parsing: trimmed) {
            self.host = .ipv6(address)
        } else {
            self.host = .domain(trimmed.lowercased())
        }
        self.port = port
    }

    /// Parses a `"host:port"` string; IPv6 literals require brackets
    /// (e.g. `"[::1]:443"`).
    public init?(parsing text: some StringProtocol) {
        guard let separator = text.lastIndex(of: ":"),
              separator > text.startIndex
        else { return nil }
        let hostPart = text[..<separator]
        let portPart = text[text.index(after: separator)...]
        guard let port = UInt16(portPart), port > 0 else { return nil }

        if hostPart.hasPrefix("[") && hostPart.hasSuffix("]") {
            let literal = hostPart.dropFirst().dropLast()
            guard let address = IPv6Address(parsing: literal) else { return nil }
            self.host = .ipv6(address)
        } else if let address = IPv6Address(parsing: hostPart) {
            self.host = .ipv6(address)
        } else if let address = IPv4Address(parsing: hostPart) {
            self.host = .ipv4(address)
        } else {
            self.host = .domain(String(hostPart).lowercased())
        }
        self.port = port
    }

    public var description: String {
        switch host {
        case .ipv6(let address):
            return "[\(address)]:\(port)"
        default:
            return "\(host):\(port)"
        }
    }
}
