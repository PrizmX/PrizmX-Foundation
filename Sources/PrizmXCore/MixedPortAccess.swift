import Foundation
import PrizmXProtocols

/// Who may use a mixed-port listener and with which credentials.
///
/// Clash semantics: `authentication` (`user:pass`) applies to HTTP (Basic,
/// 407) and SOCKS5 (method 0x02); clients inside `skipAuthPrefixes` skip it.
/// With Allow LAN, only `lanAllowedIPs` sources are accepted, and a remote
/// (non-loopback) client may never target this host's loopback.
public struct MixedPortAccess: Sendable {
    /// Private / local sources accepted by default when Allow LAN is on.
    public static let defaultLANAllowedIPs = [
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "100.64.0.0/10", "169.254.0.0/16",
        "::1/128", "fc00::/7", "fe80::/10",
    ]
    /// Clash `skip-auth-prefixes` default.
    public static let defaultSkipAuthPrefixes = ["127.0.0.1/8", "::1/128"]

    let credentials: Set<String>
    let skipAuth: [CIDR]
    let lanAllowed: [CIDR]

    public init(
        authentication: [String]? = nil,
        skipAuthPrefixes: [String]? = nil,
        lanAllowedIPs: [String]? = nil
    ) {
        self.credentials = Set((authentication ?? []).filter { $0.contains(":") })
        self.skipAuth = (skipAuthPrefixes ?? Self.defaultSkipAuthPrefixes).compactMap(CIDR.init)
        self.lanAllowed = (lanAllowedIPs ?? Self.defaultLANAllowedIPs).compactMap(CIDR.init)
    }

    public var requiresAuthentication: Bool { !credentials.isEmpty }

    /// Allow LAN source filter. Unparsable addresses are refused.
    public func acceptsSource(_ address: String) -> Bool {
        guard let ip = CIDR.Address(parsing: address) else { return false }
        return lanAllowed.contains { $0.contains(ip) }
    }

    public func needsAuthentication(from address: String) -> Bool {
        guard requiresAuthentication else { return false }
        guard let ip = CIDR.Address(parsing: address) else { return true }
        return !skipAuth.contains { $0.contains(ip) }
    }

    public func accepts(credentials candidate: String?) -> Bool {
        guard let candidate else { return false }
        return credentials.contains(candidate)
    }

    /// A remote client must not reach services bound to this host's loopback.
    public static func isLoopbackTarget(host: String) -> Bool {
        var name = host.lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        if name == "localhost" || name.hasSuffix(".localhost") { return true }
        guard let ip = CIDR.Address(parsing: name) else { return false }
        return loopbackTargets.contains { $0.contains(ip) }
    }

    private static let loopbackTargets = ["127.0.0.0/8", "::1/128", "0.0.0.0/32", "::/128"].compactMap(CIDR.init)

    static func isLoopbackSource(_ address: String) -> Bool {
        guard let ip = CIDR.Address(parsing: address) else { return address.isEmpty }
        return loopbackTargets.prefix(2).contains { $0.contains(ip) }
    }

    /// Minimal v4/v6 prefix matcher (IPv4-mapped IPv6 is matched as IPv4).
    struct CIDR: Sendable {
        enum Address: Sendable {
            case v4(UInt32)
            case v6(UInt64, UInt64)

            init?(parsing text: String) {
                var host = text
                if let percent = host.firstIndex(of: "%") { host = String(host[..<percent]) }
                if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
                if let v4 = IPv4Address(parsing: host) {
                    self = .v4(v4.rawValue)
                } else if let v6 = IPv6Address(parsing: host) {
                    if v6.high == 0, v6.low >> 32 == 0xFFFF {
                        self = .v4(UInt32(truncatingIfNeeded: v6.low))
                    } else {
                        self = .v6(v6.high, v6.low)
                    }
                } else {
                    return nil
                }
            }
        }

        let network: Address
        let prefix: Int

        init?(_ text: String) {
            let parts = text.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
            guard let address = Address(parsing: String(parts[0])) else { return nil }
            let limit: Int
            if case .v4 = address { limit = 32 } else { limit = 128 }
            if parts.count == 2 {
                guard let value = Int(parts[1]), value >= 0, value <= limit else { return nil }
                prefix = value
            } else {
                prefix = limit
            }
            network = address
        }

        func contains(_ address: Address) -> Bool {
            switch (network, address) {
            case (.v4(let net), .v4(let ip)):
                let mask: UInt32 = prefix == 0 ? 0 : ~UInt32(0) << UInt32(32 - prefix)
                return net & mask == ip & mask
            case (.v6(let netHigh, let netLow), .v6(let high, let low)):
                if prefix <= 64 {
                    let mask: UInt64 = prefix == 0 ? 0 : ~UInt64(0) << UInt64(64 - prefix)
                    return netHigh & mask == high & mask
                }
                let rest = prefix - 64
                let mask: UInt64 = rest == 64 ? ~0 : ~UInt64(0) << UInt64(64 - rest)
                return netHigh == high && netLow & mask == low & mask
            default:
                return false
            }
        }
    }
}
