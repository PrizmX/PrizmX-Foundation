import Foundation
import PrizmXCore

/// Clash inbound listen ports (`port` / `socks-port` / `mixed-port`).
///
/// Missing keys use app defaults (HTTP 7890, SOCKS 7891). Bind address is
/// not stored here — Allow LAN chooses `0.0.0.0` vs `127.0.0.1` at start.
public struct InboundListenConfig: Sendable, Equatable, Hashable {
    public var mixedPort: UInt16?
    public var httpPort: UInt16?
    public var socksPort: UInt16?

    public init(mixedPort: UInt16? = nil, httpPort: UInt16? = nil, socksPort: UInt16? = nil) {
        self.mixedPort = mixedPort
        self.httpPort = httpPort
        self.socksPort = socksPort
    }

    public static let appDefault = InboundListenConfig(
        httpPort: UInt16(clamping: TunnelProviderKeys.defaultMixedPort),
        socksPort: UInt16(clamping: TunnelProviderKeys.defaultSOCKSPort)
    )

    /// Clash YAML top-level ports. Non-YAML / empty → app defaults.
    public static func parse(from rawString: String?) -> InboundListenConfig {
        guard let trimmed = rawString?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty,
              let first = trimmed.first, first != "{", first != "[",
              let root = try? YAMLParser.parse(trimmed),
              let mapping = root.mapping
        else {
            return .appDefault
        }
        let mixed = port(mapping, "mixed-port") ?? port(mapping, "mixed_port")
        let http = port(mapping, "port")
        let socks = port(mapping, "socks-port") ?? port(mapping, "socks_port")
        if mixed == nil, http == nil, socks == nil {
            return .appDefault
        }
        return InboundListenConfig(mixedPort: mixed, httpPort: http, socksPort: socks)
    }

    /// HTTP/HTTPS system-proxy port (always pointed at 127.0.0.1).
    public var systemProxyHTTPPort: UInt16 {
        httpPort ?? mixedPort ?? UInt16(clamping: TunnelProviderKeys.defaultMixedPort)
    }

    /// SOCKS system-proxy port (always pointed at 127.0.0.1).
    public var systemProxySOCKSPort: UInt16 {
        socksPort ?? mixedPort ?? systemProxyHTTPPort
    }

    public var sockets: [Socket] {
        var used = Set<UInt16>()
        var result: [Socket] = []
        func add(_ port: UInt16?, accept: MixedPortServer.Accept) {
            guard let port, used.insert(port).inserted else { return }
            result.append(Socket(port: port, accept: accept))
        }
        add(mixedPort, accept: .mixed)
        add(httpPort, accept: .http)
        add(socksPort, accept: .socks)
        if result.isEmpty {
            return InboundListenConfig.appDefault.sockets
        }
        return result
    }

    public struct Socket: Sendable, Equatable, Hashable {
        public var port: UInt16
        public var accept: MixedPortServer.Accept

        public init(port: UInt16, accept: MixedPortServer.Accept) {
            self.port = port
            self.accept = accept
        }
    }

    private static func port(_ mapping: [String: YAMLNode], _ key: String) -> UInt16? {
        guard let raw = mapping[key]?.string, let value = Int(raw), (1...65_535).contains(value) else {
            return nil
        }
        return UInt16(value)
    }
}
