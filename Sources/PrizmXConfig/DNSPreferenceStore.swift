import Foundation

/// App Group copy of the "Override DNS" switch, read wherever an engine or
/// node pin refresh is built (Packet Tunnel, mixed-port, app) so every start
/// path honors it.
///
/// Off (default) mirrors Clash clients with DNS override disabled: the
/// profile's own nameservers resolve node hostnames. On restores PrizmX's
/// merged resolvers (public + system + proven addresses).
public enum DNSPreferenceStore: Sendable {
    public static let relativePath = "tunnel/dns.json"

    public struct State: Sendable, Codable, Equatable {
        public var overrideDNS: Bool

        public init(overrideDNS: Bool = false) {
            self.overrideDNS = overrideDNS
        }
    }

    public static func load(
        appGroupIdentifier: String = TunnelConfigStorage.defaultAppGroupIdentifier,
        directoryName: String = TunnelConfigStorage.defaultDirectoryName
    ) -> State {
        guard let url = fileURL(
            appGroupIdentifier: appGroupIdentifier,
            directoryName: directoryName
        ),
            let data = try? Data(contentsOf: url),
            let state = try? JSONDecoder().decode(State.self, from: data)
        else { return State() }
        return state
    }

    /// Always writes the file (also when off) so staging replaces a stale
    /// runtime-kit copy.
    public static func save(
        _ state: State,
        appGroupIdentifier: String = TunnelConfigStorage.defaultAppGroupIdentifier,
        directoryName: String = TunnelConfigStorage.defaultDirectoryName
    ) throws {
        guard let url = fileURL(
            appGroupIdentifier: appGroupIdentifier,
            directoryName: directoryName
        ) else {
            throw TunnelConfigStorageError.appGroupUnavailable
        }
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try JSONEncoder().encode(state).write(to: url, options: .atomic)
    }

    private static func fileURL(
        appGroupIdentifier: String,
        directoryName: String
    ) -> URL? {
        TunnelConfigStorage.containerURL(
            appGroupIdentifier: appGroupIdentifier,
            directoryName: directoryName
        )?.appendingPathComponent(relativePath)
    }
}
