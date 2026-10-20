import Foundation

/// App Group copy of the "Route All Traffic" switch (experimental), read by
/// the Packet Tunnel when it starts and on a reload.
///
/// Off (default): TUN routes only the FakeIP range 198.18.0.0/16, so apps
/// that connect to IP addresses directly bypass it. On: TUN takes the
/// default route (IPv4 and IPv6) except local networks, and PrizmX keeps its
/// own connections off the tunnel (`TunnelEgress`).
public enum CapturePreferenceStore: Sendable {
    public static let relativePath = "tunnel/capture.json"

    public struct State: Sendable, Codable, Equatable {
        public var allTraffic: Bool

        public init(allTraffic: Bool = false) {
            self.allTraffic = allTraffic
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
