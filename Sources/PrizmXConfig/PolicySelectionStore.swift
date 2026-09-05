import Foundation

/// Per-group `select` membership chosen in the App, stored in the App Group
/// so the Packet Tunnel uses the same mapping as Policies.
///
/// Clash keeps this in a runtime cache; the subscription YAML does not.
public enum PolicySelectionStore: Sendable {
    public static let relativePath = "tunnel/selections.json"

    public static func load(
        appGroupIdentifier: String = TunnelConfigStorage.defaultAppGroupIdentifier,
        directoryName: String = TunnelConfigStorage.defaultDirectoryName
    ) -> [String: String] {
        guard let url = fileURL(
            appGroupIdentifier: appGroupIdentifier,
            directoryName: directoryName
        ),
            let data = try? Data(contentsOf: url),
            let dict = try? JSONDecoder().decode([String: String].self, from: data)
        else { return [:] }
        return dict.filter { !$0.key.isEmpty && !$0.value.isEmpty }
    }

    public static func save(
        _ map: [String: String],
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
        let data = try JSONEncoder().encode(map)
        try data.write(to: url, options: .atomic)
    }

    public static func set(
        _ member: String,
        inGroup group: String,
        appGroupIdentifier: String = TunnelConfigStorage.defaultAppGroupIdentifier,
        directoryName: String = TunnelConfigStorage.defaultDirectoryName
    ) {
        var map = load(appGroupIdentifier: appGroupIdentifier, directoryName: directoryName)
        map[group] = member
        try? save(map, appGroupIdentifier: appGroupIdentifier, directoryName: directoryName)
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
