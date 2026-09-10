import Foundation
import PrizmXProtocols

/// Stores tunnel config text in the App Group container so the
/// NetworkExtension profile only carries a small relative path.
/// (Profiles are limited to 512 KB; subscription configs routinely exceed it.)
public enum TunnelConfigStorage: Sendable {
    public static let defaultAppGroupIdentifier = PrizmXAppGroup.identifier
    public static let defaultDirectoryName = "PrizmXKit"
    /// Relative path (inside the container directory) of the active config.
    public static let activeConfigRelativePath = "tunnel/active.conf"

    public static func containerURL(
        appGroupIdentifier: String = defaultAppGroupIdentifier,
        directoryName: String = defaultDirectoryName
    ) -> URL? {
        // System extension runs as root; `containerURL` would be
        // `/var/root/Library/Group Containers/…`. Bind the user's kit
        // root from `providerConfiguration` before reading anything.
        if let kitRoot = TunnelLog.kitRoot {
            return kitRoot
        }
        return FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupIdentifier)?
            .appendingPathComponent(directoryName, isDirectory: true)
    }

    /// Writes config text into the shared container; returns the relative path
    /// suitable for `TunnelProviderKeys.configPath`.
    public static func write(
        configText: String,
        relativePath: String = activeConfigRelativePath,
        appGroupIdentifier: String = defaultAppGroupIdentifier,
        directoryName: String = defaultDirectoryName
    ) throws -> String {
        guard let root = containerURL(
            appGroupIdentifier: appGroupIdentifier,
            directoryName: directoryName
        ) else {
            throw TunnelConfigStorageError.appGroupUnavailable
        }
        let url = root.appendingPathComponent(relativePath)
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try configText.write(to: url, atomically: true, encoding: .utf8)
        return relativePath
    }

    public static func read(
        relativePath: String,
        appGroupIdentifier: String = defaultAppGroupIdentifier,
        directoryName: String = defaultDirectoryName
    ) -> String? {
        guard let root = containerURL(
            appGroupIdentifier: appGroupIdentifier,
            directoryName: directoryName
        ) else {
            return nil
        }
        return try? String(
            contentsOf: root.appendingPathComponent(relativePath),
            encoding: .utf8
        )
    }

    /// Resolves config text from `providerConfiguration` via `configPath`.
    public static func configText(from provider: [String: Any]) -> String? {
        guard let path = provider[TunnelProviderKeys.configPath] as? String else {
            return nil
        }
        if path.hasPrefix("/") {
            return try? String(contentsOfFile: path, encoding: .utf8)
        }
        if let root = provider[TunnelProviderKeys.containerPath] as? String {
            let url = URL(fileURLWithPath: root).appendingPathComponent(path)
            return try? String(contentsOf: url, encoding: .utf8)
        }
        return read(relativePath: path)
    }
}

public enum TunnelConfigStorageError: Error, Sendable {
    /// App Group container unavailable (missing entitlement).
    case appGroupUnavailable
}
