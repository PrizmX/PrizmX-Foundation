import Foundation

/// Canonical App Group shared by the app and the network extensions.
///
/// The identifier is **team-ID prefixed**: macOS treats unprefixed
/// `group.*` containers as TCC-protected cross-app data for the extensions
/// (containermanagerd rejects them: "Group containers identifiers should be
/// prefixed by requestor's team ID"), which produced the
/// "PrizmX.app would like to access data from other apps" prompt on every
/// tunnel start.
public enum PrizmXAppGroup: Sendable {
    public static let identifier = "N49M3Z72D3.group.app.prizmx"
    /// Pre-team-prefix identifier. Kept in entitlements so the app can read
    /// and migrate existing data; extensions never touch it.
    public static let legacyIdentifier = "group.app.prizmx"

    /// One-time copy of the legacy container's contents into the
    /// team-prefixed container. App-side only (extensions must not read the
    /// legacy container — that is the TCC prompt we are removing).
    public static func migrateLegacyContainerIfNeeded(
        directoryName: String = TunnelLog.defaultDirectoryName,
        fileManager: FileManager = .default
    ) {
        guard let newRoot = fileManager.containerURL(
            forSecurityApplicationGroupIdentifier: identifier
        )?.appendingPathComponent(directoryName, isDirectory: true),
            !fileManager.fileExists(atPath: newRoot.path),
            let legacyRoot = fileManager.containerURL(
                forSecurityApplicationGroupIdentifier: legacyIdentifier
            )?.appendingPathComponent(directoryName, isDirectory: true),
            fileManager.fileExists(atPath: legacyRoot.path)
        else { return }
        do {
            try fileManager.copyItem(at: legacyRoot, to: newRoot)
            TunnelLog.write(.info, "app group migrated to team-prefixed container")
        } catch {
            TunnelLog.write(.error, "app group migration failed: \(error.localizedDescription)")
        }
    }
}
