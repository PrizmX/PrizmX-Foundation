import Foundation

/// Staging area the Packet Tunnel system extension can actually read.
///
/// The extension runs as root. The user App Group is a containermanager
/// vault, so even an unsandboxed root process cannot use it. The app copies
/// the kit into `~/Library/Application Support/PrizmX/kit` (not a container)
/// and passes that absolute path as `containerPath`.
public enum TunnelRuntimeStore: Sendable {
    public static let relativeKitPath = "Library/Application Support/PrizmX/kit"

    private static let stagedFiles = [
        "tunnel/active.conf",
        "tunnel/node-addrs.json",
        "tunnel/overlay.json",
        "tunnel/selections.json",
        "tunnel/outbound-mode.json",
        "dns-good.json",
    ]

    public static func runtimeKitRoot(
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> URL {
        home.appendingPathComponent(relativeKitPath, isDirectory: true)
    }

    /// Copies extension inputs from the App Group kit into `destinationKit`.
    /// Missing sources are skipped. Returns the destination root.
    public static func stage(
        from sourceKit: URL,
        to destinationKit: URL,
        fileManager: FileManager = .default
    ) throws -> URL {
        try fileManager.createDirectory(at: destinationKit, withIntermediateDirectories: true)
        try setPOSIXPermissions(0o755, on: destinationKit, fileManager: fileManager)
        for name in stagedFiles {
            try copyFileIfPresent(
                from: sourceKit.appendingPathComponent(name),
                to: destinationKit.appendingPathComponent(name),
                fileManager: fileManager
            )
        }
        try copyDirectoryIfPresent(
            from: sourceKit.appendingPathComponent("geo", isDirectory: true),
            to: destinationKit.appendingPathComponent("geo", isDirectory: true),
            fileManager: fileManager
        )
        let logs = destinationKit.appendingPathComponent("logs", isDirectory: true)
        try fileManager.createDirectory(at: logs, withIntermediateDirectories: true)
        try setPOSIXPermissions(0o755, on: logs, fileManager: fileManager)
        return destinationKit
    }

    public static func stageFromAppGroup(
        sourceKit: URL? = TunnelConfigStorage.containerURL(),
        fileManager: FileManager = .default
    ) throws -> URL {
        guard let sourceKit else {
            throw TunnelConfigStorageError.appGroupUnavailable
        }
        return try stage(
            from: sourceKit,
            to: runtimeKitRoot(),
            fileManager: fileManager
        )
    }

    private static func copyFileIfPresent(
        from source: URL,
        to destination: URL,
        fileManager: FileManager
    ) throws {
        guard fileManager.fileExists(atPath: source.path) else { return }
        try fileManager.createDirectory(
            at: destination.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        if fileManager.fileExists(atPath: destination.path) {
            try fileManager.removeItem(at: destination)
        }
        try fileManager.copyItem(at: source, to: destination)
        try setPOSIXPermissions(0o644, on: destination, fileManager: fileManager)
    }

    private static func copyDirectoryIfPresent(
        from source: URL,
        to destination: URL,
        fileManager: FileManager
    ) throws {
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: source.path, isDirectory: &isDirectory),
              isDirectory.boolValue else { return }
        if fileManager.fileExists(atPath: destination.path) {
            try fileManager.removeItem(at: destination)
        }
        try fileManager.copyItem(at: source, to: destination)
        try setPOSIXPermissions(0o755, on: destination, fileManager: fileManager)
        if let enumerator = fileManager.enumerator(at: destination, includingPropertiesForKeys: nil) {
            for case let file as URL in enumerator {
                var isDir: ObjCBool = false
                guard fileManager.fileExists(atPath: file.path, isDirectory: &isDir) else { continue }
                try setPOSIXPermissions(
                    isDir.boolValue ? 0o755 : 0o644,
                    on: file,
                    fileManager: fileManager
                )
            }
        }
    }

    private static func setPOSIXPermissions(
        _ mode: Int,
        on url: URL,
        fileManager: FileManager
    ) throws {
        try fileManager.setAttributes(
            [.posixPermissions: NSNumber(value: mode)],
            ofItemAtPath: url.path
        )
    }
}
