import Foundation

/// Where the community Mac app keeps its kit: one directory shared by the app
/// and the Packet Tunnel system extension.
///
/// The extension runs as root. The user App Group is a containermanager
/// vault, so even an unsandboxed root process cannot use it. The app binds
/// this path (`TunnelLog.bind`), keeps everything there, and passes it as
/// `containerPath`.
public enum TunnelRuntimeStore: Sendable {
    public static let relativeKitPath = "Library/Application Support/PrizmX/kit"

    public static func runtimeKitRoot(home: URL? = nil) -> URL {
        let resolvedHome: URL
        if let home {
            resolvedHome = home
        } else {
            #if os(macOS)
            resolvedHome = FileManager.default.homeDirectoryForCurrentUser
            #else
            resolvedHome = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
            #endif
        }
        return resolvedHome.appendingPathComponent(relativeKitPath, isDirectory: true)
    }
}
