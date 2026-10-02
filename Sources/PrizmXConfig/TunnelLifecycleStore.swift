import Foundation
import PrizmXProtocols

/// Records why the tunnel process ended, shared with the app. macOS has no
/// `fetchLastDisconnectReason`; instead:
/// - `stopTunnel(.userInitiated)` runs on a user stop (Settings toggle / app)
/// - a pkd/launchd SIGTERM kills the extension without calling `stopTunnel`
///
/// So a clean stop whose `stoppedAt` is newer than `startedAt` with reason
/// userInitiated means "the user turned it off" — the app must not reconnect.
///
/// Where the record lives: an app extension shares the App Group defaults
/// with the app. The open-core *system* extension runs as root, whose
/// defaults land in root's own domain the app never sees, so once it is bound
/// to the user's kit (`containerPath`) it writes `relativePath` there instead
/// (as `TunnelMetricsStore` does), and the app reads that file first.
public enum TunnelLifecycleStore {
    public static let relativePath = "tunnel/lifecycle.json"

    private static let suite = PrizmXAppGroup.identifier
    private static let startedAtKey = "tunnel.startedAt"
    private static let stoppedAtKey = "tunnel.stoppedAt"
    private static let stopReasonKey = "tunnel.lastStopReason"

    /// NEProviderStopReason.userInitiated raw value.
    public static let userInitiatedReason = 1

    struct Record: Sendable, Codable, Equatable {
        var startedAt: TimeInterval?
        var stoppedAt: TimeInterval?
        var stopReason: Int?
    }

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: suite)
    }

    /// App-side: drop a stale user-stop record before `startVPNTunnel` so a
    /// leftover Settings toggle cannot abort the new session.
    public static func clearStop(kitRoot: URL? = nil) {
        try? FileManager.default.removeItem(at: fileURL(appKitRoot(kitRoot)))
        defaults?.removeObject(forKey: stoppedAtKey)
        defaults?.removeObject(forKey: stopReasonKey)
        defaults?.synchronize()
    }

    /// Called by the extension when the tunnel comes up.
    public static func markStarted(kitRoot: URL? = TunnelLog.kitRoot) {
        record(Record(startedAt: Date().timeIntervalSince1970), kitRoot: kitRoot)
    }

    /// Called by the extension inside `stopTunnel(with:)`.
    public static func markStopped(reason: Int, kitRoot: URL? = TunnelLog.kitRoot) {
        var current = kitRoot.map(load(fileAt:)) ?? loadDefaults()
        current.stoppedAt = Date().timeIntervalSince1970
        current.stopReason = reason
        record(current, kitRoot: kitRoot)
    }

    /// True when the current/last session was cleanly stopped by the user.
    /// A stale record from an older session (or none at all) means the
    /// plugin died without `stopTunnel` — treat as a kill and reconnect.
    public static func stopWasUserInitiated(kitRoot: URL? = nil) -> Bool {
        let root = appKitRoot(kitRoot)
        let current = FileManager.default.fileExists(atPath: fileURL(root).path)
            ? load(fileAt: root)
            : loadDefaults()
        guard let stoppedAt = current.stoppedAt,
              let startedAt = current.startedAt,
              stoppedAt >= startedAt
        else { return false }
        return current.stopReason == userInitiatedReason
    }

    // MARK: - Storage

    private static func fileURL(_ kitRoot: URL) -> URL {
        kitRoot.appendingPathComponent(relativePath)
    }

    /// The kit the system extension was bound to, seen from the app.
    private static func appKitRoot(_ kitRoot: URL?) -> URL {
        kitRoot ?? TunnelLog.kitRoot ?? TunnelRuntimeStore.runtimeKitRoot()
    }

    private static func record(_ record: Record, kitRoot: URL?) {
        guard let kitRoot else {
            saveDefaults(record)
            return
        }
        do {
            // Root writing into the user's kit: never follow a planted link.
            try SafeFileWriter.replace(JSONEncoder().encode(record), at: fileURL(kitRoot), mode: 0o644)
        } catch {
            TunnelLog.write(.error, "lifecycle file write failed: \(error.localizedDescription)")
        }
    }

    private static func load(fileAt kitRoot: URL) -> Record {
        guard let data = try? Data(contentsOf: fileURL(kitRoot)),
              let record = try? JSONDecoder().decode(Record.self, from: data)
        else { return Record() }
        return record
    }

    private static func loadDefaults() -> Record {
        guard let defaults else { return Record() }
        return Record(
            startedAt: defaults.object(forKey: startedAtKey) as? TimeInterval,
            stoppedAt: defaults.object(forKey: stoppedAtKey) as? TimeInterval,
            stopReason: defaults.object(forKey: stopReasonKey) as? Int
        )
    }

    private static func saveDefaults(_ record: Record) {
        guard let defaults else { return }
        func put(_ value: Any?, _ key: String) {
            if let value { defaults.set(value, forKey: key) } else { defaults.removeObject(forKey: key) }
        }
        put(record.startedAt, startedAtKey)
        put(record.stoppedAt, stoppedAtKey)
        put(record.stopReason, stopReasonKey)
        defaults.synchronize()
    }
}
