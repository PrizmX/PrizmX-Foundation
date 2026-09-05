import Foundation

/// Records why the tunnel process ended, shared with the app via App Group
/// UserDefaults. macOS has no `fetchLastDisconnectReason`; instead:
/// - `stopTunnel(.userInitiated)` runs on a user stop (Settings toggle / app)
/// - a pkd/launchd SIGTERM kills the extension without calling `stopTunnel`
///
/// So a clean stop whose `stoppedAt` is newer than `startedAt` with reason
/// userInitiated means "the user turned it off" — the app must not reconnect.
public enum TunnelLifecycleStore {
    private static let suite = "group.app.prizmx"
    private static let startedAtKey = "tunnel.startedAt"
    private static let stoppedAtKey = "tunnel.stoppedAt"
    private static let stopReasonKey = "tunnel.lastStopReason"

    /// NEProviderStopReason.userInitiated raw value.
    public static let userInitiatedReason = 1

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: suite)
    }

    /// App-side: drop a stale user-stop record before `startVPNTunnel` so a
    /// leftover Settings toggle cannot abort the new session.
    public static func clearStop() {
        defaults?.removeObject(forKey: stoppedAtKey)
        defaults?.removeObject(forKey: stopReasonKey)
        defaults?.synchronize()
    }

    /// Called by the extension when the tunnel comes up.
    public static func markStarted() {
        defaults?.set(Date().timeIntervalSince1970, forKey: startedAtKey)
        defaults?.removeObject(forKey: stoppedAtKey)
        defaults?.removeObject(forKey: stopReasonKey)
        defaults?.synchronize()
    }

    /// Called by the extension inside `stopTunnel(with:)`.
    public static func markStopped(reason: Int) {
        defaults?.set(Date().timeIntervalSince1970, forKey: stoppedAtKey)
        defaults?.set(reason, forKey: stopReasonKey)
        defaults?.synchronize()
    }

    /// True when the current/last session was cleanly stopped by the user.
    /// A stale record from an older session (or none at all) means the
    /// plugin died without `stopTunnel` — treat as a kill and reconnect.
    public static func stopWasUserInitiated() -> Bool {
        guard let defaults,
              let stoppedAt = defaults.object(forKey: stoppedAtKey) as? TimeInterval,
              let startedAt = defaults.object(forKey: startedAtKey) as? TimeInterval,
              stoppedAt >= startedAt
        else { return false }
        return defaults.integer(forKey: stopReasonKey) == userInitiatedReason
    }
}
