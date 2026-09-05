import Darwin

/// Session caps for the TUN stack. Named for the iOS jetsam budget these
/// limits were tuned against (a packet tunnel dies around 50 MB resident).
public enum MemoryWatchdog: Sendable {
    public static let maxTCPSessions = 256
    public static let maxUDPSessions = 128
    /// Per-stream splice buffer. 32 KB was wiping whole HTTP bodies on macOS
    /// (Grok/Kimi uploads) and looked like random disconnects.
    public static let maxBufferPerSession: Int = {
        #if os(iOS)
        32 * 1024
        #else
        1024 * 1024
        #endif
    }()
}
