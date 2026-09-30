import Darwin

/// Session caps for the TUN stack. Named for the iOS jetsam budget these
/// limits were tuned against (a packet tunnel dies around 50 MB resident).
///
/// `maxTCPSessions` is the whole stack's budget: SwiftTCP enforces
/// `TCPStackConfig.maxConnections` across all event loops, not per loop.
public enum MemoryWatchdog: Sendable {
    /// Worst case per TCP flow ≈ receive window + send ring. iOS: 256 × 64 KB
    /// ≈ 16 MB. macOS has no jetsam ceiling; 1024 is twice the old effective
    /// cap (256 per loop × 2 loops) and still bounds a SYN flood.
    public static let maxTCPSessions: Int = {
        #if os(iOS) || os(tvOS)
        256
        #else
        1024
        #endif
    }()
    public static let maxUDPSessions = 128
    /// Per-stream splice buffer. 32 KB was wiping whole HTTP bodies on macOS
    /// (Grok/Kimi uploads) and looked like random disconnects.
    public static let maxBufferPerSession: Int = {
        #if os(iOS) || os(tvOS)
        32 * 1024
        #else
        1024 * 1024
        #endif
    }()
    /// Per-flow send ring cap: one receive window. SwiftTCP never sizes the
    /// ring below one window, so this keeps it at exactly one on both.
    public static let sendBufferLimit: Int = maxBufferPerSession
    /// Datagrams queued between SwiftTCP and the UDP relay before the oldest
    /// are dropped (UDP is lossy by contract; memory must not be).
    public static let udpIngestBuffer = 1024
    /// Datagrams queued per UDP session while its outbound is being set up.
    public static let udpSessionBuffer = 64
}
