import Darwin
import Foundation
import PrizmXAttributionC

/// Process lookup from `net.inet.tcp.pcblist_n` / `udp.pcblist_n`.
public enum PCBListLookup {
    /// Resolve the process that owns `port` (host endian). Prefers `so_e_pid`,
    /// then `so_last_pid`.
    public static func findPID(forLocalPort port: UInt16, isTCP: Bool) -> pid_t? {
        let pid = prizmx_find_pid_pcblist_n(port, isTCP ? 1 : 0)
        return pid > 0 ? pid : nil
    }
}
