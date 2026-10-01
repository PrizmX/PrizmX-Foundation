import Darwin
import Foundation
import PrizmXAttributionC
import PrizmXCore
import PrizmXProtocols

/// Socket address in comparable form. IPv4 and IPv4-mapped IPv6 both become
/// `.v4`; the unspecified address (0.0.0.0 / ::) is `nil` (unbound or
/// unconnected side).
enum SocketAddress: Hashable, Sendable {
    case v4(UInt32)
    case v6(UInt64, UInt64)

    init?(bytes: UnsafeRawBufferPointer, isIPv6: Bool) {
        guard bytes.count >= 16 else { return nil }
        if isIPv6 {
            var high: UInt64 = 0
            var low: UInt64 = 0
            for index in 0..<8 { high = high << 8 | UInt64(bytes[index]) }
            for index in 8..<16 { low = low << 8 | UInt64(bytes[index]) }
            self.init(high: high, low: low)
        } else {
            let value = UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16
                | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
            guard value != 0 else { return nil }
            self = .v4(value)
        }
    }

    /// Dotted IPv4 or IPv6 text (zone suffix ignored). Empty or unparsable
    /// text is `nil`, which callers treat as "any address".
    init?(_ text: String) {
        let host = text.split(separator: "%", maxSplits: 1).first.map(String.init) ?? text
        if let v4 = IPv4Address(parsing: host) {
            guard v4.rawValue != 0 else { return nil }
            self = .v4(v4.rawValue)
        } else if let v6 = IPv6Address(parsing: host) {
            self.init(high: v6.high, low: v6.low)
        } else {
            return nil
        }
    }

    /// 127.0.0.0/8 or ::1.
    var isLoopback: Bool {
        switch self {
        case .v4(let value): value >> 24 == 127
        case .v6(let high, let low): high == 0 && low == 1
        }
    }

    private init?(high: UInt64, low: UInt64) {
        if high == 0, low >> 32 == 0xFFFF {
            let value = UInt32(truncatingIfNeeded: low)
            guard value != 0 else { return nil }
            self = .v4(value)
        } else if high == 0, low == 0 {
            return nil
        } else {
            self = .v6(high, low)
        }
    }
}

struct SocketOwner: Sendable, Equatable {
    var pid: Int32
    var transport: FlowTransport
    var localPort: UInt16
    var remotePort: UInt16
    var localAddress: SocketAddress?
    var remoteAddress: SocketAddress?
}

protocol SocketTableReading: Sendable {
    func snapshot(skipPID: Int32) -> [SocketOwner]
    /// One process's sockets (the caller's own is always readable).
    func sockets(ofPID pid: Int32) -> [SocketOwner]
}

extension SocketTableReading {
    func sockets(ofPID pid: Int32) -> [SocketOwner] { [] }
}

/// `pcblist_n` first, libproc fallback (when the table comes back filtered).
/// Reuses one row buffer and grows it when the kernel has more sockets.
final class LibprocSocketTable: SocketTableReading, @unchecked Sendable {
    private var buffer: [prizmx_socket_row]
    private let maxSockets: Int
    private let lock = NSLock()

    init(initialSockets: Int = 4_096, maxSockets: Int = 65_536) {
        buffer = Array(repeating: prizmx_socket_row(), count: initialSockets)
        self.maxSockets = maxSockets
    }

    func snapshot(skipPID: Int32) -> [SocketOwner] {
        lock.lock()
        defer { lock.unlock() }
        let fromPCB = decodeLocked(skipPID: skipPID, fill: prizmx_list_pcblist_n)
        if !fromPCB.isEmpty {
            return fromPCB
        }
        let fromLibproc = decodeLocked(skipPID: skipPID, fill: prizmx_list_sockets)
        if fromLibproc.isEmpty {
            TunnelLog.writeOnce(
                "attribution-socket-table-empty",
                .warn,
                "process attribution unavailable: pcblist_n and libproc both returned no sockets"
            )
        }
        return fromLibproc
    }

    func sockets(ofPID pid: Int32) -> [SocketOwner] {
        lock.lock()
        defer { lock.unlock() }
        return decodeLocked(skipPID: 0) { rows, count, _ in
            prizmx_list_sockets_of_pid(pid, rows, count)
        }
    }

    private func decodeLocked(
        skipPID: Int32,
        fill: (UnsafeMutablePointer<prizmx_socket_row>, Int32, pid_t) -> Int32
    ) -> [SocketOwner] {
        var count = 0
        while true {
            count = buffer.withUnsafeMutableBufferPointer { rows -> Int in
                guard let base = rows.baseAddress else { return 0 }
                return Int(fill(base, Int32(rows.count), skipPID))
            }
            // A full buffer may have truncated the table: grow and re-read.
            guard count >= buffer.count, buffer.count < maxSockets else { break }
            buffer = Array(repeating: prizmx_socket_row(), count: min(buffer.count * 2, maxSockets))
        }
        guard count > 0 else { return [] }
        var owners: [SocketOwner] = []
        owners.reserveCapacity(count)
        for index in 0..<count {
            let row = buffer[index]
            guard let transport = FlowTransport(rawValue: row.transport) else { continue }
            let isIPv6 = row.is_ipv6 != 0
            owners.append(
                SocketOwner(
                    pid: row.pid,
                    transport: transport,
                    localPort: row.local_port,
                    remotePort: row.remote_port,
                    localAddress: withUnsafeBytes(of: row.local_addr) { SocketAddress(bytes: $0, isIPv6: isIPv6) },
                    remoteAddress: withUnsafeBytes(of: row.remote_addr) { SocketAddress(bytes: $0, isIPv6: isIPv6) }
                )
            )
        }
        return owners
    }
}
