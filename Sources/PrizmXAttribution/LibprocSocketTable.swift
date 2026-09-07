import Darwin
import Foundation
import PrizmXAttributionC
import PrizmXCore

struct SocketOwner: Sendable, Equatable {
    var pid: Int32
    var transport: FlowTransport
    var localPort: UInt16
    var remotePort: UInt16
    var localAddress: String
    var remoteAddress: String
}

protocol SocketTableReading: Sendable {
    func snapshot(skipPID: Int32) -> [SocketOwner]
}

/// `pcblist_n` first (works inside the NE sandbox), libproc fallback
/// (unsandboxed / CLI). Reuses one row buffer so SYN misses don't allocate.
final class LibprocSocketTable: SocketTableReading, @unchecked Sendable {
    private var buffer: [prizmx_socket_row]
    private let lock = NSLock()

    init(maxSockets: Int = 4_096) {
        buffer = Array(repeating: prizmx_socket_row(), count: maxSockets)
    }

    func snapshot(skipPID: Int32) -> [SocketOwner] {
        lock.lock()
        defer { lock.unlock() }
        let fromPCB = decodeLocked(skipPID: skipPID, fill: prizmx_list_pcblist_n)
        if !fromPCB.isEmpty {
            return fromPCB
        }
        return decodeLocked(skipPID: skipPID, fill: prizmx_list_sockets)
    }

    private func decodeLocked(
        skipPID: Int32,
        fill: (UnsafeMutablePointer<prizmx_socket_row>, Int32, pid_t) -> Int32
    ) -> [SocketOwner] {
        let count = buffer.withUnsafeMutableBufferPointer { rows -> Int in
            guard let base = rows.baseAddress else { return 0 }
            return Int(fill(base, Int32(rows.count), skipPID))
        }
        guard count > 0 else { return [] }
        var owners: [SocketOwner] = []
        owners.reserveCapacity(count)
        for index in 0..<count {
            let row = buffer[index]
            guard let transport = FlowTransport(rawValue: row.transport) else { continue }
            owners.append(
                SocketOwner(
                    pid: row.pid,
                    transport: transport,
                    localPort: row.local_port,
                    remotePort: row.remote_port,
                    localAddress: "",
                    remoteAddress: ""
                )
            )
        }
        return owners
    }
}
