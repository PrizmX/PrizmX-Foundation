import Foundation
import PrizmXCore
import PrizmXProtocols

/// Clients of the in-app mixed-port listeners, as the Packet Tunnel
/// extension sees them.
///
/// The sandboxed app attributes mixed-port flows from its own socket table
/// read, which cannot see root / system-account processes (cloudd, apsd,
/// trustd …). The extension runs as root and sees every socket, so it writes
/// the listeners' loopback clients here each second (next to
/// `TunnelMetricsStore`) and the app looks up what it could not place.
public enum ProxyClientStore: Sendable {
    public static let relativePath = "tunnel/proxy-clients.json"
    /// Written every second; older means the extension is not publishing.
    public static let defaultMaxAge: TimeInterval = 3

    public struct Snapshot: Sendable, Codable, Equatable {
        /// Seconds since 1970, taken before the socket table read (not at
        /// the write): sockets opened before this are listed if alive.
        public var writtenAt: TimeInterval
        public var clients: [LoopbackClient]

        public init(writtenAt: TimeInterval, clients: [LoopbackClient]) {
            self.writtenAt = writtenAt
            self.clients = clients
        }

        public func client(port: UInt16, listenPort: UInt16) -> LoopbackClient? {
            clients.first { $0.clientPort == port && $0.listenPort == listenPort }
        }
    }

    public static func fileURL(kitRoot: URL? = nil) -> URL {
        (kitRoot ?? TunnelLog.kitRoot ?? TunnelRuntimeStore.runtimeKitRoot())
            .appendingPathComponent(relativePath)
    }

    /// Atomically replace the file (root writer, user reader — see
    /// `TunnelMetricsStore.save`). Returns `false` on I/O or encode failure.
    @discardableResult
    public static func save(
        _ clients: [LoopbackClient],
        kitRoot: URL? = nil,
        writtenAt: TimeInterval = Date().timeIntervalSince1970
    ) -> Bool {
        do {
            let data = try JSONEncoder().encode(Snapshot(writtenAt: writtenAt, clients: clients))
            try SafeFileWriter.replace(data, at: fileURL(kitRoot: kitRoot), mode: 0o644)
            return true
        } catch {
            TunnelLog.writeOnce(
                "proxy-clients-write-failed",
                .error,
                "proxy clients file write failed: \(error.localizedDescription)"
            )
            return false
        }
    }

    /// Latest snapshot if fresh. `nil` when missing, unreadable, or stale.
    public static func load(
        maxAge: TimeInterval = defaultMaxAge,
        kitRoot: URL? = nil,
        now: TimeInterval = Date().timeIntervalSince1970
    ) -> Snapshot? {
        guard let data = try? Data(contentsOf: fileURL(kitRoot: kitRoot)),
              let snapshot = try? JSONDecoder().decode(Snapshot.self, from: data),
              now - snapshot.writtenAt <= maxAge
        else { return nil }
        return snapshot
    }

    public static func clear(kitRoot: URL? = nil) {
        try? FileManager.default.removeItem(at: fileURL(kitRoot: kitRoot))
    }
}
