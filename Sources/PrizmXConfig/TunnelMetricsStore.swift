import Foundation
import PrizmXCore
import PrizmXProtocols

/// Live tunnel counters for the host UI.
///
/// `NETunnelProviderSession.sendProviderMessage` is unreliable for a
/// Developer ID Packet Tunnel *system* extension: the extension can be
/// forwarding traffic while the sandboxed host gets an empty reply, so
/// Upload/Download stay at zero. The extension already writes logs under
/// `containerPath` as root; this file uses the same kit so the app can
/// read snapshots without that IPC.
public enum TunnelMetricsStore: Sendable {
    public static let relativePath = "tunnel/metrics.json"
    /// Host poll is 1s; allow one missed dump plus clock skew.
    public static let defaultMaxAge: TimeInterval = 3

    struct File: Sendable, Codable, Equatable {
        var writtenAt: TimeInterval
        var metrics: TrafficSnapshot
    }

    public static func fileURL(kitRoot: URL? = nil) -> URL {
        // The system extension runs as root; `homeDirectoryForCurrentUser`
        // would be `/var/root`. Prefer the bound user kit (`containerPath`).
        (kitRoot ?? TunnelLog.kitRoot ?? TunnelRuntimeStore.runtimeKitRoot())
            .appendingPathComponent(relativePath)
    }

    /// Atomically replace the snapshot. Returns `false` on I/O or encode failure.
    @discardableResult
    public static func save(
        _ snapshot: TrafficSnapshot,
        kitRoot: URL? = nil,
        writtenAt: TimeInterval = Date().timeIntervalSince1970
    ) -> Bool {
        let url = fileURL(kitRoot: kitRoot)
        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            let data = try JSONEncoder().encode(File(writtenAt: writtenAt, metrics: snapshot))
            try data.write(to: url, options: .atomic)
            try? inheritOwnership(of: url)
            return true
        } catch {
            TunnelLog.write(.error, "metrics file write failed: \(error.localizedDescription)")
            return false
        }
    }

    /// Latest snapshot if it is fresh enough. `nil` when missing, unreadable, or stale.
    public static func load(
        maxAge: TimeInterval = defaultMaxAge,
        kitRoot: URL? = nil,
        now: TimeInterval = Date().timeIntervalSince1970
    ) -> TrafficSnapshot? {
        let url = fileURL(kitRoot: kitRoot)
        guard let data = try? Data(contentsOf: url),
              let file = try? JSONDecoder().decode(File.self, from: data)
        else { return nil }
        guard now - file.writtenAt <= maxAge else { return nil }
        return file.metrics
    }

    public static func clear(kitRoot: URL? = nil) {
        try? FileManager.default.removeItem(at: fileURL(kitRoot: kitRoot))
    }

    /// The extension writes as root into the user's kit. World-readable is
    /// not enough inside a container — chown to the kit directory owner so
    /// the sandboxed host can open the file.
    private static func inheritOwnership(of url: URL) throws {
        let directory = url.deletingLastPathComponent()
        let attrs = try FileManager.default.attributesOfItem(atPath: directory.path)
        var update: [FileAttributeKey: Any] = [
            .posixPermissions: NSNumber(value: 0o644)
        ]
        if let owner = attrs[.ownerAccountID] {
            update[.ownerAccountID] = owner
        }
        if let group = attrs[.groupOwnerAccountID] {
            update[.groupOwnerAccountID] = group
        }
        try FileManager.default.setAttributes(update, ofItemAtPath: url.path)
    }
}
