import Foundation

/// Low-volume runtime event log for the tunnel, appended to a file in the
/// App Group container. Per-flow request data belongs to the Inspector's
/// request list, not here.
public enum TunnelLog: Sendable {
    public enum Level: String, Sendable {
        case debug
        case info
        case warn
        case error
    }

    public static let defaultAppGroupIdentifier = PrizmXAppGroup.identifier
    public static let defaultDirectoryName = "PrizmXKit"
    public static let relativePath = "logs/tunnel.log"

    private static let maxBytes = 512 * 1024
    private static let keepBytes = 256 * 1024

    private static let ioQueue = DispatchQueue(label: "prizmx.tunnellog")
    nonisolated(unsafe) private static var writtenOnceKeys = Set<String>()
    nonisolated(unsafe) private static var cachedFormatter: DateFormatter?

    /// Kit root (`…/PrizmXKit`) used when `containerURL` is the wrong user
    /// (Packet Tunnel system extension runs as root).
    nonisolated(unsafe) private static var boundKitRoot: URL?

    public static func bind(kitRoot: URL?) {
        ioQueue.sync { boundKitRoot = kitRoot }
    }

    /// `…/PrizmXKit` after `bind`; nil when the process should use `containerURL`.
    public static var kitRoot: URL? {
        ioQueue.sync { boundKitRoot }
    }

    public static func fileURL(
        appGroupIdentifier: String = defaultAppGroupIdentifier,
        directoryName: String = defaultDirectoryName
    ) -> URL? {
        if let boundKitRoot {
            return boundKitRoot.appendingPathComponent(relativePath)
        }
        return FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupIdentifier)?
            .appendingPathComponent(directoryName, isDirectory: true)
            .appendingPathComponent(relativePath)
    }

    public static func write(_ level: Level, _ message: @autoclosure () -> String) {
        let text = message()
        ioQueue.async { appendLocked(level, text) }
    }

    /// Logs once per `key` for the process lifetime (e.g. unsupported UDP kinds).
    public static func writeOnce(_ key: String, _ level: Level, _ message: @autoclosure () -> String) {
        let text = message()
        ioQueue.async {
            guard writtenOnceKeys.insert(key).inserted else { return }
            appendLocked(level, text)
        }
    }

    public static func read() -> String {
        ioQueue.sync {
            guard let url = fileURL(),
                  let data = try? Data(contentsOf: url),
                  let text = String(data: data, encoding: .utf8) else {
                return ""
            }
            return text
        }
    }

    public static func clear() {
        ioQueue.sync {
            writtenOnceKeys.removeAll()
            if let url = fileURL() {
                try? FileManager.default.removeItem(at: url)
            }
        }
    }

    private static func appendLocked(_ level: Level, _ message: String) {
        guard let url = fileURL() else {
            NSLog("PrizmX TunnelLog skipped (no file URL): %@", message)
            return
        }
        let fileManager = FileManager.default
        let line = "\(timestamp()) [\(level.rawValue)] \(message)\n"
        guard let data = line.data(using: .utf8) else { return }
        do {
            try fileManager.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            rotateIfNeeded(url)
            if fileManager.fileExists(atPath: url.path) {
                let handle = try FileHandle(forWritingTo: url)
                defer { try? handle.close() }
                _ = try handle.seekToEnd()
                try handle.write(contentsOf: data)
            } else {
                try data.write(to: url, options: .atomic)
            }
        } catch {
            NSLog("PrizmX TunnelLog write failed %@: %@", url.path, error.localizedDescription)
        }
    }

    private static func rotateIfNeeded(_ url: URL) {
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        guard let size = attributes?[.size] as? Int, size > maxBytes,
              let data = try? Data(contentsOf: url) else { return }
        try? Data(data.suffix(keepBytes)).write(to: url)
    }

    private static func timestamp() -> String {
        if cachedFormatter == nil {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.dateFormat = "MM-dd HH:mm:ss.SSS"
            cachedFormatter = formatter
        }
        return cachedFormatter?.string(from: Date()) ?? ""
    }
}
