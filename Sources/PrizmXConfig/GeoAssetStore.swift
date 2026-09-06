import Foundation
import PrizmXProtocols

/// App Group copies of Clash/Mihomo `geoip.metadb` and `geosite.dat`.
///
/// The Network Extension profile is capped at 512 KB, so the databases live
/// as files (same pattern as the active config). `prepare` downloads them
/// once when a profile actually uses `GEOIP` / `GEOSITE` rules.
public enum GeoAssetStore: Sendable {
    public static let geoIPRelativePath = "geo/geoip.metadb"
    public static let geositeRelativePath = "geo/geosite.dat"

    public struct Sources: Sendable {
        public var geoIP: [URL]
        public var geosite: [URL]

        public init(geoIP: [URL], geosite: [URL]) {
            self.geoIP = geoIP
            self.geosite = geosite
        }

        public static let none = Sources(geoIP: [], geosite: [])

        /// Mihomo defaults, then jsDelivr if GitHub is unreachable.
        public static let `default` = Sources(
            geoIP: [
                URL(string: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb")!,
                URL(string: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb")!,
            ],
            geosite: [
                URL(string: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat")!,
                URL(string: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat")!,
            ]
        )
    }

    public struct Prepared: Sendable, Equatable {
        public var geoIPPath: String?
        public var geositePath: String?

        public init(geoIPPath: String? = nil, geositePath: String? = nil) {
            self.geoIPPath = geoIPPath
            self.geositePath = geositePath
        }
    }

    /// Ensures the requested databases exist under `root` (App Group by default).
    /// Missing files are downloaded; a failed download leaves that path nil so
    /// the tunnel still starts (those rules simply never match).
    public static func prepare(
        root: URL? = TunnelConfigStorage.containerURL(),
        geoIP: Bool,
        geosite: Bool,
        sources: Sources = .default,
        fileManager: FileManager = .default,
        session: URLSession = .shared
    ) async -> Prepared {
        guard let root else { return Prepared() }
        var prepared = Prepared()
        if geoIP {
            let url = root.appendingPathComponent(geoIPRelativePath)
            if await ensureFile(at: url, sources: sources.geoIP, fileManager: fileManager, session: session) {
                prepared.geoIPPath = geoIPRelativePath
            }
        }
        if geosite {
            let url = root.appendingPathComponent(geositeRelativePath)
            if await ensureFile(at: url, sources: sources.geosite, fileManager: fileManager, session: session) {
                prepared.geositePath = geositeRelativePath
            }
        }
        return prepared
    }

    public static func resolve(
        _ relativeOrAbsolute: String?,
        root: URL? = TunnelConfigStorage.containerURL()
    ) -> URL? {
        guard let relativeOrAbsolute, !relativeOrAbsolute.isEmpty else { return nil }
        if relativeOrAbsolute.hasPrefix("/") {
            return URL(fileURLWithPath: relativeOrAbsolute)
        }
        return root?.appendingPathComponent(relativeOrAbsolute)
    }

    private static func ensureFile(
        at url: URL,
        sources: [URL],
        fileManager: FileManager,
        session: URLSession
    ) async -> Bool {
        if isPresent(url, fileManager: fileManager) { return true }
        guard !sources.isEmpty else { return false }
        try? fileManager.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        for source in sources {
            do {
                let (data, response) = try await session.data(from: source)
                if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                    continue
                }
                guard data.count > 1_024 else { continue }
                let temporary = url.appendingPathExtension("tmp")
                try data.write(to: temporary, options: .atomic)
                if fileManager.fileExists(atPath: url.path) {
                    try fileManager.removeItem(at: url)
                }
                try fileManager.moveItem(at: temporary, to: url)
                TunnelLog.write(.info, "geo downloaded \(url.lastPathComponent) bytes=\(data.count)")
                return true
            } catch {
                TunnelLog.write(
                    .error,
                    "geo download \(source.absoluteString) failed: \(error.localizedDescription)"
                )
            }
        }
        return isPresent(url, fileManager: fileManager)
    }

    private static func isPresent(_ url: URL, fileManager: FileManager) -> Bool {
        guard let values = try? url.resourceValues(forKeys: [.fileSizeKey]),
              let size = values.fileSize else {
            return false
        }
        return size > 1_024
    }
}
