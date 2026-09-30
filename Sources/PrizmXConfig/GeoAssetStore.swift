import Foundation
import PrizmXProtocols
import PrizmXRules

/// App Group copies of Clash/Mihomo `geoip.metadb` and `geosite.dat`.
///
/// The Network Extension profile is capped at 512 KB, so the databases live
/// as files (same pattern as the active config). `prepare` downloads them
/// when a profile actually uses `GEOIP` / `GEOSITE` rules. Downloads are
/// validated before they replace a file (a captive-portal page must never be
/// persisted), and a valid file older than `refreshAge` is refreshed in the
/// background without delaying the caller.
public enum GeoAssetStore: Sendable {
    public static let geoIPRelativePath = "geo/geoip.metadb"
    public static let geositeRelativePath = "geo/geosite.dat"
    public static let refreshAge: TimeInterval = 7 * 24 * 3_600

    enum Kind: Sendable {
        case geoIP
        case geosite
    }

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
            if await ensureFile(at: url, kind: .geoIP, sources: sources.geoIP, session: session) {
                prepared.geoIPPath = geoIPRelativePath
            }
        }
        if geosite {
            let url = root.appendingPathComponent(geositeRelativePath)
            if await ensureFile(at: url, kind: .geosite, sources: sources.geosite, session: session) {
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
        kind: Kind,
        sources: [URL],
        session: URLSession
    ) async -> Bool {
        if isValidFile(url, kind: kind) {
            if !sources.isEmpty, isStale(url) {
                Task.detached(priority: .utility) {
                    _ = await download(to: url, kind: kind, sources: sources, session: session)
                }
            }
            return true
        }
        return await download(to: url, kind: kind, sources: sources, session: session)
    }

    /// Tries each source; the first body that validates atomically replaces
    /// `url`. On failure an existing file is left untouched.
    static func download(
        to url: URL,
        kind: Kind,
        sources: [URL],
        session: URLSession
    ) async -> Bool {
        guard !sources.isEmpty else { return false }
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        for source in sources {
            do {
                let (data, response) = try await session.data(from: source)
                if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                    continue
                }
                guard isValid(data, kind: kind) else {
                    TunnelLog.write(.error, "geo download \(source.absoluteString) rejected: invalid \(url.lastPathComponent)")
                    continue
                }
                // `.atomic` writes a temporary file and renames it over `url`.
                try data.write(to: url, options: .atomic)
                TunnelLog.write(.info, "geo downloaded \(url.lastPathComponent) bytes=\(data.count)")
                return true
            } catch {
                TunnelLog.write(
                    .error,
                    "geo download \(source.absoluteString) failed: \(error.localizedDescription)"
                )
            }
        }
        return false
    }

    static func isValidFile(_ url: URL, kind: Kind) -> Bool {
        guard let data = try? Data(contentsOf: url, options: [.mappedIfSafe]) else { return false }
        return isValid(data, kind: kind)
    }

    static func isValid(_ data: Data, kind: Kind) -> Bool {
        switch kind {
        case .geoIP:
            let marker = Data([0xAB, 0xCD, 0xEF] + Array("MaxMind.com".utf8))
            guard data.range(of: marker, options: .backwards) != nil else { return false }
            return (try? GeoIPMatcher(data: data)) != nil
        case .geosite:
            // `GeoSiteList` starts with field 1 (length-delimited); walking it
            // with a tag filter that matches nothing checks the framing only.
            guard data.first == 0x0A else { return false }
            return (try? GeositeDatParser.parse(data: data, includeTags: ["\u{0}"])) != nil
        }
    }

    private static func isStale(_ url: URL) -> Bool {
        guard let values = try? url.resourceValues(forKeys: [.contentModificationDateKey]),
              let modified = values.contentModificationDate
        else {
            return true
        }
        return Date().timeIntervalSince(modified) > refreshAge
    }
}
