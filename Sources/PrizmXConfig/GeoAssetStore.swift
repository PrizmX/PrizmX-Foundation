import Foundation
import PrizmXProtocols
import PrizmXRules

/// App Group copies of Clash/Mihomo `geoip.metadb`, `geosite.dat` and
/// `GeoLite2-ASN.mmdb`.
///
/// The Network Extension profile is capped at 512 KB, so the databases live
/// as files (same pattern as the active config). `prepare` downloads them
/// when a profile actually uses `GEOIP` / `GEOSITE` / `IP-ASN` rules.
/// Downloads are validated before they replace a file (a captive-portal page
/// must never be persisted), and a valid file older than `refreshAge` is
/// refreshed in the background without delaying the caller.
public enum GeoAssetStore: Sendable {
    public static let geoIPRelativePath = "geo/geoip.metadb"
    public static let geositeRelativePath = "geo/geosite.dat"
    public static let asnRelativePath = "geo/GeoLite2-ASN.mmdb"
    public static let refreshAge: TimeInterval = 7 * 24 * 3_600

    enum Kind: Sendable {
        case geoIP
        case geosite
        case asn
    }

    public struct Sources: Sendable {
        public var geoIP: [URL]
        public var geosite: [URL]
        public var asn: [URL]

        public init(geoIP: [URL], geosite: [URL], asn: [URL] = []) {
            self.geoIP = geoIP
            self.geosite = geosite
            self.asn = asn
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
            ],
            asn: [
                URL(string: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb")!,
                URL(string: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb")!,
            ]
        )
    }

    public struct Prepared: Sendable, Equatable {
        public var geoIPPath: String?
        public var geositePath: String?
        public var asnPath: String?

        public init(geoIPPath: String? = nil, geositePath: String? = nil, asnPath: String? = nil) {
            self.geoIPPath = geoIPPath
            self.geositePath = geositePath
            self.asnPath = asnPath
        }
    }

    public struct AssetInfo: Sendable, Equatable {
        public var name: String
        public var relativePath: String
        public var exists: Bool
        public var byteSize: Int64?
        public var updatedAt: Date?

        public init(
            name: String,
            relativePath: String,
            exists: Bool,
            byteSize: Int64? = nil,
            updatedAt: Date? = nil
        ) {
            self.name = name
            self.relativePath = relativePath
            self.exists = exists
            self.byteSize = byteSize
            self.updatedAt = updatedAt
        }
    }

    public struct Status: Sendable, Equatable {
        public var geoIP: AssetInfo
        public var geosite: AssetInfo
        public var asn: AssetInfo

        public var all: [AssetInfo] { [geoIP, geosite, asn] }
    }

    public struct RefreshResult: Sendable, Equatable {
        public var geoIPUpdated: Bool
        public var geositeUpdated: Bool
        public var asnUpdated: Bool

        public var updatedCount: Int {
            [geoIPUpdated, geositeUpdated, asnUpdated].filter { $0 }.count
        }
    }

    /// Reads local file metadata for GeoIP, Geosite and ASN databases without
    /// loading their payloads into memory.
    public static func inspectStatus(
        root: URL? = TunnelConfigStorage.containerURL(),
        fileManager: FileManager = .default
    ) -> Status {
        func info(name: String, relativePath: String) -> AssetInfo {
            guard let url = root?.appendingPathComponent(relativePath),
                  fileManager.fileExists(atPath: url.path)
            else {
                return AssetInfo(name: name, relativePath: relativePath, exists: false)
            }
            let values = try? url.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey])
            return AssetInfo(
                name: name,
                relativePath: relativePath,
                exists: true,
                byteSize: values?.fileSize.map(Int64.init),
                updatedAt: values?.contentModificationDate
            )
        }
        return Status(
            geoIP: info(name: "GeoIP", relativePath: geoIPRelativePath),
            geosite: info(name: "Geosite", relativePath: geositeRelativePath),
            asn: info(name: "GeoLite2-ASN", relativePath: asnRelativePath)
        )
    }

    /// Forces a fresh validated download of Geo databases into `root`.
    /// Existing files remain untouched if a download fails.
    public static func refreshAll(
        root: URL? = TunnelConfigStorage.containerURL(),
        sources: Sources = .default,
        session: URLSession? = nil
    ) async -> RefreshResult {
        guard let root else {
            return RefreshResult(geoIPUpdated: false, geositeUpdated: false, asnUpdated: false)
        }
        let ownSession: URLSession?
        let activeSession: URLSession
        if let session {
            ownSession = nil
            activeSession = session
        } else {
            let config = URLSessionConfiguration.ephemeral
            config.timeoutIntervalForRequest = 20
            config.httpAdditionalHeaders = ["Connection": "close"]
            let created = URLSession(configuration: config)
            ownSession = created
            activeSession = created
        }
        defer { ownSession?.finishTasksAndInvalidate() }

        async let geoIP = download(
            to: root.appendingPathComponent(geoIPRelativePath),
            kind: .geoIP,
            sources: sources.geoIP,
            session: activeSession
        )
        async let geosite = download(
            to: root.appendingPathComponent(geositeRelativePath),
            kind: .geosite,
            sources: sources.geosite,
            session: activeSession
        )
        async let asn = download(
            to: root.appendingPathComponent(asnRelativePath),
            kind: .asn,
            sources: sources.asn,
            session: activeSession
        )
        return await RefreshResult(
            geoIPUpdated: geoIP,
            geositeUpdated: geosite,
            asnUpdated: asn
        )
    }

    /// Ensures the requested databases exist under `root` (App Group by default).
    /// Missing files are downloaded; a failed download leaves that path nil so
    /// the tunnel still starts (those rules simply never match).
    public static func prepare(
        root: URL? = TunnelConfigStorage.containerURL(),
        geoIP: Bool,
        geosite: Bool,
        asn: Bool = false,
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
        if asn {
            let url = root.appendingPathComponent(asnRelativePath)
            if await ensureFile(at: url, kind: .asn, sources: sources.asn, session: session) {
                prepared.asnPath = asnRelativePath
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
        case .geoIP, .asn:
            let marker = Data([0xAB, 0xCD, 0xEF] + Array("MaxMind.com".utf8))
            guard data.range(of: marker, options: .backwards) != nil else { return false }
            if kind == .asn { return (try? ASNMatcher(data: data)) != nil }
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
