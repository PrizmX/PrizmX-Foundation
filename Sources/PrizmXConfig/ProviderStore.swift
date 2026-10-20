import CryptoKit
import Foundation
import os
import PrizmXProtocols
import PrizmXRules

/// Clash `rule-providers` and `proxy-providers`.
///
/// The app downloads `type: http` providers into the kit (`prepare`); the
/// importer reads them from there wherever a profile is parsed, in the app
/// and in the Packet Tunnel (the kit is staged next to the config). Parsing
/// never touches the network: a provider not downloaded yet counts as empty
/// and is reported.
public enum ProviderStore: Sendable {
    public enum Kind: String, Sendable {
        case rule = "rules"
        case proxy = "proxies"
    }

    /// One provider as the profile declares it.
    public struct Definition: Sendable, Hashable {
        public var kind: Kind
        public var name: String
        /// `http`, `file` or `inline`.
        public var type: String
        public var url: URL?
        /// Refresh period for `http`; mihomo's `interval` (seconds).
        public var interval: TimeInterval
        /// Rule providers: `domain`, `ipcidr` or `classical`.
        public var behavior: String?
        /// `yaml`, `text` or `mrs`.
        public var format: String
        /// Proxy providers: name filters applied before any group sees them.
        public var filter: String?
        public var excludeFilter: String?
        public var excludeType: String?
        /// `override` / `dialer-proxy` keys the importer cannot honor.
        public var unsupportedKeys: [String]

        /// Cache file name: the URL's hash, so two profiles naming the same
        /// provider differently share it and same names never collide.
        public var cacheKey: String? {
            guard let url else { return nil }
            let digest = SHA256.hash(data: Data(url.absoluteString.utf8))
            return digest.prefix(12).map { String(format: "%02x", $0) }.joined()
        }
    }

    /// Default refresh for an `http` provider without `interval`.
    public static let defaultInterval: TimeInterval = 24 * 3_600
    /// Largest provider body accepted.
    public static let maxBytes = 32 * 1024 * 1024

    /// Overrides the cache root (tests).
    @TaskLocal public static var rootOverride: URL?

    static var root: URL? {
        rootOverride ?? TunnelConfigStorage.containerURL()
    }

    // MARK: - Definitions

    /// Providers declared by a Clash YAML profile (empty for other formats
    /// or text that does not parse).
    public static func definitions(configText: String) -> [Definition] {
        guard let root = try? YAMLParser.parse(ConfigText.normalized(configText)) else { return [] }
        return definitions(in: root)
    }

    static func definitions(in root: YAMLNode) -> [Definition] {
        var result: [Definition] = []
        for (key, kind) in [("rule-providers", Kind.rule), ("proxy-providers", Kind.proxy)] {
            guard let providers = root.mapping?[key]?.mapping else { continue }
            for name in providers.keys.sorted() {
                guard let node = providers[name] else { continue }
                result.append(definition(name: name, kind: kind, node: node))
            }
        }
        return result
    }

    private static func definition(name: String, kind: Kind, node: YAMLNode) -> Definition {
        let type = (node.string(for: "type") ?? "http").lowercased()
        let interval = node.string(for: "interval").flatMap(TimeInterval.init) ?? defaultInterval
        var unsupported: [String] = []
        for key in ["override", "dialer-proxy"] where node.mapping?[key] != nil {
            unsupported.append(key)
        }
        return Definition(
            kind: kind,
            name: name,
            type: type,
            url: node.string(for: "url").flatMap(URL.init(string:)),
            interval: interval > 0 ? interval : defaultInterval,
            behavior: node.string(for: "behavior")?.lowercased(),
            format: (node.string(for: "format") ?? "yaml").lowercased(),
            filter: node.string(for: "filter"),
            excludeFilter: node.string(for: "exclude-filter"),
            excludeType: node.string(for: "exclude-type"),
            unsupportedKeys: unsupported
        )
    }

    // MARK: - Cache

    static func cacheURL(for definition: Definition, root: URL?) -> URL? {
        guard let root, let key = definition.cacheKey else { return nil }
        return root
            .appendingPathComponent("providers", isDirectory: true)
            .appendingPathComponent(definition.kind.rawValue, isDirectory: true)
            .appendingPathComponent(key)
    }

    /// The downloaded body, or nil when it is not there yet.
    static func cachedBody(for definition: Definition) -> (text: String, modified: Date)? {
        guard let url = cacheURL(for: definition, root: root),
              let data = try? Data(contentsOf: url),
              let text = String(data: data, encoding: .utf8)
        else { return nil }
        let modified = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?
            .contentModificationDate ?? .distantPast
        return (text, modified)
    }

    // MARK: - Download (app)

    /// Downloads every `http` provider of `configText` that is missing, or
    /// older than its interval (all of them with `force`). A failed download
    /// keeps the previous file. Returns true when any file changed.
    @discardableResult
    public static func prepare(
        configText: String,
        force: Bool = false,
        session: URLSession = .shared
    ) async -> Bool {
        let pending = definitions(configText: configText).filter { definition in
            guard definition.type == "http", let url = cacheURL(for: definition, root: root) else { return false }
            return force || isStale(url, interval: definition.interval)
        }
        guard !pending.isEmpty, let root else { return false }
        var changed = false
        // A few at a time: profiles list dozens of providers on one host.
        await withTaskGroup(of: Bool.self) { group in
            var iterator = pending.makeIterator()
            func enqueue() {
                guard let next = iterator.next() else { return }
                group.addTask { await download(next, root: root, session: session) }
            }
            for _ in 0..<4 { enqueue() }
            for await updated in group {
                if updated { changed = true }
                enqueue()
            }
        }
        return changed
    }

    /// Next time a provider of `configText` is due, for the app's refresh
    /// timer; nil when none is downloaded over http.
    public static func nextRefresh(configText: String) -> Date? {
        definitions(configText: configText).compactMap { definition -> Date? in
            guard definition.type == "http", let url = cacheURL(for: definition, root: root) else { return nil }
            let modified = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?
                .contentModificationDate ?? .distantPast
            return modified.addingTimeInterval(definition.interval)
        }.min()
    }

    /// Latest change among the downloaded providers of `configText`, so the
    /// app can tell when a catalog parsed earlier is out of date.
    public static func stamp(configText: String) -> Date? {
        definitions(configText: configText).compactMap { definition -> Date? in
            guard let url = cacheURL(for: definition, root: root) else { return nil }
            return (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
        }.max()
    }

    private static func isStale(_ url: URL, interval: TimeInterval) -> Bool {
        guard let modified = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?
            .contentModificationDate
        else { return true }
        return Date().timeIntervalSince(modified) >= interval
    }

    private static func download(_ definition: Definition, root: URL, session: URLSession) async -> Bool {
        guard let source = definition.url, let target = cacheURL(for: definition, root: root) else { return false }
        var request = URLRequest(url: source, timeoutInterval: 30)
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        do {
            let (data, response) = try await session.data(for: request)
            if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                TunnelLog.write(.warn, "provider \(definition.name) download failed: HTTP \(http.statusCode)")
                return false
            }
            guard !data.isEmpty, data.count <= maxBytes, isPlausibleBody(data) else {
                TunnelLog.write(.warn, "provider \(definition.name) download rejected: not a provider body")
                return false
            }
            if let existing = try? Data(contentsOf: target), existing == data {
                // Unchanged: touch it so the interval restarts.
                try? FileManager.default.setAttributes([.modificationDate: Date()], ofItemAtPath: target.path)
                return false
            }
            try FileManager.default.createDirectory(
                at: target.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try data.write(to: target, options: .atomic)
            TunnelLog.write(.info, "provider \(definition.name) updated bytes=\(data.count)")
            return true
        } catch {
            TunnelLog.write(.warn, "provider \(definition.name) download failed: \(error.localizedDescription)")
            return false
        }
    }

    /// Same User-Agent as subscriptions: panels serve Clash formats to it.
    private static var userAgent: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.0"
        return "clash.meta mihomo/1.19 PrizmX/\(version)"
    }

    /// Rejects captive-portal / error pages before they replace a good file.
    private static func isPlausibleBody(_ data: Data) -> Bool {
        let head = String(decoding: data.prefix(256), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        return !(head.hasPrefix("<!doctype") || head.hasPrefix("<html"))
    }
}

/// Rule sets compiled from provider files, reused while the file is
/// unchanged: one profile is parsed several times (catalog, validation,
/// engine), and a large list takes a while to index.
enum RuleSetCache {
    private struct Key: Hashable {
        var cacheKey: String
        var behavior: String
        var format: String
    }

    private static let entries = OSAllocatedUnfairLock<[Key: (modified: Date, set: RuleSet, skipped: Int)]>(
        initialState: [:]
    )
    private static let capacity = 64

    static func lookup(_ definition: ProviderStore.Definition, modified: Date) -> (RuleSet, Int)? {
        guard let key = key(definition) else { return nil }
        return entries.withLock { state in
            guard let hit = state[key], hit.modified == modified else { return nil }
            return (hit.set, hit.skipped)
        }
    }

    static func store(_ set: RuleSet, skipped: Int, for definition: ProviderStore.Definition, modified: Date) {
        guard let key = key(definition) else { return }
        entries.withLock { state in
            if state.count >= capacity, state[key] == nil { state.removeAll() }
            state[key] = (modified, set, skipped)
        }
    }

    private static func key(_ definition: ProviderStore.Definition) -> Key? {
        definition.cacheKey.map { Key(cacheKey: $0, behavior: definition.behavior ?? "", format: definition.format) }
    }
}
