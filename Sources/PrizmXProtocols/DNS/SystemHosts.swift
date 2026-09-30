import Foundation
import os

/// `/etc/hosts` lookup for destinations that never reach libc.
///
/// With the system proxy on, apps send the hostname to the mixed port
/// (HTTP CONNECT / SOCKS domain) and skip `getaddrinfo`, so a hosts-file
/// edit is invisible. Mappings found here replace upstream DNS. Local
/// bindings (loopback / LAN / link-local / unspecified) are dialed on this
/// machine, since a remote node cannot reach them; public addresses follow
/// the rule and are handed to the chosen outbound (as mihomo does).
/// `REJECT` rules still win.
public enum SystemHosts: Sendable {
    public static let defaultPath = "/etc/hosts"
    /// `/etc` is a symlink to `/private/etc`. App Sandbox allows the latter
    /// literally; try both so a denied symlink open still sees the file.
    static let candidatePaths = [defaultPath, "/private/etc/hosts"]
    /// Re-stat at most this often. A changed mtime/size is reparsed immediately
    /// once the window elapses, so an edit applies on the next connection.
    static let refreshInterval: TimeInterval = 1

    /// Addresses for one name, in file order.
    public struct Mapping: Sendable, Equatable {
        public var addresses: [Endpoint.Host]
        public var ipv4: [IPv4Address]
        public var ipv6: [IPv6Address]

        public var isEmpty: Bool { addresses.isEmpty }

        public var summary: String {
            addresses.map(\.description).joined(separator: ",")
        }

        /// True when any address only means something on this host or its
        /// LAN (127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, 0.0.0.0,
        /// ::1, ::, fc00::/7, fe80::/10). A remote node would dial its own
        /// network instead, so such mappings stay DIRECT.
        public var isLocalBinding: Bool {
            ipv4.contains(where: Self.isLocal) || ipv6.contains(where: Self.isLocal)
        }

        static func isLocal(_ address: IPv4Address) -> Bool {
            let value = address.rawValue
            return value >> 24 == 127
                || value >> 24 == 10
                || value >> 20 == 0xAC1
                || value >> 16 == 0xC0A8
                || value >> 16 == 0xA9FE
                || value == 0
        }

        static func isLocal(_ address: IPv6Address) -> Bool {
            if address.high == 0, address.low <= 1 { return true } // :: and ::1
            let top = address.high >> 48
            return top & 0xFE00 == 0xFC00 || top & 0xFFC0 == 0xFE80
        }

        public init(
            addresses: [Endpoint.Host] = [],
            ipv4: [IPv4Address] = [],
            ipv6: [IPv6Address] = []
        ) {
            self.addresses = addresses
            self.ipv4 = ipv4
            self.ipv6 = ipv6
        }
    }

    /// Test seam. Production leaves this unset and reads `candidatePaths`.
    @TaskLocal static var pathOverride: String?

    private struct Cache {
        var path = ""
        var stamp = Stamp.missing
        var expires = Date.distantPast
        var table: [String: Mapping] = [:]
    }

    private struct Stamp: Equatable {
        var exists: Bool
        var mtime: Date
        var size: Int64

        static let missing = Stamp(exists: false, mtime: .distantPast, size: -1)
    }

    private static let cache = OSAllocatedUnfairLock(initialState: Cache())
    private static let loggedUnreadable = OSAllocatedUnfairLock(initialState: Set<String>())

    /// Lowercased hosts-file hit, or nil when the name is not listed.
    public static func lookup(_ name: String) -> Mapping? {
        let key = normalize(name)
        guard !key.isEmpty else { return nil }
        return load()[key]
    }

    /// Parses hosts-file text. Names are lowercased; a trailing dot is stripped.
    /// Comments (`#`) and non-IP first fields are ignored. Later lines append
    /// addresses for the same name.
    public static func parse(_ text: String) -> [String: Mapping] {
        var table: [String: Mapping] = [:]
        for rawLine in text.split(whereSeparator: \.isNewline) {
            var line = String(rawLine)
            if let hash = line.firstIndex(of: "#") {
                line = String(line[..<hash])
            }
            let fields = line.split(whereSeparator: \.isWhitespace).map(String.init)
            guard fields.count >= 2 else { continue }
            guard let host = addressHost(fields[0]) else { continue }
            for name in fields.dropFirst() {
                let key = normalize(name)
                guard !key.isEmpty else { continue }
                var mapping = table[key] ?? Mapping()
                append(host, to: &mapping)
                table[key] = mapping
            }
        }
        return table
    }

    static func normalize(_ name: String) -> String {
        var key = name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while key.hasSuffix(".") { key.removeLast() }
        return key
    }

    private static func addressHost(_ text: String) -> Endpoint.Host? {
        if let address = IPv4Address(parsing: text) {
            return .ipv4(address)
        }
        // Drop a zone id (`fe80::1%lo0`); the address parser rejects it.
        let literal = text.split(separator: "%", maxSplits: 1).first.map(String.init) ?? text
        if let address = IPv6Address(parsing: literal) {
            return .ipv6(address)
        }
        return nil
    }

    private static func append(_ host: Endpoint.Host, to mapping: inout Mapping) {
        switch host {
        case .ipv4(let address):
            guard !mapping.ipv4.contains(address) else { return }
            mapping.ipv4.append(address)
            mapping.addresses.append(host)
        case .ipv6(let address):
            guard !mapping.ipv6.contains(address) else { return }
            mapping.ipv6.append(address)
            mapping.addresses.append(host)
        case .domain:
            return
        }
    }

    private static func load() -> [String: Mapping] {
        let paths = pathOverride.map { [$0] } ?? candidatePaths
        let now = Date()
        if let hit = cache.withLock({ state -> [String: Mapping]? in
            guard paths.contains(state.path) else { return nil }
            if state.expires > now { return state.table }
            // Window elapsed: re-stat, but keep the table unless the file changed.
            guard state.stamp == fileStamp(state.path) else { return nil }
            state.expires = now.addingTimeInterval(refreshInterval)
            return state.table
        }) {
            return hit
        }
        let (path, table) = readFirst(paths)
        cache.withLock { state in
            state = Cache(
                path: path,
                stamp: fileStamp(path),
                expires: now.addingTimeInterval(refreshInterval),
                table: table
            )
        }
        return table
    }

    private static func readFirst(_ paths: [String]) -> (String, [String: Mapping]) {
        var lastError: Error?
        for path in paths {
            do {
                return (path, parse(try text(at: path)))
            } catch {
                lastError = error
            }
        }
        let joined = paths.joined(separator: ", ")
        let first = loggedUnreadable.withLock { seen -> Bool in
            seen.insert(joined).inserted
        }
        if first, let lastError {
            TunnelLog.write(.warn, "system hosts unreadable \(joined): \(lastError.localizedDescription)")
        }
        return (paths[0], [:])
    }

    private static func text(at path: String) throws -> String {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        return String(data: data, encoding: .utf8)
            ?? String(data: data, encoding: .isoLatin1)
            ?? ""
    }

    private static func fileStamp(_ path: String) -> Stamp {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else {
            return .missing
        }
        return Stamp(
            exists: true,
            mtime: attrs[.modificationDate] as? Date ?? .distantPast,
            size: (attrs[.size] as? NSNumber)?.int64Value ?? 0
        )
    }
}
