import Foundation
import Network
import os

/// Outbound DNS plane (Clash internal DNS client).
///
/// FakeIP answers App queries on the TUN. This type is the only resolver
/// allowed to produce real IPs for node dials and DIRECT destinations.
///
/// Answers are merged across the role's nameservers (Clash-style concurrent
/// querying), cached per answer TTL, and single-flighted per domain. A dial
/// failure should call `markBad` so the next dial re-resolves instead of
/// pinning a dead CDN edge.
public final class DNSClient: Sendable {
    /// Bound for the duration of a splice / probe so outbounds do not fall
    /// back to the system resolver (which is FakeDNS inside the tunnel).
    @TaskLocal public static var current: DNSClient?

    public let settings: DNSSettings

    private struct CacheKey: Hashable, Sendable {
        var domain: String
        var role: DNSRole

        var persistKey: String { "\(role.description)|\(domain)" }

        static func from(persistKey: String) -> CacheKey? {
            guard let separator = persistKey.firstIndex(of: "|") else { return nil }
            let role: DNSRole
            switch persistKey[..<separator] {
            case "proxy-server": role = .proxyServer
            case "direct": role = .direct
            default: return nil
            }
            return CacheKey(domain: String(persistKey[persistKey.index(after: separator)...]), role: role)
        }
    }

    private struct CachedEntry: Sendable {
        var addresses: [IPv4Address]
        var expires: Date
    }

    private let cache = OSAllocatedUnfairLock<[CacheKey: CachedEntry]>(initialState: [:])
    private let inflight = OSAllocatedUnfairLock<[CacheKey: Task<([IPv4Address], TimeInterval), Error>]>(initialState: [:])
    private let bootstrapCache = OSAllocatedUnfairLock<[String: CachedEntry]>(initialState: [:])
    /// Last-known-good addresses per key, most-recent first. Set only on a
    /// *successful dial*, so forged/poisoned answers can never get in.
    private let good = OSAllocatedUnfairLock<[CacheKey: (addresses: [IPv4Address], touched: Date)]>(initialState: [:])
    private let persistenceURL: URL?
    /// Test seam: replaces the nameserver transport factory (the real one
    /// rejects loopback nameservers, which local test responders need).
    var transportFactory: (@Sendable (NameserverEndpoint) -> (any NameserverTransport)?)? {
        get { transportFactoryLock.withLock { $0 } }
        set { transportFactoryLock.withLock { $0 = newValue } }
    }
    private let transportFactoryLock = OSAllocatedUnfairLock<(@Sendable (NameserverEndpoint) -> (any NameserverTransport)?)?>(initialState: nil)
    /// Hostnames resolved in the **app** process (system DNS). First-class
    /// candidates for node dials — the extension must not re-guess them.
    private let pinned: [String: [IPv4Address]]
    /// Per-address blacklist from failed dials. Time-boxed: a "dead" CDN edge
    /// must be retried later — a permanent mark bricks single-A fast-flux
    /// domains (the only answer gets filtered out forever).
    private let bad = OSAllocatedUnfairLock<[CacheKey: [IPv4Address: Date]]>(initialState: [:])
    private let badTTL: TimeInterval
    /// Clean public resolvers queried when every pinned / configured answer
    /// for a node hostname was marked bad — the Clash
    /// `proxy-server-nameserver` safety net. Overrides are a test seam.
    public let lastResortNameservers: [NameserverEndpoint]

    /// CN-public resolvers that answer node hostnames without the carrier's
    /// GeoDNS/poisoned view. UDP only: reachable from the extension without
    /// bootstrap resolution.
    public static var defaultLastResortNameservers: [NameserverEndpoint] {
        ["223.5.5.5", "119.29.29.29"].compactMap { NameserverEndpoint.udp(ip: $0) }
    }

    public init(
        settings: DNSSettings,
        persistenceURL: URL? = nil,
        pinnedNodeAddresses: [String: [IPv4Address]] = [:],
        badTTL: TimeInterval = 60,
        lastResortNameservers: [NameserverEndpoint]? = nil
    ) {
        self.settings = settings
        self.persistenceURL = persistenceURL
        self.pinned = Dictionary(uniqueKeysWithValues: pinnedNodeAddresses.map {
            ($0.key.lowercased(), $0.value)
        })
        self.badTTL = badTTL
        self.lastResortNameservers = lastResortNameservers ?? Self.defaultLastResortNameservers
        loadPersisted()
    }

    /// Reads the persisted last-known-good node addresses (proxy-server
    /// plane) written by the tunnel extension after successful dials.
    /// The app's pin refresh leads with these: DNS answers are just
    /// candidates — a proven address survives rotation / poisoning.
    public static func persistedGoodNodeAddresses(
        url: URL? = defaultPersistenceURL
    ) -> [String: [IPv4Address]] {
        guard let url,
              let data = try? Data(contentsOf: url),
              let dict = try? JSONDecoder().decode([String: [String]].self, from: data) else { return [:] }
        var result: [String: [IPv4Address]] = [:]
        for (key, raw) in dict {
            guard key.hasPrefix("proxy-server|") else { continue }
            let addresses = raw.compactMap { IPv4Address(parsing: $0) }
            if !addresses.isEmpty {
                result[String(key.dropFirst("proxy-server|".count))] = addresses
            }
        }
        return result
    }

    /// App Group persistence used by the tunnel providers (survives process
    /// restarts; a proven edge outlives any single tunnel session).
    public static var defaultPersistenceURL: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: TunnelLog.defaultAppGroupIdentifier)?
            .appendingPathComponent(TunnelLog.defaultDirectoryName, isDirectory: true)
            .appendingPathComponent("dns-good.json")
    }

    /// All A records for `domain` on the given plane, merged across the
    /// role's nameservers. Cached and single-flighted.
    ///
    /// Proven (`markGood`) addresses win over App-pinned ones, which win over
    /// a fresh lookup. If any preferred address exists, it is returned
    /// immediately — the union lookup must not block the first dial.
    public func resolveAll(_ domain: String, role: DNSRole) async throws -> [IPv4Address] {
        let key = CacheKey(domain: domain.lowercased(), role: role)
        let preferred = preferredAddresses(key: key)
        if !preferred.isEmpty {
            Task { _ = try? await lookupCached(key) }
            return preferred
        }
        do {
            let answers = try await lookupCached(key)
            let filtered = answers.filter { !isBad(key, $0) }
            if !filtered.isEmpty {
                return Self.mergeGoodFirst(good: preferred, answers: filtered)
            }
            // Every candidate was marked bad recently. Node planes re-query
            // the clean last-resort resolvers (pin + poisoned channels are
            // bypassed) instead of retrying a dead answer in place.
            if let fresh = try await lastResortAnswers(domain: domain, key: key, role: role) {
                return fresh
            }
            if !answers.isEmpty {
                TunnelLog.write(.debug, "dns \(role) \(domain) all \(answers.count) candidates were marked bad, retrying")
            }
            return Self.mergeGoodFirst(good: preferred, answers: filtered.isEmpty ? answers : filtered)
        } catch {
            // Configured channels failed outright (e.g. a dead DoH): same net.
            if let fresh = try await lastResortAnswers(domain: domain, key: key, role: role) {
                return fresh
            }
            throw error
        }
    }

    func preferredAddresses(domain: String, role: DNSRole) -> [IPv4Address] {
        preferredAddresses(key: CacheKey(domain: domain.lowercased(), role: role))
    }

    private func preferredAddresses(key: CacheKey) -> [IPv4Address] {
        let goodList = good.withLock { $0[key]?.addresses ?? [] }
        let pinList = pinned[key.domain] ?? []
        return Self.mergeGoodFirst(good: goodList, answers: pinList).filter { !isBad(key, $0) }
    }

    private func isBad(_ key: CacheKey, _ address: IPv4Address) -> Bool {
        bad.withLock { map in
            guard let marked = map[key]?[address] else { return false }
            if Date().timeIntervalSince(marked) > badTTL {
                map[key]?[address] = nil
                if map[key]?.isEmpty == true { map[key] = nil }
                return false
            }
            return true
        }
    }

    private func lookupCached(_ key: CacheKey) async throws -> [IPv4Address] {
        if let hit = cache.withLock({ $0[key] }), hit.expires > .now, !hit.addresses.isEmpty {
            return hit.addresses
        }
        let task: Task<([IPv4Address], TimeInterval), Error> = inflight.withLock { map in
            if let existing = map[key] { return existing }
            let spawned = Task { try await self.lookup(domain: key.domain, role: key.role) }
            map[key] = spawned
            return spawned
        }
        do {
            let (addresses, ttl) = try await task.value
            cache.withLock {
                $0[key] = CachedEntry(addresses: addresses, expires: Date().addingTimeInterval(ttl))
            }
            inflight.withLock { $0[key] = nil }
            return addresses
        } catch {
            inflight.withLock { $0[key] = nil }
            throw error
        }
    }

    /// First A record (compatibility for single-dial call sites).
    public func resolve(_ domain: String, role: DNSRole) async throws -> IPv4Address {
        guard let first = try await resolveAll(domain, role: role).first else {
            throw DNSError.noRecord(domain)
        }
        return first
    }

    /// Good addresses for a key (test seam + fake-ip-filter callers).
    func goodAddresses(domain: String, role: DNSRole) -> [IPv4Address] {
        good.withLock { $0[CacheKey(domain: domain.lowercased(), role: role)]?.addresses ?? [] }
    }

    /// Good-first, deduplicated candidate ordering.
    static func mergeGoodFirst(good: [IPv4Address], answers: [IPv4Address]) -> [IPv4Address] {
        var merged = good
        for address in answers where !merged.contains(address) {
            merged.append(address)
        }
        return merged
    }

    /// A dial to `address` failed: drop it from the cache so the next dial
    /// re-resolves (CDN edges drift; a dead edge must not be pinned).
    public func markBad(domain: String, role: DNSRole, address: IPv4Address) {
        let key = CacheKey(domain: domain.lowercased(), role: role)
        cache.withLock { map in
            guard var entry = map[key] else { return }
            entry.addresses.removeAll { $0 == address }
            if entry.addresses.isEmpty {
                map[key] = nil
            } else {
                map[key] = entry
            }
        }
        let removed = good.withLock { map -> Bool in
            guard var entry = map[key], entry.addresses.contains(address) else { return false }
            entry.addresses.removeAll { $0 == address }
            entry.touched = Date()
            map[key] = entry.addresses.isEmpty ? nil : entry
            return true
        }
        bad.withLock { map in
            map[key, default: [:]][address] = Date()
            return
        }
        if removed { persist() }
    }

    /// A dial to `address` succeeded: remember it as last-known-good. Only
    /// proven addresses enter this list, so it can prefer a live edge even
    /// when every resolver currently serves a dead generation.
    public func markGood(domain: String, role: DNSRole, address: IPv4Address) {
        let key = CacheKey(domain: domain.lowercased(), role: role)
        let changed = good.withLock { map -> Bool in
            var entry = map[key] ?? (addresses: [], touched: Date())
            guard entry.addresses.first != address else { return false }
            entry.addresses.removeAll { $0 == address }
            entry.addresses.insert(address, at: 0)
            if entry.addresses.count > 3 { entry.addresses = Array(entry.addresses.prefix(3)) }
            entry.touched = Date()
            map[key] = entry
            if map.count > 2048 {
                let cutoff = map.sorted { $0.value.touched < $1.value.touched }.prefix(map.count / 4).map(\.key)
                for stale in cutoff { map[stale] = nil }
            }
            return true
        }
        bad.withLock { map in
            map[key]?[address] = nil
            if map[key]?.isEmpty == true { map[key] = nil }
            return
        }
        if changed { persist() }
    }

    /// Resolve a host for `NWConnection` (first candidate). IP literals pass
    /// through; domains require `DNSClient.current` and never use the system
    /// resolver.
    public static func resolve(_ host: Endpoint.Host, role: DNSRole) async throws -> NWEndpoint.Host {
        switch host {
        case .ipv4(let address):
            return NWEndpoint.Host(address.description)
        case .ipv6(let address):
            return NWEndpoint.Host(address.description)
        case .domain(let domain):
            guard let client = DNSClient.current else { throw DNSError.notConfigured }
            let address = try await client.resolve(domain, role: role)
            TunnelLog.write(.debug, "dns \(role) \(domain) → \(address)")
            return NWEndpoint.Host(address.description)
        }
    }

    /// All candidates for a host. Empty for IP literals (the caller dials the
    /// literal directly); domains produce ordered A records.
    public static func resolveAll(_ host: Endpoint.Host, role: DNSRole) async throws -> [IPv4Address] {
        guard case .domain(let domain) = host else { return [] }
        guard let client = DNSClient.current else { throw DNSError.notConfigured }
        let addresses = try await client.resolveAll(domain, role: role)
        TunnelLog.write(.debug, "dns \(role) \(domain) → \(addresses.map(\.description))")
        return addresses
    }

    // MARK: - Persistence

    private func persist() {
        guard let persistenceURL else { return }
        let snapshot: [String: [String]] = good.withLock { map in
            Dictionary(uniqueKeysWithValues: map.map { ($0.key.persistKey, $0.value.addresses.map(\.description)) })
        }
        guard let data = try? JSONEncoder().encode(snapshot) else { return }
        try? FileManager.default.createDirectory(
            at: persistenceURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try? data.write(to: persistenceURL, options: .atomic)
    }

    private func loadPersisted() {
        guard let persistenceURL,
              let data = try? Data(contentsOf: persistenceURL),
              let dict = try? JSONDecoder().decode([String: [String]].self, from: data) else { return }
        var loaded: [CacheKey: (addresses: [IPv4Address], touched: Date)] = [:]
        for (persistKey, addresses) in dict {
            guard let key = CacheKey.from(persistKey: persistKey) else { continue }
            let parsed = addresses.compactMap { IPv4Address(parsing: $0) }
            if !parsed.isEmpty {
                loaded[key] = (addresses: parsed, touched: Date())
            }
        }
        let final = loaded
        good.withLock { $0 = final }
    }

    // MARK: - Lookup

    /// Last-resort re-query for node hostnames whose pinned / configured
    /// answers all failed. Returns nil when the role is not `.proxyServer`,
    /// no last-resort nameservers exist, or the fresh answers are also all
    /// bad-marked. A successful answer is cached briefly so the next dial
    /// skips the failed-channel timeout dance.
    private func lastResortAnswers(domain: String, key: CacheKey, role: DNSRole) async throws -> [IPv4Address]? {
        guard role == .proxyServer, !lastResortNameservers.isEmpty else { return nil }
        guard let (answers, ttl) = try? await query(
            endpoints: lastResortNameservers,
            domain: domain,
            role: role
        ) else { return nil }
        let clean = answers.filter { !isBad(key, $0) }
        guard !clean.isEmpty else { return nil }
        TunnelLog.write(.info, "dns \(role) \(domain) last-resort → \(clean.map(\.description))")
        cache.withLock {
            $0[key] = CachedEntry(addresses: clean, expires: Date().addingTimeInterval(min(ttl, 120)))
        }
        return clean
    }

    private func lookup(domain: String, role: DNSRole) async throws -> ([IPv4Address], TimeInterval) {
        let endpoints = settings.endpoints(for: role)
        guard !endpoints.isEmpty else { throw DNSError.noNameserver }
        return try await query(endpoints: endpoints, domain: domain, role: role)
    }

    private func query(
        endpoints: [NameserverEndpoint],
        domain: String,
        role: DNSRole
    ) async throws -> ([IPv4Address], TimeInterval) {
        var merged: [IPv4Address] = []
        var minTTL: UInt32?
        var sawTimeout = false
        var lastError: Error?
        for endpoint in endpoints {
            guard let transport = makeTransport(endpoint) else { continue }
            do {
                let records = try await transport.query(domain)
                for record in records {
                    if !merged.contains(record.address) { merged.append(record.address) }
                    minTTL = min(minTTL ?? record.ttl, record.ttl)
                }
            } catch DNSError.timeout {
                TunnelLog.write(.debug, "dns \(role) \(domain) via \(endpoint) timeout")
                sawTimeout = true
            } catch {
                TunnelLog.write(.debug, "dns \(role) \(domain) via \(endpoint) failed: \(error.localizedDescription)")
                lastError = error
            }
        }
        guard !merged.isEmpty else {
            if sawTimeout { throw DNSError.timeout }
            if let lastError { throw lastError }
            throw DNSError.noRecord(domain)
        }
        // Clamp: keep entries long enough to matter, short enough to follow
        // fast-flux CDN edges.
        let ttl = TimeInterval(min(max(minTTL ?? 30, 15), 300))
        return (merged, ttl)
    }

    private func makeTransport(_ endpoint: NameserverEndpoint) -> (any NameserverTransport)? {
        if let override = transportFactory { return override(endpoint) }
        switch endpoint {
        case .udp:
            return try? NameserverFactory.make(endpoint)
        case .doh(let urlString):
            guard let url = URL(string: urlString) else { return nil }
            return DoHNameserver(url: url) { [weak self] host in
                guard let self else { throw DNSError.notConfigured }
                return try await self.bootstrapResolve(host)
            }
        }
    }

    /// Resolves a DoH server's hostname via the bootstrap (`default-`)
    /// nameservers only — never the system resolver, never the role plane.
    private func bootstrapResolve(_ host: String) async throws -> [IPv4Address] {
        if let literal = IPv4Address(parsing: host) { return [literal] }
        let key = host.lowercased()
        if let hit = bootstrapCache.withLock({ $0[key] }), hit.expires > .now, !hit.addresses.isEmpty {
            return hit.addresses
        }
        var lastError: Error = DNSError.noNameserver
        for endpoint in settings.defaultNameservers {
            guard case .udp = endpoint, let transport = try? NameserverFactory.make(endpoint) else { continue }
            do {
                let records = try await transport.query(key)
                let addresses = records.map(\.address)
                if !addresses.isEmpty {
                    let ttl = TimeInterval(min(max(records.map(\.ttl).min() ?? 60, 30), 600))
                    bootstrapCache.withLock {
                        $0[key] = CachedEntry(addresses: addresses, expires: Date().addingTimeInterval(ttl))
                    }
                    return addresses
                }
            } catch {
                TunnelLog.write(.debug, "dns bootstrap \(key) via \(endpoint) failed: \(error.localizedDescription)")
                lastError = error
            }
        }
        throw lastError
    }
}
