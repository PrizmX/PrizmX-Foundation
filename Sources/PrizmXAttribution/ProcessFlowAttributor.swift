import Darwin
import Foundation
import os
import PrizmXCore

/// Cache / snapshot policy for process attribution.
public struct AttributionCachePolicy: Sendable, Equatable {
    public var tcpTTL: Duration
    public var udpTTL: Duration
    public var negativeTTL: Duration
    public var minRefresh: Duration
    public var identityTTL: Duration

    public static let `default` = AttributionCachePolicy(
        /// Safety bound if FIN/RST never arrives (NAT drop, crash).
        tcpTTL: .seconds(600),
        udpTTL: .seconds(5),
        negativeTTL: .milliseconds(200),
        minRefresh: .milliseconds(250),
        identityTTL: .seconds(30)
    )
}

/// Thread-safe 5-tuple → process lookup.
///
/// Lives in the Packet Tunnel process (jetsam ~50 MB). Stores only PIDs and
/// short strings — never app icons. TCP is populated at SYN and dropped at
/// FIN/RST. UDP is cache-first; a miss walks `pcblist_n` and slides a short TTL.
///
/// Hot-path invariants:
/// - cache hit: one lock, one dictionary probe, no syscalls, no allocations
///   (UDP re-touches expiry at most once per half TTL);
/// - identity resolution (`proc_pidpath` / `Bundle`) happens outside the
///   lookup lock under its own lock, so one slow PID never stalls lookups.
public final class ProcessFlowAttributor: FlowAttributing, @unchecked Sendable {
    struct CacheKey: Hashable {
        var transport: FlowTransport
        var localPort: UInt16
        var remotePort: UInt16
        var remoteAddress: String
    }

    private struct CacheEntry {
        var attribution: FlowAttribution?
        var expiresAt: ContinuousClock.Instant
    }

    private struct IdentityEntry {
        var attribution: FlowAttribution
        var expiresAt: ContinuousClock.Instant
    }

    /// Owners indexed once per refresh so a miss is bucket lookup, not a scan.
    private struct State {
        var cache: [CacheKey: CacheEntry] = [:]
        var owners: [SocketOwner] = []
        var ownerIndex: [FlowTransport: [UInt16: [SocketOwner]]] = [:]
        var lastRefresh: ContinuousClock.Instant?
    }

    private let lock = OSAllocatedUnfairLock(initialState: State())
    private let identityLock = OSAllocatedUnfairLock(initialState: [Int32: IdentityEntry]())
    private let table: any SocketTableReading
    private let identities: ProcessIdentityResolver
    private let policy: AttributionCachePolicy
    private let ownPID: Int32
    private let now: @Sendable () -> ContinuousClock.Instant
    private let maxCacheEntries = 1_024

    public convenience init(policy: AttributionCachePolicy = .default) {
        self.init(
            table: LibprocSocketTable(),
            identities: ProcessIdentityResolver(),
            policy: policy,
            ownPID: getpid(),
            now: { ContinuousClock.now }
        )
    }

    init(
        table: any SocketTableReading,
        identities: ProcessIdentityResolver = ProcessIdentityResolver(),
        policy: AttributionCachePolicy = .default,
        ownPID: Int32,
        now: @escaping @Sendable () -> ContinuousClock.Instant
    ) {
        self.table = table
        self.identities = identities
        self.policy = policy
        self.ownPID = ownPID
        self.now = now
    }

    public func attribute(
        transport: FlowTransport,
        localAddress: String,
        localPort: UInt16,
        remoteAddress: String,
        remotePort: UInt16
    ) -> FlowAttribution? {
        _ = localAddress
        guard localPort > 0 else { return nil }
        let key = Self.key(
            transport: transport,
            localPort: localPort,
            remoteAddress: remoteAddress,
            remotePort: remotePort
        )
        let instant = now()
        // Fast path: one lock, one dictionary probe, no syscalls.
        if let hit = lock.withLock({ state -> CacheEntry? in
            guard let hit = state.cache[key], hit.expiresAt > instant else { return nil }
            if transport == .udp,
               hit.attribution != nil,
               instant.duration(to: hit.expiresAt) < policy.udpTTL / 2 {
                // Slide lazily: one dictionary write per half TTL at most.
                state.cache[key] = CacheEntry(
                    attribution: hit.attribution,
                    expiresAt: instant + policy.udpTTL
                )
            }
            return hit
        }) {
            return hit.attribution
        }
        // Slow path: find the owner under the lookup lock, then resolve the
        // identity (syscalls / plist reads) under its own lock.
        let owner: SocketOwner? = lock.withLock { state in
            let refreshed = refreshIfNeeded(&state, at: instant)
            if let found = Self.match(
                transport: transport,
                localPort: localPort,
                remoteAddress: remoteAddress,
                remotePort: remotePort,
                in: state.ownerIndex
            ) {
                return found
            }
            guard !refreshed else { return nil }
            refresh(&state, at: instant)
            return Self.match(
                transport: transport,
                localPort: localPort,
                remoteAddress: remoteAddress,
                remotePort: remotePort,
                in: state.ownerIndex
            )
        }

        let attribution = owner.flatMap { resolvedIdentity(for: $0.pid) }
        let ttl: Duration
        if attribution == nil {
            ttl = policy.negativeTTL
        } else if transport == .udp {
            ttl = policy.udpTTL
        } else {
            ttl = policy.tcpTTL
        }
        lock.withLock { state in
            state.cache[key] = CacheEntry(attribution: attribution, expiresAt: instant + ttl)
            if state.cache.count > maxCacheEntries {
                state.cache = state.cache.filter { $0.value.expiresAt > instant }
            }
        }
        return attribution
    }

    public func forget(
        transport: FlowTransport,
        localPort: UInt16,
        remoteAddress: String,
        remotePort: UInt16
    ) {
        let key = Self.key(
            transport: transport,
            localPort: localPort,
            remoteAddress: remoteAddress,
            remotePort: remotePort
        )
        lock.withLock { state in
            state.cache[key] = nil
            guard var bucket = state.ownerIndex[transport]?[localPort] else { return }
            if transport == .tcp {
                bucket.removeAll { $0.transport == .tcp }
            } else {
                bucket.removeAll { $0.remotePort == remotePort }
            }
            state.ownerIndex[transport]?[localPort] = bucket.isEmpty ? nil : bucket
            state.owners.removeAll {
                transport == .tcp
                    ? ($0.transport == .tcp && $0.localPort == localPort)
                    : ($0.transport == .udp && $0.localPort == localPort && $0.remotePort == remotePort)
            }
        }
    }

    /// Force a socket-table walk. Used by the startup probe.
    public func refresh() -> Int {
        lock.withLock { state in
            let instant = now()
            refresh(&state, at: instant)
            return state.owners.count
        }
    }

    @discardableResult
    private func refreshIfNeeded(_ state: inout State, at instant: ContinuousClock.Instant) -> Bool {
        if let last = state.lastRefresh, last.duration(to: instant) < policy.minRefresh {
            return false
        }
        refresh(&state, at: instant)
        return true
    }

    private func refresh(_ state: inout State, at instant: ContinuousClock.Instant) {
        state.owners = table.snapshot(skipPID: ownPID)
        var index: [FlowTransport: [UInt16: [SocketOwner]]] = [:]
        for owner in state.owners {
            index[owner.transport, default: [:]][owner.localPort, default: []].append(owner)
        }
        state.ownerIndex = index
        state.lastRefresh = instant
        state.cache = state.cache.filter { $0.value.expiresAt > instant }
        identityLock.withLock { identities in
            identities = identities.filter { $0.value.expiresAt > instant }
        }
    }

    private func resolvedIdentity(for pid: Int32) -> FlowAttribution? {
        let instant = now()
        if let hit = identityLock.withLock({ $0[pid] }), hit.expiresAt > instant {
            return hit.attribution
        }
        guard let resolved = identities.resolve(pid: pid) else { return nil }
        identityLock.withLock { entries in
            entries[pid] = IdentityEntry(
                attribution: resolved,
                expiresAt: instant + policy.identityTTL
            )
        }
        return resolved
    }

    static func key(
        transport: FlowTransport,
        localPort: UInt16,
        remoteAddress: String,
        remotePort: UInt16
    ) -> CacheKey {
        CacheKey(
            transport: transport,
            localPort: localPort,
            remotePort: transport == .udp ? remotePort : 0,
            remoteAddress: transport == .udp ? remoteAddress : ""
        )
    }

    private static func match(
        transport: FlowTransport,
        localPort: UInt16,
        remoteAddress: String,
        remotePort: UInt16,
        in index: [FlowTransport: [UInt16: [SocketOwner]]]
    ) -> SocketOwner? {
        guard let candidates = index[transport]?[localPort], !candidates.isEmpty else { return nil }
        if transport == .udp {
            if let exact = candidates.first(where: {
                $0.remotePort == remotePort && $0.remoteAddress == remoteAddress
            }) {
                return exact
            }
            return candidates.first { $0.remotePort == remotePort }
        }
        return candidates.first { $0.remotePort == remotePort } ?? candidates.first
    }
}
