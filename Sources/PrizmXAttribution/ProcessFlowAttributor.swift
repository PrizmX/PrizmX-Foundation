import Darwin
import Foundation
import os
import PrizmXCore

/// Timing policy for process attribution.
public struct AttributionCachePolicy: Sendable, Equatable {
    /// A snapshot this recent may answer an exact match without re-reading
    /// the socket table (bursts of new flows share one read).
    public var snapshotReuse: Duration
    /// PID → app identity (`proc_pidpath` / bundle) cache lifetime.
    public var identityTTL: Duration

    public static let `default` = AttributionCachePolicy(
        snapshotReuse: .seconds(1),
        identityTTL: .seconds(30)
    )

    public init(snapshotReuse: Duration, identityTTL: Duration) {
        self.snapshotReuse = snapshotReuse
        self.identityTTL = identityTTL
    }
}

/// Socket → process lookup at flow open (mihomo-style, from `pcblist_n`).
///
/// A client creates its socket before the first packet leaves it, so a
/// socket table read that starts after the lookup was requested always
/// contains the flow's socket. Lookups first try the current snapshot
/// (exact match only, while it is recent) and re-read the table only when
/// that snapshot predates the request, so a burst of new flows costs one
/// read. Matching never guesses:
///
/// - TCP: local port + remote port, plus the remote address when the
///   caller knows it (TUN passes the wire destination, FakeIP included;
///   mixed-port passes none and matches on its listen port).
/// - UDP: connected sockets match the same way; otherwise an unconnected
///   socket on the local port, if all such sockets belong to one process.
///
/// Lives in the Packet Tunnel (jetsam ~50 MB): stores PIDs and short
/// strings only. Identity resolution runs outside the snapshot lock.
///
/// The table skips the caller's own sockets (the tunnel's outbound dials
/// are never clients). The in-app mixed-port listener sets
/// `includesOwnProcess`: there the app's own requests through the system
/// proxy (External IP lookup, downloads) are real clients.
public final class ProcessFlowAttributor: FlowAttributing, @unchecked Sendable {
    private struct IdentityEntry {
        var attribution: FlowAttribution
        var expiresAt: ContinuousClock.Instant
    }

    private struct State {
        var index: [FlowTransport: [UInt16: [SocketOwner]]] = [:]
        var count = 0
        /// When the current snapshot's table read began.
        var takenAt: ContinuousClock.Instant?
    }

    private struct Query {
        var transport: FlowTransport
        var localPort: UInt16
        var remotePort: UInt16
        var remote: SocketAddress?
    }

    /// Held across the table read: concurrent lookups wait and then reuse it.
    private let lock = OSAllocatedUnfairLock(initialState: State())
    private let identityLock = OSAllocatedUnfairLock(initialState: [Int32: IdentityEntry]())
    private let table: any SocketTableReading
    private let identities: ProcessIdentityResolver
    private let policy: AttributionCachePolicy
    private let ownPID: Int32
    private let includesOwnProcess: Bool
    private let now: @Sendable () -> ContinuousClock.Instant

    public convenience init(
        policy: AttributionCachePolicy = .default,
        includesOwnProcess: Bool = false
    ) {
        self.init(
            table: LibprocSocketTable(),
            identities: ProcessIdentityResolver(),
            policy: policy,
            ownPID: getpid(),
            includesOwnProcess: includesOwnProcess,
            now: { ContinuousClock.now }
        )
    }

    init(
        table: any SocketTableReading,
        identities: ProcessIdentityResolver = ProcessIdentityResolver(),
        policy: AttributionCachePolicy = .default,
        ownPID: Int32,
        includesOwnProcess: Bool = false,
        now: @escaping @Sendable () -> ContinuousClock.Instant
    ) {
        self.table = table
        self.identities = identities
        self.policy = policy
        self.ownPID = ownPID
        self.includesOwnProcess = includesOwnProcess
        self.now = now
    }

    /// `remoteAddress` is the destination as the client's socket sees it;
    /// empty means "any" (match on ports only). `localAddress` is unused:
    /// the local port plus the remote side already identify the socket.
    public func attribute(
        transport: FlowTransport,
        localAddress: String,
        localPort: UInt16,
        remoteAddress: String,
        remotePort: UInt16
    ) -> FlowAttribution? {
        _ = localAddress
        guard localPort > 0 else { return nil }
        let query = Query(
            transport: transport,
            localPort: localPort,
            remotePort: remotePort,
            remote: SocketAddress(remoteAddress)
        )
        let requested = now()
        let owner: SocketOwner? = lock.withLock { state in
            if let takenAt = state.takenAt,
               takenAt.duration(to: requested) <= policy.snapshotReuse,
               let hit = Self.match(query, in: state.index) {
                return hit
            }
            // Only a read that starts after the request is sure to include
            // the socket; a newer one (taken by a concurrent lookup) counts.
            if state.takenAt.map({ $0 < requested }) ?? true {
                refresh(&state)
            }
            return Self.match(query, in: state.index)
        }
        return owner.flatMap { resolvedIdentity(for: $0.pid) }
    }

    /// TCP sockets connected to a loopback `listenPorts` (the app's
    /// mixed-port listeners), with their owners. Re-reads the table. The root
    /// tunnel publishes these for the sandboxed app (`ProxyClientStore`).
    public func loopbackClients(listenPorts: Set<UInt16>) -> [LoopbackClient] {
        guard !listenPorts.isEmpty else { return [] }
        let owners = lock.withLock { state -> [SocketOwner] in
            refresh(&state)
            return (state.index[.tcp] ?? [:]).values.joined().filter {
                listenPorts.contains($0.remotePort) && $0.remoteAddress?.isLoopback == true
            }
        }
        return owners.compactMap { owner in
            resolvedIdentity(for: owner.pid).map {
                LoopbackClient(clientPort: owner.localPort, listenPort: owner.remotePort, attribution: $0)
            }
        }
    }

    /// Re-reads the socket table. Used by the startup probe.
    public func refresh() -> Int {
        lock.withLock { state in
            refresh(&state)
            return state.count
        }
    }

    private func refresh(_ state: inout State) {
        let started = now()
        var owners = table.snapshot(skipPID: ownPID)
        if includesOwnProcess {
            // Read separately: a sandboxed caller's pcblist_n holds only its
            // own sockets, and keeping them out of the table read keeps that
            // filtered-table check (and the libproc fallback) working.
            owners += table.sockets(ofPID: ownPID)
        }
        var index: [FlowTransport: [UInt16: [SocketOwner]]] = [:]
        for owner in owners {
            index[owner.transport, default: [:]][owner.localPort, default: []].append(owner)
        }
        state.index = index
        state.count = owners.count
        state.takenAt = started
        identityLock.withLock { identities in
            identities = identities.filter { $0.value.expiresAt > started }
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

    private static func match(
        _ query: Query,
        in index: [FlowTransport: [UInt16: [SocketOwner]]]
    ) -> SocketOwner? {
        guard let candidates = index[query.transport]?[query.localPort], !candidates.isEmpty else {
            return nil
        }
        if let connected = candidates.first(where: {
            $0.remotePort == query.remotePort
                && (query.remote == nil || $0.remoteAddress == query.remote)
        }) {
            return connected
        }
        guard query.transport == .udp else { return nil }
        // Unconnected UDP (QUIC / STUN / DNS clients that sendto()) records
        // no peer. Accept it only when every such socket on this port is
        // owned by one process.
        let unconnected = candidates.filter { $0.remotePort == 0 && $0.remoteAddress == nil }
        guard let first = unconnected.first,
              unconnected.allSatisfy({ $0.pid == first.pid })
        else {
            return nil
        }
        return first
    }
}
