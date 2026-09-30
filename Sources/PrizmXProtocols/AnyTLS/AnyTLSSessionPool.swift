import Foundation
import os

/// Clash / anytls-go client pool: reuse **idle** sessions (newest first),
/// never hand a busy mux a second stream, close the whole session if
/// `OpenStream` fails, and reap the oldest idle sessions on a timer.
public actor AnyTLSSessionPool {
    public static let shared = AnyTLSSessionPool()

    var establish: @Sendable (AnyTLSServerIdentity) async throws -> AnyTLSSession = { identity in
        try await AnyTLSSession.establish(identity: identity)
    }

    private struct Group {
        var nextSeq: UInt64 = 0
        var sessions: [UInt64: AnyTLSSession] = [:]
        /// Newest first (anytls-go skip-list key = MaxUint64 - seq).
        var idle: [AnyTLSSession] = []
    }

    private var groups: [AnyTLSServerIdentity: Group] = [:]
    private var janitor: Task<Void, Never>?

    public func openStream(
        identity: AnyTLSServerIdentity,
        to target: Endpoint
    ) async throws -> AnyTLSSessionStream {
        ensureJanitor(interval: identity.sessionConfig.checkInterval)
        var lastError: Error?
        for _ in 0..<2 {
            if let idle = takeIdle(identity) {
                if await idle.probe() {
                    do {
                        return try await idle.openStream(to: target)
                    } catch {
                        idle.terminate()
                        lastError = error
                    }
                }
                continue
            }
            do {
                let session = try await createSession(identity)
                do {
                    return try await session.openStream(to: target)
                } catch {
                    session.terminate()
                    lastError = error
                }
            } catch {
                lastError = error
            }
        }
        throw lastError ?? OutboundError.unreachable(identity.server)
    }

    func sessionCount(for identity: AnyTLSServerIdentity) -> Int {
        groups[identity]?.sessions.count ?? 0
    }

    func idleCount(for identity: AnyTLSServerIdentity) -> Int {
        groups[identity]?.idle.count ?? 0
    }

    func reset() {
        janitor?.cancel()
        janitor = nil
        let live = groups.values.flatMap { $0.sessions.values }
        groups.removeAll()
        for session in live { session.terminate() }
    }

    func setEstablishForTesting(
        _ factory: @escaping @Sendable (AnyTLSServerIdentity) async throws -> AnyTLSSession
    ) {
        establish = factory
    }

    // MARK: - Idle / create

    private func takeIdle(_ identity: AnyTLSServerIdentity) -> AnyTLSSession? {
        guard var group = groups[identity], !group.idle.isEmpty else { return nil }
        while !group.idle.isEmpty {
            let session = group.idle.removeFirst()
            if session.isUsable {
                groups[identity] = group
                return session
            }
            session.terminate()
        }
        groups[identity] = group
        return nil
    }

    private func createSession(_ identity: AnyTLSServerIdentity) async throws -> AnyTLSSession {
        let session = try await establish(identity)
        var group = groups[identity] ?? Group()
        group.nextSeq += 1
        session.seq = group.nextSeq
        group.sessions[session.seq] = session
        groups[identity] = group
        installHooks(session, identity: identity)
        TunnelLog.write(.debug, "anytls session established \(identity.server) seq=\(session.seq)")
        return session
    }

    private func installHooks(_ session: AnyTLSSession, identity: AnyTLSServerIdentity) {
        session.onTerminate = { [weak self] dead in
            Task { await self?.remove(dead, identity: identity) }
        }
        session.onBecameIdle = { [weak self] idle in
            Task { await self?.putIdle(idle, identity: identity) }
        }
    }

    private func putIdle(_ session: AnyTLSSession, identity: AnyTLSServerIdentity) {
        guard session.isUsable else { return }
        var group = groups[identity] ?? Group()
        if group.idle.contains(where: { $0 === session }) {
            groups[identity] = group
            return
        }
        session.idleSince = ContinuousClock.now
        group.idle.insert(session, at: 0)
        groups[identity] = group
    }

    private func remove(_ session: AnyTLSSession, identity: AnyTLSServerIdentity) {
        guard var group = groups[identity] else { return }
        group.sessions[session.seq] = nil
        group.idle.removeAll { $0 === session }
        groups[identity] = group
    }

    private func ensureJanitor(interval: TimeInterval) {
        guard janitor == nil else { return }
        let seconds = max(interval, 5)
        janitor = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(seconds))
                await self?.idleCleanup()
            }
        }
    }

    /// Reuse newest, cleanup oldest. Keep `minIdleSession` newest even if expired.
    ///
    /// `probe()` suspends, and actor reentrancy lets `openStream` / `putIdle`
    /// / `remove` run meanwhile. So decisions come from a synchronous pass
    /// over the *current* idle list, and every mutation is an incremental
    /// removal applied to whatever the group holds at that moment — never a
    /// wholesale write-back of a stale snapshot (which would resurrect taken
    /// sessions, drop freshly idled ones, or reset `nextSeq`).
    func idleCleanup() async {
        let now = ContinuousClock.now
        for identity in Array(groups.keys) {
            guard let idle = groups[identity]?.idle, !idle.isEmpty else { continue }
            let timeout = identity.sessionConfig.idleTimeout
            // Never empty the idle pool: a cold TLS+SYNACK after a pause was
            // taking down every proxied site (browser included).
            let minKeep = max(identity.sessionConfig.minIdleSession, 1)
            var kept = 0
            var remain: [AnyTLSSession] = []
            var drop: [AnyTLSSession] = []
            for session in idle {
                let idleFor = session.idleSince.map { now - $0 } ?? .seconds(0)
                if idleFor < .seconds(timeout) {
                    kept += 1
                    remain.append(session)
                    continue
                }
                if kept < minKeep {
                    session.idleSince = now
                    kept += 1
                    remain.append(session)
                    continue
                }
                drop.append(session)
            }
            removeIdle(drop, identity: identity)
            for session in drop {
                TunnelLog.write(.debug, "anytls session idle-close \(identity.server) seq=\(session.seq)")
                session.terminate()
            }
            for session in remain {
                // Taken by `openStream` while we were suspended: not ours to probe.
                guard isIdle(session, identity: identity) else { continue }
                if !(await session.probe()) {
                    // `probe` already terminated it; drop it from idle now
                    // rather than waiting for the async `onTerminate` hop.
                    removeIdle([session], identity: identity)
                }
            }
        }
    }

    private func isIdle(_ session: AnyTLSSession, identity: AnyTLSServerIdentity) -> Bool {
        groups[identity]?.idle.contains { $0 === session } ?? false
    }

    private func removeIdle(_ sessions: [AnyTLSSession], identity: AnyTLSServerIdentity) {
        guard !sessions.isEmpty, groups[identity] != nil else { return }
        groups[identity]?.idle.removeAll { candidate in sessions.contains { $0 === candidate } }
    }

    /// Test seam: registers `session` as idle with a given idle-start instant.
    func insertIdleForTesting(
        _ session: AnyTLSSession,
        identity: AnyTLSServerIdentity,
        idleSince: ContinuousClock.Instant
    ) {
        var group = groups[identity] ?? Group()
        group.nextSeq += 1
        session.seq = group.nextSeq
        session.idleSince = idleSince
        group.sessions[session.seq] = session
        group.idle.append(session)
        groups[identity] = group
        installHooks(session, identity: identity)
    }

    func takeIdleForTesting(_ identity: AnyTLSServerIdentity) -> AnyTLSSession? {
        takeIdle(identity)
    }

    func nextSeqForTesting(_ identity: AnyTLSServerIdentity) -> UInt64 {
        groups[identity]?.nextSeq ?? 0
    }
}
