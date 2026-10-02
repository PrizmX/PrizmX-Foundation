import Foundation
import os
import PrizmXProtocols

/// Per-flow failover across a `select` group's members.
///
/// Selection stays sticky (Clash semantics) — this only walks the candidate
/// list when `open()` fails. Once a member is open, all I/O binds to it.
public final class FailoverGroupConnection: OutboundConnection, @unchecked Sendable {
    public let endpoint: Endpoint
    /// Group this connection was dispatched through.
    public let groupName: String
    /// Group member names in failover order (selected / first member first).
    public let candidateNames: [String]
    private let makers: [(name: String, make: () throws -> any OutboundConnection)]
    private let lifecycle = OSAllocatedUnfairLock(initialState: State())

    private struct State {
        var active: (any OutboundConnection)?
        var openTask: Task<(chain: [String], connection: any OutboundConnection), Error>?
        /// The opened member's route plus this group; empty until then.
        var chain: [String] = []
    }

    init(target: Endpoint, groupName: String, makers: [(String, () throws -> any OutboundConnection)]) {
        self.endpoint = target
        self.groupName = groupName
        self.candidateNames = makers.map(\.0)
        self.makers = makers
    }

    public var state: OutboundConnectionState {
        lifecycle.withLock { $0.active?.state ?? .idle }
    }

    /// The opened member's route plus this group: `["DIRECT", "🎯Direct"]`,
    /// `["JP 03", "Proxies", "AI"]` for nested groups. Just the group name
    /// before `open()`.
    public var chain: [String] {
        lifecycle.withLock { $0.chain.isEmpty ? [groupName] : $0.chain }
    }

    public func open() async throws {
        let task: Task<(chain: [String], connection: any OutboundConnection), Error> = lifecycle.withLock { life in
            if let active = life.active {
                let chain = life.chain
                return Task { (chain, active) }
            }
            if let openTask = life.openTask {
                return openTask
            }
            let task = Task { try await self.openSequenced() }
            life.openTask = task
            return task
        }
        do {
            let opened = try await task.value
            lifecycle.withLock { life in
                life.active = opened.connection
                life.chain = opened.chain
                life.openTask = nil
            }
        } catch {
            lifecycle.withLock { $0.openTask = nil }
            throw error
        }
    }

    private func openSequenced() async throws -> (chain: [String], connection: any OutboundConnection) {
        var lastError: Error = OutboundError.unreachable(endpoint)
        for (index, maker) in makers.enumerated() {
            do {
                let candidate = try maker.make()
                try await candidate.open()
                if index > 0 {
                    TunnelLog.write(.debug, "failover \(endpoint) → \(maker.name)")
                }
                // A node does not name itself; its member name does.
                let member = candidate.chain.isEmpty ? [maker.name] : candidate.chain
                return (member + [groupName], candidate)
            } catch {
                TunnelLog.write(.debug, "failover member \(maker.name) for \(endpoint) failed: \(error.localizedDescription)")
                lastError = error
            }
        }
        throw lastError
    }

    public func write(_ buffer: UnsafeRawBufferPointer) async throws -> Int {
        try await open()
        guard let active = lifecycle.withLock({ $0.active }) else {
            throw OutboundError.alreadyClosed(endpoint)
        }
        return try await active.write(buffer)
    }

    public func read(into buffer: UnsafeMutableRawBufferPointer) async throws -> Int {
        try await open()
        guard let active = lifecycle.withLock({ $0.active }) else {
            throw OutboundError.alreadyClosed(endpoint)
        }
        return try await active.read(into: buffer)
    }

    public var supportsHalfClose: Bool {
        lifecycle.withLock { $0.active?.supportsHalfClose ?? false }
    }

    public func closeWrite() async {
        await lifecycle.withLock({ $0.active })?.closeWrite()
    }

    public func close() async {
        let active = lifecycle.withLock { life -> (any OutboundConnection)? in
            let current = life.active
            life.active = nil
            life.openTask = nil
            return current
        }
        await active?.close()
    }
}
