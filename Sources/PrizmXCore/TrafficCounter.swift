import Foundation
import os
import PrizmXProtocols

/// Per-label byte counts (cumulative since tunnel start).
public struct TrafficByteCount: Sendable, Hashable, Codable, Equatable {
    public var up: UInt64
    public var down: UInt64

    public init(up: UInt64 = 0, down: UInt64 = 0) {
        self.up = up
        self.down = down
    }
}

/// Throughput snapshot exchanged over tunnel IPC.
public struct TrafficSnapshot: Sendable, Hashable, Codable, Equatable {
    public var uploadBytesPerSecond: Double
    public var downloadBytesPerSecond: Double
    public var uplinkBytes: UInt64
    public var downlinkBytes: UInt64
    public var activeConnections: Int
    /// Bytes that went DIRECT (proxy = uplink/downlink minus these).
    public var directUplinkBytes: UInt64
    public var directDownlinkBytes: UInt64
    /// Cumulative bytes per policy / domain, capped to the top entries so the
    /// 1s IPC poll stays small.
    public var policyBytes: [String: TrafficByteCount]
    public var domainBytes: [String: TrafficByteCount]
    /// Open TCP splices (Inspector Active).
    public var activeFlows: [FlowRecord]
    /// Recently closed TCP splices (Inspector Recent).
    public var recentFlows: [FlowRecord]

    public init(
        uploadBytesPerSecond: Double = 0,
        downloadBytesPerSecond: Double = 0,
        uplinkBytes: UInt64 = 0,
        downlinkBytes: UInt64 = 0,
        activeConnections: Int = 0,
        directUplinkBytes: UInt64 = 0,
        directDownlinkBytes: UInt64 = 0,
        policyBytes: [String: TrafficByteCount] = [:],
        domainBytes: [String: TrafficByteCount] = [:],
        activeFlows: [FlowRecord] = [],
        recentFlows: [FlowRecord] = []
    ) {
        self.uploadBytesPerSecond = uploadBytesPerSecond
        self.downloadBytesPerSecond = downloadBytesPerSecond
        self.uplinkBytes = uplinkBytes
        self.downlinkBytes = downlinkBytes
        self.activeConnections = activeConnections
        self.directUplinkBytes = directUplinkBytes
        self.directDownlinkBytes = directDownlinkBytes
        self.policyBytes = policyBytes
        self.domainBytes = domainBytes
        self.activeFlows = activeFlows
        self.recentFlows = recentFlows
    }

    public static let zero = TrafficSnapshot()
}

/// One TCP splice for Inspector (open or closed).
public struct FlowRecord: Sendable, Hashable, Codable, Equatable, Identifiable {
    public var id: UUID
    public var startedAt: Date
    public var endpoint: Endpoint
    public var via: String
    public var uplinkBytes: UInt64
    public var downlinkBytes: UInt64
    public var milliseconds: Int
    public var clientEnd: String
    public var remoteEnd: String
    public var closed: Bool
    public var rule: String

    public init(
        id: UUID = UUID(),
        startedAt: Date = Date(),
        endpoint: Endpoint,
        via: String,
        uplinkBytes: UInt64 = 0,
        downlinkBytes: UInt64 = 0,
        milliseconds: Int = 0,
        clientEnd: String = "",
        remoteEnd: String = "",
        closed: Bool = true,
        rule: String = ""
    ) {
        self.id = id
        self.startedAt = startedAt
        self.endpoint = endpoint
        self.via = via
        self.uplinkBytes = uplinkBytes
        self.downlinkBytes = downlinkBytes
        self.milliseconds = milliseconds
        self.clientEnd = clientEnd
        self.remoteEnd = remoteEnd
        self.closed = closed
        self.rule = rule
    }
}

/// Process-wide counters owned by `Engine`. TUN splice records here; the
/// Packet Tunnel snapshots it for the app.
public final class TrafficCounter: Sendable {
    private struct State {
        var uplinkBytes: UInt64 = 0
        var downlinkBytes: UInt64 = 0
        var active: Int = 0
        var sampleAt: ContinuousClock.Instant = .now
        var sampleUp: UInt64 = 0
        var sampleDown: UInt64 = 0
        var recent: [FlowRecord] = []
        var open: [UUID: FlowRecord] = [:]
        var directUp: UInt64 = 0
        var directDown: UInt64 = 0
        var policy: [String: TrafficByteCount] = [:]
        var domains: [String: TrafficByteCount] = [:]
    }

    private let lock = OSAllocatedUnfairLock(initialState: State())
    private let recentCap = 64
    /// Distinct domains kept for ranking; the map is cumulative so a hard cap
    /// keeps long sessions bounded (top entries survive — they keep growing).
    private let domainCap = 1024
    /// IPC payload bound per snapshot.
    private let snapshotMapCap = 32

    public init() {}

    public func flowDidOpen() {
        lock.withLock { $0.active += 1 }
    }

    public func flowDidBegin(_ record: FlowRecord) {
        lock.withLock { state in
            state.active += 1
            state.open[record.id] = record
        }
    }

    public func addFlowBytes(id: UUID, up: UInt64, down: UInt64) {
        lock.withLock { state in
            guard var record = state.open[id] else { return }
            record.uplinkBytes &+= up
            record.downlinkBytes &+= down
            state.open[id] = record
        }
    }

    /// Datagram / splice bytes with the routing label of the pipe they
    /// crossed. `direct` feeds the Direct bucket; every other label (policy
    /// group, bare proxy) is proxied traffic ranked per policy.
    public func addBytes(up: UInt64, down: UInt64, via: String) {
        lock.withLock { state in
            state.uplinkBytes &+= up
            state.downlinkBytes &+= down
            if via == "direct" {
                state.directUp &+= up
                state.directDown &+= down
            } else {
                var count = state.policy[via] ?? TrafficByteCount()
                count.up &+= up
                count.down &+= down
                state.policy[via] = count
            }
        }
    }

    public func flowDidClose(_ record: FlowRecord) {
        lock.withLock { state in
            state.active = max(0, state.active - 1)
            state.open[record.id] = nil
            var closed = record
            closed.closed = true
            state.recent.append(closed)
            if state.recent.count > recentCap {
                state.recent.removeFirst(state.recent.count - recentCap)
            }
            if case .domain(let domain) = record.endpoint.host,
               state.domains[domain] != nil || state.domains.count < domainCap {
                var count = state.domains[domain] ?? TrafficByteCount()
                count.up &+= record.uplinkBytes
                count.down &+= record.downlinkBytes
                state.domains[domain] = count
            }
        }
    }

    public func snapshot() -> TrafficSnapshot {
        lock.withLock { state in
            let now = ContinuousClock.now
            let elapsed = now - state.sampleAt
            let seconds = max(durationSeconds(elapsed), 0.001)
            let upRate = Double(state.uplinkBytes &- state.sampleUp) / seconds
            let downRate = Double(state.downlinkBytes &- state.sampleDown) / seconds
            state.sampleAt = now
            state.sampleUp = state.uplinkBytes
            state.sampleDown = state.downlinkBytes
            return TrafficSnapshot(
                uploadBytesPerSecond: upRate,
                downloadBytesPerSecond: downRate,
                uplinkBytes: state.uplinkBytes,
                downlinkBytes: state.downlinkBytes,
                activeConnections: state.active,
                directUplinkBytes: state.directUp,
                directDownlinkBytes: state.directDown,
                policyBytes: Self.top(state.policy, cap: snapshotMapCap),
                domainBytes: Self.top(state.domains, cap: snapshotMapCap),
                activeFlows: Array(state.open.values.sorted { $0.startedAt > $1.startedAt }.prefix(snapshotMapCap)),
                recentFlows: Array(state.recent.suffix(snapshotMapCap).reversed())
            )
        }
    }

    private static func top(
        _ map: [String: TrafficByteCount],
        cap: Int
    ) -> [String: TrafficByteCount] {
        guard map.count > cap else { return map }
        let keys = map.sorted { $0.value.up &+ $0.value.down > $1.value.up &+ $1.value.down }
            .prefix(cap)
            .map(\.key)
        return map.filter { keys.contains($0.key) }
    }

    public func recentFlows() -> [FlowRecord] {
        lock.withLock { $0.recent }
    }

    public func clearRecent() {
        lock.withLock { $0.recent = [] }
    }
}

private func durationSeconds(_ duration: Duration) -> Double {
    let parts = duration.components
    return Double(parts.seconds) + Double(parts.attoseconds) / 1e18
}
