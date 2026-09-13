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

    public static func + (lhs: TrafficByteCount, rhs: TrafficByteCount) -> TrafficByteCount {
        TrafficByteCount(up: lhs.up &+ rhs.up, down: lhs.down &+ rhs.down)
    }
}

/// Throughput snapshot exchanged over tunnel IPC.
public struct TrafficSnapshot: Sendable, Hashable, Codable, Equatable {
    public var uploadBytesPerSecond: Double
    public var downloadBytesPerSecond: Double
    public var uplinkBytes: UInt64
    public var downlinkBytes: UInt64
    public var activeConnections: Int
    /// Live TCP splices. `activeConnections` is TCP + UDP.
    public var tcpConnections: Int
    /// Live UDP sessions (TUN 4-tuple table).
    public var udpConnections: Int
    /// Bytes that went DIRECT (proxy = uplink/downlink minus these).
    public var directUplinkBytes: UInt64
    public var directDownlinkBytes: UInt64
    /// Cumulative bytes per policy / domain, capped to the top entries so the
    /// 1s IPC poll stays small.
    public var policyBytes: [String: TrafficByteCount]
    public var domainBytes: [String: TrafficByteCount]
    /// Cumulative bytes per app accounting key (bundle ID or process name).
    public var appBytes: [String: TrafficByteCount]
    /// Display name for each app key (process name).
    public var appNames: [String: String]
    /// Open TCP splices (Inspector Active).
    public var activeFlows: [FlowRecord]
    /// Recently closed TCP splices (Inspector Recent).
    public var recentFlows: [FlowRecord]
    /// Per-key TCP / UDP totals for ranking bars.
    public var appTCPBytes: [String: UInt64]
    public var appUDPBytes: [String: UInt64]
    public var domainTCPBytes: [String: UInt64]
    public var domainUDPBytes: [String: UInt64]
    public var policyTCPBytes: [String: UInt64]
    public var policyUDPBytes: [String: UInt64]

    public init(
        uploadBytesPerSecond: Double = 0,
        downloadBytesPerSecond: Double = 0,
        uplinkBytes: UInt64 = 0,
        downlinkBytes: UInt64 = 0,
        activeConnections: Int = 0,
        tcpConnections: Int = 0,
        udpConnections: Int = 0,
        directUplinkBytes: UInt64 = 0,
        directDownlinkBytes: UInt64 = 0,
        policyBytes: [String: TrafficByteCount] = [:],
        domainBytes: [String: TrafficByteCount] = [:],
        appBytes: [String: TrafficByteCount] = [:],
        appNames: [String: String] = [:],
        activeFlows: [FlowRecord] = [],
        recentFlows: [FlowRecord] = [],
        appTCPBytes: [String: UInt64] = [:],
        appUDPBytes: [String: UInt64] = [:],
        domainTCPBytes: [String: UInt64] = [:],
        domainUDPBytes: [String: UInt64] = [:],
        policyTCPBytes: [String: UInt64] = [:],
        policyUDPBytes: [String: UInt64] = [:]
    ) {
        self.uploadBytesPerSecond = uploadBytesPerSecond
        self.downloadBytesPerSecond = downloadBytesPerSecond
        self.uplinkBytes = uplinkBytes
        self.downlinkBytes = downlinkBytes
        self.activeConnections = activeConnections
        self.tcpConnections = tcpConnections
        self.udpConnections = udpConnections
        self.directUplinkBytes = directUplinkBytes
        self.directDownlinkBytes = directDownlinkBytes
        self.policyBytes = policyBytes
        self.domainBytes = domainBytes
        self.appBytes = appBytes
        self.appNames = appNames
        self.activeFlows = activeFlows
        self.recentFlows = recentFlows
        self.appTCPBytes = appTCPBytes
        self.appUDPBytes = appUDPBytes
        self.domainTCPBytes = domainTCPBytes
        self.domainUDPBytes = domainUDPBytes
        self.policyTCPBytes = policyTCPBytes
        self.policyUDPBytes = policyUDPBytes
    }

    public static let zero = TrafficSnapshot()

    /// Combine tunnel IPC counters with the in-app mixed-port engine.
    /// The two paths are disjoint (FakeIP TUN vs HTTP/SOCKS listener).
    public func merging(_ other: TrafficSnapshot) -> TrafficSnapshot {
        func mergeMap(
            _ lhs: [String: TrafficByteCount],
            _ rhs: [String: TrafficByteCount]
        ) -> [String: TrafficByteCount] {
            var merged = lhs
            for (key, value) in rhs {
                merged[key] = (merged[key] ?? TrafficByteCount()) + value
            }
            return merged
        }
        func mergeCount(
            _ lhs: [String: UInt64],
            _ rhs: [String: UInt64]
        ) -> [String: UInt64] {
            var merged = lhs
            for (key, value) in rhs {
                merged[key, default: 0] &+= value
            }
            return merged
        }
        var names = appNames
        for (key, name) in other.appNames where names[key] == nil {
            names[key] = name
        }
        return TrafficSnapshot(
            uploadBytesPerSecond: uploadBytesPerSecond + other.uploadBytesPerSecond,
            downloadBytesPerSecond: downloadBytesPerSecond + other.downloadBytesPerSecond,
            uplinkBytes: uplinkBytes &+ other.uplinkBytes,
            downlinkBytes: downlinkBytes &+ other.downlinkBytes,
            activeConnections: activeConnections + other.activeConnections,
            tcpConnections: tcpConnections + other.tcpConnections,
            udpConnections: udpConnections + other.udpConnections,
            directUplinkBytes: directUplinkBytes &+ other.directUplinkBytes,
            directDownlinkBytes: directDownlinkBytes &+ other.directDownlinkBytes,
            policyBytes: mergeMap(policyBytes, other.policyBytes),
            domainBytes: mergeMap(domainBytes, other.domainBytes),
            appBytes: mergeMap(appBytes, other.appBytes),
            appNames: names,
            activeFlows: Array(
                (activeFlows + other.activeFlows)
                    .sorted { $0.startedAt > $1.startedAt }
                    .prefix(32)
            ),
            recentFlows: Array(
                (recentFlows + other.recentFlows)
                    .sorted { $0.startedAt > $1.startedAt }
                    .prefix(32)
            ),
            appTCPBytes: mergeCount(appTCPBytes, other.appTCPBytes),
            appUDPBytes: mergeCount(appUDPBytes, other.appUDPBytes),
            domainTCPBytes: mergeCount(domainTCPBytes, other.domainTCPBytes),
            domainUDPBytes: mergeCount(domainUDPBytes, other.domainUDPBytes),
            policyTCPBytes: mergeCount(policyTCPBytes, other.policyTCPBytes),
            policyUDPBytes: mergeCount(policyUDPBytes, other.policyUDPBytes)
        )
    }

    enum CodingKeys: String, CodingKey {
        case uploadBytesPerSecond, downloadBytesPerSecond
        case uplinkBytes, downlinkBytes, activeConnections
        case tcpConnections, udpConnections
        case directUplinkBytes, directDownlinkBytes
        case policyBytes, domainBytes, appBytes, appNames
        case activeFlows, recentFlows
        case appTCPBytes, appUDPBytes, domainTCPBytes, domainUDPBytes
        case policyTCPBytes, policyUDPBytes
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        uploadBytesPerSecond = try container.decode(Double.self, forKey: .uploadBytesPerSecond)
        downloadBytesPerSecond = try container.decode(Double.self, forKey: .downloadBytesPerSecond)
        uplinkBytes = try container.decode(UInt64.self, forKey: .uplinkBytes)
        downlinkBytes = try container.decode(UInt64.self, forKey: .downlinkBytes)
        activeConnections = try container.decode(Int.self, forKey: .activeConnections)
        udpConnections = try container.decodeIfPresent(Int.self, forKey: .udpConnections) ?? 0
        // Older Packet Tunnel dumps only had `activeConnections` (TCP). Treat
        // a missing TCP key as that total so Home does not show 0/0.
        if let tcp = try container.decodeIfPresent(Int.self, forKey: .tcpConnections) {
            tcpConnections = tcp
        } else {
            tcpConnections = max(0, activeConnections - udpConnections)
        }
        directUplinkBytes = try container.decode(UInt64.self, forKey: .directUplinkBytes)
        directDownlinkBytes = try container.decode(UInt64.self, forKey: .directDownlinkBytes)
        policyBytes = try container.decodeIfPresent([String: TrafficByteCount].self, forKey: .policyBytes) ?? [:]
        domainBytes = try container.decodeIfPresent([String: TrafficByteCount].self, forKey: .domainBytes) ?? [:]
        appBytes = try container.decodeIfPresent([String: TrafficByteCount].self, forKey: .appBytes) ?? [:]
        appNames = try container.decodeIfPresent([String: String].self, forKey: .appNames) ?? [:]
        activeFlows = try container.decodeIfPresent([FlowRecord].self, forKey: .activeFlows) ?? []
        recentFlows = try container.decodeIfPresent([FlowRecord].self, forKey: .recentFlows) ?? []
        appTCPBytes = try container.decodeIfPresent([String: UInt64].self, forKey: .appTCPBytes) ?? [:]
        appUDPBytes = try container.decodeIfPresent([String: UInt64].self, forKey: .appUDPBytes) ?? [:]
        domainTCPBytes = try container.decodeIfPresent([String: UInt64].self, forKey: .domainTCPBytes) ?? [:]
        domainUDPBytes = try container.decodeIfPresent([String: UInt64].self, forKey: .domainUDPBytes) ?? [:]
        policyTCPBytes = try container.decodeIfPresent([String: UInt64].self, forKey: .policyTCPBytes) ?? [:]
        policyUDPBytes = try container.decodeIfPresent([String: UInt64].self, forKey: .policyUDPBytes) ?? [:]
    }
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
    public var attribution: FlowAttribution?
    /// Session number for Inspector (Surge-style ID). Optional so older snapshots decode.
    public var serial: UInt64?
    /// Remote socket of the inbound connection (mixed-port client). Optional
    /// so older tunnel snapshots still decode.
    public var sourceHost: String?

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
        rule: String = "",
        attribution: FlowAttribution? = nil,
        serial: UInt64? = nil,
        sourceHost: String? = nil
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
        self.attribution = attribution
        self.serial = serial
        self.sourceHost = sourceHost
    }
}

/// Process-wide counters owned by `Engine`. TUN splice records here; the
/// Packet Tunnel snapshots it for the app.
public final class TrafficCounter: Sendable {
    private struct State {
        var uplinkBytes: UInt64 = 0
        var downlinkBytes: UInt64 = 0
        var active: Int = 0
        var udpActive: Int = 0
        var sampleAt: ContinuousClock.Instant = .now
        var sampleUp: UInt64 = 0
        var sampleDown: UInt64 = 0
        var recent: [FlowRecord] = []
        var open: [UUID: FlowRecord] = [:]
        var directUp: UInt64 = 0
        var directDown: UInt64 = 0
        var policy: [String: TrafficByteCount] = [:]
        var domains: [String: TrafficByteCount] = [:]
        var apps: [String: TrafficByteCount] = [:]
        var appNames: [String: String] = [:]
        var appTCP: [String: UInt64] = [:]
        var appUDP: [String: UInt64] = [:]
        var domainTCP: [String: UInt64] = [:]
        var domainUDP: [String: UInt64] = [:]
        var policyTCP: [String: UInt64] = [:]
        var policyUDP: [String: UInt64] = [:]
        var nextSerial: UInt64 = 0
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
            var record = record
            if record.serial == nil {
                state.nextSerial += 1
                record.serial = state.nextSerial
            }
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
    public func addBytes(
        up: UInt64,
        down: UInt64,
        via: String,
        app: FlowAttribution? = nil,
        transport: FlowTransport? = nil,
        domain: String? = nil
    ) {
        let added = up &+ down
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
                Self.addProtocol(added, transport: transport, tcp: &state.policyTCP, udp: &state.policyUDP, key: via)
            }
            if let app {
                let key = app.accountingKey
                var count = state.apps[key] ?? TrafficByteCount()
                count.up &+= up
                count.down &+= down
                state.apps[key] = count
                if state.appNames[key] == nil {
                    state.appNames[key] = app.processName
                }
                Self.addProtocol(added, transport: transport, tcp: &state.appTCP, udp: &state.appUDP, key: key)
            }
            if let domain, !domain.isEmpty {
                Self.addProtocol(added, transport: transport, tcp: &state.domainTCP, udp: &state.domainUDP, key: domain)
            }
        }
    }

    public func udpDidOpen() {
        lock.withLock { $0.udpActive += 1 }
    }

    public func udpDidClose() {
        lock.withLock { state in
            state.udpActive = max(0, state.udpActive - 1)
        }
    }

    public func flowDidClose(_ record: FlowRecord) {
        lock.withLock { state in
            state.active = max(0, state.active - 1)
            let open = state.open[record.id]
            state.open[record.id] = nil
            var closed = record
            closed.closed = true
            if closed.serial == nil {
                closed.serial = open?.serial
            }
            if closed.serial == nil {
                state.nextSerial += 1
                closed.serial = state.nextSerial
            }
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
                let added = record.uplinkBytes &+ record.downlinkBytes
                Self.addProtocol(added, transport: .tcp, tcp: &state.domainTCP, udp: &state.domainUDP, key: domain)
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
            let topApps = Self.top(state.apps, cap: snapshotMapCap)
            let topDomains = Self.top(state.domains, cap: snapshotMapCap)
            let topPolicies = Self.top(state.policy, cap: snapshotMapCap)
            return TrafficSnapshot(
                uploadBytesPerSecond: upRate,
                downloadBytesPerSecond: downRate,
                uplinkBytes: state.uplinkBytes,
                downlinkBytes: state.downlinkBytes,
                activeConnections: state.active + state.udpActive,
                tcpConnections: state.active,
                udpConnections: state.udpActive,
                directUplinkBytes: state.directUp,
                directDownlinkBytes: state.directDown,
                policyBytes: topPolicies,
                domainBytes: topDomains,
                appBytes: topApps,
                appNames: state.appNames.filter { topApps[$0.key] != nil },
                activeFlows: Array(state.open.values.sorted { $0.startedAt > $1.startedAt }.prefix(snapshotMapCap)),
                recentFlows: Array(state.recent.suffix(snapshotMapCap).reversed()),
                appTCPBytes: Self.slice(state.appTCP, keys: Set(topApps.keys)),
                appUDPBytes: Self.slice(state.appUDP, keys: Set(topApps.keys)),
                domainTCPBytes: Self.slice(state.domainTCP, keys: Set(topDomains.keys)),
                domainUDPBytes: Self.slice(state.domainUDP, keys: Set(topDomains.keys)),
                policyTCPBytes: Self.slice(state.policyTCP, keys: Set(topPolicies.keys)),
                policyUDPBytes: Self.slice(state.policyUDP, keys: Set(topPolicies.keys))
            )
        }
    }

    private static func addProtocol(
        _ bytes: UInt64,
        transport: FlowTransport?,
        tcp: inout [String: UInt64],
        udp: inout [String: UInt64],
        key: String
    ) {
        guard bytes > 0, let transport else { return }
        switch transport {
        case .tcp: tcp[key, default: 0] &+= bytes
        case .udp: udp[key, default: 0] &+= bytes
        }
    }

    private static func slice(_ map: [String: UInt64], keys: Set<String>) -> [String: UInt64] {
        map.filter { keys.contains($0.key) }
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
