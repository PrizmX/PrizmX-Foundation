import Foundation
import os
import PrizmXProtocols

/// Byte stream accepted by `EngineTCPRelay.pipe`.
///
/// Packet Tunnel SwiftTCP stream (`TUNTCPStream`) and mixed-port
/// (`NWInboundStream`) both conform so splice logic stays in Core.
public protocol InboundStream: Sendable {
    var endpoint: Endpoint { get }
    /// Client (app) address/port of the original socket, when known.
    var clientAddress: String { get }
    var clientPort: UInt16 { get }
    /// True for Packet Tunnel flows (SwiftTCP). Their source address is the
    /// tunnel interface, not a remote LAN client, so they keep process
    /// attribution even though the address is not loopback.
    var isTunnelInbound: Bool { get }
    /// Mixed-port listen port. Process attribution looks up the socket to
    /// this port, not the ultimate destination port.
    var listenPort: UInt16? { get }
    /// The destination as the client's socket sees it (TUN: the original
    /// IP, FakeIP included). nil: attribution matches on `listenPort`.
    var socketRemote: (address: String, port: UInt16)? { get }
    func read() async throws -> Data?
    func write(_ data: Data) async throws
    func close() async
    /// Half-close: send end-of-stream to the client (TCP FIN) while `read`
    /// keeps delivering its remaining upload. Only called when
    /// `supportsHalfClose` is true.
    func closeWrite() async
    var supportsHalfClose: Bool { get }
}

extension InboundStream {
    public func closeWrite() async { await close() }
    public var supportsHalfClose: Bool { false }
    public var clientAddress: String { "" }
    public var clientPort: UInt16 { 0 }
    public var isTunnelInbound: Bool { false }
    public var listenPort: UInt16? { nil }
    public var socketRemote: (address: String, port: UInt16)? { nil }
}

/// Splices an inbound TCP stream through `Engine.dispatch`, recording traffic
/// (`TrafficCounter`) and one `FlowRecord` per closed flow. Used by both the
/// Packet Tunnel (SwiftTCP) and mixed-port paths.
public enum EngineTCPRelay: Sendable {
    public static func pipe(stream: some InboundStream, engine: Engine) async {
        let prepared = await Self.prepare(stream: stream)
        let inbound = prepared.stream
        let target = prepared.endpoint
        // Mixed-port LAN clients are remote sockets: their ephemeral port
        // says nothing about apps on this Mac. TUN flows match the client
        // socket by its wire destination; mixed-port ones by the listener.
        let attribution: FlowAttribution?
        if inbound.isTunnelInbound || Self.isLoopbackClient(inbound.clientAddress) {
            let remote = inbound.socketRemote
            attribution = engine.flowAttributor?.attributeFresh(
                transport: .tcp,
                localAddress: inbound.clientAddress,
                localPort: inbound.clientPort,
                remoteAddress: remote?.address ?? "",
                remotePort: remote?.port ?? inbound.listenPort ?? target.port
            )
        } else {
            attribution = nil
        }
        let outbound: any OutboundConnection
        let rule: String
        do {
            let dispatched = try await engine.resolveAndDispatch(target: target)
            outbound = dispatched.connection
            rule = dispatched.rule
            try await DNSClient.$current.withValue(engine.dns) {
                try await outbound.open()
            }
        } catch {
            TunnelLog.write(.error, "open \(target) failed: \(error.localizedDescription)")
            await inbound.close()
            return
        }
        let via = outbound.routingLabel
        let flowID = UUID()
        let startedAt = Date()
        let sourceHost = inbound.clientAddress.isEmpty ? nil : inbound.clientAddress
        engine.traffic.flowDidBegin(
            FlowRecord(
                id: flowID,
                startedAt: startedAt,
                endpoint: target,
                via: via,
                closed: false,
                rule: rule,
                attribution: attribution,
                sourceHost: sourceHost
            )
        )
        TunnelLog.write(
            .debug,
            "flow opened \(target) via \(via)\(attribution.map { " app=\($0.accountingKey)" } ?? "")"
        )
        let started = ContinuousClock.now
        let snapshot = await splice(inbound: inbound, outbound: outbound) { up, down in
            engine.traffic.addBytes(up: up, down: down, via: via, app: attribution, transport: .tcp)
            engine.traffic.addFlowBytes(id: flowID, up: up, down: down)
        }
        let elapsed = started.duration(to: ContinuousClock.now)
        let ms = Int(elapsed / .milliseconds(1))
        engine.traffic.flowDidClose(
            FlowRecord(
                id: flowID,
                startedAt: startedAt,
                endpoint: target,
                via: via,
                uplinkBytes: UInt64(snapshot.up),
                downlinkBytes: UInt64(snapshot.down),
                milliseconds: ms,
                clientEnd: snapshot.client,
                remoteEnd: snapshot.remote,
                closed: true,
                rule: rule,
                attribution: attribution,
                sourceHost: sourceHost
            )
        )
        TunnelLog.write(
            .debug,
            "flow closed \(target) via \(via) up=\(snapshot.up) down=\(snapshot.down) client=\(snapshot.client) remote=\(snapshot.remote) ms=\(ms)"
        )
    }

    /// Bidirectional copy until both directions end. Inbound EOF half-closes
    /// the outbound when it supports that (else closes it); outbound EOF
    /// half-closes the inbound likewise. Once one side has finished, the
    /// other is bounded by `LingerWatch`.
    static func splice(
        inbound: any InboundStream,
        outbound: any OutboundConnection,
        record: @escaping @Sendable (_ up: UInt64, _ down: UInt64) -> Void
    ) async -> FlowTally.Snapshot {
        let tally = FlowTally()
        let linger = LingerWatch()
        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                do {
                    while let chunk = try await inbound.read() {
                        tally.touch()
                        guard !chunk.isEmpty else { continue }
                        try await outbound.writeAll(chunk)
                        tally.addUp(chunk.count)
                        record(UInt64(chunk.count), 0)
                    }
                    tally.clientEnded("eof")
                    if outbound.supportsHalfClose {
                        // Keep the downlink until the remote finishes too
                        // (bounded by the linger watch).
                        await outbound.closeWrite()
                        linger.start(tally: tally, outbound: outbound, inbound: inbound)
                        return
                    }
                } catch {
                    tally.clientEnded("write-error")
                }
                await outbound.close()
            }
            group.addTask {
                do {
                    while true {
                        let data = try await outbound.readData(upTo: 16 * 1024)
                        tally.touch()
                        if data.isEmpty {
                            tally.remoteEnded("eof")
                            break
                        }
                        try await inbound.write(data)
                        tally.addDown(data.count)
                        record(0, UInt64(data.count))
                    }
                    if inbound.supportsHalfClose {
                        // FIN toward the client; its remaining upload still flows.
                        await inbound.closeWrite()
                        linger.start(tally: tally, outbound: outbound, inbound: inbound)
                        return
                    }
                } catch {
                    tally.remoteEnded("error")
                }
                await inbound.close()
            }
            await group.waitForAll()
        }
        linger.cancel()
        await outbound.close()
        await inbound.close()
        return tally.snapshot()
    }

    static func isLoopbackClient(_ address: String) -> Bool {
        if address.isEmpty { return true }
        var host = address
        if let percent = host.firstIndex(of: "%") {
            host = String(host[..<percent])
        }
        let lowered = host.lowercased()
        if lowered.hasPrefix("::ffff:") {
            host = String(host.dropFirst(7))
        }
        return host == "127.0.0.1" || host.hasPrefix("127.") || lowered == "::1" || lowered == "localhost"
    }

    /// Total sniff budget. Server-speaks-first protocols (SSH, SMTP, MySQL)
    /// send nothing, so the wait must end on time without losing a late read.
    static let sniffBudget: Duration = .milliseconds(400)

    /// Peek at the first client bytes on IP destinations so DOMAIN / GEOSITE
    /// rules can match (Clash sniffing). Domain endpoints (FakeIP) skip this.
    ///
    /// `read()` implementations ignore task cancellation, so a timed-out read
    /// is never abandoned: it keeps running and the returned stream's first
    /// `read()` awaits it, so bytes arriving after the budget are not lost.
    static func prepare(
        stream: some InboundStream,
        budget: Duration = sniffBudget
    ) async -> PreparedStream {
        if case .domain = stream.endpoint.host {
            return PreparedStream(stream: stream, endpoint: stream.endpoint)
        }
        var prefix = Data()
        var pending: Task<Result<Data?, Error>, Never>?
        let deadline = ContinuousClock.now + budget
        sniffing: while prefix.count < TrafficSniffer.maxPrefix {
            if case .needMore = TrafficSniffer.sniff(prefix) {} else { break }
            let remaining = deadline - ContinuousClock.now
            if remaining <= .zero { break }
            let read = pending ?? Task {
                do { return .success(try await stream.read()) } catch { return .failure(error) }
            }
            pending = read
            guard let outcome = await Self.value(of: read, within: remaining) else { break }
            switch outcome {
            case .success(let chunk?) where !chunk.isEmpty:
                pending = nil
                prefix.append(chunk)
            case .success(let chunk?) where chunk.isEmpty:
                pending = nil
            default:
                // EOF / error: keep the finished task so the relay sees it.
                break sniffing
            }
        }
        let wrapped = PrefixedInboundStream(inner: stream, prefix: prefix, pending: pending)
        if case .hostname(let name) = TrafficSniffer.sniff(prefix),
           let endpoint = sniffedEndpoint(name, port: stream.endpoint.port) {
            return PreparedStream(stream: wrapped, endpoint: endpoint)
        }
        return PreparedStream(stream: wrapped, endpoint: stream.endpoint)
    }

    /// A sniffed name becomes the routing target only when it is a real
    /// domain. IP literals (`Host: 192.168.1.1`, `[::1]`) keep the original
    /// IP endpoint so IP-CIDR / GEOIP rules and the direct dial still work.
    static func sniffedEndpoint(_ name: String, port: UInt16) -> Endpoint? {
        var host = name
        if host.hasPrefix("["), host.hasSuffix("]") {
            host = String(host.dropFirst().dropLast())
        }
        if host.hasSuffix(".") { host.removeLast() }
        guard !host.isEmpty,
              IPv4Address(parsing: host) == nil,
              IPv6Address(parsing: host) == nil
        else { return nil }
        return Endpoint(domain: host, port: port)
    }

    /// Waits for `task` up to `timeout` without cancelling or awaiting it
    /// past the deadline. `nil` means the deadline won.
    static func value<T: Sendable>(of task: Task<T, Never>, within timeout: Duration) async -> T? {
        await withCheckedContinuation { (continuation: CheckedContinuation<T?, Never>) in
            let slot = OSAllocatedUnfairLock<CheckedContinuation<T?, Never>?>(initialState: continuation)
            let take: @Sendable () -> CheckedContinuation<T?, Never>? = { slot.withLock { current in
                let value = current
                current = nil
                return value
            } }
            let timer = Task {
                try? await Task.sleep(for: timeout)
                take()?.resume(returning: nil)
            }
            Task {
                let value = await task.value
                timer.cancel()
                take()?.resume(returning: value)
            }
        }
    }
}

struct PreparedStream: Sendable {
    var stream: any InboundStream
    var endpoint: Endpoint
}

/// Replays the sniffed prefix, then the read still in flight from sniffing
/// (if any), then the inner stream.
final class PrefixedInboundStream: InboundStream, @unchecked Sendable {
    let endpoint: Endpoint
    var clientAddress: String { inner.clientAddress }
    var clientPort: UInt16 { inner.clientPort }
    var isTunnelInbound: Bool { inner.isTunnelInbound }
    var listenPort: UInt16? { inner.listenPort }
    var socketRemote: (address: String, port: UInt16)? { inner.socketRemote }
    var supportsHalfClose: Bool { inner.supportsHalfClose }
    private let inner: any InboundStream
    private struct Buffered {
        var prefix: Data
        var pending: Task<Result<Data?, Error>, Never>?
    }
    private let buffered: OSAllocatedUnfairLock<Buffered>

    init(inner: some InboundStream, prefix: Data, pending: Task<Result<Data?, Error>, Never>? = nil) {
        self.endpoint = inner.endpoint
        self.inner = inner
        self.buffered = OSAllocatedUnfairLock(initialState: Buffered(prefix: prefix, pending: pending))
    }

    func read() async throws -> Data? {
        let (prefix, pending) = buffered.withLock { state -> (Data, Task<Result<Data?, Error>, Never>?) in
            if !state.prefix.isEmpty {
                let data = state.prefix
                state.prefix = Data()
                return (data, nil)
            }
            let task = state.pending
            state.pending = nil
            return (Data(), task)
        }
        if !prefix.isEmpty { return prefix }
        if let pending { return try await pending.value.get() }
        return try await inner.read()
    }

    func write(_ data: Data) async throws { try await inner.write(data) }
    func close() async { await inner.close() }
    func closeWrite() async { await inner.closeWrite() }
}

/// Bounds a half-closed flow: once one direction has finished, the flow is
/// torn down after `limit` without activity on the other.
final class LingerWatch: @unchecked Sendable {
    static let limit: Duration = .seconds(60)
    private let task = OSAllocatedUnfairLock<Task<Void, Never>?>(initialState: nil)

    func start(tally: FlowTally, outbound: any OutboundConnection, inbound: any InboundStream) {
        task.withLock { current in
            guard current == nil else { return }
            current = Task {
                while !Task.isCancelled {
                    let idle = ContinuousClock.now - tally.lastActivity
                    if idle >= Self.limit {
                        await outbound.close()
                        await inbound.close()
                        return
                    }
                    try? await Task.sleep(for: Self.limit - idle)
                }
            }
        }
    }

    func cancel() {
        task.withLock { current in
            current?.cancel()
            current = Task {}
        }
    }
}

final class FlowTally: @unchecked Sendable {
    private let lock = NSLock()
    private var up = 0
    private var down = 0
    private var client = "eof"
    private var remote = "eof"
    private var activity = ContinuousClock.now

    var lastActivity: ContinuousClock.Instant {
        lock.lock(); defer { lock.unlock() }
        return activity
    }

    func touch() {
        lock.lock(); activity = ContinuousClock.now; lock.unlock()
    }

    func addUp(_ count: Int) {
        lock.lock(); up += count; lock.unlock()
    }

    func addDown(_ count: Int) {
        lock.lock(); down += count; lock.unlock()
    }

    func clientEnded(_ reason: String) {
        lock.lock(); client = reason; lock.unlock()
    }

    func remoteEnded(_ reason: String) {
        lock.lock(); remote = reason; lock.unlock()
    }

    func snapshot() -> Snapshot {
        lock.lock()
        defer { lock.unlock() }
        return Snapshot(up: up, down: down, client: client, remote: remote)
    }

    struct Snapshot: Sendable {
        var up: Int
        var down: Int
        var client: String
        var remote: String
    }
}
