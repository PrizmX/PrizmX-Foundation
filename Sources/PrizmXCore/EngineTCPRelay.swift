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
    func read() async throws -> Data?
    func write(_ data: Data) async throws
    func close() async
}

extension InboundStream {
    public var clientAddress: String { "" }
    public var clientPort: UInt16 { 0 }
}

/// Splices an inbound TCP stream through `Engine.dispatch`, recording traffic
/// (`TrafficCounter`) and one `FlowRecord` per closed flow. Used by both the
/// Packet Tunnel (SwiftTCP) and mixed-port paths.
public enum EngineTCPRelay: Sendable {
    public static func pipe(stream: some InboundStream, engine: Engine) async {
        let prepared = await Self.prepare(stream: stream)
        let inbound = prepared.stream
        let target = prepared.endpoint
        let attribution = engine.flowAttributor?.attribute(
            transport: .tcp,
            localAddress: inbound.clientAddress,
            localPort: inbound.clientPort,
            remoteAddress: target.host.description,
            remotePort: target.port
        )
        let ipv4 = await engine.resolveIPv4(for: target)
        let outbound: any OutboundConnection
        let rule: String
        do {
            let dispatched = try engine.dispatchDetailed(target: target, resolvedIPv4: ipv4)
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
        engine.traffic.flowDidBegin(
            FlowRecord(
                id: flowID,
                startedAt: startedAt,
                endpoint: target,
                via: via,
                closed: false,
                rule: rule,
                attribution: attribution
            )
        )
        TunnelLog.write(
            .debug,
            "flow opened \(target) via \(via)\(attribution.map { " app=\($0.accountingKey)" } ?? "")"
        )
        let started = ContinuousClock.now
        let tally = FlowTally()
        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                do {
                    while let chunk = try await inbound.read() {
                        try await outbound.writeAll(chunk)
                        tally.addUp(chunk.count)
                        let bytes = UInt64(chunk.count)
                        engine.traffic.addBytes(up: bytes, down: 0, via: via, app: attribution)
                        engine.traffic.addFlowBytes(id: flowID, up: bytes, down: 0)
                    }
                    tally.clientEnded("eof")
                } catch {
                    tally.clientEnded("write-error")
                }
                await outbound.close()
            }
            group.addTask {
                do {
                    while true {
                        let data = try await outbound.readData(upTo: 16 * 1024)
                        if data.isEmpty {
                            tally.remoteEnded("eof")
                            break
                        }
                        try await inbound.write(data)
                        tally.addDown(data.count)
                        let bytes = UInt64(data.count)
                        engine.traffic.addBytes(up: 0, down: bytes, via: via, app: attribution)
                        engine.traffic.addFlowBytes(id: flowID, up: 0, down: bytes)
                    }
                } catch {
                    tally.remoteEnded("error")
                }
                await inbound.close()
            }
            await group.waitForAll()
        }
        let elapsed = started.duration(to: ContinuousClock.now)
        let ms = Int(elapsed / .milliseconds(1))
        let snapshot = tally.snapshot()
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
                attribution: attribution
            )
        )
        TunnelLog.write(
            .debug,
            "flow closed \(target) via \(via) up=\(snapshot.up) down=\(snapshot.down) client=\(snapshot.client) remote=\(snapshot.remote) ms=\(ms)"
        )
    }

    /// Peek at the first client bytes on IP destinations so DOMAIN / GEOSITE
    /// rules can match (Clash sniffing). Domain endpoints (FakeIP) skip this.
    private static func prepare(stream: some InboundStream) async -> PreparedStream {
        if case .domain = stream.endpoint.host {
            return PreparedStream(stream: stream, endpoint: stream.endpoint)
        }
        var prefix = Data()
        let deadline = ContinuousClock.now + .milliseconds(400)
        while prefix.count < TrafficSniffer.maxPrefix {
            switch TrafficSniffer.sniff(prefix) {
            case .hostname(let name):
                return PreparedStream(
                    stream: PrefixedInboundStream(inner: stream, prefix: prefix),
                    endpoint: Endpoint(domain: name, port: stream.endpoint.port)
                )
            case .none:
                return PreparedStream(
                    stream: PrefixedInboundStream(inner: stream, prefix: prefix),
                    endpoint: stream.endpoint
                )
            case .needMore:
                break
            }
            let remaining = deadline - ContinuousClock.now
            if remaining <= .zero { break }
            let chunk: Data?
            do {
                chunk = try await read(stream, timeout: remaining)
            } catch {
                break
            }
            guard let chunk, !chunk.isEmpty else { break }
            prefix.append(chunk)
        }
        if case .hostname(let name) = TrafficSniffer.sniff(prefix) {
            return PreparedStream(
                stream: PrefixedInboundStream(inner: stream, prefix: prefix),
                endpoint: Endpoint(domain: name, port: stream.endpoint.port)
            )
        }
        return PreparedStream(
            stream: PrefixedInboundStream(inner: stream, prefix: prefix),
            endpoint: stream.endpoint
        )
    }

    private static func read(_ stream: some InboundStream, timeout: Duration) async throws -> Data? {
        try await withThrowingTaskGroup(of: Data?.self) { group in
            group.addTask { try await stream.read() }
            group.addTask {
                try await Task.sleep(for: timeout)
                return nil
            }
            let first = try await group.next() ?? nil
            group.cancelAll()
            return first ?? nil
        }
    }
}

private struct PreparedStream: Sendable {
    var stream: any InboundStream
    var endpoint: Endpoint
}

private final class PrefixedInboundStream: InboundStream, @unchecked Sendable {
    let endpoint: Endpoint
    var clientAddress: String { inner.clientAddress }
    var clientPort: UInt16 { inner.clientPort }
    private let inner: any InboundStream
    private let leftover = OSAllocatedUnfairLock<Data>(initialState: Data())

    init(inner: some InboundStream, prefix: Data) {
        self.endpoint = inner.endpoint
        self.inner = inner
        leftover.withLock { $0 = prefix }
    }

    func read() async throws -> Data? {
        let pending = leftover.withLock { buffer -> Data? in
            guard !buffer.isEmpty else { return nil }
            let data = buffer
            buffer = Data()
            return data
        }
        if let pending { return pending.isEmpty ? try await inner.read() : pending }
        return try await inner.read()
    }

    func write(_ data: Data) async throws { try await inner.write(data) }
    func close() async { await inner.close() }
}

private final class FlowTally: @unchecked Sendable {
    private let lock = NSLock()
    private var up = 0
    private var down = 0
    private var client = "eof"
    private var remote = "eof"

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
