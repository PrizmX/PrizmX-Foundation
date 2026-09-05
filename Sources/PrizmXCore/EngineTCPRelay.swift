import Foundation
import PrizmXProtocols

/// Byte stream accepted by `EngineTCPRelay.pipe`.
///
/// Packet Tunnel SwiftTCP stream (`TUNTCPStream`) and macOS Transparent Proxy
/// (`NEAppProxyTCPFlow` wrapper) both conform so splice logic stays in Core.
public protocol InboundStream: Sendable {
    var endpoint: Endpoint { get }
    func read() async throws -> Data?
    func write(_ data: Data) async throws
    func close() async
}

/// Splices an inbound TCP stream through `Engine.dispatch`, recording traffic
/// (`TrafficCounter`) and one `FlowRecord` per closed flow. Used by both the
/// Packet Tunnel (SwiftTCP) and the App Proxy paths.
public enum EngineTCPRelay: Sendable {
    public static func pipe(stream: some InboundStream, engine: Engine) async {
        let outbound: any OutboundConnection
        do {
            outbound = try engine.dispatch(target: stream.endpoint)
            try await DNSClient.$current.withValue(engine.dns) {
                try await outbound.open()
            }
        } catch {
            TunnelLog.write(.error, "open \(stream.endpoint) failed: \(error.localizedDescription)")
            await stream.close()
            return
        }
        let via = outbound.routingLabel
        engine.traffic.flowDidOpen()
        TunnelLog.write(.debug, "flow opened \(stream.endpoint) via \(via)")
        let started = ContinuousClock.now
        let tally = FlowTally()
        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                do {
                    while let chunk = try await stream.read() {
                        try await outbound.writeAll(chunk)
                        tally.addUp(chunk.count)
                        engine.traffic.addBytes(up: UInt64(chunk.count), down: 0, via: via)
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
                        try await stream.write(data)
                        tally.addDown(data.count)
                        engine.traffic.addBytes(up: 0, down: UInt64(data.count), via: via)
                    }
                } catch {
                    tally.remoteEnded("error")
                }
                await stream.close()
            }
            await group.waitForAll()
        }
        let elapsed = started.duration(to: ContinuousClock.now)
        let ms = Int(elapsed / .milliseconds(1))
        let snapshot = tally.snapshot()
        engine.traffic.flowDidClose(
            FlowRecord(
                endpoint: stream.endpoint,
                via: via,
                uplinkBytes: UInt64(snapshot.up),
                downlinkBytes: UInt64(snapshot.down),
                milliseconds: ms,
                clientEnd: snapshot.client,
                remoteEnd: snapshot.remote
            )
        )
        TunnelLog.write(
            .debug,
            "flow closed \(stream.endpoint) via \(via) up=\(snapshot.up) down=\(snapshot.down) client=\(snapshot.client) remote=\(snapshot.remote) ms=\(ms)"
        )
    }
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
