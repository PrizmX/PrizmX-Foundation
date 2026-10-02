import Darwin
import Foundation
import os
import Testing
import PrizmXCore
import PrizmXNodes
import PrizmXProtocols
import PrizmXRules

private let cloudd = FlowAttribution(pid: 745, processName: "cloudd")

@Test func trafficCounterCreditsLateAttributionToTheApp() {
    let counter = TrafficCounter()
    let open = FlowRecord(
        endpoint: Endpoint(domain: "api.apple-cloudkit.com", port: 443),
        route: FlowRoute(["Proxies"]),
        closed: false
    )
    counter.flowDidBegin(open)
    counter.addBytes(up: 100, down: 900, route: FlowRoute(["Proxies"]), transport: .tcp)
    counter.addFlowBytes(id: open.id, up: 100, down: 900)

    counter.flowDidAttribute(id: open.id, cloudd)
    var snapshot = counter.snapshot()
    #expect(snapshot.activeFlows.first?.attribution == cloudd)
    #expect(snapshot.appBytes["cloudd"] == TrafficByteCount(up: 100, down: 900))
    #expect(snapshot.appTCPBytes["cloudd"] == 1_000)

    // The relay built its close record before the late attribution landed.
    counter.flowDidClose(FlowRecord(
        id: open.id,
        startedAt: open.startedAt,
        endpoint: open.endpoint,
        route: FlowRoute(["Proxies"]),
        uplinkBytes: 100,
        downlinkBytes: 900,
        milliseconds: 5,
        clientEnd: "eof",
        remoteEnd: "eof"
    ))
    snapshot = counter.snapshot()
    #expect(snapshot.recentFlows.first?.attribution == cloudd)
    // Already attributed: no second credit.
    counter.flowDidAttribute(id: open.id, cloudd)
    #expect(counter.snapshot().appBytes["cloudd"] == TrafficByteCount(up: 100, down: 900))
}

@Test func trafficCounterAttributesAClosedFlowLate() {
    let counter = TrafficCounter()
    let record = FlowRecord(
        endpoint: Endpoint(domain: "ocsp2.apple.com", port: 443),
        route: FlowRoute(["Proxies"]),
        uplinkBytes: 10,
        downlinkBytes: 20,
        milliseconds: 5
    )
    counter.flowDidOpen()
    counter.flowDidClose(record)
    counter.flowDidAttribute(id: record.id, cloudd)
    let snapshot = counter.snapshot()
    #expect(snapshot.recentFlows.first?.attribution == cloudd)
    #expect(snapshot.appBytes["cloudd"] == TrafficByteCount(up: 10, down: 20))
}

@Test func relayAttributesAMixedPortFlowLate() async throws {
    let server = try ClosingServer()
    defer { server.stop() }
    let attributor = LateOnlyAttributor()
    let engine = Engine(
        router: Router(rules: [RouteRule(.matchAll, policy: .direct)], default: .direct),
        nodeManager: NodeManager(nodes: [], groups: []),
        flowAttributor: attributor
    )
    let stream = LoopbackClientStream(
        endpoint: Endpoint(host: .ipv4(IPv4Address(127, 0, 0, 1)), port: server.port)
    )
    await EngineTCPRelay.pipe(stream: stream, engine: engine)

    // The late lookup runs beside the flow; give it a moment to land.
    var attribution: FlowAttribution?
    for _ in 0..<100 {
        attribution = engine.traffic.snapshot().recentFlows.first?.attribution
        if attribution != nil { break }
        try await Task.sleep(for: .milliseconds(20))
    }
    #expect(attribution == cloudd)
    #expect(attributor.queries.withLock { $0 } == [LateOnlyAttributor.Query(clientPort: 50_000, listenPort: 7_890)])
}

/// Nothing locally (a root client, as the sandboxed app sees it); the
/// tunnel's view answers.
private final class LateOnlyAttributor: FlowAttributing, Sendable {
    struct Query: Equatable {
        var clientPort: UInt16
        var listenPort: UInt16
    }

    let queries = OSAllocatedUnfairLock<[Query]>(initialState: [])

    func attribute(
        transport: FlowTransport,
        localAddress: String,
        localPort: UInt16,
        remoteAddress: String,
        remotePort: UInt16
    ) -> FlowAttribution? {
        nil
    }

    func attributeLate(
        transport: FlowTransport,
        localPort: UInt16,
        remotePort: UInt16,
        since: Date
    ) async -> FlowAttribution? {
        queries.withLock { $0.append(Query(clientPort: localPort, listenPort: remotePort)) }
        return cloudd
    }
}

/// A mixed-port client on loopback that sends nothing and hangs up.
private final class LoopbackClientStream: InboundStream, @unchecked Sendable {
    let endpoint: Endpoint
    var clientAddress: String { "127.0.0.1" }
    var clientPort: UInt16 { 50_000 }
    var listenPort: UInt16? { 7_890 }

    init(endpoint: Endpoint) {
        self.endpoint = endpoint
    }

    func read() async throws -> Data? { nil }
    func write(_ data: Data) async throws {}
    func close() async {}
}

/// Loopback TCP listener that accepts and closes at once: the relay's
/// direct dial succeeds and its splice ends right away.
final class ClosingServer: @unchecked Sendable {
    let port: UInt16
    private let fd: Int32

    init() throws {
        let listener = socket(AF_INET, SOCK_STREAM, 0)
        guard listener >= 0 else { throw POSIXError(.EBADF) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { raw in
                bind(listener, raw, length) == 0
                    && listen(listener, 8) == 0
                    && getsockname(listener, raw, &length) == 0
            }
        }
        guard bound else {
            close(listener)
            throw POSIXError(.EADDRNOTAVAIL)
        }
        fd = listener
        port = UInt16(bigEndian: address.sin_port)
        Thread.detachNewThread {
            while true {
                let client = accept(listener, nil, nil)
                if client < 0 { return }
                close(client)
            }
        }
    }

    func stop() {
        shutdown(fd, SHUT_RDWR)
        close(fd)
    }
}
