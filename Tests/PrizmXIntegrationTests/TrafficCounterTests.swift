import Foundation
import Testing
import PrizmXCore
import PrizmXProtocols

@Test func trafficCounterSplitsDirectAndPolicy() {
    let counter = TrafficCounter()
    counter.addBytes(up: 100, down: 900, via: "direct")
    counter.addBytes(up: 50, down: 450, via: "Proxies")
    counter.addBytes(up: 25, down: 75, via: "proxy")

    let snapshot = counter.snapshot()
    #expect(snapshot.uplinkBytes == 175)
    #expect(snapshot.downlinkBytes == 1425)
    #expect(snapshot.directUplinkBytes == 100)
    #expect(snapshot.directDownlinkBytes == 900)
    #expect(snapshot.policyBytes["Proxies"] == TrafficByteCount(up: 50, down: 450))
    #expect(snapshot.policyBytes["proxy"] == TrafficByteCount(up: 25, down: 75))
    #expect(snapshot.policyBytes["direct"] == nil)
}

@Test func trafficCounterRanksDomainsFromClosedFlows() {
    let counter = TrafficCounter()
    let endpoint = Endpoint(host: .domain("github.com"), port: 443)
    counter.flowDidOpen()
    counter.flowDidClose(FlowRecord(
        endpoint: endpoint,
        via: "Proxies",
        uplinkBytes: 1_000,
        downlinkBytes: 9_000,
        milliseconds: 42,
        clientEnd: "eof",
        remoteEnd: "eof"
    ))
    // IP-literal endpoints never enter domain ranking.
    counter.flowDidOpen()
    counter.flowDidClose(FlowRecord(
        endpoint: Endpoint(host: .ipv4(IPv4Address(1, 1, 1, 1)), port: 443),
        via: "Proxies",
        uplinkBytes: 5,
        downlinkBytes: 5,
        milliseconds: 1,
        clientEnd: "eof",
        remoteEnd: "eof"
    ))

    let snapshot = counter.snapshot()
    #expect(snapshot.domainBytes == ["github.com": TrafficByteCount(up: 1_000, down: 9_000)])
    #expect(snapshot.activeConnections == 0)
    #expect(snapshot.recentFlows.count == 2)
    #expect(snapshot.activeFlows.isEmpty)
}

@Test func trafficCounterRanksApps() {
    let counter = TrafficCounter()
    let safari = FlowAttribution(
        pid: 1,
        processName: "Safari",
        bundleID: "com.apple.Safari"
    )
    counter.addBytes(up: 10, down: 90, via: "Proxies", app: safari)
    counter.addBytes(up: 5, down: 5, via: "direct", app: safari)
    let snapshot = counter.snapshot()
    #expect(snapshot.appBytes["com.apple.Safari"] == TrafficByteCount(up: 15, down: 95))
    #expect(snapshot.appNames["com.apple.Safari"] == "Safari")
}

@Test func trafficCounterTracksOpenAndClearsRecent() {
    let counter = TrafficCounter()
    let open = FlowRecord(
        endpoint: Endpoint(domain: "example.com", port: 443),
        via: "Proxies",
        closed: false
    )
    counter.flowDidBegin(open)
    counter.addFlowBytes(id: open.id, up: 10, down: 20)
    var snapshot = counter.snapshot()
    #expect(snapshot.activeFlows.count == 1)
    #expect(snapshot.activeFlows[0].uplinkBytes == 10)
    #expect(snapshot.activeConnections == 1)

    counter.flowDidClose(
        FlowRecord(
            id: open.id,
            startedAt: open.startedAt,
            endpoint: open.endpoint,
            via: "Proxies",
            uplinkBytes: 10,
            downlinkBytes: 20,
            milliseconds: 5,
            clientEnd: "eof",
            remoteEnd: "eof"
        )
    )
    snapshot = counter.snapshot()
    #expect(snapshot.activeFlows.isEmpty)
    #expect(snapshot.recentFlows.count == 1)
    counter.clearRecent()
    #expect(counter.snapshot().recentFlows.isEmpty)
}

@Test func trafficSnapshotMergesTunnelAndMixedPort() {
    let tunnel = TrafficSnapshot(
        uploadBytesPerSecond: 10,
        downloadBytesPerSecond: 20,
        uplinkBytes: 100,
        downlinkBytes: 200,
        activeConnections: 1,
        directUplinkBytes: 5,
        policyBytes: ["Proxies": TrafficByteCount(up: 100, down: 200)],
        activeFlows: [
            FlowRecord(endpoint: Endpoint(domain: "a.example", port: 443), via: "Proxies")
        ]
    )
    let mixed = TrafficSnapshot(
        uploadBytesPerSecond: 3,
        downloadBytesPerSecond: 7,
        uplinkBytes: 30,
        downlinkBytes: 70,
        activeConnections: 2,
        directUplinkBytes: 1,
        policyBytes: ["Proxies": TrafficByteCount(up: 10, down: 20)],
        activeFlows: [
            FlowRecord(endpoint: Endpoint(domain: "b.example", port: 443), via: "Proxies")
        ]
    )
    let merged = tunnel.merging(mixed)
    #expect(merged.uploadBytesPerSecond == 13)
    #expect(merged.downloadBytesPerSecond == 27)
    #expect(merged.uplinkBytes == 130)
    #expect(merged.downlinkBytes == 270)
    #expect(merged.activeConnections == 3)
    #expect(merged.directUplinkBytes == 6)
    #expect(merged.policyBytes["Proxies"] == TrafficByteCount(up: 110, down: 220))
    #expect(merged.activeFlows.count == 2)
}
