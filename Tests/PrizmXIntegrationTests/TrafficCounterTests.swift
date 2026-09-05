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
}
