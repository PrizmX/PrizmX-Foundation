import Foundation
import Testing
import PrizmXCore
@testable import PrizmXNodes
import PrizmXProtocols

private func anytlsNode(id: String, host: String, port: UInt16) -> OutboundNode {
    OutboundNode(
        id: id,
        name: id,
        protocolConfig: .anytls(
            server: Endpoint(domain: host, port: port),
            password: "x",
            sni: "sni.example",
            skipCertVerify: false,
            session: AnyTLSSessionConfig()
        )
    )
}

@Test func probeTargetsDedupeByNodeAndURL() {
    let nodes = [
        anytlsNode(id: "hk1", host: "a.example", port: 443),
        anytlsNode(id: "hk2", host: "a.example", port: 443),
        anytlsNode(id: "jp1", host: "b.example", port: 8443),
        OutboundNode(id: "direct", name: "direct", protocolConfig: .direct),
    ]
    let groups = [
        PolicyGroup(name: "Auto", mode: .urlTest, nodeIDs: ["hk1", "hk2", "jp1"]),
        PolicyGroup(name: "Google", mode: .urlTest, nodeIDs: ["hk1", "direct"]),
        PolicyGroup(name: "Pick", mode: .select, nodeIDs: ["hk1"]),
        PolicyGroup(name: "Backup", mode: .fallback, nodeIDs: ["hk1"]),
    ]
    let manager = NodeManager(nodes: nodes, groups: groups)
    let targets = manager.urlTestProbeTargets()

    // select is skipped; hk1 is shared by Auto/Google/Backup → one job.
    #expect(targets.count == 4)
    let hk1 = targets.first { $0.nodeID == "hk1" }
    #expect(hk1?.members.count == 3)
    #expect(targets.contains { $0.nodeID == "direct" })
}

@Test func probeTargetsSkipSelectGroups() {
    let manager = NodeManager(
        nodes: [anytlsNode(id: "hk1", host: "a.example", port: 443)],
        groups: [PolicyGroup(name: "Pick", mode: .select, nodeIDs: ["hk1"])]
    )
    #expect(manager.urlTestProbeTargets().isEmpty)
}

@Test func urlTestToleranceKeepsCurrentWinner() {
    let nodes = [
        OutboundNode(id: "a", name: "A", protocolConfig: .direct),
        OutboundNode(id: "b", name: "B", protocolConfig: .direct),
    ]
    let group = PolicyGroup(
        name: "Auto",
        mode: .urlTest,
        nodeIDs: ["a", "b"],
        selectedNodeID: "a",
        tolerance: .milliseconds(50)
    )
    let manager = NodeManager(nodes: nodes, groups: [group])
    manager.recordLatency(.milliseconds(60), nodeID: "a", inGroup: "Auto")
    manager.recordLatency(.milliseconds(20), nodeID: "b", inGroup: "Auto")
    #expect(manager.selectedNode(inGroup: "Auto")?.id == "a")

    manager.recordLatency(.milliseconds(80), nodeID: "a", inGroup: "Auto")
    #expect(manager.selectedNode(inGroup: "Auto")?.id == "b")
}

@Test func fallbackPicksFirstAliveMember() {
    let nodes = [
        OutboundNode(id: "a", name: "A", protocolConfig: .direct),
        OutboundNode(id: "b", name: "B", protocolConfig: .direct),
    ]
    let group = PolicyGroup(name: "Backup", mode: .fallback, nodeIDs: ["a", "b"])
    let manager = NodeManager(nodes: nodes, groups: [group])
    #expect(manager.selectedNode(inGroup: "Backup")?.id == "a")
    manager.recordLatency(.milliseconds(30), nodeID: "b", inGroup: "Backup")
    #expect(manager.selectedNode(inGroup: "Backup")?.id == "b")
    manager.recordLatency(.milliseconds(40), nodeID: "a", inGroup: "Backup")
    #expect(manager.selectedNode(inGroup: "Backup")?.id == "a")
}

@Test func loadBalanceHashesDestinationHost() throws {
    let nodes = [
        OutboundNode(id: "a", name: "A", protocolConfig: .direct),
        OutboundNode(id: "b", name: "B", protocolConfig: .direct),
    ]
    let group = PolicyGroup(
        name: "LB",
        mode: .loadBalance,
        nodeIDs: ["a", "b"],
        loadBalanceStrategy: .consistentHashing
    )
    let manager = NodeManager(nodes: nodes, groups: [group])
    manager.recordLatency(.milliseconds(10), nodeID: "a", inGroup: "LB")
    manager.recordLatency(.milliseconds(10), nodeID: "b", inGroup: "LB")
    let first = try manager.connection(forGroup: "LB", target: Endpoint(domain: "one.example", port: 443))
    let again = try manager.connection(forGroup: "LB", target: Endpoint(domain: "one.example", port: 443))
    let failover = try #require(first as? FailoverGroupConnection)
    let failoverAgain = try #require(again as? FailoverGroupConnection)
    #expect(failover.candidateNames.first == failoverAgain.candidateNames.first)
}

@Test func urlTestProberBuildsPlainHTTPRequest() {
    let parsed = URLTestProber.request(for: URL(string: "http://www.gstatic.com/generate_204")!)
    #expect(parsed?.endpoint.port == 80)
    #expect(parsed?.https == false)
    let body = String(data: parsed?.payload ?? Data(), encoding: .utf8) ?? ""
    #expect(body.contains("GET /generate_204 HTTP/1.1"))
    #expect(body.contains("Host: www.gstatic.com"))
    #expect(URLTestProber.request(for: URL(string: "https://example.com/")!)?.https == true)
    let hello = URLTestProber.tlsClientHello(sni: "example.com")
    #expect(hello.first == 0x16)
    #expect(TrafficSniffer.sniff(hello) == .hostname("example.com"))
}

@Test func urlTestProbeTimesOutOnStuckReadAndClosesConnection() async throws {
    // Read never completes on its own and ignores cancellation.
    let stuck = ScriptedOutbound(halfClose: false)
    let started = ContinuousClock.now
    let result = await URLTestProber.probe(
        connection: stuck,
        url: URL(string: "http://probe.example/generate_204")!,
        timeout: .milliseconds(150)
    )
    #expect(result == nil)
    #expect(ContinuousClock.now - started < .seconds(2))
    for _ in 0..<100 where !stuck.closed {
        try await Task.sleep(for: .milliseconds(5))
    }
    #expect(stuck.closed)
}

@Test func urlTestProbeMeasuresRespondingConnection() async {
    let peer = ScriptedOutbound(halfClose: false)
    peer.feed(Data("HTTP/1.1 204 No Content\r\n\r\n".utf8))
    let result = await URLTestProber.probe(
        connection: peer,
        url: URL(string: "http://probe.example/generate_204")!,
        timeout: .seconds(5)
    )
    #expect(result != nil)
}

@Test func urlTestProbeTreatsEOFAndGarbageAsDead() async {
    for reply in [Data(), Data("\u{0}\u{1}garbage".utf8)] {
        let peer = ScriptedOutbound(halfClose: false)
        peer.feed(reply)
        let result = await URLTestProber.probe(
            connection: peer,
            url: URL(string: "http://probe.example/generate_204")!,
            timeout: .seconds(5)
        )
        #expect(result == nil, "reply \(Array(reply))")
    }
    #expect(URLTestProber.isHTTPResponseStart(Data("HT".utf8)))
    #expect(URLTestProber.isHTTPResponseStart(Data("HTTP/1.1 204".utf8)))
    #expect(!URLTestProber.isHTTPResponseStart(Data("HTTX".utf8)))
}

/// `url: http://host:99999/` used to reach `UInt16(_:)` in the prober and
/// trap the Packet Tunnel at its first health check.
@Test func outOfRangeTestURLPortFallsBackToDefault() throws {
    let group = PolicyGroup(
        name: "Auto",
        mode: .urlTest,
        nodeIDs: ["hk1"],
        testURL: "http://probe.example:99999/generate_204"
    )
    #expect(group.testURL == PolicyGroup.defaultTestURL)
    let url = try #require(URL(string: "http://probe.example:70000/"))
    #expect(URLTestProber.request(for: url) == nil)
}

/// A dead first member used to cost every new flow the full dial timeout
/// until the next scheduled url-test; a dial failure now takes it out at once.
private func socksNode(_ id: String, port: UInt16) -> OutboundNode {
    OutboundNode(
        id: id,
        name: id,
        protocolConfig: .socks5(server: Endpoint(domain: "\(id).example", port: port), credentials: nil, tls: nil)
    )
}

@Test func dialFailureTakesMemberOutUntilAProbeRestoresIt() {
    let nodes = [socksNode("a", port: 1080), socksNode("b", port: 1081)]
    let group = PolicyGroup(name: "Backup", mode: .fallback, nodeIDs: ["a", "b"])
    let manager = NodeManager(nodes: nodes, groups: [group])
    manager.recordLatency(.milliseconds(40), nodeID: "a", inGroup: "Backup")
    manager.recordLatency(.milliseconds(30), nodeID: "b", inGroup: "Backup")
    #expect(manager.selectedNode(inGroup: "Backup")?.id == "a")

    manager.reportDialFailure(member: "a", inGroup: "Backup")
    #expect(manager.selectedNode(inGroup: "Backup")?.id == "b")
    #expect(manager.takePendingRechecks() == ["Backup"])
    // Rechecks of one group are spaced out.
    manager.reportDialFailure(member: "a", inGroup: "Backup")
    #expect(manager.takePendingRechecks().isEmpty)

    manager.recordLatency(.milliseconds(40), nodeID: "a", inGroup: "Backup")
    #expect(manager.selectedNode(inGroup: "Backup")?.id == "a")
}

/// A nested group is never probed, so a failure mark on it could only age
/// out; its own nodes report themselves instead.
@Test func dialFailureDoesNotMarkNestedGroupsOrDirectNodes() {
    let nodes = [socksNode("a", port: 1080), OutboundNode(id: "d", name: "D", protocolConfig: .direct)]
    let groups = [
        PolicyGroup(name: "HK", mode: .select, nodeIDs: ["a"]),
        PolicyGroup(name: "Backup", mode: .fallback, nodeIDs: ["HK", "d"]),
    ]
    let manager = NodeManager(nodes: nodes, groups: groups)
    manager.reportDialFailure(member: "HK", inGroup: "Backup")
    manager.reportDialFailure(member: "d", inGroup: "Backup")
    #expect(manager.selectedNode(inGroup: "Backup")?.id == "a")
    #expect(manager.takePendingRechecks().isEmpty)
}

/// The node answered and the target did not: not the node's fault.
@Test func targetSideFailuresAreNotCountedAgainstTheNode() {
    #expect(NodeManager.isTargetFailure(ProxyHandshakeError.socksRequestFailed(5)))
    #expect(NodeManager.isTargetFailure(ProxyHandshakeError.httpStatus(502)))
    #expect(!NodeManager.isTargetFailure(ProxyHandshakeError.socksRequestFailed(1)))
    #expect(!NodeManager.isTargetFailure(ProxyHandshakeError.httpStatus(407)))
    #expect(!NodeManager.isTargetFailure(OutboundError.refused(Endpoint(domain: "x", port: 1))))
}

@Test func directFailuresDoNotMarkDirect() {
    let nodes = [OutboundNode(id: "a", name: "A", protocolConfig: .direct)]
    let group = PolicyGroup(name: "Backup", mode: .fallback, nodeIDs: ["DIRECT", "a"])
    let manager = NodeManager(nodes: nodes, groups: [group])
    manager.reportDialFailure(member: "DIRECT", inGroup: "Backup")
    #expect(manager.takePendingRechecks().isEmpty)
}
