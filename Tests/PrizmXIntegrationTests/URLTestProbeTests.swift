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
