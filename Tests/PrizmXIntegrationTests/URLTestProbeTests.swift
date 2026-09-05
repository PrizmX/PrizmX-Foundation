import Foundation
import Testing
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

@Test func probeTargetsDedupeByServer() {
    // Two url-test groups whose members live on the same two servers.
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
    ]
    let manager = NodeManager(nodes: nodes, groups: groups)
    let targets = manager.urlTestProbeTargets()

    // Two unique servers, not five node probes. DIRECT has no server.
    #expect(targets.count == 2)
    let serverA = targets.first { $0.endpoint.port == 443 }
    #expect(serverA?.members.count == 3)  // Auto/hk1, Auto/hk2, Google/hk1
    let serverB = targets.first { $0.endpoint.port == 8443 }
    #expect(serverB?.members.count == 1)
}

@Test func probeTargetsSkipNonURLTestGroups() {
    let manager = NodeManager(
        nodes: [anytlsNode(id: "hk1", host: "a.example", port: 443)],
        groups: [PolicyGroup(name: "Pick", mode: .select, nodeIDs: ["hk1"])]
    )
    #expect(manager.urlTestProbeTargets().isEmpty)
}
