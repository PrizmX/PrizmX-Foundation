import Foundation
import Testing
import PrizmXCore
import PrizmXNodes
import PrizmXProtocols
import PrizmXRules

private func manager() -> NodeManager {
    NodeManager(
        nodes: [OutboundNode(id: "JP 03", name: "JP 03", protocolConfig: .direct)],
        groups: [
            PolicyGroup(name: "🎯Direct", mode: .select, nodeIDs: ["DIRECT"]),
            PolicyGroup(name: "Proxies", mode: .select, nodeIDs: ["JP 03"]),
            PolicyGroup(name: "AI", mode: .select, nodeIDs: ["Proxies"]),
        ]
    )
}

@Test func flowRouteReadsExitAndPolicy() {
    let route = FlowRoute(["JP 03", "Proxies", "AI"])
    #expect(route.exit == "JP 03")
    #expect(route.policy == "AI")
    #expect(!route.isDirect)
    #expect(route.description == "AI → Proxies → JP 03")
    #expect(FlowRoute(["DIRECT", "🎯Direct"]).isDirect)
}

@Test func trafficCounterSplitsByExitNotByRulePolicy() {
    let counter = TrafficCounter()
    // A rule on a group that selects DIRECT is direct traffic.
    counter.addBytes(up: 10, down: 90, route: FlowRoute(["DIRECT", "🎯Direct"]), transport: .tcp)
    counter.addBytes(up: 5, down: 45, route: FlowRoute(["JP 03", "Proxies", "AI"]), transport: .tcp)
    counter.addBytes(up: 1, down: 9, route: FlowRoute(["DIRECT"]), transport: .udp)

    let snapshot = counter.snapshot()
    #expect(snapshot.directUplinkBytes == 11)
    #expect(snapshot.directDownlinkBytes == 99)
    // Proxied bytes rank under the rule's policy; direct ones do not.
    #expect(snapshot.policyBytes == ["AI": TrafficByteCount(up: 5, down: 45)])
    #expect(snapshot.exitBytes["DIRECT"] == TrafficByteCount(up: 11, down: 99))
    #expect(snapshot.exitBytes["JP 03"] == TrafficByteCount(up: 5, down: 45))
    #expect(snapshot.exitTCPBytes["DIRECT"] == 100)
    #expect(snapshot.exitUDPBytes["DIRECT"] == 10)
}

@Test func selectedChainFollowsNestedGroupsToTheExit() {
    let nodes = manager()
    #expect(nodes.selectedChain(inGroup: "AI") == ["JP 03", "Proxies", "AI"])
    #expect(nodes.selectedChain(inGroup: "🎯Direct") == ["DIRECT", "🎯Direct"])
    #expect(nodes.selectedChain(inGroup: "JP 03") == ["JP 03"])
}

@Test func dispatchNamesTheRulePolicy() throws {
    let engine = Engine(
        router: Router(rules: [RouteRule(.matchAll, policy: .proxy(targetGroup: "JP 03"))], default: .direct),
        nodeManager: manager()
    )
    // A rule naming a node: the relay takes the route from this name.
    #expect(try engine.dispatchDetailed(target: Endpoint(domain: "example.com", port: 443)).policy == "JP 03")
}

@Test func relayRoutesAGroupSelectingDirectAsDirect() async throws {
    let server = try ClosingServer()
    defer { server.stop() }
    let engine = Engine(
        router: Router(rules: [RouteRule(.matchAll, policy: .proxy(targetGroup: "🎯Direct"))], default: .direct),
        nodeManager: manager()
    )
    let stream = SendingStream(
        endpoint: Endpoint(host: .ipv4(IPv4Address(127, 0, 0, 1)), port: server.port),
        payload: Data("hello".utf8)
    )
    await EngineTCPRelay.pipe(stream: stream, engine: engine)

    let snapshot = engine.traffic.snapshot()
    let flow = try #require(snapshot.recentFlows.first)
    #expect(flow.route == FlowRoute(["DIRECT", "🎯Direct"]))
    #expect(snapshot.policyBytes.isEmpty)
    #expect(snapshot.directUplinkBytes == flow.uplinkBytes)
    #expect(snapshot.exitBytes["DIRECT"]?.up == flow.uplinkBytes)
}

/// Sends one chunk, then hangs up.
private final class SendingStream: InboundStream, @unchecked Sendable {
    let endpoint: Endpoint
    private var payload: Data?

    init(endpoint: Endpoint, payload: Data) {
        self.endpoint = endpoint
        self.payload = payload
    }

    func read() async throws -> Data? {
        defer { payload = nil }
        return payload
    }

    func write(_ data: Data) async throws {}
    func close() async {}
}
