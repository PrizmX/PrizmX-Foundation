import Foundation
import Testing
import PrizmXCore
import PrizmXNodes
import PrizmXProtocols
import PrizmXRules

private let testUUID = "b831381d-6324-4d53-ad4f-8cda3b4b0c7f"

private func makeEngine() throws -> Engine {
    let router = Router(
        rules: [
            RouteRule(.domainSuffix("google.com"), policy: .proxy(targetGroup: "US-Group")),
            RouteRule(.domainSuffix("ads.example"), policy: .reject),
        ],
        default: .direct
    )

    let vless = OutboundNode(
        id: "vless-us",
        name: "US-VLESS",
        protocolConfig: .vless(
            server: Endpoint(domain: "us.vless.example", port: 443),
            uuid: testUUID,
            sni: "us.vless.example",
            tls: true,
            reality: nil
        )
    )
    let shadowsocks = OutboundNode(
        id: "ss-us",
        name: "US-SS",
        protocolConfig: .shadowsocks(
            server: Endpoint(domain: "us.ss.example", port: 8388),
            password: "test-password",
            cipher: .aes256GCM
        )
    )
    let group = PolicyGroup(
        name: "US-Group",
        mode: .select,
        nodeIDs: [vless.id, shadowsocks.id],
        selectedNodeID: vless.id
    )
    let nodes = NodeManager(nodes: [vless, shadowsocks], groups: [group])
    return Engine(router: router, nodeManager: nodes)
}

@Test func googleDispatchesToUSGroupVLESSNode() async throws {
    let engine = try makeEngine()
    let target = Endpoint(domain: "google.com", port: 443)

    #expect(engine.router.match(endpoint: target) == .proxy(targetGroup: "US-Group"))
    #expect(engine.nodeManager.selectedNode(inGroup: "US-Group")?.id == "vless-us")

    let connection = try engine.dispatch(target: target)
    // Multi-member select group: per-flow failover wrapper, selected first.
    let failover = try #require(connection as? FailoverGroupConnection)
    #expect(failover.endpoint == target)
    #expect(failover.candidateNames == ["vless-us"])
    #expect(failover.state == .idle)
}

@Test func baiduHitsDefaultDirect() async throws {
    let engine = try makeEngine()
    let target = Endpoint(domain: "baidu.com", port: 443)

    #expect(engine.router.match(endpoint: target) == .direct)

    let connection = try engine.dispatch(target: target)
    let direct = try #require(connection as? DirectOutboundConnection)
    #expect(direct.endpoint == target)
    #expect(direct.state == .idle)
}

@Test func rejectPolicyThrows() async throws {
    let engine = try makeEngine()
    let target = Endpoint(domain: "tracker.ads.example", port: 443)
    #expect(engine.router.match(endpoint: target) == .reject)
    do {
        _ = try engine.dispatch(target: target)
        Issue.record("expected rejected")
    } catch let error as EngineError {
        #expect(error == .rejected(target))
    }
}

@Test func outboundDirectBypassesRules() async throws {
    let engine = try makeEngine()
    engine.setOutboundMode(.direct)
    #expect(engine.policy(for: Endpoint(domain: "google.com", port: 443)) == .direct)
    let connection = try engine.dispatch(target: Endpoint(domain: "google.com", port: 443))
    #expect(connection is DirectOutboundConnection)
    #expect(await engine.dnsPolicy(host: "google.com") == .direct)
}

@Test func outboundGlobalPinsEveryFlowToSelectedGroup() async throws {
    let engine = try makeEngine()
    engine.setOutboundMode(.global, globalGroup: "US-Group")
    let target = Endpoint(domain: "baidu.com", port: 443)
    #expect(engine.router.match(endpoint: target) == .direct)
    #expect(engine.policy(for: target) == .proxy(targetGroup: "US-Group"))
    let connection = try engine.dispatch(target: target)
    let failover = try #require(connection as? FailoverGroupConnection)
    #expect(failover.candidateNames.first == "vless-us")
    #expect(await engine.dnsPolicy(host: "baidu.com") == .proxy(targetGroup: "US-Group"))
}

@Test func outboundModeHotSwapRestoresRuleRouting() async throws {
    let engine = try makeEngine()
    engine.setOutboundMode(.direct)
    engine.setOutboundMode(.rule)
    let target = Endpoint(domain: "google.com", port: 443)
    #expect(engine.policy(for: target) == .proxy(targetGroup: "US-Group"))
    #expect(await engine.dnsPolicy(host: "ads.example") == .reject)
}

@Test func selectModeCanSwitchToShadowsocksNode() async throws {
    let engine = try makeEngine()
    try engine.nodeManager.select(nodeID: "ss-us", inGroup: "US-Group")

    let connection = try engine.dispatch(
        target: Endpoint(domain: "maps.google.com", port: 443)
    )
    // Selection sticks first, the other member is the failover leg.
    let failover = try #require(connection as? FailoverGroupConnection)
    #expect(failover.candidateNames == ["ss-us"])
}

@Test func urlTestPicksLowestLatencyNode() throws {
    let vless = OutboundNode(
        id: "a",
        name: "A",
        protocolConfig: .direct
    )
    let ss = OutboundNode(
        id: "b",
        name: "B",
        protocolConfig: .direct
    )
    let group = PolicyGroup(
        name: "Auto",
        mode: .urlTest,
        nodeIDs: ["a", "b"]
    )
    let manager = NodeManager(nodes: [vless, ss], groups: [group])
    manager.recordLatency(.milliseconds(80), nodeID: "a", inGroup: "Auto")
    manager.recordLatency(.milliseconds(20), nodeID: "b", inGroup: "Auto")
    #expect(manager.selectedNode(inGroup: "Auto")?.id == "b")
}

@Test func engineTCPRelayClosesRejectedInbound() async throws {
    let router = Router(
        rules: [RouteRule(.matchAll, policy: .reject)],
        default: .reject
    )
    let engine = Engine(router: router, nodeManager: NodeManager(nodes: [], groups: []))
    let stream = MockInboundStream(endpoint: Endpoint(domain: "blocked.example", port: 443))
    await EngineTCPRelay.pipe(stream: stream, engine: engine)
    #expect(stream.closed)
}

private final class MockInboundStream: InboundStream, @unchecked Sendable {
    let endpoint: Endpoint
    private(set) var closed = false

    init(endpoint: Endpoint) {
        self.endpoint = endpoint
    }

    func read() async throws -> Data? { nil }
    func write(_ data: Data) async throws {}
    func close() async { closed = true }
}

@Test func failoverSkipsClonedServerPort() throws {
    func anytls(_ id: String, port: UInt16) -> OutboundNode {
        OutboundNode(
            id: id,
            name: id,
            protocolConfig: .anytls(
                server: Endpoint(domain: "node.example.sbs", port: port),
                password: "x",
                sni: "sni.example",
                skipCertVerify: true,
                session: AnyTLSSessionConfig()
            )
        )
    }
    let info = anytls("info", port: 5868)
    let hk01 = anytls("hk01", port: 5868)
    let hk02 = anytls("hk02", port: 2748)
    let group = PolicyGroup(
        name: "Proxies",
        mode: .select,
        nodeIDs: [info.id, hk01.id, hk02.id]
    )
    let router = Router(
        rules: [RouteRule(.matchAll, policy: .proxy(targetGroup: "Proxies"))],
        default: .direct
    )
    let engine = Engine(
        router: router,
        nodeManager: NodeManager(nodes: [info, hk01, hk02], groups: [group])
    )
    let connection = try engine.dispatch(target: Endpoint(domain: "www.google.com", port: 443))
    let failover = try #require(connection as? FailoverGroupConnection)
    #expect(failover.candidateNames == ["info"])
}

@Test func selectedNodeWalksNestedGroups() {
    let leaf = OutboundNode(
        id: "hk01",
        name: "hk01",
        protocolConfig: .anytls(
            server: Endpoint(domain: "node.example.sbs", port: 5868),
            password: "x",
            sni: "sni.example",
            skipCertVerify: true,
            session: AnyTLSSessionConfig()
        )
    )
    let proxies = PolicyGroup(name: "Proxies", mode: .select, nodeIDs: [leaf.id])
    let google = PolicyGroup(name: "Google", mode: .select, nodeIDs: ["Proxies"])
    let manager = NodeManager(nodes: [leaf], groups: [proxies, google])
    #expect(manager.selectedNode(inGroup: "Google")?.id == "hk01")
}

@Test func selectDirectMemberIsUsedForDispatch() throws {
    let leaf = OutboundNode(
        id: "hk01",
        name: "hk01",
        protocolConfig: .anytls(
            server: Endpoint(domain: "node.example.sbs", port: 5868),
            password: "x",
            sni: "sni.example",
            skipCertVerify: true,
            session: AnyTLSSessionConfig()
        )
    )
    let proxies = PolicyGroup(name: "Proxies", mode: .select, nodeIDs: [leaf.id])
    let final = PolicyGroup(name: "Final", mode: .select, nodeIDs: ["Proxies", "DIRECT"])
    let manager = NodeManager(nodes: [leaf], groups: [proxies, final])
    manager.applySelections(["Final": "DIRECT"])
    #expect(manager.selectedMemberID(inGroup: "Final") == "DIRECT")
    let engine = Engine(
        router: Router(
            rules: [RouteRule(.matchAll, policy: .proxy(targetGroup: "Final"))],
            default: .direct
        ),
        nodeManager: manager
    )
    let connection = try engine.dispatch(target: Endpoint(domain: "api.kimi.com", port: 443))
    let failover = try #require(connection as? FailoverGroupConnection)
    #expect(failover.candidateNames.first == "DIRECT")
    #expect(manager.selectedLeaf(inGroup: "Final") == .direct)
    #expect(manager.selectedNode(inGroup: "Final") == nil)
}

@Test func dnsPolicyWalksSelectGroupToDirect() async {
    let leaf = OutboundNode(
        id: "hk01",
        name: "hk01",
        protocolConfig: .anytls(
            server: Endpoint(domain: "node.example.sbs", port: 5868),
            password: "x",
            sni: "sni.example",
            skipCertVerify: true,
            session: AnyTLSSessionConfig()
        )
    )
    let google = PolicyGroup(name: "Google", mode: .select, nodeIDs: [leaf.id])
    let final = PolicyGroup(name: "Final", mode: .select, nodeIDs: ["DIRECT", "Google"])
    let manager = NodeManager(nodes: [leaf], groups: [google, final])
    manager.applySelections(["Final": "DIRECT"])
    let engine = Engine(
        router: Router(
            rules: [
                RouteRule(.domainSuffix("google.com"), policy: .proxy(targetGroup: "Google")),
                RouteRule(.matchAll, policy: .proxy(targetGroup: "Final")),
            ],
            default: .direct
        ),
        nodeManager: manager
    )
    #expect(await engine.dnsPolicy(host: "api.kimi.com") == .direct)
    #expect(await engine.dnsPolicy(host: "www.google.com") == .proxy(targetGroup: "Google"))
}

@Test func trafficCounterTracksFlowsAndSnapshot() {
    let counter = TrafficCounter()
    counter.flowDidOpen()
    counter.flowDidOpen()
    #expect(counter.snapshot().activeConnections == 2)
    counter.addBytes(up: 100, down: 50, via: "Proxies")
    counter.flowDidClose(
        FlowRecord(
            endpoint: Endpoint(domain: "api.x.ai", port: 443),
            via: "Proxies",
            uplinkBytes: 100,
            downlinkBytes: 50,
            milliseconds: 20,
            clientEnd: "eof",
            remoteEnd: "eof"
        )
    )
    let snap = counter.snapshot()
    #expect(snap.activeConnections == 1)
    #expect(snap.uplinkBytes == 100)
    #expect(snap.downlinkBytes == 50)
    #expect(counter.recentFlows().count == 1)
    counter.addBytes(up: 10, down: 5, via: "Proxies")
    #expect(counter.snapshot().uplinkBytes == 110)
}
