import Foundation
import Testing
import PrizmXCore
import PrizmXNodes
import PrizmXRules
@testable import PrizmXProtocols

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

@Test func systemHostsBypassesProxyAndStillHonorsReject() async throws {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("prizmx-hosts-\(UUID().uuidString)")
    try """
    127.0.0.1 maps.google.com
    10.9.8.7 tracker.ads.example
    """.write(to: url, atomically: true, encoding: .utf8)
    defer { try? FileManager.default.removeItem(at: url) }

    let engine = try makeEngine()
    try await SystemHosts.$pathOverride.withValue(url.path) {
        let proxied = Endpoint(domain: "maps.google.com", port: 443)
        let connection = try engine.dispatchDetailed(target: proxied)
        let direct = try #require(connection.connection as? DirectOutboundConnection)
        #expect(direct.endpoint == proxied)
        #expect(connection.rule == "HOSTS,maps.google.com,DIRECT")

        let blocked = Endpoint(domain: "tracker.ads.example", port: 443)
        do {
            _ = try engine.dispatch(target: blocked)
            Issue.record("expected hosts-mapped reject")
        } catch let error as EngineError {
            #expect(error == .rejected(blocked))
        }

        let untouched = try engine.dispatch(target: Endpoint(domain: "google.com", port: 443))
        #expect(untouched is FailoverGroupConnection)

        let ipRouter = Router(
            rules: [try RouteRule(type: .ipCIDR("10.9.8.7/32"), policy: .reject)],
            default: .proxy(targetGroup: "US-Group")
        )
        let ipEngine = Engine(router: ipRouter, nodeManager: engine.nodeManager)
        let mapped = Endpoint(domain: "tracker.ads.example", port: 80)
        #expect(await ipEngine.resolveIPv4(for: mapped) == IPv4Address(10, 9, 8, 7))
        do {
            _ = try ipEngine.dispatch(target: mapped)
            Issue.record("expected IP-CIDR reject via hosts address")
        } catch let error as EngineError {
            #expect(error == .rejected(mapped))
        }
    }
}

@Test func publicHostsMappingFollowsTheRuleAndProxiesTheMappedAddress() async throws {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("prizmx-hosts-\(UUID().uuidString)")
    try """
    140.82.112.4 www.google.com
    93.184.215.14 example.org
    192.168.1.20 nas.google.com
    """.write(to: url, atomically: true, encoding: .utf8)
    defer { try? FileManager.default.removeItem(at: url) }

    let engine = try makeEngine()
    try await SystemHosts.$pathOverride.withValue(url.path) {
        // Public mapping + proxy rule: stays proxied, and the node is asked
        // for the mapped address instead of the name (mihomo semantics).
        let proxied = Endpoint(domain: "www.google.com", port: 443)
        let viaProxy = try engine.dispatchDetailed(target: proxied)
        let group = try #require(viaProxy.connection as? FailoverGroupConnection)
        #expect(group.endpoint == Endpoint(host: .ipv4(IPv4Address(140, 82, 112, 4)), port: 443))
        #expect(!viaProxy.rule.hasPrefix("HOSTS,"))
        #expect(await engine.resolvePolicy(for: proxied) == .proxy(targetGroup: "US-Group"))

        // Public mapping + DIRECT rule: direct, resolved through hosts.
        let direct = Endpoint(domain: "example.org", port: 443)
        let viaDirect = try engine.dispatchDetailed(target: direct)
        #expect((viaDirect.connection as? DirectOutboundConnection)?.endpoint == direct)

        // LAN mapping under a proxy rule: still dialed locally (TCP and UDP).
        let lan = Endpoint(domain: "nas.google.com", port: 445)
        let viaLAN = try engine.dispatchDetailed(target: lan)
        #expect(viaLAN.connection is DirectOutboundConnection)
        #expect(viaLAN.rule == "HOSTS,nas.google.com,DIRECT")
        #expect(await engine.resolvePolicy(for: lan) == .direct)
    }
}

@Test func hostsLocalBindingCoversLoopbackLANAndUnspecified() {
    func v4(_ text: String) -> SystemHosts.Mapping {
        let address = IPv4Address(parsing: text)!
        return SystemHosts.Mapping(addresses: [.ipv4(address)], ipv4: [address])
    }
    func v6(_ text: String) -> SystemHosts.Mapping {
        let address = IPv6Address(parsing: text)!
        return SystemHosts.Mapping(addresses: [.ipv6(address)], ipv6: [address])
    }
    for local in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.0.10", "169.254.1.1", "0.0.0.0"] {
        #expect(v4(local).isLocalBinding, "\(local)")
    }
    for global in ["8.8.8.8", "172.32.0.1", "172.15.255.255", "192.169.0.1", "100.64.0.1", "140.82.112.4"] {
        #expect(!v4(global).isLocalBinding, "\(global)")
    }
    for local in ["::1", "::", "fd00::1", "fc12::1", "fe80::1"] {
        #expect(v6(local).isLocalBinding, "\(local)")
    }
    for global in ["2606:4700::1111", "2001:db8::1", "fec0::1"] {
        #expect(!v6(global).isLocalBinding, "\(global)")
    }
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

@Test func dnsPolicyNeverResolvesOnThePacketPath() async {
    let engine = Engine(
        router: Router(
            rules: [
                RouteRule(.domainSuffix("ads.example"), policy: .reject),
                RouteRule(.ipv4CIDR(IPv4Address(10, 0, 0, 0), prefixLength: 8), policy: .direct),
                RouteRule(.matchAll, policy: .reject),
            ],
            default: .direct
        ),
        nodeManager: NodeManager(nodes: [], groups: [])
    )
    #expect(await engine.dnsPolicy(host: "x.ads.example") == .reject)
    // Reaching the IP-CIDR rule would need a direct lookup: left to the dial.
    #expect(await engine.dnsPolicy(host: "unresolvable.invalid") == nil)
}

@Test func trafficCounterTracksFlowsAndSnapshot() {
    let counter = TrafficCounter()
    counter.flowDidOpen()
    counter.flowDidOpen()
    #expect(counter.snapshot().activeConnections == 2)
    counter.addBytes(up: 100, down: 50, route: FlowRoute(["Proxies"]))
    counter.flowDidClose(
        FlowRecord(
            endpoint: Endpoint(domain: "api.x.ai", port: 443),
            route: FlowRoute(["Proxies"]),
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
    counter.addBytes(up: 10, down: 5, route: FlowRoute(["Proxies"]))
    #expect(counter.snapshot().uplinkBytes == 110)
}
