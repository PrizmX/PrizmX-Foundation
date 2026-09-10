import Foundation
import Testing
import PrizmXConfig
import PrizmXProtocols

@Test func nodeHostnamesExtractedFromClashYAML() {
    let yaml = """
    proxies:
      - {name: HK01, type: anytls, server: node.example.sbs, port: 5868, password: x, sni: a.com}
      - {name: info, type: anytls, server: node.example.sbs, port: 5868, password: x, sni: a.com}
      - {name: US, type: anytls, server: other.example.sbs, port: 443, password: x, sni: a.com}
    proxy-groups:
      - {name: Proxies, type: select, proxies: [HK01, US]}
    rules:
      - MATCH,Proxies
    """
    let hosts = NodeAddressStore.nodeHostnames(in: yaml)
    #expect(hosts == ["node.example.sbs", "other.example.sbs"])
}

@Test func nodeEndpointsCollectPortsPerHost() {
    let yaml = """
    proxies:
      - {name: HK01, type: anytls, server: node.example.sbs, port: 5868, password: x, sni: a.com}
      - {name: HK02, type: anytls, server: node.example.sbs, port: 5869, password: x, sni: a.com}
      - {name: US, type: anytls, server: other.example.sbs, port: 443, password: x, sni: a.com}
    proxy-groups:
      - {name: Proxies, type: select, proxies: [HK01, US]}
    rules:
      - MATCH,Proxies
    """
    let endpoints = NodeAddressStore.nodeEndpoints(in: yaml)
    #expect(endpoints["node.example.sbs"] == [5868, 5869])
    #expect(endpoints["other.example.sbs"] == [443])
    #expect(NodeAddressStore.nodeHostnames(in: yaml) == ["node.example.sbs", "other.example.sbs"])
}

@Test func orderedCandidatesDropFakeIP() {
    let real = PrizmXProtocols.IPv4Address(218, 245, 102, 118)
    let fake = PrizmXProtocols.IPv4Address(198, 18, 0, 4)
    let ordered = NodeAddressStore.orderedCandidates(
        good: [fake, real],
        previous: [fake],
        publicAnswers: [fake],
        captured: [fake],
        system: [fake, real]
    )
    #expect(ordered == [real])
}

@Test func orderedCandidatesPreferProvenGood() {
    let good = PrizmXProtocols.IPv4Address(218, 245, 102, 118)
    let oldPin = PrizmXProtocols.IPv4Address(203, 0, 113, 9)
    let poisoned = PrizmXProtocols.IPv4Address(155, 254, 102, 209)
    let ordered = NodeAddressStore.orderedCandidates(
        good: [good],
        previous: [oldPin],
        publicAnswers: [poisoned],
        captured: [poisoned],
        system: [poisoned, good]
    )
    #expect(ordered == [good, oldPin, poisoned])
}

@Test func persistedGoodNodeAddressesReadsProxyServerPlane() throws {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("dns-good-test-\(UUID().uuidString).json")
    let payload = [
        "proxy-server|node.example.sbs": ["218.245.102.118", "198.18.0.4", "203.0.113.9"],
        "direct|www.apple.com": ["17.1.1.1"],
    ]
    try JSONEncoder().encode(payload).write(to: url)
    defer { try? FileManager.default.removeItem(at: url) }

    let good = DNSClient.persistedGoodNodeAddresses(url: url)
    #expect(good["node.example.sbs"] == [
        PrizmXProtocols.IPv4Address(218, 245, 102, 118),
        PrizmXProtocols.IPv4Address(203, 0, 113, 9),
    ])
    #expect(good["www.apple.com"] == nil)
}
