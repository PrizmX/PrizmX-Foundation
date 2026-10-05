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

@Test func clearCacheRemovesPinsAndProvenAddresses() throws {
    let fileManager = FileManager.default
    let root = fileManager.temporaryDirectory.appendingPathComponent("node-dns-clear-\(UUID().uuidString)")
    let appGroupKit = root.appendingPathComponent("group", isDirectory: true)
    let runtimeKit = root.appendingPathComponent("runtime", isDirectory: true)
    defer { try? fileManager.removeItem(at: root) }
    for kit in [appGroupKit, runtimeKit] {
        try fileManager.createDirectory(
            at: kit.appendingPathComponent("tunnel", isDirectory: true),
            withIntermediateDirectories: true
        )
        try #"{"node.example.sbs":["1.2.3.4"]}"#.write(
            to: kit.appendingPathComponent(NodeAddressStore.relativePath),
            atomically: true,
            encoding: .utf8
        )
        try #"{"proxy-server|node.example.sbs":["1.2.3.4"]}"#.write(
            to: kit.appendingPathComponent("dns-good.json"),
            atomically: true,
            encoding: .utf8
        )
        try "proxies: []\n".write(
            to: kit.appendingPathComponent("tunnel/active.conf"),
            atomically: true,
            encoding: .utf8
        )
    }

    NodeAddressStore.clearCache(kitRoots: [appGroupKit, runtimeKit])

    for kit in [appGroupKit, runtimeKit] {
        #expect(!fileManager.fileExists(atPath: kit.appendingPathComponent(NodeAddressStore.relativePath).path))
        #expect(!fileManager.fileExists(atPath: kit.appendingPathComponent("dns-good.json").path))
        // Only the DNS cache goes; the staged profile stays.
        #expect(fileManager.fileExists(atPath: kit.appendingPathComponent("tunnel/active.conf").path))
    }
}

@Test func followsProfileDNSNeedsEnabledNameserverWithoutOverride() {
    let yaml = """
    dns:
      enable: true
      nameserver:
        - https://dns.example.com/dns-query
    proxies: []
    rules:
      - MATCH,DIRECT
    """
    #expect(NodeAddressStore.followsProfileDNS(configText: yaml, overrideDNS: false))
    #expect(!NodeAddressStore.followsProfileDNS(configText: yaml, overrideDNS: true))
    #expect(!NodeAddressStore.followsProfileDNS(configText: "proxies: []\nrules:\n  - MATCH,DIRECT\n", overrideDNS: false))
}
