import Foundation
import Testing
@testable import PrizmXConfig
import PrizmXNodes
import PrizmXProtocols
@testable import PrizmXRules

// MARK: - YAML subset

@Test func yamlSequenceAtKeyIndentIsParsed() throws {
    // Generated subscriptions often put `- ` at the key's own indent.
    let yaml = """
    proxies:
    - {name: a, type: ss, server: 1.1.1.1, port: 8388, cipher: aes-256-gcm, password: x}
    proxy-groups:
    - name: G
      type: select
      proxies:
      - a
    rules:
    - DOMAIN-SUFFIX,google.com,G
    - MATCH,DIRECT
    """
    let (router, nodes) = try ClashConfigParser().parse(rawString: yaml)
    #expect(nodes.nodesByID.keys.sorted() == ["a"])
    #expect(nodes.groupsByName["G"]?.nodeIDs == ["a"])
    #expect(router.rules.count == 2)
    #expect(router.match(host: "www.google.com", port: 443) == .proxy(targetGroup: "G"))
}

@Test func yamlRejectsUnconsumedContent() {
    // Anything the parser cannot place must fail loudly, not truncate.
    let yaml = """
    - a
    key: value
    """
    #expect(throws: ConfigError.self) {
        _ = try YAMLParser.parse(yaml)
    }
}

@Test func yamlHashWithoutLeadingSpaceIsNotAComment() throws {
    let yaml = """
    password: abc#123
    quoted: 'a # b' # trailing
    name: Tom's node # comment
    apostrophe key's: v
    url: "http://x/#frag"
    """
    let root = try YAMLParser.parse(yaml)
    #expect(root.string(for: "password") == "abc#123")
    #expect(root.string(for: "quoted") == "a # b")
    #expect(root.string(for: "name") == "Tom's node")
    #expect(root.string(for: "apostrophe key's") == "v")
    #expect(root.string(for: "url") == "http://x/#frag")
}

@Test func leadingBOMIsIgnored() throws {
    let yaml = "\u{FEFF}proxies: []\nrules:\n  - MATCH,REJECT\n"
    let (router, _) = try ConfigAdapter.parse(rawString: yaml)
    #expect(router.rules.count == 1)
    let json = "\u{FEFF}{\"outbounds\": [], \"route\": {\"final\": \"block\"}}"
    let (jsonRouter, _) = try ConfigAdapter.parse(rawString: json)
    #expect(jsonRouter.defaultPolicy == .reject)
    #expect(InboundListenConfig.parse(from: "\u{FEFF}mixed-port: 7000\n").mixedPort == 7000)
}

// MARK: - Clash rule fidelity

@Test func clashUnsupportedRulesAreSkippedWithWarnings() throws {
    let yaml = """
    proxies: []
    rules:
      - RULE-SET,ads,REJECT
      - AND,((DOMAIN,a.com),(NETWORK,UDP)),REJECT
      - DST-PORT,443,REJECT
      - PROCESS-NAME,curl,REJECT
      - GEOIP,CN,DIRECT,src
      - DOMAIN-SUFFIX,example.com,DIRECT
    """
    let result = try ConfigAdapter.parseWithWarnings(rawString: yaml)
    #expect(result.router.rules.count == 1)
    let skipped = result.warnings.filter { $0.kind == .rule }.map(\.text)
    #expect(skipped == [
        "RULE-SET,ads,REJECT",
        "AND,((DOMAIN,a.com),(NETWORK,UDP)),REJECT",
        "DST-PORT,443,REJECT",
        "PROCESS-NAME,curl,REJECT",
        "GEOIP,CN,DIRECT,src",
    ])
}

@Test func clashGeoIPLANExpandsToPrivateRanges() throws {
    let yaml = """
    proxies: []
    rules:
      - GEOIP,LAN,DIRECT,no-resolve
      - MATCH,REJECT
    """
    let (router, _) = try ClashConfigParser().parse(rawString: yaml)
    #expect(router.rules.dropLast().allSatisfy { $0.noResolve && $0.policy == .direct })
    for host in ["10.1.2.3", "192.168.1.1", "172.20.0.1", "127.0.0.1", "169.254.1.1", "::1", "fd00::1", "fe80::1"] {
        #expect(router.match(host: host, port: 80) == .direct, "\(host)")
    }
    #expect(router.match(host: "8.8.8.8", port: 80) == .reject)
}

@Test func clashIncludeAllGroupsAndProviderWarnings() throws {
    let yaml = """
    proxies:
      - {name: HK1, type: ss, server: 1.1.1.1, port: 8388, cipher: aes-256-gcm, password: x}
      - {name: JP1, type: ss, server: 2.2.2.2, port: 8388, cipher: aes-256-gcm, password: x}
      - {name: HK2, type: vmess, server: 3.3.3.3, port: 443, uuid: u}
    proxy-groups:
      - {name: All, type: select, include-all: true}
      - {name: HK, type: url-test, include-all: true, filter: "HK"}
      - {name: Remote, type: select, use: [provider1]}
    rules:
      - DOMAIN,a.com,HK
      - DOMAIN,b.com,Remote
      - MATCH,All
    """
    let result = try ConfigAdapter.parseWithWarnings(rawString: yaml)
    let groups = result.nodeManager.groupsByName
    #expect(groups["All"]?.nodeIDs == ["HK1", "JP1"])
    #expect(groups["HK"]?.nodeIDs == ["HK1"])
    #expect(groups["Remote"] == nil)
    // The rule stays and fails closed instead of silently disappearing.
    #expect(result.router.match(host: "b.com", port: 443) == .proxy(targetGroup: "Remote"))
    #expect(result.warnings.contains { $0.kind == .proxy && $0.text == "HK2" })
    #expect(result.warnings.contains { $0.kind == .group && $0.text == "Remote" && $0.reason.contains("providers") })
    #expect(result.warnings.contains { $0.kind == .group && $0.text == "Remote" && $0.reason.contains("not defined") })
}

@Test func clashIntervalZeroUsesDefault() throws {
    #expect(ConfigMapping.interval("0") == .seconds(300))
    #expect(ConfigMapping.interval("-5") == .seconds(300))
    #expect(ConfigMapping.interval("0s") == .seconds(300))
    #expect(ConfigMapping.interval("120") == .seconds(120))
    #expect(ConfigMapping.interval("2m") == .seconds(120))
    #expect(ConfigMapping.interval("99999999999999h") > .seconds(0))
}

// MARK: - sing-box rule fidelity

@Test func singboxRulesWithUnsupportedFieldsAreSkipped() throws {
    let json = """
    {
      "outbounds": [
        {"type": "shadowsocks", "tag": "ss", "server": "1.1.1.1", "server_port": 8388, "method": "aes-256-gcm", "password": "x"},
        {"type": "direct", "tag": "direct-out"},
        {"type": "block", "tag": "block-out"}
      ],
      "route": {
        "rules": [
          {"domain_suffix": ["a.com"], "invert": true, "outbound": "ss"},
          {"domain_suffix": ["b.com"], "port": 443, "outbound": "ss"},
          {"network": "udp", "outbound": "ss"},
          {"rule_set": ["geosite-ads"], "outbound": "block-out"},
          {"type": "logical", "mode": "and", "rules": [], "outbound": "ss"},
          {"protocol": "dns", "action": "hijack-dns"},
          {"domain_suffix": ["ads.com"], "action": "reject"},
          {"domain_suffix": ["c.com"], "action": "route", "outbound": "ss"},
          {"ip_is_private": true, "outbound": "direct-out"}
        ],
        "final": "ss"
      }
    }
    """
    let result = try ConfigAdapter.parseWithWarnings(rawString: json)
    let router = result.router
    #expect(result.warnings.filter { $0.kind == .rule }.count == 6)
    #expect(router.match(host: "x.ads.com", port: 443) == .reject)
    #expect(router.match(host: "c.com", port: 443) == .proxy(targetGroup: "ss"))
    #expect(router.match(host: "192.168.1.10", port: 80) == .direct)
    // Skipped rules must not have been imported in a broadened form.
    #expect(router.match(host: "a.com", port: 443) == .proxy(targetGroup: "ss"))
    #expect(router.match(host: "b.com", port: 80) == .proxy(targetGroup: "ss"))
    #expect(!router.rules.contains { $0.matcher == .matchAll })
}

// MARK: - TLS options

@Test func clashAndSingboxParseTLSOptions() throws {
    let yaml = """
    proxies:
      - {name: v, type: vless, server: v.example, port: 443, uuid: 00000000-0000-0000-0000-000000000001, tls: true, servername: v.example, skip-cert-verify: true, alpn: [h2, http/1.1]}
      - {name: t, type: trojan, server: t.example, port: 443, password: p, sni: t.example, skip-cert-verify: true}
    """
    let (_, clash) = try ClashConfigParser().parse(rawString: yaml)
    guard case .vless(_, _, _, _, _, _, let skipV, let alpn) = clash.nodesByID["v"]?.protocolConfig,
          case .trojan(_, _, _, let skipT) = clash.nodesByID["t"]?.protocolConfig
    else {
        Issue.record("unexpected node shapes")
        return
    }
    #expect(skipV && skipT)
    #expect(alpn == ["h2", "http/1.1"])

    let json = """
    {"outbounds": [
      {"type": "vless", "tag": "v", "server": "v.example", "server_port": 443, "uuid": "00000000-0000-0000-0000-000000000001",
       "tls": {"enabled": true, "server_name": "v.example", "insecure": true, "alpn": "h2"}},
      {"type": "trojan", "tag": "t", "server": "t.example", "server_port": 443, "password": "p",
       "tls": {"enabled": true, "insecure": false}}
    ]}
    """
    let (_, singbox) = try SingboxConfigParser().parse(rawString: json)
    guard case .vless(_, _, _, _, _, _, let sbSkipV, let sbALPN) = singbox.nodesByID["v"]?.protocolConfig,
          case .trojan(_, _, _, let sbSkipT) = singbox.nodesByID["t"]?.protocolConfig
    else {
        Issue.record("unexpected node shapes")
        return
    }
    #expect(sbSkipV && !sbSkipT)
    #expect(sbALPN == ["h2"])

    // Wired through to the protocol connections.
    let target = Endpoint(domain: "example.com", port: 443)
    let vless = try NodeFactory.makeConnection(from: clash.nodesByID["v"]!, to: target)
    let trojan = try NodeFactory.makeConnection(from: clash.nodesByID["t"]!, to: target)
    #expect((vless as? VLESSOutboundConnection)?.skipCertVerify == true)
    #expect((vless as? VLESSOutboundConnection)?.alpn == ["h2", "http/1.1"])
    #expect((trojan as? TrojanOutboundConnection)?.skipCertVerify == true)
}

// MARK: - Inbound authentication

@Test func inboundListenParsesAuthentication() {
    let listen = InboundListenConfig.parse(from: """
    mixed-port: 7890
    authentication:
      - "alice:pa:ss"
      - "bad-entry"
      - "bob:"
    skip-auth-prefixes:
      - 127.0.0.1/8
      - 192.168.0.0/16
    """)
    #expect(listen.authentication == [
        .init(username: "alice", password: "pa:ss"),
        .init(username: "bob", password: ""),
    ])
    #expect(listen.skipAuthPrefixes == ["127.0.0.1/8", "192.168.0.0/16"])

    let defaults = InboundListenConfig.parse(from: "authentication: [\"u:p\"]\n")
    #expect(defaults.httpPort == InboundListenConfig.appDefault.httpPort)
    #expect(defaults.authentication == [.init(username: "u", password: "p")])
    #expect(defaults.skipAuthPrefixes == nil)
}

// MARK: - Geo assets

func geositeFixture() -> Data {
    // GeoSiteList { entry { country_code: "cn", domain { type: Domain, value: "x.cn" } } }
    let domain: [UInt8] = [0x08, 0x02, 0x12, 0x04] + Array("x.cn".utf8)
    let site: [UInt8] = [0x0A, 0x02] + Array("cn".utf8) + [0x12, UInt8(domain.count)] + domain
    return Data([0x0A, UInt8(site.count)] + site)
}

func geoIPFixture() -> Data {
    MMDBWriter.build(records: [(IPv4Address(parsing: "1.0.0.0")!, 8, "CN")])
}

private final class StubProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var body = Data()
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Self.body)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

@Test func geoAssetValidationRejectsCaptivePortalAndKeepsOldFile() async throws {
    #expect(GeoAssetStore.isValid(geoIPFixture(), kind: .geoIP))
    #expect(GeoAssetStore.isValid(geositeFixture(), kind: .geosite))
    let portal = Data(("<!DOCTYPE html><html>" + String(repeating: "login ", count: 400) + "</html>").utf8)
    #expect(!GeoAssetStore.isValid(portal, kind: .geoIP))
    #expect(!GeoAssetStore.isValid(portal, kind: .geosite))

    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("prizmx-geo-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let url = root.appendingPathComponent(GeoAssetStore.geoIPRelativePath)
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    let original = geoIPFixture()
    try original.write(to: url)

    StubProtocol.body = portal
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [StubProtocol.self]
    let session = URLSession(configuration: configuration)
    let ok = await GeoAssetStore.download(
        to: url,
        kind: .geoIP,
        sources: [URL(string: "https://geo.invalid/geoip.metadb")!],
        session: session
    )
    #expect(!ok)
    #expect(try Data(contentsOf: url) == original)
}
