import Foundation
import Testing
import PrizmXConfig
import PrizmXCore
import PrizmXNodes
import PrizmXProtocols
import PrizmXRules

private let clashYAML = """
proxies:
  - name: ss-us
    type: ss
    server: us.ss.example
    port: 8388
    cipher: aes-256-gcm
    password: test-password
  - name: vless-us
    type: vless
    server: us.vless.example
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda3b4b0c7f
    tls: true
    servername: us.vless.example

proxy-groups:
  - name: US-Group
    type: select
    proxies:
      - vless-us
      - ss-us

rules:
  - DOMAIN-SUFFIX,google.com,US-Group
  - DOMAIN-KEYWORD,ads,REJECT
  - IP-CIDR,10.0.0.0/8,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,US-Group
"""

private let singboxJSON = """
{
  "outbounds": [
    {
      "type": "shadowsocks",
      "tag": "ss-us",
      "server": "us.ss.example",
      "server_port": 8388,
      "method": "aes-256-gcm",
      "password": "test-password"
    },
    {
      "type": "vless",
      "tag": "vless-us",
      "server": "us.vless.example",
      "server_port": 443,
      "uuid": "b831381d-6324-4d53-ad4f-8cda3b4b0c7f",
      "tls": { "enabled": true, "server_name": "us.vless.example" }
    },
    {
      "type": "selector",
      "tag": "US-Group",
      "outbounds": ["vless-us", "ss-us"]
    },
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],
  "route": {
    "rules": [
      { "domain_suffix": "google.com", "outbound": "US-Group" },
      { "domain_keyword": "ads", "outbound": "block" },
      { "ip_cidr": "10.0.0.0/8", "outbound": "direct" },
      { "geosite": "cn", "outbound": "direct" },
      { "geoip": "cn", "outbound": "direct" }
    ],
    "final": "US-Group"
  }
}
"""

private let expectedRuleCount = 5
private let expectedNodeCount = 2

@Test func clashYAMLRestoresRouterAndNodes() throws {
    let (router, nodes) = try ClashConfigParser().parse(rawString: clashYAML)
    #expect(router.rules.count == expectedRuleCount)
    #expect(nodes.nodesByID.count == expectedNodeCount)
    #expect(nodes.group(named: "US-Group")?.mode == .select)
    #expect(nodes.group(named: "US-Group")?.nodeIDs == ["vless-us", "ss-us"])

    #expect(router.match(endpoint: Endpoint(domain: "www.google.com", port: 443)) == .proxy(targetGroup: "US-Group"))
    #expect(router.match(endpoint: Endpoint(domain: "tracker.adservice.net", port: 443)) == .reject)
    #expect(router.match(host: "10.1.2.3", port: 1) == .direct)
    #expect(router.match(endpoint: Endpoint(domain: "baidu.com", port: 443)) == .proxy(targetGroup: "US-Group"))

    let ss = try #require(nodes.node(id: "ss-us"))
    #expect(ss.protocolConfig == .shadowsocks(
        server: Endpoint(domain: "us.ss.example", port: 8388),
        password: "test-password",
        cipher: .aes256GCM
    ))
    let vless = try #require(nodes.node(id: "vless-us"))
    guard case .vless(let server, let uuid, let sni, let tls, let reality) = vless.protocolConfig else {
        Issue.record("expected vless node")
        return
    }
    #expect(server == Endpoint(domain: "us.vless.example", port: 443))
    #expect(uuid == "b831381d-6324-4d53-ad4f-8cda3b4b0c7f")
    #expect(sni == "us.vless.example")
    #expect(tls)
    #expect(reality == nil)
}

@Test func singboxJSONRestoresRouterAndNodes() throws {
    let (router, nodes) = try SingboxConfigParser().parse(rawString: singboxJSON)
    #expect(router.rules.count == expectedRuleCount)
    #expect(nodes.nodesByID.count == expectedNodeCount)
    #expect(nodes.group(named: "US-Group")?.mode == .select)
    #expect(nodes.group(named: "US-Group")?.nodeIDs == ["vless-us", "ss-us"])

    #expect(router.match(endpoint: Endpoint(domain: "maps.google.com", port: 443)) == .proxy(targetGroup: "US-Group"))
    #expect(router.match(endpoint: Endpoint(domain: "tracker.adservice.net", port: 443)) == .reject)
    #expect(router.match(host: "10.9.0.1", port: 80) == .direct)
    #expect(router.defaultPolicy == .proxy(targetGroup: "US-Group"))

    #expect(nodes.node(id: "ss-us") != nil)
    #expect(nodes.node(id: "vless-us") != nil)
}

@Test func configAdapterDetectsJSONVersusYAML() throws {
    let fromYAML = try ConfigAdapter.parse(rawString: clashYAML)
    let fromJSON = try ConfigAdapter.parse(rawString: singboxJSON)
    #expect(fromYAML.0.rules.count == expectedRuleCount)
    #expect(fromJSON.0.rules.count == expectedRuleCount)
    #expect(fromYAML.1.nodesByID.count == expectedNodeCount)
    #expect(fromJSON.1.nodesByID.count == expectedNodeCount)
}

@Test func clashSkipsUnknownRuleTypes() throws {
    // Subscriptions carry rule kinds we do not support yet (PROCESS-NAME,
    // RULE-SET…); Clash YAML import skips them instead of failing wholesale.
    let yaml = """
    proxies: []
    rules:
      - DOMAIN-SUFFIX,google.com,Proxy
      - NOT-A-REAL-TYPE,foo
    """
    let (router, _) = try ClashConfigParser().parse(rawString: yaml)
    #expect(router.rules.count == 1)
}

@Test func surgeRejectsMalformedRule() {
    let ini = """
    [Rule]
    NOT-A-REAL-TYPE,foo
    """
    do {
        _ = try ClashConfigParser().parse(rawString: ini)
        Issue.record("expected malformedRule")
    } catch let error as ConfigError {
        #expect(error == .malformedRule("NOT-A-REAL-TYPE,foo"))
    } catch {
        Issue.record("unexpected \(error)")
    }
}

@Test func singboxRejectsBadJSON() {
    do {
        _ = try SingboxConfigParser().parse(rawString: "{ not json")
        Issue.record("expected jsonSyntax")
    } catch let error as ConfigError {
        guard case .jsonSyntax = error else {
            Issue.record("expected jsonSyntax, got \(error)")
            return
        }
    } catch {
        Issue.record("unexpected \(error)")
    }
}

@Test func emptyInputThrows() {
    do {
        _ = try ClashConfigParser().parse(rawString: "   \n")
        Issue.record("expected emptyInput")
    } catch let error as ConfigError {
        #expect(error == .emptyInput)
    } catch {
        Issue.record("unexpected \(error)")
    }
}

@Test func surgeINIParsesProxyAndRules() throws {
    let surge = """
    [Proxy]
    ss-us = ss, us.ss.example, 8388, encrypt-method=aes-256-gcm, password=test-password

    [Proxy Group]
    PROXY = select, ss-us

    [Rule]
    DOMAIN-SUFFIX,google.com,PROXY
    FINAL,DIRECT
    """
    let (router, nodes) = try ClashConfigParser().parse(rawString: surge)
    #expect(nodes.nodesByID.count == 1)
    #expect(router.rules.count == 2)
    #expect(router.match(endpoint: Endpoint(domain: "www.google.com", port: 443)) == .proxy(targetGroup: "PROXY"))
    #expect(router.match(endpoint: Endpoint(domain: "baidu.com", port: 443)) == .direct)
}

@Test func engineFactoryDirectOnlyWhenConfigEmpty() throws {
    let engine = try EngineFactory.make(configText: nil)
    #expect(engine.router.match(host: "example.com", port: 443) == .direct)
}

@Test func engineFactoryHonorsOutboundMode() throws {
    let yaml = """
    proxies:
      - {name: HK01, type: ss, server: 1.1.1.1, port: 8388, cipher: aes-256-gcm, password: x}
    proxy-groups:
      - {name: Proxies, type: select, proxies: [HK01]}
    rules:
      - DOMAIN-SUFFIX,google.com,Proxies
      - MATCH,DIRECT
    """
    let global = try EngineFactory.make(
        configText: yaml,
        outboundMode: .global,
        globalGroup: "Proxies"
    )
    #expect(global.policy(for: Endpoint(domain: "baidu.com", port: 443)) == .proxy(targetGroup: "Proxies"))

    let direct = try EngineFactory.make(configText: yaml, outboundMode: .direct)
    #expect(direct.policy(for: Endpoint(domain: "google.com", port: 443)) == .direct)
}

@Test func geositeAndGeoIPArePreservedOnRouter() throws {
    let (clashRouter, _) = try ClashConfigParser().parse(rawString: clashYAML)
    #expect(clashRouter.rules.contains { $0.matcher == .geoIP(code: "CN") })

    let (singRouter, _) = try SingboxConfigParser().parse(rawString: singboxJSON)
    #expect(singRouter.rules.contains { $0.matcher == .geosite(tag: "cn") })
    #expect(singRouter.rules.contains { $0.matcher == .geoIP(code: "CN") })
}

@Test func engineFactoryFiltersNodeHostsFromFakeIP() throws {
    let yaml = """
    proxies:
      - {name: HK01, type: anytls, server: node.example.sbs, port: 5868, password: x, sni: a.com}
    proxy-groups:
      - {name: Proxies, type: select, proxies: [HK01]}
    rules:
      - MATCH,Proxies
    """
    let engine = try EngineFactory.make(configText: yaml)
    #expect(engine.dns.settings.fakeIPFilter.contains("node.example.sbs"))
    // Built-ins stay.
    #expect(engine.dns.settings.fakeIPFilter.contains("*.lan"))
}

@Test func engineFactoryAppliesGeositeMatcher() throws {
    let yaml = """
    proxies: []
    proxy-groups: []
    rules:
      - GEOSITE,cn,DIRECT
      - MATCH,PROXY
    """
    let json = """
    {"cn":{"exact":[],"suffixes":["baidu.com"],"keywords":[]}}
    """
    let engine = try EngineFactory.make(configText: yaml, geositeJSON: json)
    #expect(engine.router.match(host: "www.baidu.com", port: 443) == .direct)
    #expect(engine.router.match(host: "google.com", port: 443) == .proxy(targetGroup: "PROXY"))
}

@Test func engineFactoryLoadsGeositeDatFromFile() throws {
    var list = Data()
    var site = Data()
    func appendVarint(_ data: inout Data, _ value: UInt64) {
        var current = value
        while current > 127 {
            data.append(UInt8(current & 0x7F) | 0x80)
            current >>= 7
        }
        data.append(UInt8(current))
    }
    func appendBytes(_ data: inout Data, field: Int, _ value: Data) {
        appendVarint(&data, UInt64((field << 3) | 2))
        appendVarint(&data, UInt64(value.count))
        data.append(value)
    }
    var domain = Data()
    appendVarint(&domain, 8) // field 1 varint type=2 (suffix)
    appendVarint(&domain, 2)
    appendBytes(&domain, field: 2, Data("baidu.com".utf8))
    appendBytes(&site, field: 1, Data("cn".utf8))
    appendBytes(&site, field: 2, domain)
    appendBytes(&list, field: 1, site)

    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("prizmx-geosite-\(UUID().uuidString).dat")
    try list.write(to: url)
    defer { try? FileManager.default.removeItem(at: url) }

    let yaml = """
    proxies: []
    proxy-groups: []
    rules:
      - GEOSITE,cn,DIRECT
      - MATCH,PROXY
    """
    let engine = try EngineFactory.make(configText: yaml, geositeURL: url)
    #expect(engine.router.match(host: "tieba.baidu.com", port: 443) == .direct)
    #expect(engine.router.match(host: "google.com", port: 443) == .proxy(targetGroup: "PROXY"))
}

@Test func geoAssetStoreReusesExistingFilesWithoutDownload() async throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("prizmx-geo-\(UUID().uuidString)", isDirectory: true)
    let geoDir = root.appendingPathComponent("geo", isDirectory: true)
    try FileManager.default.createDirectory(at: geoDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try Data(repeating: 1, count: 2_048).write(to: geoDir.appendingPathComponent("geoip.metadb"))
    try Data(repeating: 2, count: 2_048).write(to: geoDir.appendingPathComponent("geosite.dat"))

    let prepared = await GeoAssetStore.prepare(
        root: root,
        geoIP: true,
        geosite: true,
        sources: .none
    )
    #expect(prepared.geoIPPath == GeoAssetStore.geoIPRelativePath)
    #expect(prepared.geositePath == GeoAssetStore.geositeRelativePath)
    #expect(
        GeoAssetStore.resolve(prepared.geoIPPath, root: root)
            == root.appendingPathComponent(GeoAssetStore.geoIPRelativePath)
    )
}

@Test func clashAndSingboxParseHealthCheckGroupSettings() throws {
    let clash = """
    proxies:
      - {name: HK01, type: ss, server: 1.1.1.1, port: 8388, cipher: aes-256-gcm, password: x}
      - {name: JP01, type: ss, server: 2.2.2.2, port: 8388, cipher: aes-256-gcm, password: x}
    proxy-groups:
      - name: Auto
        type: url-test
        url: http://www.gstatic.com/generate_204
        interval: 120
        tolerance: 80
        proxies: [HK01, JP01]
      - name: Backup
        type: fallback
        url: http://cp.cloudflare.com/generate_204
        interval: 60
        proxies: [HK01, JP01]
      - name: Spread
        type: load-balance
        strategy: round-robin
        proxies: [HK01, JP01]
    rules:
      - MATCH,Auto
    """
    let (_, nodes) = try ClashConfigParser().parse(rawString: clash)
    let auto = try #require(nodes.group(named: "Auto"))
    #expect(auto.mode == .urlTest)
    #expect(auto.interval == .seconds(120))
    #expect(auto.tolerance == .milliseconds(80))
    #expect(auto.testURL.contains("gstatic"))
    #expect(nodes.group(named: "Backup")?.mode == .fallback)
    #expect(nodes.group(named: "Spread")?.mode == .loadBalance)
    #expect(nodes.group(named: "Spread")?.loadBalanceStrategy == .roundRobin)

    let singbox = """
    {
      "outbounds": [
        {"type":"shadowsocks","tag":"HK01","server":"1.1.1.1","server_port":8388,"method":"aes-256-gcm","password":"x"},
        {"type":"urltest","tag":"Auto","outbounds":["HK01"],"url":"http://www.gstatic.com/generate_204","interval":"2m","tolerance":40}
      ]
    }
    """
    let (_, sb) = try SingboxConfigParser().parse(rawString: singbox)
    let urlTest = try #require(sb.group(named: "Auto"))
    #expect(urlTest.mode == .urlTest)
    #expect(urlTest.interval == .seconds(120))
    #expect(urlTest.tolerance == .milliseconds(40))
}

@Test func clashParsesNoResolveOnGeoIP() throws {
    let yaml = """
    proxies: []
    proxy-groups: []
    rules:
      - GEOIP,CN,DIRECT,no-resolve
      - MATCH,PROXY
    """
    let (router, _) = try ClashConfigParser().parse(rawString: yaml)
    let geo = try #require(router.rules.first)
    #expect(geo.noResolve)
    if case .geoIP(let code) = geo.matcher {
        #expect(code == "CN")
    } else {
        Issue.record("expected GEOIP")
    }
}
