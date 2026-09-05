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

@Test func geositeAndGeoIPArePreservedOnRouter() throws {
    let (clashRouter, _) = try ClashConfigParser().parse(rawString: clashYAML)
    #expect(clashRouter.rules.contains { $0.matcher == .geoIP(code: "CN") })

    let (singRouter, _) = try SingboxConfigParser().parse(rawString: singboxJSON)
    #expect(singRouter.rules.contains { $0.matcher == .geosite(tag: "cn") })
    #expect(singRouter.rules.contains { $0.matcher == .geoIP(code: "CN") })
}
