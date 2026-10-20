import Foundation
import Testing
@testable import PrizmXConfig
import PrizmXNodes
import PrizmXProtocols
import PrizmXRules

/// Writes `body` where `ProviderStore` caches the provider for `url`.
private func cache(_ body: String, kind: ProviderStore.Kind, url: String, root: URL) throws {
    let definition = ProviderStore.Definition(
        kind: kind, name: "x", type: "http", url: URL(string: url), interval: 3_600,
        behavior: nil, format: "yaml", filter: nil, excludeFilter: nil, excludeType: nil, unsupportedKeys: []
    )
    let file = try #require(ProviderStore.cacheURL(for: definition, root: root))
    try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
    try body.write(to: file, atomically: true, encoding: .utf8)
}

private func temporaryRoot() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("prizmx-providers-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

@Suite struct ProviderImportTests {
    @Test func ruleProvidersOfEveryBehaviorImport() throws {
        let root = try temporaryRoot()
        try cache("payload:\n  - '+.ads.example'\n  - 'exact.example'\n", kind: .rule, url: "https://p.example/ads.yaml", root: root)
        try cache("1.0.1.0/24\n# comment\n240e::/20\n", kind: .rule, url: "https://p.example/cn.txt", root: root)
        let yaml = """
        proxies:
          - {name: P1, type: ss, server: 1.1.1.1, port: 8388, cipher: aes-256-gcm, password: x}
        rule-providers:
          ads: {type: http, behavior: domain, url: "https://p.example/ads.yaml", interval: 86400}
          cn: {type: http, behavior: ipcidr, format: text, url: "https://p.example/cn.txt"}
          apps:
            type: inline
            behavior: classical
            payload:
              - PROCESS-NAME,Telegram
              - DOMAIN-SUFFIX,t.me
              - IP-ASN,62041
          missing: {type: http, behavior: domain, url: "https://p.example/none.yaml"}
          binary: {type: http, behavior: domain, format: mrs, url: "https://p.example/x.mrs"}
        rules:
          - RULE-SET,ads,REJECT
          - RULE-SET,cn,DIRECT,no-resolve
          - RULE-SET,apps,P1
          - RULE-SET,missing,REJECT
          - RULE-SET,binary,REJECT
          - MATCH,P1
        """
        let result = try ProviderStore.$rootOverride.withValue(root) {
            try ConfigAdapter.parseWithWarnings(rawString: yaml)
        }
        let router = result.router
        #expect(router.match(host: "x.ads.example", port: 443) == .reject)
        #expect(router.match(host: "1.0.1.9", port: 443) == .direct)
        #expect(router.match(host: "web.t.me", port: 443) == .proxy(targetGroup: "P1"))
        let telegram = RouteContext(network: .tcp, processName: "Telegram")
        #expect(router.match(endpoint: Endpoint(domain: "149.example", port: 443), context: telegram) == .proxy(targetGroup: "P1"))
        // Not downloaded: kept (matches nothing yet) and reported; mrs is refused.
        #expect(router.rules.count == 5)
        let texts = result.warnings.map(\.text)
        #expect(texts.contains("RULE-SET missing"))
        #expect(texts.contains("RULE-SET apps"))
        #expect(texts.contains("RULE-SET,binary,REJECT"))
    }

    @Test func proxyProvidersFeedGroups() throws {
        let root = try temporaryRoot()
        try cache("""
        proxies:
          - {name: HK 01, type: ss, server: 2.2.2.2, port: 8388, cipher: aes-256-gcm, password: x}
          - {name: JP 01, type: ss, server: 3.3.3.3, port: 8388, cipher: aes-256-gcm, password: x}
          - {name: P1, type: ss, server: 4.4.4.4, port: 8388, cipher: aes-256-gcm, password: x}
          - {name: Chain, type: ss, server: 5.5.5.5, port: 8388, cipher: aes-256-gcm, password: x, dialer-proxy: P1}
        """, kind: .proxy, url: "https://p.example/sub", root: root)
        let links = "trojan://pw@sg.example:443?sni=sg.example#SG 01"
        try cache(Data(links.utf8).base64EncodedString(), kind: .proxy, url: "https://p.example/links", root: root)
        let yaml = """
        proxies:
          - {name: P1, type: ss, server: 1.1.1.1, port: 8388, cipher: aes-256-gcm, password: x}
        proxy-providers:
          sub: {type: http, url: "https://p.example/sub", exclude-filter: "JP"}
          links: {type: http, url: "https://p.example/links"}
          local:
            type: inline
            payload:
              - {name: US 01, type: ss, server: 6.6.6.6, port: 8388, cipher: aes-256-gcm, password: x}
        proxy-groups:
          - {name: HK, type: url-test, use: [sub], filter: "HK"}
          - {name: All, type: select, include-all-providers: true}
          - {name: Chain, type: relay, proxies: [P1, HK]}
          - {name: Smart, type: smart, use: [local]}
          - {name: Odd, type: weird, proxies: [P1]}
        rules:
          - DOMAIN,c.example,PASS
          - MATCH,All
        """
        let result = try ProviderStore.$rootOverride.withValue(root) {
            try ConfigAdapter.parseWithWarnings(rawString: yaml)
        }
        let groups = result.nodeManager.groupsByName
        #expect(groups["HK"]?.nodeIDs == ["HK 01"])
        // JP filtered out by the provider, P1 renamed, the chained proxy left out.
        #expect(Set(groups["All"]?.nodeIDs ?? []) == ["HK 01", "P1 (sub)", "SG 01", "US 01"])
        #expect(groups["Chain"] == nil)
        #expect(groups["Smart"]?.mode == .urlTest)
        #expect(groups["Odd"]?.mode == .select)
        #expect(result.warnings.contains { $0.text == "Chain" && $0.reason.contains("dialer-proxy") })
        #expect(result.warnings.contains { $0.text == "Chain" && $0.reason.contains("relay") })
        #expect(result.warnings.contains { $0.text == "Odd" && $0.reason.contains("unknown group type") })
        // PASS leaves the rule out.
        #expect(result.router.rules.count == 1)
    }

    @Test func undownloadedProvidersAreReportedAndPrepareFetchesThem() async throws {
        let root = try temporaryRoot()
        let source = root.appendingPathComponent("source.yaml")
        try "payload:\n  - '+.fetched.example'\n".write(to: source, atomically: true, encoding: .utf8)
        let yaml = """
        rule-providers:
          r: {type: http, behavior: domain, url: "\(source.absoluteString)"}
        rules:
          - RULE-SET,r,REJECT
          - MATCH,DIRECT
        """
        try await ProviderStore.$rootOverride.withValue(root) {
            let before = try ConfigAdapter.parseWithWarnings(rawString: yaml)
            #expect(before.router.match(host: "a.fetched.example", port: 443) == .direct)
            #expect(await ProviderStore.prepare(configText: yaml))
            // Fresh files are not fetched again before their interval.
            #expect(!(await ProviderStore.prepare(configText: yaml)))
            let after = try ConfigAdapter.parseWithWarnings(rawString: yaml)
            #expect(after.router.match(host: "a.fetched.example", port: 443) == .reject)
            #expect(ProviderStore.nextRefresh(configText: yaml) != nil)
        }
    }
}
