import Foundation
import Testing
@testable import PrizmXConfig
import PrizmXProtocols
@testable import PrizmXRules

@Test func srcOptionMatchesTheClientAddress() throws {
    let yaml = """
    proxies: []
    rules:
      - IP-CIDR,192.168.1.0/24,DIRECT,src
      - IP-CIDR6,fd00::/8,DIRECT,src
      - GEOIP,CN,DIRECT,src
      - IP-ASN,13335,DIRECT,src
      - IP-SUFFIX,0.0.0.5/8,DIRECT,src
      - DOMAIN,example.com,DIRECT,src
      - AND,((IP-CIDR,10.0.0.0/8,src),(DST-PORT,22)),REJECT
    """
    let result = try ConfigAdapter.parseWithWarnings(rawString: yaml)
    #expect(result.warnings.filter { $0.kind == .rule }.isEmpty)
    #expect(result.router.rules.map(\.inspectorLabel) == [
        "SRC-IP-CIDR,192.168.1.0/24,DIRECT",
        "SRC-IP-CIDR,fd00::/8,DIRECT",
        "SRC-GEOIP,CN,DIRECT",
        "SRC-IP-ASN,13335,DIRECT",
        "SRC-IP-SUFFIX,0.0.0.5/8,DIRECT",
        // Other rules ignore `src`, as in mihomo.
        "DOMAIN,example.com,DIRECT",
        "AND,((SRC-IP-CIDR,10.0.0.0/8),(DST-PORT,22)),REJECT",
    ])
    // Client addresses are never looked up.
    #expect(!result.router.needsIPResolution)
}

@Test func srcOnARuleSetIsSkipped() throws {
    // mihomo matches the set with source and destination swapped, ports
    // too. PrizmX does not, so it reports the rule instead of matching the
    // destination.
    let yaml = """
    proxies: []
    rule-providers:
      lan: {type: inline, behavior: ipcidr, payload: [192.168.0.0/16]}
    rules:
      - RULE-SET,lan,DIRECT,src
      - AND,((RULE-SET,lan,src),(DST-PORT,22)),REJECT
      - RULE-SET,lan,REJECT
    """
    let result = try ConfigAdapter.parseWithWarnings(rawString: yaml)
    #expect(result.router.rules.map(\.inspectorLabel) == ["RULE-SET,lan,REJECT"])
    #expect(result.warnings.filter { $0.kind == .rule }.map(\.text) == [
        "RULE-SET,lan,DIRECT,src",
        "AND,((RULE-SET,lan,src),(DST-PORT,22)),REJECT",
    ])
}

@Test func addressRuleTypesImport() throws {
    let yaml = """
    proxies: []
    rules:
      - IP-SUFFIX,8.8.8.8/24,REJECT,no-resolve
      - SRC-IP-SUFFIX,::1/16,REJECT
      - IP-ASN,15169,REJECT
      - SRC-IP-ASN,13335,REJECT
      - SRC-GEOIP,cn,REJECT
      - IP-ASN,AS13335,REJECT
    """
    let result = try ConfigAdapter.parseWithWarnings(rawString: yaml)
    #expect(result.router.rules.map(\.inspectorLabel) == [
        "IP-SUFFIX,8.8.8.8/24,REJECT",
        "SRC-IP-SUFFIX,::1/16,REJECT",
        "IP-ASN,15169,REJECT",
        "SRC-IP-ASN,13335,REJECT",
        "SRC-GEOIP,CN,REJECT",
    ])
    #expect(result.router.rules[0].noResolve)
    // mihomo keeps a rule that can never match; PrizmX says so instead.
    #expect(result.warnings.filter { $0.kind == .rule }.map(\.text) == ["IP-ASN,AS13335,REJECT"])
}

@Test func lanWithSrcIsAClientOnThePrivateRanges() throws {
    let yaml = """
    proxies: []
    rules:
      - GEOIP,LAN,DIRECT,src
      - MATCH,REJECT
    """
    let (router, _) = try ConfigAdapter.parse(rawString: yaml)
    #expect(router.rules.dropLast().map(\.displayType) == Array(repeating: "SRC-IP-CIDR", count: ConfigMapping.privateCIDRs.count))
    let destination = Endpoint(host: .ipv4(IPv4Address(8, 8, 8, 8)), port: 443)
    let lan = RouteContext(network: .tcp, sourceHost: .ipv4(IPv4Address(192, 168, 1, 2)))
    #expect(router.match(endpoint: destination, context: lan) == .direct)
    // A private destination is not a private client.
    #expect(router.match(host: "192.168.1.2", port: 443) == .reject)

    let logical = """
    proxies: []
    rules:
      - AND,((SRC-GEOIP,LAN),(NETWORK,TCP)),DIRECT
      - MATCH,REJECT
    """
    let (nested, _) = try ConfigAdapter.parse(rawString: logical)
    #expect(nested.match(endpoint: destination, context: lan) == .direct)
    let wan = RouteContext(network: .tcp, sourceHost: .ipv4(IPv4Address(203, 0, 113, 9)))
    #expect(nested.match(endpoint: destination, context: wan) == .reject)
}

@Test func asnDatabaseIsCheckedBeforeItIsKept() async throws {
    let asn = MMDBWriter.buildASN(records: [(IPv4Address(1, 1, 1, 0), 24, 13335)])
    #expect(GeoAssetStore.isValid(asn, kind: .asn))
    // A country database is a valid MMDB, but not an ASN one.
    #expect(!GeoAssetStore.isValid(geoIPFixture(), kind: .asn))
    #expect(!GeoAssetStore.isValid(Data("<!DOCTYPE html><html>login</html>".utf8), kind: .asn))

    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("prizmx-geo-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let url = root.appendingPathComponent(GeoAssetStore.asnRelativePath)
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try asn.write(to: url)
    let prepared = await GeoAssetStore.prepare(root: root, geoIP: false, geosite: false, asn: true, sources: .none)
    #expect(prepared == GeoAssetStore.Prepared(asnPath: GeoAssetStore.asnRelativePath))
}

@Test func engineMatchesIPASNWithTheDatabaseTheAppPrepared() throws {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("prizmx-asn-\(UUID().uuidString).mmdb")
    defer { try? FileManager.default.removeItem(at: url) }
    try MMDBWriter.buildASN(records: [(IPv4Address(1, 1, 1, 0), 24, 13335)]).write(to: url)
    let provider: [String: Any] = [TunnelProviderKeys.asnPath: url.path]
    #expect(ExtensionBootstrap(providerConfiguration: provider, options: nil).asnURL?.path == url.path)

    let yaml = """
    proxies: []
    rules:
      - IP-ASN,13335,REJECT
      - MATCH,DIRECT
    """
    let engine = try EngineFactory.make(configText: yaml, asnURL: url, dnsPersistenceURL: nil)
    #expect(engine.router.match(host: "1.1.1.1", port: 443) == .reject)
    #expect(engine.router.match(host: "9.9.9.9", port: 443) == .direct)
}
