import Foundation
import Testing
@testable import PrizmXRules
import PrizmXProtocols

private let hit = Policy.proxy(targetGroup: "Hit")
private let miss = Policy.proxy(targetGroup: "Miss")

private func suffix(_ text: String) throws -> IPSuffix {
    guard case .ipSuffix(let suffix) = try RouteRule.compile(.ipSuffix(text)) else {
        throw RuleCompileError.invalidCIDR(text)
    }
    return suffix
}

private func address(_ text: String) throws -> Endpoint.Host {
    .ipv6(try #require(IPv6Address(parsing: text)))
}

// MARK: - IP-SUFFIX

@Test func ipSuffixComparesTheTrailingBits() throws {
    // As in mihomo: `8.8.8.8/24` is every address ending in .8.8.8.
    let dns = try suffix("8.8.8.8/24")
    #expect(dns.matches(.ipv4(IPv4Address(1, 8, 8, 8))))
    #expect(!dns.matches(.ipv4(IPv4Address(8, 8, 9, 8))))
    #expect(!dns.matches(.ipv6(IPv6Address(high: 0, low: 0x0808_0808))))
    // Bits that do not fill a byte: the low 3 bits of the last one (101).
    let odd = try suffix("0.0.0.5/3")
    #expect(odd.matches(.ipv4(IPv4Address(10, 0, 0, 13))))
    #expect(!odd.matches(.ipv4(IPv4Address(10, 0, 0, 6))))
    #expect(try suffix("1.2.3.4/0").matches(.ipv4(IPv4Address(9, 9, 9, 9))))
    // Past 64 bits the comparison reaches into the high word.
    let v6 = try suffix("2001:db8:0:ffff::1/80")
    #expect(v6.matches(try address("2400:cb00:1:ffff::1")))
    #expect(!v6.matches(try address("2400:cb00:1:fffe::1")))
    #expect(!v6.matches(try address("2400:cb00:1:ffff::2")))
    #expect(throws: RuleCompileError.invalidCIDR("8.8.8.8/33")) {
        try RouteRule.compile(.ipSuffix("8.8.8.8/33"))
    }
}

@Test func ipSuffixRulesMatchLikeOtherIPRules() async throws {
    let router = Router(rules: [
        try RouteRule(type: .ipSuffix("0.0.0.53/8"), policy: hit),
        RouteRule(.matchAll, policy: miss),
    ])
    #expect(router.rules[0].inspectorLabel == "IP-SUFFIX,0.0.0.53/8,Hit")
    #expect(router.match(host: "10.0.0.53", port: 53) == hit)
    #expect(router.match(host: "10.0.0.54", port: 53) == miss)
    // A name is looked up for it, as for IP-CIDR without `no-resolve`.
    #expect(router.needsIPResolution)
    let result = await router.matchResult(endpoint: Endpoint(domain: "dns.example", port: 53)) {
        ResolvedAddresses(ipv4: IPv4Address(192, 0, 2, 53))
    }
    #expect(result.policy == hit)
}

// MARK: - IP-ASN

private func asnDatabase() throws -> ASNMatcher {
    try ASNMatcher(data: MMDBWriter.buildASN(records: [
        (IPv4Address(1, 1, 1, 0), 24, 13335),
        (IPv4Address(8, 8, 8, 0), 24, 15169),
    ]))
}

@Test func ipASNMatchesTheAutonomousSystem() async throws {
    let asn = try asnDatabase()
    #expect(asn.lookup(ipv4: IPv4Address(1, 1, 1, 1)) == 13335)
    #expect(asn.lookup(ipv4: IPv4Address(9, 9, 9, 9)) == nil)

    let rules = [
        try RouteRule(type: .ipASN("13335"), policy: hit),
        RouteRule(.matchAll, policy: miss),
    ]
    #expect(rules[0].inspectorLabel == "IP-ASN,13335,Hit")
    let router = Router(rules: rules, asn: asn)
    #expect(router.match(host: "1.1.1.1", port: 443) == hit)
    #expect(router.match(host: "8.8.8.8", port: 443) == miss)
    let lazy = await router.matchResult(endpoint: Endpoint(domain: "one.example", port: 443)) {
        ResolvedAddresses(ipv4: IPv4Address(1, 1, 1, 1))
    }
    #expect(lazy.policy == hit)
    // Without the database the rule never matches.
    #expect(Router(rules: rules).match(host: "1.1.1.1", port: 443) == miss)
    #expect(throws: RuleCompileError.invalidPayload("AS13335")) {
        try RouteRule.compile(.ipASN("AS13335"))
    }
}

@Test func asnMatcherRefusesACountryDatabase() {
    #expect(throws: GeoIPError.invalidMetadata) {
        try ASNMatcher(data: MMDBWriter.build(records: [(IPv4Address(1, 0, 0, 0), 8, "CN")]))
    }
}

// MARK: - Client address

@Test func sourceRulesMatchTheClientAddress() throws {
    let geoIP = try GeoIPMatcher(data: MMDBWriter.build(records: [(IPv4Address(1, 0, 0, 0), 8, "CN")]))
    let router = Router(
        rules: [
            RouteRule(.srcGeoIP(code: "cn"), policy: .proxy(targetGroup: "GeoIP")),
            RouteRule(.srcIPASN(15169), policy: .proxy(targetGroup: "ASN")),
            try RouteRule(type: .srcIPSuffix("0.0.0.7/8"), policy: .proxy(targetGroup: "Suffix")),
            RouteRule(.matchAll, policy: miss),
        ],
        geoIP: geoIP,
        asn: try asnDatabase()
    )
    // The destination is in CN and AS13335 itself; only the client counts.
    let destination = Endpoint(host: .ipv4(IPv4Address(1, 1, 1, 1)), port: 443)
    func from(_ source: IPv4Address) -> Policy {
        router.match(endpoint: destination, context: RouteContext(network: .tcp, sourceHost: .ipv4(source)))
    }
    #expect(from(IPv4Address(1, 2, 3, 4)) == .proxy(targetGroup: "GeoIP"))
    #expect(from(IPv4Address(8, 8, 8, 8)) == .proxy(targetGroup: "ASN"))
    #expect(from(IPv4Address(192, 168, 1, 7)) == .proxy(targetGroup: "Suffix"))
    #expect(from(IPv4Address(192, 168, 1, 8)) == miss)
    #expect(router.match(endpoint: destination) == miss)
    // Client addresses are never looked up, and FakeDNS leaves them to the dial.
    #expect(!router.needsIPResolution)
    #expect(router.matchWithoutResolving(endpoint: Endpoint(domain: "a.example", port: 443)) == nil)
}
