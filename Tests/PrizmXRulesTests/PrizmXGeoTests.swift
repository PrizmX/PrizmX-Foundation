import Foundation
import Testing
@testable import PrizmXRules
import PrizmXProtocols

// MARK: - GeoIP / MMDB

private func sampleGeoIPData() -> Data {
    MMDBWriter.build(records: [
        (IPv4Address(parsing: "1.0.0.0")!, 8, "CN"),
        (IPv4Address(parsing: "1.1.1.1")!, 32, "AU"),
        (IPv4Address(parsing: "8.8.8.8")!, 32, "US"),
        (IPv4Address(parsing: "220.181.38.148")!, 32, "CN"),
    ])
}

@Test func geoIPLookupReturnsCountryCode() throws {
    let matcher = try GeoIPMatcher(data: sampleGeoIPData())
    #expect(matcher.lookup(ip: "220.181.38.148") == "CN")
    #expect(matcher.lookup(ip: "8.8.8.8") == "US")
    #expect(matcher.lookup(ip: "1.1.1.1") == "AU")
    #expect(matcher.lookup(ip: "1.2.3.4") == "CN")
    #expect(matcher.lookup(ip: "9.9.9.9") == nil)
    #expect(matcher.lookup(ip: "not-an-ip") == nil)
}

@Test func geoIPMemoryMapsMMDBFile() throws {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("prizmx-geoip-\(UUID().uuidString).mmdb")
    try sampleGeoIPData().write(to: url)
    defer { try? FileManager.default.removeItem(at: url) }

    let matcher = try GeoIPMatcher(contentsOf: url)
    #expect(matcher.lookup(ip: "220.181.38.148") == "CN")
    #expect(matcher.lookup(ip: "8.8.8.8") == "US")
}

@Test func geoIPLookupIsMicrosecondScale() throws {
    let matcher = try GeoIPMatcher(data: sampleGeoIPData())
    let address = IPv4Address(parsing: "220.181.38.148")!
    let iterations = 20_000
    let elapsed = ContinuousClock().measure {
        for _ in 0..<iterations {
            precondition(matcher.lookup(ipv4: address) == "CN")
        }
    }
    // Debug-build budget: a few microseconds per walk (release is typically < 1 µs).
    #expect(elapsed < .milliseconds(250))
}

@Test func geoIPRouterSplitsDomesticTraffic() throws {
    let matcher = try GeoIPMatcher(data: sampleGeoIPData())
    let router = Router(
        rules: [
            RouteRule(.geoIP(code: "CN"), policy: .direct),
            RouteRule(.matchAll, policy: .proxy(targetGroup: "PROXY")),
        ],
        default: .direct,
        geoIP: matcher
    )
    #expect(router.match(host: "220.181.38.148", port: 443) == .direct)
    #expect(router.match(host: "8.8.8.8", port: 443) == .proxy(targetGroup: "PROXY"))
    #expect(
        router.match(endpoint: Endpoint(host: .ipv4(IPv4Address(parsing: "1.1.1.1")!), port: 443))
            == .proxy(targetGroup: "PROXY")
    )
}

@Test func geoIPMatchesDomainWhenResolvedIPv4Provided() throws {
    let matcher = try GeoIPMatcher(data: sampleGeoIPData())
    let router = Router(
        rules: [
            RouteRule(.geoIP(code: "CN"), policy: .direct),
            RouteRule(.matchAll, policy: .proxy(targetGroup: "PROXY")),
        ],
        default: .direct,
        geoIP: matcher
    )
    let baidu = Endpoint(domain: "baidu.com", port: 443)
    #expect(router.match(endpoint: baidu) == .proxy(targetGroup: "PROXY"))
    #expect(
        router.match(endpoint: baidu, resolvedIPv4: IPv4Address(parsing: "220.181.38.148")!)
            == .direct
    )
    let skipped = Router(
        rules: [
            RouteRule(.geoIP(code: "CN"), policy: .direct, noResolve: true),
            RouteRule(.matchAll, policy: .proxy(targetGroup: "PROXY")),
        ],
        default: .direct,
        geoIP: matcher
    )
    #expect(
        skipped.match(endpoint: baidu, resolvedIPv4: IPv4Address(parsing: "220.181.38.148")!)
            == .proxy(targetGroup: "PROXY")
    )
}

// MARK: - Geosite trie

@Test func geositeExactSuffixAndKeyword() {
    let matcher = GeositeMatcher(entries: [
        (tag: "cn", value: "www.baidu.com", kind: .exact),
        (tag: "cn", value: "baidu.com", kind: .suffix),
        (tag: "cn", value: "qq", kind: .keyword),
        (tag: "google", value: "google.com", kind: .suffix),
    ])

    #expect(matcher.match(domain: "www.baidu.com", group: "cn"))
    #expect(matcher.match(domain: "tieba.baidu.com", group: "cn"))
    #expect(matcher.match(domain: "baidu.com", group: "cn"))
    #expect(matcher.match(domain: "im.qq.com", group: "cn"))
    #expect(!matcher.match(domain: "baidu.com.evil.net", group: "cn"))
    #expect(!matcher.match(domain: "www.google.com", group: "cn"))
    #expect(matcher.match(domain: "www.google.com", group: "google"))
    #expect(!matcher.match(domain: "www.google.com", group: "missing"))
}

@Test func geositeSuffixTrieAccuracyAndTiming() {
    var entries: [(tag: String, value: String, kind: GeositeEntryKind)] = [
        (tag: "cn", value: "baidu.com", kind: .suffix),
        (tag: "cn", value: "qq.com", kind: .suffix),
        (tag: "cn", value: "163.com", kind: .suffix),
    ]
    entries.reserveCapacity(5_003)
    for index in 0..<5_000 {
        entries.append((tag: "cn", value: "site\(index).example.cn", kind: .suffix))
    }
    let matcher = GeositeMatcher(entries: entries)

    #expect(matcher.match(domain: "tieba.baidu.com", group: "cn"))
    #expect(matcher.match(domain: "www.site42.example.cn", group: "cn"))
    #expect(matcher.match(domain: "site42.example.cn", group: "cn"))
    #expect(!matcher.match(domain: "example.cn", group: "cn"))
    #expect(!matcher.match(domain: "notbaidu.com", group: "cn"))
    #expect(!matcher.match(domain: "baidu.com.attacker.test", group: "cn"))

    let probes = [
        "www.baidu.com",
        "a.b.qq.com",
        "mail.163.com",
        "www.site999.example.cn",
        "google.com",
    ]
    let iterations = 10_000
    let elapsed = ContinuousClock().measure {
        for index in 0..<iterations {
            _ = matcher.match(domain: probes[index % probes.count], group: "cn")
        }
    }
    #expect(elapsed < .milliseconds(100))
}

@Test func geositeRouterSplitsDomesticDomains() {
    let geosite = GeositeMatcher(entries: [
        (tag: "cn", value: "baidu.com", kind: .suffix),
        (tag: "cn", value: "qq.com", kind: .suffix),
    ])
    let router = Router(
        rules: [
            RouteRule(.geosite(tag: "cn"), policy: .direct),
            RouteRule(.matchAll, policy: .proxy(targetGroup: "PROXY")),
        ],
        default: .direct,
        geosite: geosite
    )
    #expect(router.match(host: "www.baidu.com", port: 443) == .direct)
    #expect(router.match(host: "im.qq.com", port: 443) == .direct)
    #expect(router.match(host: "www.google.com", port: 443) == .proxy(targetGroup: "PROXY"))
}
