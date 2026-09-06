import Foundation
import Testing
@testable import PrizmXRules
import PrizmXProtocols

@Test func exactDomainMatch() {
    let router = Router(
        rules: [RouteRule(.domain("ads.example.com"), policy: .reject)],
        default: .direct
    )
    #expect(router.match(host: "ads.example.com", port: 80) == .reject)
    #expect(router.match(host: "ADS.EXAMPLE.COM", port: 80) == .reject)
    #expect(router.match(host: "other.example.com", port: 80) == .direct)
    #expect(router.match(host: "xads.example.com", port: 80) == .direct)
}

@Test func domainSuffixMatch() {
    let router = Router(
        rules: [
            RouteRule(.domainSuffix("example.com"), policy: .proxy(targetGroup: "PROXY")),
            RouteRule(.domainSuffix(".fast.example.com"), policy: .direct),
        ],
        default: .reject
    )
    // The suffix matches the domain itself and any subdomain.
    #expect(router.match(host: "example.com", port: 443) == .proxy(targetGroup: "PROXY"))
    #expect(router.match(host: "cdn.example.com", port: 443) == .proxy(targetGroup: "PROXY"))
    #expect(router.match(host: "a.b.example.com", port: 443) == .proxy(targetGroup: "PROXY"))
    // Similar-but-different domains must not be matched.
    #expect(router.match(host: "notexample.com", port: 443) == .reject)
    #expect(router.match(host: "example.com.evil.net", port: 443) == .reject)
    // Longest suffix only wins when it is listed first (Clash order).
    #expect(router.match(host: "cdn.fast.example.com", port: 443) == .proxy(targetGroup: "PROXY"))
}

@Test func firstMatchingSuffixWinsByListOrder() {
    let specificFirst = Router(
        rules: [
            RouteRule(.domainSuffix("direct.example.com"), policy: .direct),
            RouteRule(.domainSuffix("example.com"), policy: .proxy(targetGroup: "PROXY")),
        ],
        default: .reject
    )
    #expect(specificFirst.match(host: "a.direct.example.com", port: 0) == .direct)
    #expect(specificFirst.match(host: "a.other.example.com", port: 0) == .proxy(targetGroup: "PROXY"))

    let broadFirst = Router(
        rules: [
            RouteRule(.domainSuffix("example.com"), policy: .proxy(targetGroup: "PROXY")),
            RouteRule(.domainSuffix("direct.example.com"), policy: .direct),
        ],
        default: .reject
    )
    #expect(broadFirst.match(host: "a.direct.example.com", port: 0) == .proxy(targetGroup: "PROXY"))
}

@Test func portScopedRulesFallThrough() {
    let router = Router(
        rules: [
            RouteRule(.domain("example.com"), port: 80, policy: .direct),
            RouteRule(.domainSuffix("example.com"), policy: .proxy(targetGroup: "PROXY")),
        ],
        default: .direct
    )
    #expect(router.match(host: "example.com", port: 80) == .direct)
    // An exact rule not matching the port falls back to the suffix rule.
    #expect(router.match(host: "example.com", port: 443) == .proxy(targetGroup: "PROXY"))
    #expect(router.match(host: "example.com", port: 8080) == .proxy(targetGroup: "PROXY"))
}

@Test func ipv4AndCIDRMatch() {
    let router = Router(
        rules: [
            RouteRule(.ipv4(IPv4Address(parsing: "10.1.2.3")!), policy: .reject),
            RouteRule(
                .ipv4CIDR(IPv4Address(parsing: "192.168.0.0")!, prefixLength: 16),
                policy: .direct
            ),
        ],
        default: .proxy(targetGroup: "PROXY")
    )
    #expect(router.match(host: "10.1.2.3", port: 1) == .reject)
    #expect(router.match(host: "192.168.5.5", port: 1) == .direct)
    #expect(router.match(host: "192.169.0.1", port: 1) == .proxy(targetGroup: "PROXY"))
    #expect(router.match(host: "10.1.2.4", port: 1) == .proxy(targetGroup: "PROXY"))
}

@Test func ipv6ExactMatch() {
    let loopback = IPv6Address(parsing: "::1")!
    let router = Router(
        rules: [RouteRule(.ipv6(loopback), policy: .direct)],
        default: .proxy(targetGroup: "PROXY")
    )
    #expect(router.match(host: "::1", port: 1) == .direct)
    #expect(router.match(host: "::2", port: 1) == .proxy(targetGroup: "PROXY"))
}

@Test func emptyRulesReturnDefault() {
    let router = Router(default: .reject)
    #expect(router.match(host: "anything.example.com", port: 443) == .reject)
}

@Test func matchViaEndpoint() {
    let router = Router(
        rules: [RouteRule(.domainSuffix("example.com"), policy: .reject)],
        default: .proxy(targetGroup: "PROXY")
    )
    #expect(
        router.match(endpoint: .init(domain: "api.example.com", port: 443)) == .reject
    )
    #expect(
        router.match(
            endpoint: .init(host: .ipv4(IPv4Address(1, 1, 1, 1)), port: 53)
        ) == .proxy(targetGroup: "PROXY")
    )
}

@Test func matchViaURL() throws {
    let router = Router(
        rules: [RouteRule(.domainSuffix("example.com"), policy: .reject)],
        default: .proxy(targetGroup: "PROXY")
    )
    let url = try #require(URL(string: "https://api.example.com/v1"))
    #expect(router.match(url: url, defaultPort: 443) == .reject)

    let noHost = try #require(URL(string: "file:///tmp/prizmx"))
    #expect(router.match(url: noHost, defaultPort: 443) == nil)
}

@Test func routerIsConcurrencySafe() async {
    // Sendable check + concurrent reads: compile-time guarantee + runtime smoke.
    let router = Router(
        rules: [RouteRule(.domainSuffix("example.com"), policy: .proxy(targetGroup: "PROXY"))],
        default: .direct
    )
    await withTaskGroup(of: Policy.self) { group in
        for index in 0..<1000 {
            group.addTask {
                router.match(host: "host\(index).example.com", port: 443)
            }
        }
        for await decision in group {
            #expect(decision == .proxy(targetGroup: "PROXY"))
        }
    }
}

@Test func domainKeywordMatch() {
    let router = Router(
        rules: [
            RouteRule(type: .domainKeyword("ads"), policy: .reject),
            RouteRule(.domainSuffix("example.com"), policy: .proxy(targetGroup: "PROXY")),
        ],
        default: .direct
    )
    // List order: keyword is first, but this host has no "ads" substring.
    #expect(router.match(endpoint: Endpoint(domain: "cdn.example.com", port: 443)) == .proxy(targetGroup: "PROXY"))
    #expect(router.match(host: "tracker.adservice.net", port: 443) == .reject)
    #expect(router.match(host: "example.org", port: 443) == .direct)
}

@Test func matchAllAndRuleTypeCIDR() {
    let router = Router(
        rules: [
            RouteRule(type: .ipCIDR("10.0.0.0/8"), policy: .direct),
            RouteRule(type: .matchAll, policy: .proxy(targetGroup: "FINAL")),
        ],
        default: .reject
    )
    #expect(router.match(host: "10.1.2.3", port: 1) == .direct)
    #expect(router.match(host: "unlisted.example", port: 443) == .proxy(targetGroup: "FINAL"))
}

@Test func matchAllFirstRuleCapturesEverything() {
    let router = Router(
        rules: [
            RouteRule(type: .matchAll, policy: .proxy(targetGroup: "PROXY")),
            RouteRule(type: .domain("google.com"), policy: .direct),
        ],
        default: .reject
    )
    #expect(router.match(host: "google.com", port: 443) == .proxy(targetGroup: "PROXY"))
    #expect(router.match(host: "anything.example", port: 80) == .proxy(targetGroup: "PROXY"))
}
