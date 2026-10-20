import Foundation
import Testing
import PrizmXProtocols
@testable import PrizmXRules

@Suite struct RuleContextTests {
    private let curl = RouteContext(
        network: .tcp,
        sourceHost: .ipv4(IPv4Address(192, 168, 1, 20)),
        sourcePort: 50_000,
        processName: "curl",
        processPath: "/usr/bin/curl"
    )

    @Test func logicalRulesCombineConditions() throws {
        let rule = RouteRule(
            .and([
                RuleCondition(try RouteRule.compile(.domainSuffix("example.com"))),
                RuleCondition(.not(RuleCondition(.network(.udp)))),
                RuleCondition(.or([
                    RuleCondition(try RouteRule.compile(.dstPort("443/8443"))),
                    RuleCondition(try RouteRule.compile(.processName("Curl"))),
                ])),
            ]),
            policy: .reject
        )
        let router = Router(rules: [rule, RouteRule(.matchAll, policy: .direct)])
        let target = Endpoint(domain: "www.example.com", port: 80)
        #expect(router.match(endpoint: target, context: curl) == .reject)
        var udp = curl
        udp.network = .udp
        #expect(router.match(endpoint: target, context: udp) == .direct)
        #expect(router.match(endpoint: target, context: RouteContext(network: .tcp)) == .direct)
        #expect(router.match(endpoint: Endpoint(domain: "www.example.com", port: 443), context: RouteContext(network: .tcp)) == .reject)
    }

    /// FakeDNS knows only the name: a rule that needs the connection leaves
    /// the answer to the dial instead of guessing.
    @Test func contextRulesAreUndecidedAtDNSTime() throws {
        let router = Router(rules: [
            RouteRule(try RouteRule.compile(.processName("curl")), policy: .reject),
            RouteRule(try RouteRule.compile(.domain("a.example")), policy: .direct),
        ])
        #expect(router.matchWithoutResolving(endpoint: Endpoint(domain: "a.example", port: 443)) == nil)

        let decided = Router(rules: [
            RouteRule(.and([
                RuleCondition(try RouteRule.compile(.domain("b.example"))),
                RuleCondition(.network(.udp)),
            ]), policy: .reject),
            RouteRule(.matchAll, policy: .direct),
        ])
        // The domain condition already fails, so the AND is false whatever the network.
        #expect(decided.matchWithoutResolving(endpoint: Endpoint(domain: "a.example", port: 443))?.policy == .direct)
    }

    @Test func sourceAndPortRules() throws {
        let router = Router(rules: [
            RouteRule(try RouteRule.compile(.srcIPCIDR("192.168.1.0/24")), policy: .reject),
            RouteRule(.matchAll, policy: .direct),
        ])
        #expect(router.match(endpoint: Endpoint(domain: "x.example", port: 80), context: curl) == .reject)
        #expect(router.match(endpoint: Endpoint(domain: "x.example", port: 80), context: .none) == .direct)
        #expect(PortSet(parsing: "80/443,8000-8100")?.contains(8050) == true)
        #expect(PortSet(parsing: "9-1") == nil)
    }

    @Test func domainRegexAndWildcard() throws {
        let router = Router(rules: [
            RouteRule(try RouteRule.compile(.domainRegex("^ad[0-9]+\\.")), policy: .reject),
            RouteRule(try RouteRule.compile(.domainWildcard("*.cdn.example")), policy: .direct),
            RouteRule(.matchAll, policy: .proxy(targetGroup: "P")),
        ])
        #expect(router.match(host: "ad12.tracker.example", port: 443) == .reject)
        #expect(router.match(host: "img.cdn.example", port: 443) == .direct)
        // DOMAIN-WILDCARD's `*` spans labels (rule-set entries do not).
        #expect(router.match(host: "a.b.cdn.example", port: 443) == .direct)
        #expect(router.match(host: "cdn.example", port: 443) == .proxy(targetGroup: "P"))
    }

    /// A hosts entry stands in for a lookup at FakeDNS time; a rule that
    /// needs the connection still leaves the answer undecided.
    @Test func dnsTimeMatchingWithKnownAddresses() throws {
        let router = Router(rules: [
            RouteRule(try RouteRule.compile(.ipCIDR("10.0.0.0/8")), policy: .direct),
            RouteRule(.matchAll, policy: .reject),
        ])
        let name = Endpoint(domain: "nas.home", port: 443)
        #expect(router.matchWithoutResolving(endpoint: name) == nil)
        #expect(router.matchWithoutResolving(endpoint: name, resolvedIPv4: IPv4Address(10, 0, 0, 5))?.policy == .direct)
        let contextual = Router(rules: [
            RouteRule(try RouteRule.compile(.dstPort("443")), policy: .reject),
            RouteRule(.matchAll, policy: .direct),
        ])
        #expect(contextual.matchWithoutResolving(endpoint: name, resolvedIPv4: IPv4Address(10, 0, 0, 5)) == nil)
    }

    /// Indexed runs keep first-match order across exact and suffix rules.
    @Test func indexedDomainRunsKeepRuleOrder() throws {
        var rules: [RouteRule] = []
        for index in 0..<20 {
            rules.append(try RouteRule(type: .domainSuffix("filler\(index).example"), policy: .direct))
        }
        rules.append(try RouteRule(type: .domainSuffix("example.com"), policy: .proxy(targetGroup: "Early")))
        rules.append(try RouteRule(type: .domain("www.example.com"), policy: .reject))
        rules.append(try RouteRule(type: .domain("only.example.org"), policy: .reject))
        rules.append(RouteRule(.matchAll, policy: .proxy(targetGroup: "Final")))
        let router = Router(rules: rules)
        #expect(router.match(host: "www.example.com", port: 443) == .proxy(targetGroup: "Early"))
        #expect(router.match(host: "only.example.org", port: 443) == .reject)
        #expect(router.match(host: "sub.only.example.org", port: 443) == .proxy(targetGroup: "Final"))
        #expect(router.match(host: "1.2.3.4", port: 443) == .proxy(targetGroup: "Final"))
    }

    @Test func ruleSetsMatchByBehavior() throws {
        let domains = RuleSet(name: "ads", domains: ["+.ads.example", ".track.example", "exact.example", "*.wild.example"])
        #expect(domains.contains(domain: "ads.example"))
        #expect(domains.contains(domain: "x.y.ads.example"))
        #expect(!domains.contains(domain: "track.example"))
        #expect(domains.contains(domain: "a.track.example"))
        #expect(domains.contains(domain: "exact.example"))
        #expect(!domains.contains(domain: "sub.exact.example"))
        #expect(domains.contains(domain: "one.wild.example"))
        #expect(!domains.contains(domain: "two.one.wild.example"))

        let cidrs = RuleSet(name: "cn", cidrs: ["1.0.1.0/24", "240e::/20", "bad"])
        #expect(cidrs.count == 2)
        let router = Router(rules: [
            RouteRule(.ruleSet(cidrs), policy: .direct),
            RouteRule(.ruleSet(domains), policy: .reject),
            RouteRule(.matchAll, policy: .proxy(targetGroup: "P")),
        ])
        #expect(router.match(host: "1.0.1.77", port: 443) == .direct)
        #expect(router.match(host: "240e:1::1", port: 443) == .direct)
        #expect(router.match(host: "x.ads.example", port: 443) == .reject)
        #expect(router.needsIPResolution)
    }
}
