import Foundation
import Testing
@testable import PrizmXRules
import PrizmXProtocols

// MARK: - Sniffed connections

private final class LookupCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    var count: Int { lock.withLock { value } }
    func bump() { lock.withLock { value += 1 } }
}

/// A connection whose name was sniffed after the client dialed `address`.
private func sniffed(_ address: Endpoint.Host) -> RouteContext {
    RouteContext(network: .tcp, destinationAddress: address)
}

private let telegram = Policy.proxy(targetGroup: "Telegram")
private let proxy = Policy.proxy(targetGroup: "Proxy")

@Test func sniffedNameMatchesIPRulesByTheDialedAddress() throws {
    // As rule lists write Telegram's ranges.
    let router = Router(rules: [
        RouteRule(.ipv4CIDR(IPv4Address(149, 154, 160, 0), prefixLength: 20), policy: telegram, noResolve: true),
        RouteRule(.ipv6CIDR(try #require(IPv6Address(parsing: "2001:b28:f23d::")), prefixLength: 48), policy: telegram, noResolve: true),
        RouteRule(.matchAll, policy: proxy),
    ])
    let name = Endpoint(domain: "api.telegram.org", port: 443)
    #expect(router.match(endpoint: name, context: sniffed(.ipv4(IPv4Address(149, 154, 167, 50)))) == telegram)
    let ipv6 = try #require(IPv6Address(parsing: "2001:b28:f23d:f001::a"))
    #expect(router.match(endpoint: name, context: sniffed(.ipv6(ipv6))) == telegram)
    // Without it, `no-resolve` leaves the name to MATCH.
    #expect(router.match(endpoint: name, context: RouteContext(network: .tcp)) == proxy)
}

@Test func dialedAddressWinsOverALookup() {
    let router = Router(rules: [
        RouteRule(.ipv4CIDR(IPv4Address(10, 0, 0, 0), prefixLength: 8), policy: .direct),
        RouteRule(.matchAll, policy: proxy),
    ])
    let name = Endpoint(domain: "intranet.example", port: 443)
    let lookedUp = IPv4Address(10, 1, 2, 3)
    #expect(router.match(endpoint: name, resolvedIPv4: lookedUp) == .direct)
    let context = sniffed(.ipv4(IPv4Address(192, 0, 2, 1)))
    #expect(router.match(endpoint: name, resolvedIPv4: lookedUp, context: context) == proxy)
}

@Test func sniffedNameIsNeverLookedUp() async {
    let router = Router(rules: [
        RouteRule(.ipv4CIDR(IPv4Address(10, 0, 0, 0), prefixLength: 8), policy: .direct),
        RouteRule(.geoIP(code: "CN"), policy: .direct),
        RouteRule(.matchAll, policy: proxy),
    ])
    let name = Endpoint(domain: "intranet.example", port: 443)
    let cases: [(Endpoint.Host, Policy)] = [
        (.ipv4(IPv4Address(10, 1, 2, 3)), .direct),
        (.ipv4(IPv4Address(192, 0, 2, 1)), proxy),
        // An IPv6 dial does not fall back to the name's IPv4.
        (.ipv6(IPv6Address(high: 0x2001_0db8_0000_0000, low: 1)), proxy),
    ]
    let lookups = LookupCounter()
    for (dialed, expected) in cases {
        let result = await router.matchResult(endpoint: name, context: sniffed(dialed)) {
            lookups.bump()
            return ResolvedAddresses(ipv4: IPv4Address(10, 9, 9, 9))
        }
        #expect(result.policy == expected, "\(dialed)")
        #expect(result.resolved == nil)
    }
    #expect(lookups.count == 0)
}

@Test func geoIPAndRuleSetsSeeTheDialedAddress() throws {
    let geoIP = try GeoIPMatcher(data: MMDBWriter.build(records: [(IPv4Address(1, 0, 0, 0), 8, "CN")]))
    let cidrs = RuleSet(name: "telegram", cidrs: ["91.108.4.0/22"])
    let router = Router(
        rules: [
            RouteRule(.ruleSet(cidrs), policy: telegram, noResolve: true),
            RouteRule(.geoIP(code: "CN"), policy: .direct, noResolve: true),
            RouteRule(.matchAll, policy: proxy),
        ],
        geoIP: geoIP
    )
    let name = Endpoint(domain: "sniffed.example", port: 443)
    #expect(router.match(endpoint: name, context: sniffed(.ipv4(IPv4Address(91, 108, 4, 10)))) == telegram)
    #expect(router.match(endpoint: name, context: sniffed(.ipv4(IPv4Address(1, 2, 3, 4)))) == .direct)
    #expect(router.match(endpoint: name) == proxy)
}

// MARK: - Indexed IP runs

/// `count` IP-CIDR rules, enough to be indexed, in 172.16.0.0/12.
private func fillers(_ count: Int, noResolve: Bool = false) -> [RouteRule] {
    (0..<count).map { index in
        RouteRule(
            .ipv4CIDR(IPv4Address(172, 16, UInt8(index), 0), prefixLength: 24),
            policy: .reject,
            noResolve: noResolve
        )
    }
}

@Test func indexedAddressRunKeepsRuleOrder() throws {
    var rules = fillers(40)
    rules.append(RouteRule(.ipv4CIDR(IPv4Address(10, 0, 0, 0), prefixLength: 8), policy: .proxy(targetGroup: "Wide"), noResolve: true))
    rules.append(RouteRule(.ipv4CIDR(IPv4Address(10, 1, 0, 0), prefixLength: 16), policy: .proxy(targetGroup: "Narrow")))
    rules.append(RouteRule(.ipv6CIDR(try #require(IPv6Address(parsing: "2001:db8::")), prefixLength: 32), policy: .proxy(targetGroup: "V6")))
    rules.append(RouteRule(.matchAll, policy: .proxy(targetGroup: "Final")))
    let router = Router(rules: rules)
    let address = IPv4Address(10, 1, 2, 3)
    let name = Endpoint(domain: "a.example", port: 443)
    // The earliest match wins, `no-resolve` or not, for an IP destination,
    // the address a sniffed client dialed and a hosts address.
    #expect(router.match(endpoint: Endpoint(host: .ipv4(address), port: 443)) == .proxy(targetGroup: "Wide"))
    #expect(router.match(endpoint: name, context: sniffed(.ipv4(address))) == .proxy(targetGroup: "Wide"))
    #expect(router.match(endpoint: name, resolvedIPv4: address) == .proxy(targetGroup: "Wide"))
    #expect(router.match(host: "172.16.39.9", port: 443) == .reject)
    #expect(router.match(host: "2001:db8::1", port: 443) == .proxy(targetGroup: "V6"))
    #expect(router.match(host: "192.0.2.1", port: 443) == .proxy(targetGroup: "Final"))
}

/// The run's first rule without `no-resolve` looks the name up: the
/// `no-resolve` rules before it go without the answer, the ones after
/// match it, as in mihomo.
@Test func indexedRunLooksTheNameUpAtItsFirstResolvingRule() async {
    var rules = [RouteRule(.ipv4CIDR(IPv4Address(10, 0, 0, 0), prefixLength: 8), policy: .proxy(targetGroup: "Before"), noResolve: true)]
    rules += fillers(40, noResolve: true)
    rules.append(RouteRule(.ipv4CIDR(IPv4Address(192, 0, 2, 0), prefixLength: 24), policy: .reject))
    rules.append(RouteRule(.ipv4CIDR(IPv4Address(10, 1, 0, 0), prefixLength: 16), policy: .proxy(targetGroup: "After"), noResolve: true))
    rules.append(RouteRule(.matchAll, policy: proxy))
    let router = Router(rules: rules)
    let name = Endpoint(domain: "a.example", port: 443)
    let lookups = LookupCounter()
    let result = await router.matchResult(endpoint: name) {
        lookups.bump()
        return ResolvedAddresses(ipv4: IPv4Address(10, 1, 2, 3))
    }
    #expect(result.policy == .proxy(targetGroup: "After"))
    #expect(lookups.count == 1)
    // Known from the start (a hosts entry), the address meets "Before" first.
    #expect(router.match(endpoint: name, resolvedIPv4: IPv4Address(10, 1, 2, 3)) == .proxy(targetGroup: "Before"))
}

@Test func noResolveRulesMatchAnAddressLookedUpEarlier() async {
    let router = Router(rules: [
        RouteRule(.ipv4CIDR(IPv4Address(10, 0, 0, 0), prefixLength: 8), policy: .proxy(targetGroup: "Before"), noResolve: true),
        RouteRule(.ipv4CIDR(IPv4Address(192, 0, 2, 0), prefixLength: 24), policy: .reject),
        RouteRule(.ipv4CIDR(IPv4Address(10, 1, 0, 0), prefixLength: 16), policy: .proxy(targetGroup: "After"), noResolve: true),
        RouteRule(.matchAll, policy: proxy),
    ])
    let name = Endpoint(domain: "a.example", port: 443)
    let result = await router.matchResult(endpoint: name) { ResolvedAddresses(ipv4: IPv4Address(10, 1, 2, 3)) }
    #expect(result.policy == .proxy(targetGroup: "After"))
    #expect(router.match(endpoint: name, resolvedIPv4: IPv4Address(10, 1, 2, 3)) == .proxy(targetGroup: "Before"))
}

@Test func dnsTimeMatchPassesARunOfNoResolveRules() {
    let tail = RouteRule(.domainSuffix("example.com"), policy: .direct)
    let www = Endpoint(domain: "www.example.com", port: 443)
    let noResolve = Router(rules: fillers(40, noResolve: true) + [tail], default: proxy)
    #expect(noResolve.matchWithoutResolving(endpoint: www)?.policy == .direct)
    // A rule that matches looked-up names leaves the answer to the dial.
    let resolving = Router(rules: fillers(40) + [tail], default: proxy)
    #expect(resolving.matchWithoutResolving(endpoint: www) == nil)
}

/// Indexed runs decide exactly like a rule-by-rule walk: with a
/// never-matching port-scoped rule between each pair, nothing is indexed.
@Test func indexedAddressRunsMatchARuleByRuleWalk() async {
    var random = SplitMix64(seed: 0x5EED_1DEA)
    let rules = randomRules(count: 600, using: &random)
    let indexed = Router(rules: rules, default: .proxy(targetGroup: "default"))
    let separator = RouteRule(.matchAll, port: 1, policy: .reject)
    let walked = Router(rules: rules.flatMap { [$0, separator] }, default: .proxy(targetGroup: "default"))
    for _ in 0..<3_000 {
        let probe = randomProbe(using: &random)
        let resolved = probe.resolved
        #expect(
            indexed.match(endpoint: probe.endpoint, resolvedIPv4: resolved.ipv4, resolvedIPv6: resolved.ipv6, context: probe.context)
                == walked.match(endpoint: probe.endpoint, resolvedIPv4: resolved.ipv4, resolvedIPv6: resolved.ipv6, context: probe.context),
            "\(probe)"
        )
        let lazy = await indexed.matchResult(endpoint: probe.endpoint, context: probe.context) { resolved }
        let lazyWalked = await walked.matchResult(endpoint: probe.endpoint, context: probe.context) { resolved }
        #expect(lazy.policy == lazyWalked.policy, "\(probe)")
        #expect(lazy.resolved == lazyWalked.resolved, "\(probe)")
        #expect(
            indexed.matchWithoutResolving(endpoint: probe.endpoint, resolvedIPv4: resolved.ipv4, resolvedIPv6: resolved.ipv6)?.policy
                == walked.matchWithoutResolving(endpoint: probe.endpoint, resolvedIPv4: resolved.ipv4, resolvedIPv6: resolved.ipv6)?.policy,
            "\(probe)"
        )
    }
}

private struct SplitMix64: RandomNumberGenerator {
    var state: UInt64

    init(seed: UInt64) { state = seed }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var mixed = state
        mixed = (mixed ^ (mixed >> 30)) &* 0xBF58_476D_1CE4_E5B9
        mixed = (mixed ^ (mixed >> 27)) &* 0x94D0_49BB_1331_11EB
        return mixed ^ (mixed >> 31)
    }
}

/// Addresses from a small space, so rules overlap and probes hit them.
private func randomIPv4(using random: inout SplitMix64) -> IPv4Address {
    IPv4Address(10, UInt8.random(in: 0...3, using: &random), UInt8.random(in: 0...3, using: &random), UInt8.random(in: 0...255, using: &random))
}

private func randomIPv6(using random: inout SplitMix64) -> IPv6Address {
    IPv6Address(
        high: 0x2001_0db8_0000_0000 | UInt64.random(in: 0...3, using: &random) << 16 | UInt64.random(in: 0...3, using: &random),
        low: UInt64.random(in: 0...3, using: &random) << 32 | UInt64.random(in: 0...255, using: &random)
    )
}

private func randomAddressMatcher(using random: inout SplitMix64) -> RouteRule.HostMatcher {
    if Bool.random(using: &random) {
        let prefix = [UInt8(8), 14, 16, 22, 24, 30, 32].randomElement(using: &random)!
        let network = randomIPv4(using: &random)
        return prefix == 32 && Bool.random(using: &random) ? .ipv4(network) : .ipv4CIDR(network, prefixLength: prefix)
    }
    let prefix = [UInt8(32), 46, 48, 64, 80, 96, 120, 128].randomElement(using: &random)!
    let network = randomIPv6(using: &random)
    return prefix == 128 && Bool.random(using: &random) ? .ipv6(network) : .ipv6CIDR(network, prefixLength: prefix)
}

/// Stretches of IP rules (some long enough to be indexed), each ended by a
/// rule that is not indexed with them. Every rule has its own policy.
private func randomRules(count: Int, using random: inout SplitMix64) -> [RouteRule] {
    var rules: [RouteRule] = []
    while rules.count < count {
        for _ in 0..<Int.random(in: 1...90, using: &random) {
            let policy = Policy.proxy(targetGroup: "r\(rules.count)")
            let noResolve = Int.random(in: 0..<3, using: &random) == 0
            rules.append(RouteRule(randomAddressMatcher(using: &random), policy: policy, noResolve: noResolve))
        }
        let policy = Policy.proxy(targetGroup: "r\(rules.count)")
        switch Int.random(in: 0..<3, using: &random) {
        case 0:
            rules.append(RouteRule(.domainSuffix("s\(rules.count).example"), policy: policy))
        case 1:
            // Port-scoped: still matches, never indexed.
            rules.append(RouteRule(randomAddressMatcher(using: &random), port: 443, policy: policy))
        default:
            rules.append(RouteRule(.domainKeyword("k\(rules.count)"), policy: policy))
        }
    }
    return rules
}

private struct Probe: CustomStringConvertible {
    var endpoint: Endpoint
    var context: RouteContext
    var resolved: ResolvedAddresses

    var description: String {
        "\(endpoint) dialed=\(context.destinationAddress.map(\.description) ?? "-") resolved=\(resolved)"
    }
}

private func randomProbe(using random: inout SplitMix64) -> Probe {
    func address() -> Endpoint.Host {
        Bool.random(using: &random) ? .ipv4(randomIPv4(using: &random)) : .ipv6(randomIPv6(using: &random))
    }
    let resolved = ResolvedAddresses(
        ipv4: Bool.random(using: &random) ? randomIPv4(using: &random) : nil,
        ipv6: Bool.random(using: &random) ? randomIPv6(using: &random) : nil
    )
    switch Int.random(in: 0..<10, using: &random) {
    case 0..<3:
        return Probe(endpoint: Endpoint(host: address(), port: 443), context: RouteContext(network: .tcp), resolved: resolved)
    case 3..<6:
        let context = RouteContext(network: .tcp, destinationAddress: address())
        return Probe(endpoint: Endpoint(domain: "n.example", port: 443), context: context, resolved: resolved)
    default:
        return Probe(endpoint: Endpoint(domain: "n.example", port: 443), context: RouteContext(network: .tcp), resolved: resolved)
    }
}
