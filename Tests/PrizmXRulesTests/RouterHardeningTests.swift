import Foundation
import Testing
@testable import PrizmXRules
import PrizmXProtocols

// MARK: - Lazy IP resolution

private final class ResolveCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    var count: Int { lock.withLock { value } }
    func bump() { lock.withLock { value += 1 } }
}

@Test func lazyMatchSkipsResolutionWhenDomainRuleMatchesFirst() async throws {
    let router = Router(
        rules: [
            RouteRule(.domainSuffix("google.com"), policy: .proxy(targetGroup: "P")),
            RouteRule(.ipv4CIDR(IPv4Address(10, 0, 0, 0), prefixLength: 8), policy: .direct),
            RouteRule(.geoIP(code: "cn"), policy: .direct),
            RouteRule(.matchAll, policy: .proxy(targetGroup: "P")),
        ],
        default: .direct
    )
    #expect(router.needsIPResolution)
    let counter = ResolveCounter()
    let hit = await router.matchResult(endpoint: Endpoint(domain: "www.google.com", port: 443)) {
        counter.bump()
        return ResolvedAddresses(ipv4: IPv4Address(10, 1, 2, 3))
    }
    #expect(hit.policy == .proxy(targetGroup: "P"))
    #expect(hit.resolved == nil)
    #expect(counter.count == 0)

    // Reaching the IP rules resolves exactly once, and the answer is returned.
    let miss = await router.matchResult(endpoint: Endpoint(domain: "intranet.example", port: 443)) {
        counter.bump()
        return ResolvedAddresses(ipv4: IPv4Address(10, 1, 2, 3))
    }
    #expect(miss.policy == .direct)
    #expect(miss.resolved?.ipv4 == IPv4Address(10, 1, 2, 3))
    #expect(counter.count == 1)
}

@Test func lazyMatchNeverResolvesForNoResolveRules() async {
    let router = Router(
        rules: [RouteRule(.ipv4CIDR(IPv4Address(10, 0, 0, 0), prefixLength: 8), policy: .reject, noResolve: true)],
        default: .direct
    )
    #expect(!router.needsIPResolution)
    let counter = ResolveCounter()
    let result = await router.matchResult(endpoint: Endpoint(domain: "a.example", port: 80)) {
        counter.bump()
        return ResolvedAddresses()
    }
    #expect(result.policy == .direct)
    #expect(counter.count == 0)
}

@Test func nonResolvingMatchStopsAtFirstRuleNeedingAnIP() {
    let router = Router(
        rules: [
            RouteRule(.domainSuffix("ads.example"), policy: .reject),
            RouteRule(.geoIP(code: "cn"), policy: .direct),
            RouteRule(.domainKeyword("tracker"), policy: .reject),
            RouteRule(.matchAll, policy: .proxy(targetGroup: "P")),
        ],
        default: .direct
    )
    // A domain rule before the GEOIP rule still decides.
    #expect(router.matchWithoutResolving(endpoint: Endpoint(domain: "x.ads.example", port: 443))?.policy == .reject)
    // Past GEOIP the answer depends on the lookup: undecided, not the later REJECT.
    #expect(router.matchWithoutResolving(endpoint: Endpoint(domain: "tracker.example", port: 443)) == nil)
    // IP destinations need no lookup.
    let ip = Endpoint(host: .ipv4(IPv4Address(1, 2, 3, 4)), port: 443)
    #expect(router.matchWithoutResolving(endpoint: ip)?.policy == .proxy(targetGroup: "P"))
}

@Test func directlyBuiltMatchersAreNormalized() {
    let router = Router(
        rules: [
            RouteRule(.domainSuffix("*.Example.COM."), policy: .reject),
            RouteRule(.domainKeyword("TRACK"), policy: .reject),
        ],
        default: .direct
    )
    #expect(router.match(host: "cdn.example.com", port: 443) == .reject)
    #expect(router.match(host: "tracker.net", port: 443) == .reject)
    #expect(router.match(host: "other.net", port: 443) == .direct)
}

// MARK: - CIDR parsing

@Test func malformedCIDRPrefixIsRejected() throws {
    for text in ["10.0.0.0/", "10.0.0.0/abc", "10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/ 8", "::1/129", "::1/x", "2001:db8::/"] {
        #expect(throws: RuleCompileError.self, "\(text)") {
            _ = try RouteRule.compile(.ipCIDR(text))
        }
    }
    #expect(try RouteRule.compile(.ipCIDR("10.0.0.0/8")) == .ipv4CIDR(IPv4Address(10, 0, 0, 0), prefixLength: 8))
    #expect(try RouteRule.compile(.ipCIDR("10.1.2.3")) == .ipv4(IPv4Address(10, 1, 2, 3)))
    #expect(try RouteRule.compile(.ipCIDR("0.0.0.0/0")) == .ipv4CIDR(IPv4Address(0, 0, 0, 0), prefixLength: 0))
}

// MARK: - MMDB decoding

private func codes(_ bytes: [UInt8], sectionStart: Int = 0) -> [String]? {
    bytes.withUnsafeBytes { raw in
        var cursor = MMDBCursor(buffer: raw, offset: 0, sectionStart: sectionStart)
        return GeoIPMatcher.readCountryCodes(&cursor, depth: 0)
    }
}

@Test func metadbArrayRecordYieldsEveryCode() {
    // Extended type 11 (array) of two strings: ["CN", "HK"].
    let record: [UInt8] = [0x02, 0x04, 0x42, 0x43, 0x4E, 0x42, 0x48, 0x4B]
    #expect(codes(record) == ["CN", "HK"])
}

@Test func mmdbSelfPointerTerminates() {
    // Pointer (size 0) to section offset 0, i.e. itself.
    #expect(codes([0x20, 0x00]) == nil)
}

@Test func mmdbTruncatedRecordsFailSafely() {
    #expect(codes([0x5D]) == nil) // string, 1-byte size extension missing
    #expect(codes([0x45, 0x43]) == nil) // string of 5, only 1 byte present
    #expect(codes([0x38]) == nil) // 4-byte pointer, no payload
    #expect(codes([0xE3, 0x42]) == nil) // map of 3 with a truncated key
    #expect(codes([0x20, 0xFF], sectionStart: 1 << 20) == nil) // pointer past the end
}
