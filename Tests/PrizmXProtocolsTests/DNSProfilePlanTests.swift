import Foundation
import os
import Testing
@testable import PrizmXProtocols

/// Answers from a table after a delay; counts queries.
private final class StubTransport: NameserverTransport, @unchecked Sendable {
    let answer: [IPv4Address]
    let delay: Duration
    private let counter = OSAllocatedUnfairLock(initialState: 0)

    init(_ answer: [IPv4Address], delay: Duration = .zero) {
        self.answer = answer
        self.delay = delay
    }

    var queries: Int { counter.withLock { $0 } }

    func query(_ domain: String) async throws -> [DNSWire.Record] {
        counter.withLock { $0 += 1 }
        try? await Task.sleep(for: delay)
        return answer.map { DNSWire.Record(address: $0, ttl: 60) }
    }

    func queryAAAA(_ domain: String) async throws -> [DNSWire.AAAARecord] { [] }
}

private let cn = IPv4Address(114, 114, 114, 114)
private let abroad = IPv4Address(8, 8, 8, 8)
private let main = NameserverEndpoint.udp(address: "10.0.0.1", port: 53)
private let slow = NameserverEndpoint.udp(address: "10.0.0.2", port: 53)
private let fallback = NameserverEndpoint.udp(address: "10.0.0.3", port: 53)
private let policyServer = NameserverEndpoint.udp(address: "10.0.0.4", port: 53)

private func client(_ settings: DNSSettings, _ transports: [NameserverEndpoint: StubTransport]) -> DNSClient {
    let client = DNSClient(settings: settings)
    client.transportFactory = { transports[$0] }
    return client
}

@Suite struct DNSProfilePlanTests {
    @Test func appTrafficUsesTheProfileResolverOnlyWhenEnabled() {
        var settings = DNSSettings(
            defaultNameservers: [main],
            nameservers: [main],
            systemNameservers: [slow]
        )
        #expect(settings.profilePlan(for: "a.example", role: .direct) == nil)
        settings.appDNSFromProfile = true
        #expect(settings.profilePlan(for: "a.example", role: .direct) == .upstreams([main]))
        settings.directNameservers = [slow]
        #expect(settings.profilePlan(for: "a.example", role: .direct) == nil)
    }

    @Test func policyThenFallbackFilterThenFallback() {
        let settings = DNSSettings(
            defaultNameservers: [main],
            nameservers: [main],
            appDNSFromProfile: true,
            nameserverPolicies: [
                NameserverPolicy(domains: DomainPredicate("cn") { $0.hasSuffix(".cn") }, nameservers: [policyServer]),
            ],
            fallbackNameservers: [fallback],
            fallbackFilter: FallbackFilter(domains: DomainPredicate("google") { $0.hasSuffix("google.com") })
        )
        #expect(settings.profilePlan(for: "www.example.cn", role: .direct) == .upstreams([policyServer]))
        #expect(settings.profilePlan(for: "www.google.com", role: .direct) == .upstreams([fallback]))
        #expect(settings.profilePlan(for: "a.example", role: .direct) == .withFallback(main: [main], fallback: [fallback]))
    }

    @Test func fallbackReplacesARejectedMainAnswer() async throws {
        let settings = DNSSettings(
            defaultNameservers: [main],
            nameservers: [main],
            appDNSFromProfile: true,
            fallbackNameservers: [fallback],
            fallbackFilter: FallbackFilter(rejectsAddress: AddressPredicate("not CN") { $0 != cn })
        )
        let poisoned = client(settings, [main: StubTransport([abroad]), fallback: StubTransport([cn])])
        #expect(try await poisoned.resolveAll("a.example", role: .direct) == [cn])
        let clean = client(settings, [main: StubTransport([cn]), fallback: StubTransport([abroad])])
        #expect(try await clean.resolveAll("a.example", role: .direct) == [cn])
    }

    /// A dead upstream used to add its whole timeout to every lookup.
    @Test func upstreamsAreQueriedInParallel() async throws {
        let settings = DNSSettings(defaultNameservers: [slow, main])
        let dns = client(settings, [slow: StubTransport([abroad], delay: .seconds(3)), main: StubTransport([cn])])
        let clock = ContinuousClock()
        let started = clock.now
        #expect(try await dns.resolveAll("a.example", role: .direct) == [cn])
        #expect(clock.now - started < .seconds(1))
    }

    /// An empty answer may be a passing upstream failure (SERVFAIL, a DoH
    /// 503): the next dial asks again instead of failing from a cache.
    @Test func emptyAnswersAreNotCached() async throws {
        let empty = StubTransport([])
        let dns = client(DNSSettings(defaultNameservers: [main]), [main: empty])
        await #expect(throws: (any Error).self) { try await dns.resolveAll("none.example", role: .direct) }
        await #expect(throws: (any Error).self) { try await dns.resolveAll("none.example", role: .direct) }
        #expect(empty.queries == 2)
    }

    /// An accepted `nameserver` answer must not wait for a slow fallback.
    @Test func acceptedMainAnswerDoesNotWaitForFallback() async throws {
        let settings = DNSSettings(
            defaultNameservers: [main],
            nameservers: [main],
            appDNSFromProfile: true,
            fallbackNameservers: [fallback],
            fallbackFilter: FallbackFilter(rejectsAddress: AddressPredicate("not CN") { $0 != cn })
        )
        let dns = client(settings, [main: StubTransport([cn]), fallback: StubTransport([abroad], delay: .seconds(3))])
        let clock = ContinuousClock()
        let started = clock.now
        #expect(try await dns.resolveAll("a.example", role: .direct) == [cn])
        #expect(clock.now - started < .seconds(1))
    }

    @Test func profileHostsWinOverUpstreams() async throws {
        let hosts = ProfileHosts([
            "router.lan": ["192.168.1.1"],
            "+.corp.example": ["10.1.1.1"],
            "*.wild.example": ["10.2.2.2"],
        ])
        #expect(hosts.lookup("router.lan")?.ipv4 == [IPv4Address(192, 168, 1, 1)])
        #expect(hosts.lookup("corp.example")?.ipv4 == [IPv4Address(10, 1, 1, 1)])
        #expect(hosts.lookup("a.b.corp.example")?.ipv4 == [IPv4Address(10, 1, 1, 1)])
        #expect(hosts.lookup("one.wild.example") != nil)
        #expect(hosts.lookup("two.one.wild.example") == nil)
        // Overlapping patterns: the more specific one wins, every time.
        let overlapping = ProfileHosts(["+.example.com": ["10.0.0.1"], "+.cdn.example.com": ["10.0.0.2"]])
        #expect(overlapping.lookup("a.cdn.example.com")?.ipv4 == [IPv4Address(10, 0, 0, 2)])
        let dns = client(DNSSettings(defaultNameservers: [main], hosts: hosts), [main: StubTransport([abroad])])
        #expect(try await dns.resolveAll("router.lan", role: .direct) == [IPv4Address(192, 168, 1, 1)])
    }

    @Test func provenDirectAddressesAreNotPersisted() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("dns-good-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: file) }
        let dns = DNSClient(settings: DNSSettings(defaultNameservers: [main]), persistenceURL: file)
        dns.markGood(domain: "node.example", role: .proxyServer, address: abroad)
        dns.markGood(domain: "site.example", role: .direct, address: cn)
        let text = try String(contentsOf: file, encoding: .utf8)
        #expect(text.contains("node.example"))
        #expect(!text.contains("site.example"))
    }
}
