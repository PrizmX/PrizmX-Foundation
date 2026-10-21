import Foundation
import Network
import os
import Testing
@testable import PrizmXProtocols

private typealias IPv4Address = PrizmXProtocols.IPv4Address
private typealias IPv6Address = PrizmXProtocols.IPv6Address

/// Answers A and AAAA from tables after a delay; counts queries.
private final class DualStackStub: NameserverTransport, @unchecked Sendable {
    let ipv4: [IPv4Address]
    let ipv6: [IPv6Address]
    let delay: Duration
    private let counter = OSAllocatedUnfairLock(initialState: (a: 0, aaaa: 0))

    init(ipv4: [IPv4Address] = [], ipv6: [IPv6Address] = [], delay: Duration = .zero) {
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.delay = delay
    }

    var queries: (a: Int, aaaa: Int) { counter.withLock { $0 } }

    func query(_ domain: String) async throws -> [DNSWire.Record] {
        counter.withLock { $0.a += 1 }
        try? await Task.sleep(for: delay)
        return ipv4.map { DNSWire.Record(address: $0, ttl: 60) }
    }

    func queryAAAA(_ domain: String) async throws -> [DNSWire.AAAARecord] {
        counter.withLock { $0.aaaa += 1 }
        try? await Task.sleep(for: delay)
        return ipv6.map { DNSWire.AAAARecord(address: $0, ttl: 60) }
    }
}

private let first = NameserverEndpoint.udp(address: "10.0.0.1", port: 53)
private let second = NameserverEndpoint.udp(address: "10.0.0.2", port: 53)
private let documentation6 = IPv6Address(high: 0x2001_0db8_0000_0000, low: 1)

private func client(_ settings: DNSSettings, _ transports: [NameserverEndpoint: DualStackStub]) -> DNSClient {
    let client = DNSClient(settings: settings)
    client.transportFactory = { transports[$0] }
    return client
}

@Suite struct DNSAAAATests {
    @Test func aaaaAsksUpstreamsTogetherAndCaches() async throws {
        let quick = DualStackStub(ipv6: [documentation6])
        let stalled = DualStackStub(ipv6: [IPv6Address(high: 0x2001_0db8_0000_0000, low: 2)], delay: .seconds(5))
        let dns = client(DNSSettings(defaultNameservers: [first, second]), [first: quick, second: stalled])
        let started = ContinuousClock.now
        #expect(try await dns.resolveAAAA("v6.example", role: .direct) == [documentation6])
        // Not held up by the stalled upstream.
        #expect(ContinuousClock.now - started < .seconds(2))
        #expect(try await dns.resolveAAAA("v6.example", role: .direct) == [documentation6])
        #expect(quick.queries.aaaa == 1)
    }

    @Test func aNameWithoutIPv4ResolvesToIPv6() async throws {
        let dns = client(DNSSettings(defaultNameservers: [first]), [first: DualStackStub(ipv6: [documentation6])])
        #expect(try await dns.resolvePreferringIPv4("v6only.example", role: .direct) == [.ipv6(documentation6)])
        // Node names stay IPv4-only.
        await #expect(throws: DNSError.noRecord("v6only.example")) {
            try await dns.resolvePreferringIPv4("v6only.example", role: .proxyServer)
        }
    }

    @Test func ipv4WinsAndIPv6CanBeOff() async throws {
        let address = IPv4Address(192, 0, 2, 1)
        let dualStack = DualStackStub(ipv4: [address], ipv6: [documentation6])
        let dns = client(DNSSettings(defaultNameservers: [first]), [first: dualStack])
        #expect(try await dns.resolvePreferringIPv4("dual.example", role: .direct) == [.ipv4(address)])
        #expect(dualStack.queries.aaaa == 0)

        // Clash `ipv6: false`.
        let ipv6Only = DualStackStub(ipv6: [documentation6])
        let off = client(DNSSettings(defaultNameservers: [first], allowsIPv6: false), [first: ipv6Only])
        await #expect(throws: DNSError.noRecord("v6only.example")) {
            try await off.resolvePreferringIPv4("v6only.example", role: .direct)
        }
        #expect(ipv6Only.queries.aaaa == 0)
    }

    /// The UDP DIRECT dial resolves through `DNSClient.resolve(_:role:)`.
    @Test func directResolveOfANameWithoutIPv4GivesIPv6() async throws {
        let dns = client(DNSSettings(defaultNameservers: [first]), [first: DualStackStub(ipv6: [.loopback])])
        let host = try await DNSClient.$current.withValue(dns) {
            try await DNSClient.resolve(.domain("v6only.example"), role: .direct)
        }
        #expect(host == NWEndpoint.Host("::1"))
    }
}
