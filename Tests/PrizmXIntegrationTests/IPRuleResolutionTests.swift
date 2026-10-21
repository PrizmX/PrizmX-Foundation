import Foundation
import os
import Testing
import PrizmXCore
import PrizmXNodes
import PrizmXRules
@testable import PrizmXProtocols

/// Answers A and AAAA per name.
private struct NameTable: NameserverTransport {
    var ipv4: [String: [IPv4Address]] = [:]
    var ipv6: [String: [IPv6Address]] = [:]

    func query(_ domain: String) async throws -> [DNSWire.Record] {
        (ipv4[domain] ?? []).map { DNSWire.Record(address: $0, ttl: 60) }
    }

    func queryAAAA(_ domain: String) async throws -> [DNSWire.AAAARecord] {
        (ipv6[domain] ?? []).map { DNSWire.AAAARecord(address: $0, ttl: 60) }
    }
}

private let table = NameTable(
    ipv4: ["dual.example": [IPv4Address(192, 0, 2, 1)]],
    ipv6: [
        "dual.example": [IPv6Address(high: 0x2001_0db8_0000_0000, low: 1)],
        "v6only.example": [IPv6Address(high: 0x2001_0db8_0000_0000, low: 2)],
    ]
)

private func engine(rules: [RouteRule], dns settings: DNSSettings) -> Engine {
    let dns = DNSClient(settings: settings)
    dns.transportFactory = { _ in table }
    return Engine(router: Router(rules: rules), nodeManager: NodeManager(nodes: [], groups: []), dns: dns)
}

private let upstream = NameserverEndpoint.udp(address: "10.0.0.1", port: 53)

@Test func ipRulesSeeIPv6OnlyForANameWithoutIPv4() async {
    let rules = [
        RouteRule(.ipv6CIDR(IPv6Address(high: 0x2001_0db8_0000_0000, low: 0), prefixLength: 32), policy: .proxy(targetGroup: "V6")),
        RouteRule(.ipv4CIDR(IPv4Address(192, 0, 2, 0), prefixLength: 24), policy: .proxy(targetGroup: "V4")),
        RouteRule(.matchAll, policy: .direct),
    ]
    let dualStack = engine(rules: rules, dns: DNSSettings(defaultNameservers: [upstream]))
    #expect(await dualStack.resolveAndMatch(Endpoint(domain: "v6only.example", port: 443)).policy == .proxy(targetGroup: "V6"))
    // As in mihomo, a name with IPv4 is matched by it alone.
    #expect(await dualStack.resolveAndMatch(Endpoint(domain: "dual.example", port: 443)).policy == .proxy(targetGroup: "V4"))

    // Clash `ipv6: false`.
    let ipv4Only = engine(rules: rules, dns: DNSSettings(defaultNameservers: [upstream], allowsIPv6: false))
    #expect(await ipv4Only.resolveAndMatch(Endpoint(domain: "v6only.example", port: 443)).policy == .direct)
}

@Test func sniffedFlowMatchesIPRulesByTheDialedAddress() async throws {
    let engine = engine(
        rules: [
            RouteRule(.ipv4CIDR(IPv4Address(149, 154, 160, 0), prefixLength: 20), policy: .reject, noResolve: true),
            RouteRule(.matchAll, policy: .proxy(targetGroup: "Proxy")),
        ],
        dns: DNSSettings(defaultNameservers: [upstream])
    )
    let name = Endpoint(domain: "api.telegram.org", port: 443)
    let context = RouteContext(network: .tcp, destinationAddress: .ipv4(IPv4Address(149, 154, 167, 50)))
    await #expect(throws: EngineError.rejected(name)) {
        try await engine.resolveAndDispatch(target: name, context: context)
    }
}

/// A hosts address is known from the start, so `no-resolve` rules match it
/// too (as in mihomo), at FakeDNS time as well.
@Test func noResolveRulesMatchAHostsAddress() async {
    let engine = engine(
        rules: [
            RouteRule(.ipv4CIDR(IPv4Address(149, 154, 160, 0), prefixLength: 20), policy: .reject, noResolve: true),
            RouteRule(.matchAll, policy: .direct),
        ],
        dns: DNSSettings(defaultNameservers: [upstream], hosts: ProfileHosts(["tg.example": ["149.154.167.50"]]))
    )
    #expect(await engine.resolvePolicy(for: Endpoint(domain: "tg.example", port: 443)) == .reject)
    #expect(await engine.dnsPolicy(host: "tg.example") == .reject)
}

/// The hosts entry decides where the name goes, so IP rules see its
/// address instead of the one the client dialed (as in mihomo).
@Test func hostsEntryOutranksTheDialedAddress() async throws {
    let engine = engine(
        rules: [
            RouteRule(.ipv4CIDR(IPv4Address(149, 154, 160, 0), prefixLength: 20), policy: .reject),
            RouteRule(.matchAll, policy: .direct),
        ],
        dns: DNSSettings(defaultNameservers: [upstream], hosts: ProfileHosts(["mapped.example": ["192.0.2.7"]]))
    )
    let name = Endpoint(domain: "mapped.example", port: 443)
    let context = RouteContext(network: .tcp, destinationAddress: .ipv4(IPv4Address(149, 154, 167, 50)))
    #expect(try await engine.resolveAndDispatch(target: name, context: context).policy == FlowRoute.direct)
    #expect(await engine.resolvePolicy(for: name, context: context) == .direct)
}
