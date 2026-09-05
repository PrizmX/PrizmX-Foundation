import Foundation
import Testing
@testable import PrizmXProtocols

@Test func fakeIPAndLoopbackAreNotNameservers() {
    #expect(NameserverEndpoint.udp(ip: "198.18.0.2") == nil)
    #expect(NameserverEndpoint.udp(ip: "198.18.1.10") == nil)
    #expect(NameserverEndpoint.udp(ip: "127.0.0.1") == nil)
    #expect(NameserverEndpoint.udp(ip: "0.0.0.0") == nil)
    #expect(NameserverEndpoint.udp(ip: "example.com") == nil)
    #expect(NameserverEndpoint.udp(ip: "192.168.31.1") != nil)
    #expect(NameserverEndpoint.udp(ip: "223.5.5.5") != nil)
}

@Test func bootstrapPrefersPhysicalAndDoesNotRacePublic() {
    let settings = DNSSettings.bootstrap(physicalIPs: ["192.168.31.1", "198.18.0.2"])
    #expect(settings.defaultNameservers == [
        .udp(address: "192.168.31.1", port: 53),
    ])
    #expect(settings.proxyServerNameservers.isEmpty)
    #expect(settings.directNameservers.isEmpty)
    #expect(settings.endpoints(for: .proxyServer) == settings.defaultNameservers)
    #expect(settings.endpoints(for: .direct) == settings.defaultNameservers)
}

@Test func bootstrapFallsBackWhenPhysicalUnusable() {
    let settings = DNSSettings.bootstrap(physicalIPs: ["198.18.0.2", "127.0.0.1"])
    #expect(settings.defaultNameservers == [.udp(address: "223.5.5.5", port: 53)])
}

@Test func roleListsOverrideDefault() {
    let settings = DNSSettings(
        defaultNameservers: [.udp(address: "192.168.31.1", port: 53)],
        proxyServerNameservers: [.udp(address: "223.5.5.5", port: 53)],
        directNameservers: []
    )
    #expect(settings.endpoints(for: .proxyServer) == [
        .udp(address: "223.5.5.5", port: 53),
        .udp(address: "192.168.31.1", port: 53),
    ])
    #expect(settings.endpoints(for: .direct) == [.udp(address: "192.168.31.1", port: 53)])
}

@Test func dohEndpointParsesButNeedsClientBootstrap() {
    // DoH transports are built by DNSClient (they need the bootstrap resolver
    // for their own hostname); the bare factory still rejects them.
    #expect(NameserverEndpoint.parse("https://dns.example.com/dns-query") == .doh(url: "https://dns.example.com/dns-query"))
    #expect(throws: DNSError.transportNotImplemented(.doh)) {
        _ = try NameserverFactory.make(.doh(url: "https://dns.google/dns-query"))
    }
}

@Test func clashNameserverValuesParse() {
    #expect(NameserverEndpoint.parse("223.5.5.5") == .udp(address: "223.5.5.5", port: 53))
    #expect(NameserverEndpoint.parse("udp://1.1.1.1:5353") == .udp(address: "1.1.1.1", port: 5353))
    // Clash's own listener collapses to nil → role falls back to `nameservers`.
    #expect(NameserverEndpoint.parse("udp://127.0.0.1:7874") == nil)
    #expect(NameserverEndpoint.parse("tls://8.8.4.4") == nil)
    #expect(NameserverEndpoint.parse("system") == nil)
    #expect(NameserverEndpoint.parse("  ") == nil)
}

@Test func fakeIPFilterMatching() {
    let patterns = ["*.lan", "+.pool.ntp.org", "time.*.com", "music.163.com"]
    #expect(FakeIPFilter.matches("printer.lan", patterns: patterns))
    #expect(FakeIPFilter.matches("lan", patterns: patterns))
    #expect(FakeIPFilter.matches("0.pool.ntp.org", patterns: patterns))
    #expect(FakeIPFilter.matches("time.apple.com", patterns: patterns))
    #expect(FakeIPFilter.matches("time1.cloud.tencent.com", patterns: ["time1.cloud.tencent.com"]))
    #expect(FakeIPFilter.matches("music.163.com", patterns: patterns))
    #expect(!FakeIPFilter.matches("www.google.com", patterns: patterns))
    #expect(!FakeIPFilter.matches("music.163.com.evil.com", patterns: patterns))
    #expect(!FakeIPFilter.matches("notlan", patterns: patterns))
}

@Test func domainResolveRequiresBoundClient() async {
    await #expect(throws: DNSError.notConfigured) {
        _ = try await DNSClient.resolve(.domain("example.com"), role: .direct)
    }
}

@Test func dohParseHandlesSliceIndices() throws {
    // Regression: Data.suffix keeps non-zero start indices; parse must rebase.
    let queryID: UInt16 = 0x1234
    let query = DNSWire.makeQuery(id: queryID, domain: "example.com")
    var wire = Data()
    wire.append(contentsOf: [0x12, 0x34]) // matching id
    wire.append(contentsOf: [0x81, 0x80]) // standard response, no error
    wire.append(contentsOf: [0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
    wire.append(query.subdata(in: 12..<query.count)) // question section
    wire.append(contentsOf: [0xC0, 0x0C]) // name → pointer to question
    wire.append(contentsOf: [0x00, 0x01, 0x00, 0x01]) // A IN
    wire.append(contentsOf: [0x00, 0x00, 0x00, 0x3C]) // TTL 60
    wire.append(contentsOf: [0x00, 0x04, 1, 2, 3, 4])
    var response = Data("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\r\n".utf8)
    response.append(wire)
    let records = try DoHNameserver.parse(response: response, expectedID: queryID)
    #expect(records.map(\.address) == [IPv4Address(1, 2, 3, 4)])
    #expect(records.map(\.ttl) == [60])
}

@Test func goodFirstOrderingAndBadEviction() async {
    let good = [IPv4Address(218, 245, 102, 118)]
    let answers = [IPv4Address(155, 254, 102, 209), IPv4Address(218, 245, 102, 118)]
    #expect(DNSClient.mergeGoodFirst(good: good, answers: answers) == [
        IPv4Address(218, 245, 102, 118),
        IPv4Address(155, 254, 102, 209),
    ])
    #expect(DNSClient.mergeGoodFirst(good: [], answers: answers) == answers)
}

@Test func markGoodPersistsAcrossClients() async throws {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("prizmx-dns-good-\(UUID().uuidString).json")
    defer { try? FileManager.default.removeItem(at: url) }
    let domain = "node.example.sbs"
    let edge = IPv4Address(218, 245, 102, 118)

    let first = DNSClient(settings: .bootstrap(physicalIPs: []), persistenceURL: url)
    first.markGood(domain: domain, role: .proxyServer, address: edge)
    #expect(first.goodAddresses(domain: domain, role: .proxyServer) == [edge])

    // New process lifetime: the proven edge survives.
    let second = DNSClient(settings: .bootstrap(physicalIPs: []), persistenceURL: url)
    #expect(second.goodAddresses(domain: domain, role: .proxyServer) == [edge])

    // markBad evicts it and persists the eviction.
    second.markBad(domain: domain, role: .proxyServer, address: edge)
    let third = DNSClient(settings: .bootstrap(physicalIPs: []), persistenceURL: url)
    #expect(third.goodAddresses(domain: domain, role: .proxyServer) == [])
}

@Test func goodWinsOverPinnedWithoutWaitingForLookup() async throws {
    let dead = IPv4Address(155, 254, 102, 209)
    let live = IPv4Address(218, 245, 102, 118)
    let client = DNSClient(
        settings: .bootstrap(physicalIPs: []),
        pinnedNodeAddresses: ["node.example.sbs": [dead]]
    )
    client.markGood(domain: "node.example.sbs", role: .proxyServer, address: live)
    let addresses = try await client.resolveAll("node.example.sbs", role: .proxyServer)
    #expect(addresses.first == live)
    #expect(addresses.contains(dead))
}

@Test func badMarkExpiresAndPinBecomesVisibleAgain() async throws {
    let edge = IPv4Address(155, 254, 102, 209)
    let client = DNSClient(
        settings: .bootstrap(physicalIPs: []),
        pinnedNodeAddresses: ["node.example.sbs": [edge]],
        badTTL: 0.05
    )
    #expect(client.preferredAddresses(domain: "node.example.sbs", role: .proxyServer) == [edge])
    client.markBad(domain: "node.example.sbs", role: .proxyServer, address: edge)
    #expect(client.preferredAddresses(domain: "node.example.sbs", role: .proxyServer).isEmpty)
    // After the TTL the edge is retried instead of bricking the domain.
    try await Task.sleep(for: .milliseconds(80))
    #expect(client.preferredAddresses(domain: "node.example.sbs", role: .proxyServer) == [edge])
}
