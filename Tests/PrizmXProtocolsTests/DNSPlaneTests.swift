import Foundation
import Testing
@testable import PrizmXProtocols
import Network

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

@Test func applyPhysicalDNSReplacesPrivateResolvers() {
    var settings = DNSSettings.bootstrap(physicalIPs: ["192.168.1.1"])
    settings.nameservers = [.udp(address: "8.8.8.8", port: 53)]
    settings.applyPhysicalDNS(["192.168.0.1"])
    #expect(settings.systemNameservers == [.udp(address: "192.168.0.1", port: 53)])
    #expect(settings.defaultNameservers == [.udp(address: "192.168.0.1", port: 53)])
    #expect(settings.nameservers == [.udp(address: "8.8.8.8", port: 53)])
}

@Test func applyPhysicalDNSDropsDeadGatewayWhenCaptureEmpty() {
    var settings = DNSSettings.bootstrap(physicalIPs: ["192.168.1.1"])
    settings.applyPhysicalDNS([])
    #expect(settings.systemNameservers.isEmpty)
    #expect(settings.defaultNameservers == [
        .udp(address: "223.5.5.5", port: 53),
        .udp(address: "119.29.29.29", port: 53),
    ])
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

@Test func dnsWireParsesAAAARecords() {
    let queryID: UInt16 = 0x2222
    let query = DNSWire.makeQuery(id: queryID, domain: "example.com", type: DNSWire.typeAAAA)
    #expect(query.suffix(4) == Data([0x00, 0x1C, 0x00, 0x01]))
    var wire = Data()
    wire.append(contentsOf: [0x22, 0x22, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
    wire.append(query.subdata(in: 12..<query.count))
    wire.append(contentsOf: [0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x10])
    wire.append(Data(repeating: 0, count: 15))
    wire.append(1)
    let records = DNSWire.aaaaRecords(in: wire, expectedID: queryID)
    #expect(records.map(\.address) == [.loopback])
    #expect(records.first?.ttl == 60)
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

// MARK: - Last-resort self-heal

/// Minimal UDP DNS responder: answers every A query with a fixed address.
private final class LocalUDPDNS: @unchecked Sendable {
    private let listener: NWListener
    private let answer: PrizmXProtocols.IPv4Address

    var port: UInt16 { listener.port?.rawValue ?? 0 }

    init(answer: PrizmXProtocols.IPv4Address) throws {
        self.answer = answer
        listener = try NWListener(using: .udp, on: .any)
        listener.newConnectionHandler = { connection in
            connection.start(queue: .global(qos: .utility))
            Self.receive(on: connection, answer: answer)
        }
    }

    func start() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: continuation.resume()
                case .failed(let error): continuation.resume(throwing: error)
                default: break
                }
            }
            listener.start(queue: .global(qos: .utility))
        }
    }

    func stop() { listener.cancel() }

    private static func receive(on connection: NWConnection, answer: PrizmXProtocols.IPv4Address) {
        connection.receiveMessage { data, _, _, _ in
            if let data, let response = Self.response(to: data, answer: answer) {
                connection.send(content: response, completion: .contentProcessed { _ in })
            }
            receive(on: connection, answer: answer)
        }
    }

    /// Query bytes with the response flags set plus one A answer (name
    /// pointer back to the question). Returns nil for malformed queries.
    private static func response(to query: Data, answer: PrizmXProtocols.IPv4Address) -> Data? {
        guard query.count >= 12 else { return nil }
        var response = query
        response[2] = 0x81  // QR + RD
        response[3] = 0x80  // RA
        response[6] = 0     // ANCOUNT hi
        response[7] = 1     // ANCOUNT lo
        var record = Data([0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4])
        var bigEndian = answer.rawValue.bigEndian
        withUnsafeBytes(of: &bigEndian) { record.append(contentsOf: $0) }
        response.append(record)
        return response
    }
}

@Test func proxyServerFallsBackToLastResortWhenPinnedBad() async throws {
    let good = PrizmXProtocols.IPv4Address(203, 0, 113, 7)
    let pinnedBad = PrizmXProtocols.IPv4Address(192, 0, 2, 9)
    let dns = try LocalUDPDNS(answer: good)
    try await dns.start()
    defer { dns.stop() }

    let client = DNSClient(
        settings: DNSSettings(
            defaultNameservers: [.udp(address: "127.0.0.1", port: 9)]  // refused: dead channel
        ),
        pinnedNodeAddresses: ["node.test": [pinnedBad]],
        badTTL: 600,
        lastResortNameservers: [.udp(address: "127.0.0.1", port: dns.port)]
    )
    // The real factory rejects loopback nameservers; the tests drive local
    // responders, so the transport is built directly.
    client.transportFactory = { endpoint in
        guard case .udp(let address, let port) = endpoint else { return nil }
        return UDPNameserver(address: address, port: port)
    }

    // Pin is preferred while clean.
    #expect(try await client.resolveAll("node.test", role: .proxyServer) == [pinnedBad])

    // Dial fails → pin marked bad → the next resolve heals via last resort
    // instead of retrying the dead pin in place.
    client.markBad(domain: "node.test", role: .proxyServer, address: pinnedBad)
    let healed = try await client.resolveAll("node.test", role: .proxyServer)
    #expect(healed == [good])

    // The healed answer is cached briefly — no last-resort storm per dial.
    #expect(try await client.resolveAll("node.test", role: .proxyServer) == [good])
}

@Test func directRoleNeverUsesLastResort() async throws {
    let dns = try LocalUDPDNS(answer: PrizmXProtocols.IPv4Address(203, 0, 113, 7))
    try await dns.start()
    defer { dns.stop() }

    let client = DNSClient(
        settings: DNSSettings(
            defaultNameservers: [.udp(address: "127.0.0.1", port: 9)]
        ),
        lastResortNameservers: [.udp(address: "127.0.0.1", port: dns.port)]
    )
    client.transportFactory = { endpoint in
        guard case .udp(let address, let port) = endpoint else { return nil }
        return UDPNameserver(address: address, port: port)
    }
    await #expect(throws: (any Error).self) {
        try await client.resolveAll("node.test", role: .direct)
    }
}
