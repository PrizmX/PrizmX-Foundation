import Foundation
import Testing
@testable import PrizmXProtocols

@Test func systemHostsParseCommentsAliasesAndCase() {
    let text = """
    # comment
    127.0.0.1 localhost Dev.Example.TEST alias.example.test
    10.0.0.8 dev.example.test
    ::1 localhost
    not-an-ip skipped.example
    192.168.1.9 trailing.example.
    """
    let table = SystemHosts.parse(text)
    #expect(table["dev.example.test"]?.ipv4 == [
        IPv4Address(127, 0, 0, 1),
        IPv4Address(10, 0, 0, 8),
    ])
    #expect(table["alias.example.test"]?.ipv4 == [IPv4Address(127, 0, 0, 1)])
    #expect(table["localhost"]?.ipv4 == [.loopback])
    #expect(table["localhost"]?.ipv6 == [.loopback])
    #expect(table["localhost"]?.addresses == [.ipv4(.loopback), .ipv6(.loopback)])
    #expect(table["skipped.example"] == nil)
    #expect(table["trailing.example"]?.ipv4 == [IPv4Address(192, 168, 1, 9)])
    #expect(table["missing.example"] == nil)
}

@Test func systemHostsLookupReadsOverrideFile() async throws {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("prizmx-hosts-\(UUID().uuidString)")
    try "10.1.2.3 Dev.Example.TEST.\n".write(to: url, atomically: true, encoding: .utf8)
    defer { try? FileManager.default.removeItem(at: url) }

    let mapping = SystemHosts.$pathOverride.withValue(url.path) {
        SystemHosts.lookup("dev.example.test")
    }
    #expect(mapping?.ipv4 == [IPv4Address(10, 1, 2, 3)])
}

@Test func hostsFileAnswersBeforeUpstreamDNS() async throws {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("prizmx-hosts-\(UUID().uuidString)")
    try "127.0.0.1 only.hosts.test\n".write(to: url, atomically: true, encoding: .utf8)
    defer { try? FileManager.default.removeItem(at: url) }

    let client = DNSClient(settings: .bootstrap(physicalIPs: []))
    try await SystemHosts.$pathOverride.withValue(url.path) {
        let addresses = try await client.resolveAll("only.hosts.test", role: .direct)
        #expect(addresses == [.loopback])
        let literal = try await DNSClient.resolveAll(.domain("only.hosts.test"), role: .proxyServer)
        #expect(literal == [.loopback])
        let host = try await DNSClient.resolve(.domain("only.hosts.test"), role: .direct)
        #expect(String(describing: host) == "127.0.0.1")
    }
}

@Test func ipv6OnlyHostsDoesNotFallThroughToPublicA() async throws {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("prizmx-hosts-\(UUID().uuidString)")
    try "::1 v6.only.test\n".write(to: url, atomically: true, encoding: .utf8)
    defer { try? FileManager.default.removeItem(at: url) }

    let client = DNSClient(settings: .bootstrap(physicalIPs: []))
    try await SystemHosts.$pathOverride.withValue(url.path) {
        await #expect(throws: DNSError.noRecord("v6.only.test")) {
            _ = try await client.resolveAll("v6.only.test", role: .direct)
        }
        let v6 = try await client.resolveAAAA("v6.only.test", role: .direct)
        #expect(v6 == [.loopback])
    }
}
