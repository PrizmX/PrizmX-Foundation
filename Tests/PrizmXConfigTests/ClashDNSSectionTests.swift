import Foundation
import Testing
import PrizmXConfig
import PrizmXProtocols

private let clashDNSYAML = """
mixed-port: 7890
dns:
  enable: true
  listen: 127.0.0.1:7874
  default-nameserver:
    - 119.29.29.29
    - 223.5.5.5
  nameserver:
    - https://dns.example.com:44443/dns-query/token123
    - https://backup.example.com/dns-query/token123
  proxy-server-nameserver:
    - udp://127.0.0.1:7874
  fake-ip-filter:
    - node-1.example.sbs
    - "*.lan"
proxies: []
rules:
  - MATCH,DIRECT
"""

@Test func clashDNSSectionParses() throws {
    let section = try #require(ClashDNSSection.parse(from: clashDNSYAML))
    #expect(section.defaultNameservers == ["119.29.29.29", "223.5.5.5"])
    #expect(section.nameservers.count == 2)
    #expect(section.proxyServerNameservers == ["udp://127.0.0.1:7874"])
    #expect(section.fakeIPFilter == ["node-1.example.sbs", "*.lan"])
}

@Test func clashDNSSectionSkipsNonYAML() {
    #expect(ClashDNSSection.parse(from: "{\"dns\":{}}") == nil)
    #expect(ClashDNSSection.parse(from: "mixed-port: 7890") == nil)
}

@Test func settingsFromClashCollapseSelfListener() throws {
    let section = try #require(ClashDNSSection.parse(from: clashDNSYAML))
    let settings = DNSSettings.fromClash(section: section, systemDNS: ["114.114.114.114"])
    // Bootstrap: config default-nameserver wins over the system snapshot.
    #expect(settings.defaultNameservers == [
        .udp(address: "119.29.29.29", port: 53),
        .udp(address: "223.5.5.5", port: 53),
    ])
    // proxy-server-nameserver pointed at Clash's own listener → nameservers,
    // with bootstrap + system appended as tail failover sources.
    #expect(settings.proxyServerNameservers.isEmpty)
    let proxyEndpoints = settings.endpoints(for: .proxyServer)
    #expect(proxyEndpoints.prefix(2).allSatisfy {
        if case .doh = $0 { return true }
        return false
    })
    #expect(Array(proxyEndpoints.suffix(3)) == [
        .udp(address: "119.29.29.29", port: 53),
        .udp(address: "223.5.5.5", port: 53),
        .udp(address: "114.114.114.114", port: 53),
    ])
    // direct-nameserver absent → the machine's effective resolver, then bootstrap.
    #expect(settings.endpoints(for: .direct) == [
        .udp(address: "114.114.114.114", port: 53),
        .udp(address: "119.29.29.29", port: 53),
        .udp(address: "223.5.5.5", port: 53),
    ])
    // Built-in LAN patterns are always appended.
    #expect(settings.fakeIPFilter.contains("*.local"))
}

@Test func settingsFromClashWithoutSection() {
    let settings = DNSSettings.fromClash(section: nil, systemDNS: ["114.114.114.114"])
    #expect(settings.defaultNameservers == [.udp(address: "114.114.114.114", port: 53)])
    #expect(settings.endpoints(for: .proxyServer) == settings.defaultNameservers)
}
