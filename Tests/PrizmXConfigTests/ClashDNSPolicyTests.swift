import Foundation
import Testing
@testable import PrizmXConfig
import PrizmXProtocols
import PrizmXRules

@Suite struct ClashDNSPolicyTests {
    private let yaml = """
    hosts:
      router.lan: 192.168.1.1
      '+.corp.example': [10.1.1.1]
    dns:
      enable: true
      enhanced-mode: redir-host
      fake-ip-range: 28.0.0.1/8
      default-nameserver: [223.5.5.5]
      nameserver: [https://dns.example/dns-query]
      fallback: [udp://8.8.8.8, tls://1.1.1.1]
      fallback-filter:
        geoip: true
        geoip-code: CN
        ipcidr: [240.0.0.0/4]
        domain: ['+.google.com']
      nameserver-policy:
        'geosite:cn': 114.114.114.114
        '+.example.cn,+.example.hk': [udp://119.29.29.29]
    proxies: []
    rules:
      - MATCH,DIRECT
    """

    @Test func sectionParsesPolicyFallbackAndHosts() throws {
        let section = try #require(ClashDNSSection.parse(from: yaml))
        // Specific names before categories.
        #expect(section.nameserverPolicy.map(\.patterns) == [["+.example.cn", "+.example.hk"], ["geosite:cn"]])
        #expect(section.fallbackFilter.domain == ["+.google.com"])
        #expect(section.fallbackFilter.ipcidr == ["240.0.0.0/4"])
        #expect(section.hosts["router.lan"] == ["192.168.1.1"])
        #expect(section.usesGeoIP)
        #expect(section.geositeTags == ["cn"])
    }

    @Test func settingsFollowTheProfile() throws {
        let section = try #require(ClashDNSSection.parse(from: yaml))
        let settings = DNSSettings.fromClash(section: section, systemDNS: ["192.168.1.1"])
        #expect(settings.appDNSFromProfile)
        #expect(settings.fallbackNameservers == [.udp(address: "8.8.8.8", port: 53)])
        #expect(settings.profilePlan(for: "www.example.hk", role: .direct) == .upstreams([.udp(address: "119.29.29.29", port: 53)]))
        #expect(settings.profilePlan(for: "mail.google.com", role: .direct) == .upstreams([.udp(address: "8.8.8.8", port: 53)]))
        // No geosite data loaded here: the geosite key matches nothing.
        #expect(settings.profilePlan(for: "a.example", role: .direct) == .withFallback(
            main: [.doh(url: "https://dns.example/dns-query")],
            fallback: [.udp(address: "8.8.8.8", port: 53)]
        ))
        // ipcidr rejects 240/4 answers even without the GeoIP database.
        #expect(settings.fallbackFilter.rejectsAddress?.matches(IPv4Address(240, 0, 0, 1)) == true)
        #expect(settings.hosts.lookup("x.corp.example")?.ipv4 == [IPv4Address(10, 1, 1, 1)])
    }

    @Test func policyKeysCarryTheirPrefix() {
        #expect(ClashDNSSection.policyPatterns("geosite:cn,private") == ["geosite:cn", "geosite:private"])
        #expect(ClashDNSSection.policyPatterns("+.a.com,+.b.com") == ["+.a.com", "+.b.com"])
    }

    @Test func unsupportedDNSKeysAreReported() throws {
        let result = try ConfigAdapter.parseWithWarnings(rawString: yaml)
        let dns = result.warnings.filter { $0.kind == .dns }
        #expect(dns.contains { $0.text == "enhanced-mode" })
        #expect(dns.contains { $0.text == "fake-ip-range" })
        #expect(dns.contains { $0.text == "fallback" && $0.reason.contains("tls://1.1.1.1") })
    }

    @Test func disabledDNSLeavesAppTrafficOnTheSystemResolver() throws {
        let section = try #require(ClashDNSSection.parse(from: "dns:\n  enable: false\n  nameserver: [1.1.1.1]\n"))
        let settings = DNSSettings.fromClash(section: section, systemDNS: ["192.168.1.1"])
        #expect(!settings.appDNSFromProfile)
        #expect(settings.profilePlan(for: "a.example", role: .direct) == nil)
    }
}
