import Foundation
import Testing
import PrizmXConfig
import PrizmXCore
import PrizmXProtocols

private let rules = """
proxies: []
rules:
  - MATCH,DIRECT
"""

/// Clash top-level `ipv6`: on by default, as in mihomo.
@Test func ipv6IsAllowedUnlessTheProfileTurnsItOff() throws {
    #expect(try ConfigAdapter.parseWithWarnings(rawString: rules).allowsIPv6)
    #expect(try ConfigAdapter.parseWithWarnings(rawString: "ipv6: true\n" + rules).allowsIPv6)
    #expect(try !ConfigAdapter.parseWithWarnings(rawString: "ipv6: false\n" + rules).allowsIPv6)
}

/// `ipv6: false` wins over `dns.ipv6` and refuses IPv6 targets; IPv4 and
/// names still go out.
@Test func ipv6OffTurnsAAAAOffAndRefusesIPv6Targets() throws {
    let profile = """
    ipv6: false
    dns:
      enable: true
      ipv6: true
      nameserver: [223.5.5.5]
    """ + "\n" + rules
    let engine = try EngineFactory.make(configText: profile, dnsPersistenceURL: nil, overrideDNS: false)
    #expect(!engine.allowsIPv6)
    #expect(!engine.dns.settings.ipv6)
    let target = Endpoint(host: .ipv6(IPv6Address(high: 0x2606_4700_4700_0000, low: 0x1111)), port: 443)
    #expect(throws: EngineError.rejected(target)) {
        try engine.dispatch(target: target)
    }
    _ = try engine.dispatch(target: Endpoint(host: .ipv4(IPv4Address(1, 1, 1, 1)), port: 443))
    _ = try engine.dispatch(target: Endpoint(domain: "example.com", port: 443))

    let on = try EngineFactory.make(
        configText: profile.replacingOccurrences(of: "ipv6: false", with: "ipv6: true"),
        dnsPersistenceURL: nil,
        overrideDNS: false
    )
    #expect(on.allowsIPv6)
    #expect(on.dns.settings.ipv6)
    _ = try on.dispatch(target: target)
}
