import Foundation
import Testing
import PrizmXConfig

@Test func parsesSurgeSGModuleWithArgumentsAndReportsMITMSkips() throws {
    let raw = """
    #!name=AdBlock Sample
    #!desc=Blocks sample ad domains and adds local host mapping.
    #!category=Privacy
    #!arguments=policy:REJECT,host_ip:127.0.0.1

    [General]
    always-real-ip = %APPEND% *.local.test, api.realip.example

    [Rule]
    DOMAIN-SUFFIX,ads.example.com,{{{policy}}}
    DOMAIN,tracker.example.org,{{{policy}}}

    [Host]
    local.service.test = {{{host_ip}}}

    [URL Rewrite]
    ^https://example\\.com/ad _ reject

    [MITM]
    hostname = %APPEND% *.example.com
    """

    let parsed = try ModuleParser.parse(raw, argumentOverrides: ["policy": "REJECT-DROP"])
    #expect(parsed.format == .sgmodule)
    #expect(parsed.name == "AdBlock Sample")
    #expect(parsed.category == "Privacy")
    #expect(parsed.rules.count == 2)
    #expect(parsed.rules[0].policy == "REJECT-DROP")
    #expect(parsed.hosts["local.service.test"] == ["127.0.0.1"])
    #expect(parsed.fakeIPFilters.contains("*.local.test"))
    #expect(parsed.skipped.contains { $0.contains("[MITM]") })
    #expect(parsed.skipped.contains { $0.contains("[url rewrite]") })
}

@Test func parsesStashStOverrideYAMLAndMergesOverlay() throws {
    let yaml = """
    name: Stash Rules Patch
    desc: Injects extra rules and hosts
    rules:
      - DOMAIN-SUFFIX,telemetry.example.com,REJECT
      - IP-CIDR,198.51.100.0/24,DIRECT
    hosts:
      dev.internal: 10.0.0.50
    dns:
      fake-ip-filter:
        - "*.corp.internal"
    http:
      mitm:
        - "api.example.com"
    """

    let parsed = try ModuleParser.parse(yaml)
    #expect(parsed.format == .stoverride)
    #expect(parsed.name == "Stash Rules Patch")
    #expect(parsed.rules.count == 2)
    #expect(parsed.hosts["dev.internal"] == ["10.0.0.50"])
    #expect(parsed.fakeIPFilters == ["*.corp.internal"])
    #expect(parsed.skipped.contains { $0.contains("http.mitm") })

    let local = ProfileOverlay(
        rules: [OverlayRule(type: .domain, payload: "override.me", policy: "DIRECT")],
        hosts: ["dev.internal": ["10.0.0.99"]]
    )
    let combined = local.merging(parsed.overlay)
    #expect(combined.rules.count == 3)
    #expect(combined.rules.first?.payload == "override.me")
    #expect(combined.hosts["dev.internal"] == ["10.0.0.99"])
    #expect(combined.fakeIPFilters == ["*.corp.internal"])
}
