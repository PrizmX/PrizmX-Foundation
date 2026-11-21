import Foundation
import Testing
import PrizmXConfig

@Test func parsesSurgeSGModuleWithFullRulesCronScriptAndMITMSkips() throws {
    let raw = """
    #!name=AdBlock Sample
    #!desc=Blocks sample ad domains and adds local host mapping.
    #!category=Privacy
    #!author=Community
    #!homepage=https://example.com/module
    #!arguments=policy:REJECT,host_ip:127.0.0.1

    [General]
    always-real-ip = %APPEND% *.local.test, api.realip.example

    [Rule]
    DOMAIN-SUFFIX,ads.example.com,{{{policy}}}
    IP-CIDR,198.51.100.0/24,DIRECT,no-resolve
    DEST-PORT,8443,{{{policy}}}
    AND,((DOMAIN-SUFFIX,tracker.org),(NETWORK,UDP)),{{{policy}}}

    [Host]
    local.service.test = {{{host_ip}}}

    [Script]
    daily-check = type=cron, cronexp="0 8 * * *", script-path=https://example.com/check.js, timeout=15, argument="mode=fast"
    net-hook = type=event, event-name=network-changed, script-path=https://example.com/net.js
    ad-rewrite = type=http-response, pattern=^https://example\\.com/ad, script-path=https://example.com/ad.js

    [URL Rewrite]
    ^https://example\\.com/ad _ reject

    [MITM]
    hostname = %APPEND% *.example.com
    """

    let parsed = try ModuleParser.parse(raw, argumentOverrides: ["policy": "REJECT-DROP"])
    #expect(parsed.format == .sgmodule)
    #expect(parsed.name == "AdBlock Sample")
    #expect(parsed.category == "Privacy")
    #expect(parsed.author == "Community")
    #expect(parsed.rawRules.count == 4)
    #expect(parsed.rawRules[0] == "DOMAIN-SUFFIX,ads.example.com,REJECT-DROP")
    #expect(parsed.rawRules[2] == "DST-PORT,8443,REJECT-DROP")
    #expect(parsed.hosts["local.service.test"] == ["127.0.0.1"])
    #expect(parsed.fakeIPFilters.contains("*.local.test"))
    #expect(parsed.scripts.count == 2)
    #expect(parsed.scripts[0].kind == .cron)
    #expect(parsed.scripts[0].pattern == "0 8 * * *")
    #expect(parsed.scripts[0].argument == "mode=fast")
    #expect(parsed.scripts[1].kind == .event)
    #expect(parsed.skipped.contains { $0.contains("ad-rewrite") })
    #expect(parsed.skipped.contains { $0.contains("[MITM]") })
    #expect(parsed.skipped.contains { $0.contains("[url rewrite]") })
}

@Test func parsesStashStOverrideYAMLAndMergesOverlay() throws {
    let yaml = """
    name: Stash Rules Patch
    desc: Injects extra rules and hosts
    rules:
      - DOMAIN-SUFFIX,telemetry.example.com,REJECT
      - IP-CIDR,198.51.100.0/24,DIRECT,no-resolve
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
    #expect(parsed.rawRules.count == 2)
    #expect(parsed.hosts["dev.internal"] == ["10.0.0.50"])
    #expect(parsed.fakeIPFilters == ["*.corp.internal"])
    #expect(parsed.skipped.contains { $0.contains("http.mitm") })

    let local = ProfileOverlay(
        rules: [OverlayRule(type: .domain, payload: "override.me", policy: "DIRECT")],
        hosts: ["dev.internal": ["10.0.0.99"]]
    )
    let combined = local.merging(parsed.overlay)
    #expect(combined.rules.count == 1)
    #expect(combined.rawRules.count == 2)
    #expect(combined.hosts["dev.internal"] == ["10.0.0.99"])
    #expect(combined.fakeIPFilters == ["*.corp.internal"])
}
