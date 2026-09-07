import Foundation
import Testing
import PrizmXConfig
import PrizmXNodes
import PrizmXRules

private let body = """
proxies:
  - name: ss-us
    type: ss
    server: us.ss.example
    port: 8388
    cipher: aes-256-gcm
    password: test-password

proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - ss-us

rules:
  - DOMAIN-SUFFIX,google.com,PROXY
  - MATCH,PROXY
"""

@Test func overlayPrependsRulesAndKeepsBody() throws {
    let overlay = ProfileOverlay(rules: [
        OverlayRule(type: .domainSuffix, payload: "corp.internal", policy: "DIRECT"),
    ])
    let parsed = try ConfigAdapter.parse(rawString: body, overlay: overlay)
    #expect(parsed.0.rules.count == 3)
    #expect(parsed.0.rules[0].displayType == "DOMAIN-SUFFIX")
    #expect(parsed.0.rules[0].displayPayload == "corp.internal")
    #expect(parsed.0.rules[0].displayPolicy == "DIRECT")
    #expect(parsed.0.rules[1].displayPayload == "google.com")
}

@Test func overlaySkipsSameNameGroup() throws {
    let overlay = ProfileOverlay(groups: [
        OverlayGroup(name: "PROXY", members: ["DIRECT"]),
        OverlayGroup(name: "Home", members: ["DIRECT", "ss-us"]),
    ])
    let parsed = try ConfigAdapter.parse(rawString: body, overlay: overlay)
    #expect(parsed.1.group(named: "PROXY")?.nodeIDs == ["ss-us"])
    #expect(parsed.1.group(named: "Home")?.nodeIDs == ["DIRECT", "ss-us"])
}

@Test func emptyOverlayIsIdentity() throws {
    let base = try ConfigAdapter.parse(rawString: body)
    let overlaid = try ConfigAdapter.parse(rawString: body, overlay: .empty)
    #expect(base.0.rules.map(\.inspectorLabel) == overlaid.0.rules.map(\.inspectorLabel))
    #expect(Set(base.1.groupsByName.keys) == Set(overlaid.1.groupsByName.keys))
}

@Test func overlayRejectsMalformedCIDR() {
    let overlay = ProfileOverlay(rules: [
        OverlayRule(type: .ipCIDR, payload: "not-an-ip", policy: "DIRECT"),
    ])
    #expect(throws: ConfigError.self) {
        try ConfigAdapter.parse(rawString: body, overlay: overlay)
    }
}

@Test func overlayJSONRoundTrip() throws {
    let overlay = ProfileOverlay(
        rules: [OverlayRule(type: .geosite, payload: "cn", policy: "DIRECT", noResolve: false)],
        groups: [OverlayGroup(name: "Backup", mode: "url-test", members: ["ss-us"])]
    )
    let data = try JSONEncoder().encode(overlay)
    let decoded = try JSONDecoder().decode(ProfileOverlay.self, from: data)
    #expect(decoded == overlay)
}
