import Foundation
import Testing
import PrizmXConfig

private func base64(_ text: String) -> String {
    Data(text.utf8).base64EncodedString()
}

private func base64URL(_ text: String) -> String {
    base64(text)
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private let vmessJSON = """
{"v":"2","ps":"JP 01","add":"jp.example.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811",\
"aid":"0","scy":"auto","net":"ws","type":"none","host":"cdn.example.com","path":"/ray","tls":"tls","sni":"cdn.example.com"}
"""

private let shareLinks = [
    "ss://\(base64URL("aes-256-gcm:pa ss"))@1.2.3.4:8388#HK%2001",
    "ss://\(base64URL("chacha20-ietf-poly1305:secret"))@5.6.7.8:443/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#HK%2001",
    "vmess://\(base64(vmessJSON))",
    "vless://b831381d-6324-4d53-ad4f-8cda48b30811@us.example.com:443?encryption=none&security=reality&sni=www.apple.com&fp=chrome&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba85179e30d4fc2&type=tcp&flow=xtls-rprx-vision#US%20Reality",
    "trojan://p%40ss@sg.example.com:443?sni=sg.example.com&type=ws&host=sg.example.com&path=%2Fws#SG",
    "hysteria2://letmein@hy.example.com:8443?sni=hy.example.com#HY2",
].joined(separator: "\n")

@Suite struct ProxyURIListTests {
    @Test func convertsShareLinksToAnImportableProfile() throws {
        let yaml = try #require(ProxyURIList.clashYAML(from: shareLinks))
        let result = try ConfigAdapter.parseWithWarnings(rawString: yaml)
        let names = Set(result.nodeManager.nodesByID.keys)
        #expect(names == ["HK 01", "HK 01 2", "JP 01", "US Reality", "SG"])
        #expect(result.nodeManager.groupsByName[ProxyURIList.selectGroupName] != nil)
        #expect(result.nodeManager.groupsByName[ProxyURIList.autoGroupName] != nil)
        #expect(result.unroutableCatchAllTarget == nil)
        // Unsupported protocols are reported, not dropped silently.
        #expect(result.warnings.contains { $0.kind == .proxy && $0.text == "HY2" })
    }

    @Test func keepsPasswordsVerbatim() throws {
        let yaml = try #require(ProxyURIList.clashYAML(from: shareLinks))
        #expect(yaml.contains("password: \"pa ss\""))
        #expect(yaml.contains("password: \"p@ss\""))
    }

    @Test func readsBase64WrappedBodies() throws {
        let wrapped = base64(shareLinks)
        let decoded = try #require(ProxyURIList.decodeBase64(wrapped))
        #expect(ProxyURIList.clashYAML(from: decoded) != nil)
    }

    @Test func rejectsTextThatIsNotALinkList() {
        #expect(ProxyURIList.clashYAML(from: "proxies: []\nrules:\n  - MATCH,DIRECT") == nil)
        #expect(ProxyURIList.clashYAML(from: "<html><body>error</body></html>") == nil)
        #expect(ProxyURIList.clashYAML(from: "ss://not-a-link") == nil)
    }

    /// `plugin=;` used to index an empty split and trap.
    @Test func emptyPluginDoesNotCrash() throws {
        let link = "ss://\(base64URL("aes-256-gcm:pw"))@1.2.3.4:443/?plugin=%3B#x"
        let yaml = try #require(ProxyURIList.clashYAML(from: link))
        #expect(yaml.contains("name: \"x\""))
    }

    @Test func dropsLinksWithOutOfRangePorts() {
        let link = "trojan://pw@example.com:99999#Bad"
        #expect(ProxyURIList.clashYAML(from: link) == nil)
    }

    @Test func reportsAnUnroutableCatchAll() throws {
        let yaml = """
        proxies: []
        proxy-groups:
          - name: Proxy
            type: select
            use: [provider]
        rules:
          - MATCH,Proxy
        """
        let result = try ConfigAdapter.parseWithWarnings(rawString: yaml)
        #expect(result.unroutableCatchAllTarget == "Proxy")
    }
}
