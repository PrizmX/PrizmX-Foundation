import Foundation
import Testing
@testable import PrizmXConfig
import PrizmXNodes
import PrizmXProtocols

/// Import of the protocols added beyond SS / VLESS / Trojan / AnyTLS, in
/// Clash YAML, Surge INI and sing-box JSON.
@Suite("Protocol import")
struct ProtocolImportTests {

    private func clashNode(_ proxy: String) throws -> OutboundNode {
        let result = try ClashConfigParser().parseWithWarnings(rawString: "proxies:\n  - \(proxy)\n")
        #expect(result.warnings.isEmpty, "\(result.warnings)")
        return try #require(result.nodeManager.nodesByID.values.first)
    }

    private func singboxNode(_ outbound: String) throws -> OutboundNode {
        let result = try SingboxConfigParser().parseWithWarnings(rawString: #"{"outbounds": [\#(outbound)]}"#)
        #expect(result.warnings.isEmpty, "\(result.warnings)")
        return try #require(result.nodeManager.nodesByID.values.first)
    }

    private func surgeNode(_ line: String) throws -> OutboundNode {
        let (_, manager) = try ClashConfigParser().parse(rawString: "[Proxy]\n\(line)\n")
        return try #require(manager.nodesByID.values.first)
    }

    // MARK: Shadowsocks ciphers

    @Test func clashChaChaAlias() throws {
        let node = try clashNode("{name: s, type: ss, server: 1.1.1.1, port: 8388, cipher: chacha20-poly1305, password: x}")
        guard case .shadowsocks(_, _, let cipher, _) = node.protocolConfig else { Issue.record("\(node)"); return }
        #expect(cipher == .chacha20IETFPoly1305)
    }

    // MARK: HTTP / SOCKS5

    @Test func clashHTTPS() throws {
        let node = try clashNode(
            "{name: h, type: http, server: p.example, port: 443, username: u, password: p, tls: true, sni: s.example, skip-cert-verify: true, headers: {X-Tag: one}}"
        )
        #expect(node.protocolConfig == .http(
            server: Endpoint(domain: "p.example", port: 443),
            credentials: ProxyCredentials(username: "u", password: "p"),
            tls: TLSSettings(serverName: "s.example", skipCertVerify: true),
            headers: ["X-Tag": "one"]
        ))
    }

    @Test func clashSOCKS5() throws {
        let node = try clashNode("{name: s, type: socks5, server: 10.0.0.1, port: 1080, udp: true}")
        #expect(node.protocolConfig == .socks5(
            server: Endpoint(host: .ipv4(IPv4Address(10, 0, 0, 1)), port: 1080),
            credentials: nil,
            tls: nil,
            udp: true
        ))
    }

    @Test func surgeHTTPAndSOCKS5() throws {
        #expect(try surgeNode("h = https, p.example, 443, u, p, sni=s.example").protocolConfig == .http(
            server: Endpoint(domain: "p.example", port: 443),
            credentials: ProxyCredentials(username: "u", password: "p"),
            tls: TLSSettings(serverName: "s.example")
        ))
        #expect(try surgeNode("s = socks5, 10.0.0.1, 1080, udp-relay=true").protocolConfig == .socks5(
            server: Endpoint(host: .ipv4(IPv4Address(10, 0, 0, 1)), port: 1080),
            credentials: nil,
            tls: nil,
            udp: true
        ))
    }

    @Test func singboxHTTPAndSOCKS() throws {
        let http = try singboxNode(
            #"{"type": "http", "tag": "h", "server": "p.example", "server_port": 8080, "username": "u", "password": "p", "headers": {"X": "1"}}"#
        )
        #expect(http.protocolConfig == .http(
            server: Endpoint(domain: "p.example", port: 8080),
            credentials: ProxyCredentials(username: "u", password: "p"),
            tls: nil,
            headers: ["X": "1"]
        ))
        let socks = try singboxNode(
            #"{"type": "socks", "tag": "s", "server": "p.example", "server_port": 1080, "network": "tcp"}"#
        )
        #expect(socks.protocolConfig == .socks5(
            server: Endpoint(domain: "p.example", port: 1080),
            credentials: nil,
            tls: nil,
            udp: false
        ))
    }

    // MARK: Transports

    @Test func clashTrojanWebSocket() throws {
        let node = try clashNode(
            "{name: t, type: trojan, server: t.example, port: 443, password: p, network: ws, ws-opts: {path: /ws?ed=2048, headers: {Host: cdn.example}}}"
        )
        guard case .trojan(_, _, _, _, let network) = node.protocolConfig else { Issue.record("\(node)"); return }
        #expect(network == .webSocket(WebSocketSettings(
            path: "/ws",
            host: "cdn.example",
            maxEarlyData: 2048,
            earlyDataHeaderName: "Sec-WebSocket-Protocol"
        )))
    }

    @Test func clashHTTPUpgradeFlag() throws {
        let node = try clashNode(
            "{name: v, type: vless, server: v.example, port: 80, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, network: ws, ws-opts: {path: /up, v2ray-http-upgrade: true}}"
        )
        guard case .vless(_, _, _, _, _, _, _, _, let network) = node.protocolConfig else { Issue.record("\(node)"); return }
        #expect(network == .httpUpgrade(HTTPUpgradeSettings(path: "/up")))
    }

    @Test func clashUnsupportedNetworkIsReported() throws {
        let result = try ClashConfigParser().parseWithWarnings(rawString: """
        proxies:
          - {name: v, type: vless, server: v.example, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, network: h2}
        """)
        #expect(result.nodeManager.nodesByID.isEmpty)
        #expect(result.warnings.first?.text == "v")
    }

    @Test func singboxWebSocketAndHTTPUpgrade() throws {
        let ws = try singboxNode(#"""
        {"type": "vless", "tag": "v", "server": "v.example", "server_port": 443, "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
         "tls": {"enabled": true, "server_name": "v.example"},
         "transport": {"type": "ws", "path": "/p", "headers": {"Host": ["cdn.example"]}, "max_early_data": 2048}}
        """#)
        guard case .vless(_, _, _, _, _, _, _, _, let network) = ws.protocolConfig else { Issue.record("\(ws)"); return }
        #expect(network == .webSocket(WebSocketSettings(path: "/p", host: "cdn.example", maxEarlyData: 2048)))

        let upgrade = try singboxNode(#"""
        {"type": "trojan", "tag": "t", "server": "t.example", "server_port": 443, "password": "p",
         "transport": {"type": "httpupgrade", "host": "h.example", "path": "/u"}}
        """#)
        guard case .trojan(_, _, _, _, let network) = upgrade.protocolConfig else { Issue.record("\(upgrade)"); return }
        #expect(network == .httpUpgrade(HTTPUpgradeSettings(path: "/u", host: "h.example")))
    }

    @Test func surgeTrojanWebSocket() throws {
        let node = try surgeNode("t = trojan, t.example, 443, password=p, ws=true, ws-path=/w, ws-headers=Host:cdn.example|X-A:b")
        guard case .trojan(_, _, _, _, let network) = node.protocolConfig else { Issue.record("\(node)"); return }
        #expect(network == .webSocket(WebSocketSettings(path: "/w", host: "cdn.example", headers: ["X-A": "b"])))
    }

    // MARK: VMess

    @Test func clashVMessWebSocketTLS() throws {
        let node = try clashNode(
            "{name: v, type: vmess, server: v.example, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, alterId: 0, cipher: auto, tls: true, servername: s.example, network: ws, ws-opts: {path: /v}}"
        )
        #expect(node.protocolConfig == .vmess(
            server: Endpoint(domain: "v.example", port: 443),
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811",
            security: .auto,
            tls: TLSSettings(serverName: "s.example"),
            network: .webSocket(WebSocketSettings(path: "/v"))
        ))
    }

    @Test func clashVMessLegacyCipherIsReported() throws {
        let result = try ClashConfigParser().parseWithWarnings(rawString: """
        proxies:
          - {name: v, type: vmess, server: v.example, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, cipher: aes-128-cfb}
        """)
        #expect(result.nodeManager.nodesByID.isEmpty)
        #expect(result.warnings.count == 1)
    }

    @Test func singboxVMess() throws {
        let node = try singboxNode(#"""
        {"type": "vmess", "tag": "v", "server": "1.2.3.4", "server_port": 8080, "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "security": "chacha20-poly1305"}
        """#)
        #expect(node.protocolConfig == .vmess(
            server: Endpoint(host: .ipv4(IPv4Address(1, 2, 3, 4)), port: 8080),
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811",
            security: .chacha20Poly1305,
            tls: nil
        ))
    }

    @Test func surgeVMess() throws {
        let node = try surgeNode("v = vmess, v.example, 443, username=b831381d-6324-4d53-ad4f-8cda48b30811, tls=true, ws=true, ws-path=/v")
        #expect(node.protocolConfig == .vmess(
            server: Endpoint(domain: "v.example", port: 443),
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811",
            security: .auto,
            tls: TLSSettings(),
            network: .webSocket(WebSocketSettings(path: "/v"))
        ))
    }

    // MARK: Shadowsocks plugins

    @Test func clashSimpleObfsAndV2rayPlugin() throws {
        let obfs = try clashNode(
            "{name: o, type: ss, server: s.example, port: 8388, cipher: aes-128-gcm, password: p, plugin: obfs, plugin-opts: {mode: tls, host: cdn.example}}"
        )
        guard case .shadowsocks(_, _, _, let obfsPlugin) = obfs.protocolConfig else { Issue.record("\(obfs)"); return }
        #expect(obfsPlugin == .obfs(SimpleObfsSettings(mode: .tls, host: "cdn.example")))

        let v2ray = try clashNode(
            "{name: v, type: ss, server: s.example, port: 443, cipher: aes-128-gcm, password: p, plugin: v2ray-plugin, plugin-opts: {mode: websocket, tls: true, host: cdn.example, path: /ws, mux: true}}"
        )
        guard case .shadowsocks(_, _, _, let v2rayPlugin) = v2ray.protocolConfig else { Issue.record("\(v2ray)"); return }
        #expect(v2rayPlugin == .v2ray(
            webSocket: WebSocketSettings(path: "/ws", host: "cdn.example"),
            tls: TLSSettings(serverName: "cdn.example")
        ))
    }

    @Test func clashUnsupportedPluginIsReported() throws {
        let result = try ClashConfigParser().parseWithWarnings(rawString: """
        proxies:
          - {name: s, type: ss, server: s.example, port: 443, cipher: aes-128-gcm, password: p, plugin: shadow-tls, plugin-opts: {host: a.com}}
        """)
        #expect(result.nodeManager.nodesByID.isEmpty)
        #expect(result.warnings.first?.reason.contains("shadow-tls") == true)
    }

    @Test func singboxSIP003Options() throws {
        let node = try singboxNode(#"""
        {"type": "shadowsocks", "tag": "s", "server": "s.example", "server_port": 443, "method": "aes-128-gcm", "password": "p",
         "plugin": "v2ray-plugin", "plugin_opts": "tls;host=cdn.example;path=/p"}
        """#)
        guard case .shadowsocks(_, _, _, let plugin) = node.protocolConfig else { Issue.record("\(node)"); return }
        #expect(plugin == .v2ray(
            webSocket: WebSocketSettings(path: "/p", host: "cdn.example"),
            tls: TLSSettings(serverName: "cdn.example")
        ))
    }

    @Test func surgeObfs() throws {
        let node = try surgeNode("s = ss, s.example, 8388, encrypt-method=aes-128-gcm, password=p, obfs=http, obfs-host=cdn.example")
        guard case .shadowsocks(_, _, _, let plugin) = node.protocolConfig else { Issue.record("\(node)"); return }
        #expect(plugin == .obfs(SimpleObfsSettings(mode: .http, host: "cdn.example")))
    }

    // MARK: Labels

    @Test func typeNamesDriveExcludeType() throws {
        let result = try ClashConfigParser().parseWithWarnings(rawString: """
        proxies:
          - {name: s, type: ss, server: 1.1.1.1, port: 8388, cipher: aes-128-gcm, password: p}
          - {name: v, type: vmess, server: 1.1.1.1, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811}
          - {name: h, type: http, server: 1.1.1.1, port: 443, tls: true}
        proxy-groups:
          - {name: G, type: select, include-all: true, exclude-type: "vmess|http"}
        """)
        #expect(result.nodeManager.group(named: "G")?.nodeIDs == ["s"])
        let labels = ["s", "v", "h"].compactMap { result.nodeManager.node(id: $0)?.protocolConfig.displayName }
        #expect(labels == ["SS", "VMess", "HTTPS"])
    }

    // MARK: Shadowsocks 2022

    @Test func clashShadowsocks2022() throws {
        let key = Data(repeating: 1, count: 32).base64EncodedString()
        let node = try clashNode("{name: s, type: ss, server: 1.1.1.1, port: 8388, cipher: 2022-blake3-aes-256-gcm, password: \"\(key):\(key)\"}")
        guard case .shadowsocks(_, let password, let cipher, _) = node.protocolConfig else { Issue.record("\(node)"); return }
        #expect(cipher == .blake3AES256GCM)
        #expect(password == "\(key):\(key)")
    }

    @Test func shadowsocks2022WithWrongKeyIsReported() throws {
        let short = Data(repeating: 1, count: 16).base64EncodedString()
        let result = try ClashConfigParser().parseWithWarnings(rawString: """
        proxies:
          - {name: s, type: ss, server: 1.1.1.1, port: 8388, cipher: 2022-blake3-aes-256-gcm, password: "\(short)"}
        """)
        #expect(result.nodeManager.nodesByID.isEmpty)
        #expect(result.warnings.first?.reason.contains("2022-blake3-aes-256-gcm") == true)
    }
}
