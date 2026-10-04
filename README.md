# PrizmX-Foundation

Core library for PrizmX: outbound protocols, rules, Clash / sing-box config, the engine, and the FakeIP TUN stack. Host apps and Packet Tunnel extensions link this; they do not own protocol code.

## Layout

Check out next to **SwiftTCP** (local package path):

```
PrizmX-Foundation/
SwiftTCP/
```

| Product | Role |
| --- | --- |
| `PrizmXProtocols` | Endpoints, DNS, outbound protocols (Shadowsocks, VMess, VLESS, Trojan, AnyTLS, HTTP, SOCKS5) and transports |
| `PrizmXRules` | Rule match / router |
| `PrizmXNodes` | Node catalog, policy groups, URL-test |
| `PrizmXCore` | Engine, traffic counters, mixed-port |
| `PrizmXConfig` | Clash YAML / sing-box → engine, tunnel IPC / kit files |
| `PrizmXScripts` | JavaScriptCore runtime for Scripts |
| `PrizmXTUN` | SwiftTCP userspace stack + FakeIP + relays |
| `PrizmXAttribution` | macOS process attribution (`libproc`). Unused on iOS |

Platforms: macOS 14+, iOS 17+, tvOS 17+. Swift 6.

## Outbound protocols

A protocol frames the proxied stream; a **transport** carries those bytes (TCP, TLS, REALITY, WebSocket, HTTP upgrade); a **plugin** wraps a Shadowsocks stream. Vision is a VLESS **flow** (how the body is padded, and whether REALITY can be spliced off after the handshake). They combine independently.

| Protocol | Transports | Plugins / extras | TCP | UDP |
| --- | --- | --- | --- | --- |
| Direct | — | — | yes | yes |
| Shadowsocks | native TCP / UDP | AEAD: `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`; plugins: simple-obfs (`http` / `tls`), v2ray-plugin (websocket, TLS, mux) | yes | yes (native, also with plugins) |
| VMess | TCP, TLS, WebSocket, HTTP upgrade | AEAD header (`alterId: 0`); `cipher`: `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none`, `zero` | yes | yes (not `zero`) |
| VLESS | TCP, TLS, REALITY, WebSocket, HTTP upgrade | `flow`: none or `xtls-rprx-vision` (TCP / TLS / REALITY only); REALITY `public-key` / `short-id` / SNI | yes | UDP-over-stream (`udp` command). No `xudp` yet, so Vision users fail on sing-box |
| Trojan | TLS, TLS + WebSocket / HTTP upgrade | SNI | yes | yes |
| AnyTLS | TLS 1.3 | SNI, `skip-cert-verify`, idle session pool | yes | no |
| HTTP | TCP, TLS (`https`) | Basic auth, extra headers (`CONNECT`) | yes | no |
| SOCKS5 | TCP, TLS | username / password | yes | yes (UDP ASSOCIATE, when `udp`) |

WebSocket supports early data (`max-early-data` / Xray `?ed=`). Clash YAML, Surge INI and sing-box JSON import the rows above; a node whose transport, cipher or plugin is not supported is skipped with a warning instead of being imported half-configured.

Half-close reaches the server where the path can carry it (TCP FIN, VMess's end chunk). Network.framework TLS, WebSocket, mux.cool and simple-obfs cannot; there the uplink just stops and the relay's linger bound ends the flow.

**Not implemented**: Hysteria, TUIC, WireGuard, Shadowsocks 2022, ShadowsocksR, gRPC / HTTP2 transport, VMess legacy `alterId > 0` auth, `client-fingerprint`, `packet-encoding: xudp`, Mux.

`Interop/` runs every protocol against real servers (sing-box, Xray, shadowsocks-libev) in Docker, with mihomo as the reference client; see [Interop/README.md](Interop/README.md).

## Develop

```bash
swift test
```

## License

[Apache License 2.0](LICENSE)
