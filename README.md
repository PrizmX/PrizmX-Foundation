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
| `PrizmXProtocols` | Endpoints, DNS, Shadowsocks / VLESS / Trojan / AnyTLS |
| `PrizmXRules` | Rule match / router |
| `PrizmXNodes` | Node catalog, policy groups, URL-test |
| `PrizmXCore` | Engine, traffic counters, mixed-port |
| `PrizmXConfig` | Clash YAML / sing-box → engine, tunnel IPC / kit files |
| `PrizmXTUN` | SwiftTCP userspace stack + FakeIP + relays |
| `PrizmXAttribution` | macOS process attribution (`libproc`). Unused on iOS |

Platforms: macOS 14+, iOS 17+, tvOS 17+. Swift 6.

## Outbound protocols

VLESS is the proxy framing. TLS and REALITY are **transports** (how those bytes ride). Vision is a VLESS **flow** (how the body is padded, and whether REALITY can be spliced off after the handshake). They combine independently.

| Protocol | Transports | Plugins / extras | TCP | UDP |
| --- | --- | --- | --- | --- |
| Direct | — | — | yes | yes |
| Shadowsocks | native TCP / UDP | AEAD: `aes-128-gcm`, `aes-256-gcm` | yes | yes |
| VLESS | TCP, TLS, REALITY | `flow`: none or `xtls-rprx-vision` (TCP); REALITY `public-key` / `short-id` / SNI | yes | UDP-over-stream (`udp` command). No `xudp`, no Vision UDP |
| Trojan | TLS | SNI | yes | no (TUN drops; header has UDP ASSOCIATE) |
| AnyTLS | TLS 1.3 | SNI, `skip-cert-verify`, idle session pool | yes | no |

Clash YAML and sing-box JSON both import the rows above. Unknown `type` values are skipped.

**Not implemented** (parsed nodes of these kinds are ignored or the extra fields are dropped): VMess, Hysteria, TUIC, WireGuard, Shadowsocks 2022, `chacha20-ietf-poly1305`, WebSocket / gRPC / HTTP2 transport, `client-fingerprint`, `packet-encoding: xudp`, Mux.

## Develop

```bash
swift test
```

## License

[Apache License 2.0](LICENSE)
