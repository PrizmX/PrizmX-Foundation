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
| `PrizmXProtocols` | Endpoints, DNS, Shadowsocks / VLESS / AnyTLS |
| `PrizmXRules` | Rule match / router |
| `PrizmXNodes` | Node catalog, policy groups, URL-test |
| `PrizmXCore` | Engine, traffic counters, mixed-port |
| `PrizmXConfig` | Clash YAML / sing-box → engine, tunnel IPC / kit files |
| `PrizmXTUN` | SwiftTCP userspace stack + FakeIP + relays |
| `PrizmXAttribution` | macOS process attribution (`libproc`). Unused on iOS |

Platforms: macOS 14+, iOS 17+, tvOS 17+. Swift 6.

## Develop

```bash
swift test
```

## License

[Apache License 2.0](LICENSE)
