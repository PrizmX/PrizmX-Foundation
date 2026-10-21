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

A protocol frames the proxied stream; a **transport** carries those bytes (TCP, TLS, REALITY, WebSocket, HTTP upgrade, gRPC); a **plugin** wraps a Shadowsocks stream. Vision is a VLESS **flow** (how the body is padded, and whether REALITY can be spliced off after the handshake). They combine independently.

| Protocol | Transports | Plugins / extras | TCP | UDP |
| --- | --- | --- | --- | --- |
| Direct | — | — | yes | yes |
| Shadowsocks | native TCP / UDP | AEAD: `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`; 2022: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm` (also multi-user identity keys), `2022-blake3-chacha20-poly1305`; plugins: simple-obfs (`http` / `tls`), v2ray-plugin (websocket, TLS, mux) | yes | yes (native, also with plugins) |
| VMess | TCP, TLS, WebSocket, HTTP upgrade, gRPC | AEAD header (`alterId: 0`); `cipher`: `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none`, `zero` | yes | yes (not `zero`) |
| VLESS | TCP, TLS, REALITY, WebSocket, HTTP upgrade, gRPC | `flow`: none or `xtls-rprx-vision` (TCP / TLS / REALITY only); REALITY `public-key` / `short-id` / SNI | yes | UDP-over-stream (`udp` command); XUDP (mux.cool) for Vision users |
| Trojan | TLS, TLS + WebSocket / HTTP upgrade / gRPC | SNI | yes | yes |
| AnyTLS | TLS 1.3 | SNI, `skip-cert-verify`, idle session pool | yes | no |
| HTTP | TCP, TLS (`https`) | Basic auth, extra headers (`CONNECT`) | yes | no |
| SOCKS5 | TCP, TLS | username / password | yes | yes (UDP ASSOCIATE, when `udp`) |
| ShadowsocksR | TCP | stream ciphers: `none`, `rc4-md5`, `aes-{128,192,256}-{cfb,ctr}`, `chacha20`, `chacha20-ietf`; `protocol`: `origin`, `auth_sha1_v4`, `auth_aes128_md5`, `auth_aes128_sha1`, `auth_chain_a` (also `protocol-param` `uid:password`); `obfs`: `plain`, `http_simple`, `http_post`, `tls1.2_ticket_auth`, `tls1.2_ticket_fastauth` | yes | no |

WebSocket supports early data (`max-early-data` / Xray `?ed=`). gRPC is Xray's "gun" (`/<service>/Tun` or a custom `/a/b/Tun` path) over HTTP/2: h2 with TLS, h2c without; multi mode (`TunMulti`) is not used. Clash YAML, Surge INI and sing-box JSON import the rows above (ShadowsocksR only from Clash YAML, `type: ssr`); a node whose transport, cipher or plugin is not supported is skipped with a warning instead of being imported half-configured.

Half-close reaches the server where the path can carry it (TCP FIN, VMess's end chunk, gRPC END_STREAM). Network.framework TLS, WebSocket, mux.cool, simple-obfs and AnyTLS cannot, and the ShadowsocksR reference server drops the whole connection on FIN; there the uplink just stops and the relay's linger bound ends the flow.

**Not implemented**: Hysteria, TUIC, WireGuard, ShadowsocksR UDP and `auth_chain_b`+, HTTP/2 (`h2`) transport, VMess legacy `alterId > 0` auth, `client-fingerprint`, Mux (multiplexing several flows per connection). `packet-encoding` is ignored: Vision users always get XUDP, others the plain `udp` command.

`Interop/` runs every protocol against real servers (sing-box, Xray, shadowsocks-libev, the Python ShadowsocksR server) in Docker, with mihomo as the reference client; see [Interop/README.md](Interop/README.md).

## Clash YAML compatibility

`PrizmXConfig` reads Clash / mihomo YAML. Anything it cannot honor exactly is **skipped and reported** (`ConfigWarning`; the app lists them under Profiles), never imported in a broadened form:

- A skipped **rule** is left out, so its traffic falls through to later rules.
- A skipped **proxy or group** is left out, and rules that name it **fail closed** (the connection errors; it never goes DIRECT).
- A subscription whose catch-all rule (`MATCH`) names a group that could not be imported is refused, and the previous version is kept.
- Keys marked *ignored* have no effect. Those marked *(warning)* are also listed with the import warnings; the rest are ignored silently.

The tables list what is **not** supported. Everything else in the sections they cover is read.

### Syntax

Full YAML 1.1 through libyaml ([Yams](https://github.com/jpsim/Yams)): anchors, aliases, merge keys (`<<`), block scalars, multi-line flow collections. A file libyaml rejects is retried with a lenient subset parser, which accepts tab indentation and several `---` documents read as one. A document that expands past 1,000,000 nodes (nested aliases) is refused.

### Top level

| Key | What happens |
| --- | --- |
| `mode`, `allow-lan`, `tun` | Ignored: the app's Rule / Global / Direct, Allow LAN and TUN switches decide. |
| `bind-address`, `lan-allowed-ips`, `external-controller`, `secret`, `external-ui` | Ignored. With Allow LAN on, the listener accepts loopback, private and CGNAT sources. |
| `sniffer` | Ignored: HTTP Host / TLS SNI sniffing is built in and always on. |
| `geox-url`, `geodata-mode`, `geo-auto-update` | Ignored: `geoip.metadb`, `geosite.dat` and `GeoLite2-ASN.mmdb` come from MetaCubeX/meta-rules-dat (jsDelivr as a fallback) when the rules use them, and refresh weekly. |
| `sub-rules`, `listeners`, `tunnels`, `ntp`, `experimental`, `profile` | Ignored. |
| `unified-delay`, `tcp-concurrent`, `global-client-fingerprint`, `keep-alive-interval`, `find-process-mode`, `interface-name`, `routing-mark` | Ignored. |

`mixed-port`, `port`, `socks-port`, `authentication`, `skip-auth-prefixes`, `hosts`, `ipv6` and the sections below are read. `ipv6` defaults to `true`, as in mihomo. A name with no IPv4 address then resolves to its IPv6 address, for IP rules and DIRECT dials; a name that has both uses IPv4. `false` turns IPv6 off: the TUN refuses the IPv6 that reaches it (TCP gets a RST), FakeDNS returns no AAAA answers whatever `dns.ipv6` says, and IPv6 targets are rejected.

### `proxies`

| Key / value | What happens |
| --- | --- |
| `type`: `hysteria`, `hysteria2`, `tuic`, `wireguard`, `ssh`, `snell`, `mieru`, … | Proxy skipped (warning). Supported types are listed under [Outbound protocols](#outbound-protocols). |
| `network`: `h2`, `http`, `kcp`, `quic`, `xhttp`, … | Proxy skipped (warning). |
| Unsupported cipher, plugin or plugin `mode` | Proxy skipped (warning). |
| `dialer-proxy` | Proxy skipped (warning). Proxy chains are not supported, and without its hop the proxy would dial the server directly. |
| `client-fingerprint`, `smux`, `ip-version`, `interface-name`, `routing-mark`, `tfo`, `mptcp`, `ech-opts` | Ignored. |
| `alterId` > 0 | Ignored: VMess always uses the AEAD header (`alterId: 0`). |
| `packet-encoding` | Ignored: Vision users get XUDP, others the plain `udp` command. |

### `proxy-groups`

| Key / value | What happens |
| --- | --- |
| `type: relay` | Group skipped (warning). Rules using it fail closed. |
| `type: smart` | Imported as `url-test` (warning). |
| Any other unknown `type` | Imported as `select` (warning). |
| `lazy`, `timeout`, `max-failed-times`, `expected-status`, `disable-udp`, `hidden`, `interface-name`, `routing-mark` | Ignored. `url-test`, `fallback` and `load-balance` groups are probed on their `interval`. A member whose dial fails is skipped at once and its group is re-tested. |
| A group left without members | Skipped (warning). Rules using it fail closed. |

`proxies`, `use`, `include-all`, `include-all-proxies`, `include-all-providers`, `filter`, `exclude-filter`, `exclude-type`, `url`, `interval`, `tolerance`, `strategy` and `icon` are read.

### `proxy-providers` and `rule-providers`

| Key / value | What happens |
| --- | --- |
| `type: file` | Provider skipped (warning). The sandboxed app cannot read arbitrary files; use `http` or `inline`. |
| `format: mrs` | Rule provider skipped (warning). `yaml` and `text` are read. |
| `path` | Ignored: downloads are cached in the app's container. |
| `override` (proxy provider) | Ignored (warning): proxies are imported as served. |
| `dialer-proxy` (proxy provider) | The provider's proxies are left out (warning). |
| `health-check` (proxy provider) | Ignored: the groups that use the proxies test them. |
| `http` provider not downloaded yet | Counts as empty (warning). Its `RULE-SET` matches nothing and its proxies are missing until the download lands. The engine then reloads in place. |

`http` providers download on import and on every engine start, then refresh on their `interval` (24 h when unset). A failed download keeps the previous file. Proxy-provider bodies may be Clash YAML or share-link lists (plain or base64). A proxy whose name is already taken gets ` (<provider>)` appended.

### `rules`

Supported:

- **Domain:** `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `DOMAIN-REGEX`, `DOMAIN-WILDCARD`, `GEOSITE`.
- **Address:** `IP-CIDR`, `IP-CIDR6`, `IP-SUFFIX`, `IP-ASN`, `GEOIP` (`LAN` expands to the private ranges), and the client-address forms `SRC-IP-CIDR`, `SRC-IP-SUFFIX`, `SRC-IP-ASN`, `SRC-GEOIP`.
- **Port and network:** `DST-PORT`, `SRC-PORT`, `IN-PORT`, `NETWORK`.
- **Process:** `PROCESS-NAME`, `PROCESS-PATH`, and their `-REGEX` forms.
- **Composite and terminal:** `AND`, `OR`, `NOT` (nested), `RULE-SET`, `MATCH`, `FINAL`.
- **Options:** `no-resolve`, and `src`, which turns `IP-CIDR`, `IP-CIDR6`, `IP-SUFFIX`, `IP-ASN` and `GEOIP` into their `SRC-` forms (other rules but `RULE-SET` ignore it, as in mihomo). `PASS` rules are dropped, which has the same effect.

| Rule / option | What happens |
| --- | --- |
| `IN-TYPE`, `IN-USER`, `IN-NAME`, `UID`, `DSCP`, `SUB-RULE` | Rule skipped (warning). |
| Any option other than `no-resolve` and `src` | Rule skipped (warning). |
| `src` on a `RULE-SET` | Rule skipped (warning). mihomo matches the set with source and destination swapped. |
| `IP-ASN` payload that is not a number (`AS13335`) | Rule skipped (warning). mihomo keeps such a rule, and it never matches. |
| A `RULE-SET` naming an undefined provider | Rule skipped (warning). |
| An entry of a `classical` rule provider that is not supported | That entry skipped (warning with the count). |

At FakeDNS time only the name is known. A rule that needs the connection (process, network, ports, source) therefore leaves the decision to the dial, and the name gets a fake IP.

IP rules (`IP-CIDR`, `IP-CIDR6`, `IP-SUFFIX`, `IP-ASN`, `GEOIP`, `ipcidr` rule sets) match a domain destination by an address. When the name was sniffed from the connection's first bytes (TLS SNI, HTTP Host), that is the address the client dialed, `no-resolve` or not, as in mihomo, unless `hosts` maps the name. Otherwise the name is looked up once, at the first such rule without `no-resolve`.

### `dns`

With `enable: true`, the profile's resolver answers **app traffic** too: DIRECT dials, `fake-ip-filter` names and the lookups that `GEOIP` / `IP-CIDR` rules need. It works in this order:

1. `hosts`
2. `nameserver-policy`
3. `fallback-filter.domain` / `geosite`, which go to `fallback` only
4. `nameserver` and `fallback` queried together; the `nameserver` answer is replaced when `fallback-filter` rejects it (`geoip` / `geoip-code`, `ipcidr`)

With `enable: false`, the machine's resolver answers. `hosts` applies either way.

Node hostnames follow `proxy-server-nameserver` when it is set, otherwise the same order, unless the app's Override DNS switch is on. For A and AAAA lookups, the upstreams within a set are queried in parallel. Answers that arrive within 150 ms of the first are merged.

| Key / value | What happens |
| --- | --- |
| `tls://`, `quic://`, `tcp://`, `dhcp://`, `system` upstreams | Upstream skipped (warning). Plain UDP (`1.1.1.1`, `udp://…`) and DoH (`https://…`) are supported. |
| `enhanced-mode` other than `fake-ip` | Ignored (warning): TUN always answers with fake IPs. |
| `fake-ip-range` | Ignored (warning): fake IPs come from `198.18.0.0/16`. |
| `fake-ip-filter-mode: whitelist` | Ignored (warning): `fake-ip-filter` lists names that skip fake IPs. |
| `respect-rules` | Ignored (warning): DNS queries do not go through proxy rules. |
| `use-system-hosts: false` | Ignored (warning): `/etc/hosts` always applies. |
| `listen`, `cache-algorithm`, `prefer-h3`, `direct-nameserver-follow-policy` | Ignored. |
| `ipv6-timeout` | Ignored: rule lookups and DIRECT dials ask for AAAA only when a name has no A record, so there is no wait to bound. |
| `nameserver-policy` order | YAML mappings carry no order. Name patterns are tried before `geosite:` / `rule-set:` keys, then alphabetically. |
| `nameserver-policy` `rule-set:` with a `classical` or `ipcidr` provider | That key matches nothing; only `domain` providers apply. |
| DoH URL fragments (`#PROXY`, `#h3=true`) | Ignored: DoH always connects directly. |
| `hosts` values that are domain names (aliases) | That entry skipped. IP literals are read; keys may be exact, `*.x` or `+.x`. |

Non-A / AAAA queries (`TXT`, `MX`, `SRV`, `PTR`) that apps send to the FakeDNS are forwarded in plain UDP to the machine's resolver, not to the profile's upstreams. `HTTPS` / `SVCB` queries get an empty answer.

## Develop

```bash
swift test
```

## License

[Apache License 2.0](LICENSE)
