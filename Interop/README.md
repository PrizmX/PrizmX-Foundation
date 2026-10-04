# Interop suite

End-to-end tests of every outbound protocol against real servers, with real
requests to targets that only a working proxy can reach. Opt-in: plain
`swift test` runs only the profile checks; `./Interop/run.sh` runs everything.

## Overview

```
macOS host: PrizmXInteropTests
  imports profile.yaml → Engine → mixed-port (127.0.0.1, ephemeral)
    URLSession (HTTP / HTTPS)          node outbounds (TCP echo, UDP)
              │                                  │
              └──────────► published ports ◄─────┘
                                 │
        sing-box · Xray · shadowsocks-libev (+ obfs, v2ray-plugin)
                                 │  "targets" network (internal: true)
                                 ▼
          target: web.test :80/:443 · dns.test :53/udp · echo.test :7

mihomo (reference client) loads the same nodes; the suite drives it through
its mixed-port and controller to tell server-side problems from ours.
```

The `targets` network has no published ports and no route out. A request that
reaches `web.test`, `dns.test` or `echo.test` therefore went through a proxy
server; no test can pass by accident over a direct path.

## Flow of a run

1. `run.sh` issues a test CA plus certificates for the proxy servers
   (`interop.prizmx.test`) and the target (`web.test`), derives mihomo's profile
   from `profile.yaml`, starts the compose stack and waits for it.
2. `ProfileTests` check the profiles (also without Docker): every node imports
   without warnings, `profile.singbox.json` imports to identical nodes, and the
   `udp:` expectations match what each node can do.
3. `NodeTests.prizmx` selects each node in the engine's `Interop` group and runs
   the scenarios that apply to it, then 8 parallel downloads.
4. `NodeTests.reference` runs HTTP scenarios through mihomo with the same node.
5. With `PRIZMX_INTEROP_LOAD=1`, `LoadTests` run the load plan and write a JSON
   report. The stack is torn down at the end (unless `PRIZMX_INTEROP_KEEP=1`).

## Scenarios

| Scenario | Route | Checks |
| --- | --- | --- |
| `http-ping` / `http-download-N` / `http-upload-N` | PrizmX mixed-port, mihomo | status and every payload byte |
| `https-download-N` | PrizmX mixed-port, mihomo | TLS to `web.test` inside the tunnel (test CA only), payload bytes |
| `tcp-echo-N` | node outbound | full-duplex stream integrity |
| `tcp-half-close` | node outbound | `closeWrite` reaches the target as EOF |
| `udp-dns` / `udp-echo-N` | node `DatagramOutbound` | a real DNS answer from `dns.test`; datagram echo |

Payloads are a seeded xorshift64* stream (`target/main.go`,
`Tests/PrizmXInteropTests/Support/PayloadPattern.swift`). Both sides generate it
on the fly and verify while streaming, so sizes are only limited by time.

## Files

| Path | Role |
| --- | --- |
| `profile.yaml` | Every node (Clash format), with `interop:` expectations. The single source of truth |
| `profile.singbox.json` | The same nodes in sing-box format (importer parity only) |
| `docker-compose.yml` | Networks, servers (pinned image versions), target, mihomo |
| `servers/` | Server configs: `sing-box.json`, `xray.json`, `ss-libev/` |
| `target/` | Go target: web, DNS, echo |
| `run.sh` | Certificates, mihomo profile, stack lifecycle, `swift test` |
| `../Tests/PrizmXInteropTests/` | Harness, scenarios, load runner, tests |

## Adding a protocol or variant

1. Add an inbound to a server config under `servers/` (or a new service in
   `docker-compose.yml` on both networks, publishing its own port range).
2. Add one node to `profile.yaml` with its `interop:` expectations, and its
   sing-box twin to `profile.singbox.json` (or `singbox: false`).
3. Run `swift test --filter PrizmXInteropTests` (profile checks), then
   `./Interop/run.sh`.

No test code changes: scenarios apply to every node by its expectations. An
open bug goes under `known-issue: {<family>: "reason"}`, so it shows as a known
issue instead of failing the run, and flags itself once it passes.

## Load testing

```sh
PRIZMX_INTEROP_LOAD=1 PRIZMX_INTEROP_FILTER=loadReport \
PRIZMX_INTEROP_NODES=ss-aes128@sing-box,vless-reality-vision@xray \
PRIZMX_LOAD_CONCURRENCY=16 PRIZMX_LOAD_ITERATIONS=8 PRIZMX_LOAD_BYTES=67108864 \
PRIZMX_LOAD_SCENARIOS=download,upload,tcp PRIZMX_INTEROP_RELEASE=1 \
./Interop/run.sh
```

Every scenario × node × route yields a `LoadReport` (throughput, latency
p50/p90/p99/max, failure count and first error), printed as `LOAD …` lines and
written to `.generated/load-report.json` (`PRIZMX_LOAD_REPORT` overrides). The
`reference` route runs the same plan through mihomo for comparison. Use the
optimized build (`PRIZMX_INTEROP_RELEASE=1`, i.e. `-c release -Xswiftc
-enable-testing`) for numbers worth comparing; debug builds measure the
harness as much as the proxy.

For new load shapes, add an `InteropScenario` (or call `LoadRunner.run` with
your own plan); nodes, routes and reports come for free.

## Known limitations

- The client runs on the macOS host (Network.framework), not in a container.
  Docker Desktop's port forwarding sits in every path.
- No TUN: UDP scenarios use the node's `DatagramOutbound` directly, not the
  packet path.
- Half-close is only expected where the path can carry it (TCP FIN or VMess's
  end chunk). WebSocket, mux.cool, simple-obfs and Network.framework TLS
  cannot, and AnyTLS treats FIN as a full close.
- GitHub's macOS runners have no Docker, so the suite is local-only.
