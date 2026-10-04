import Foundation
import Testing
@testable import PrizmXConfig
import PrizmXNodes
import PrizmXProtocols

/// Locations and switches of the interop suite.
enum InteropEnvironment {
    /// `Interop/` next to `Package.swift`.
    static let directory = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()   // Support
        .deletingLastPathComponent()   // PrizmXInteropTests
        .deletingLastPathComponent()   // Tests
        .deletingLastPathComponent()   // package root
        .appendingPathComponent("Interop")

    static var environment: [String: String] { ProcessInfo.processInfo.environment }

    /// Set by `Interop/run.sh` once the stack is up.
    static let enabled = environment["PRIZMX_INTEROP"] == "1"
    /// Load suite on top (`PRIZMX_INTEROP_LOAD=1`).
    static let loadEnabled = enabled && environment["PRIZMX_INTEROP_LOAD"] == "1"
    /// Optional `PRIZMX_INTEROP_NODES=a,b` subset.
    static let nodeFilter: Set<String>? = environment["PRIZMX_INTEROP_NODES"].map {
        Set($0.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) })
    }

    /// mihomo (reference client) ports published by docker-compose.yml.
    static let referenceProxyPort: UInt16 = 17890
    static let referenceControllerPort: UInt16 = 19090

    /// The policy group every node sits in.
    static let group = "Interop"

    /// Target services, reachable only through a proxy.
    static let webHost = "web.test"
    static let dnsTarget = Endpoint(domain: "dns.test", port: 53)
    static let echoTarget = Endpoint(domain: "echo.test", port: 7)
    /// The A record `dns.test` serves for any name under `.test`.
    static let dnsAnswer = IPv4Address(198, 51, 100, 7)
}

/// One node of `Interop/profile.yaml` with the suite's expectations.
struct InteropNode: Sendable, CustomTestStringConvertible {
    let name: String
    let node: OutboundNode
    let expectsUDP: Bool
    let expectsHalfClose: Bool
    let checksReference: Bool
    let hasSingboxTwin: Bool
    /// Open bugs by scenario family (`known-issue:`).
    let knownIssues: [String: String]

    var testDescription: String { name }
}

/// `Interop/profile.yaml`, imported through the real Clash importer.
enum InteropProfile {
    static let url = InteropEnvironment.directory.appendingPathComponent("profile.yaml")
    static let singboxURL = InteropEnvironment.directory.appendingPathComponent("profile.singbox.json")

    static let text: String = (try? String(contentsOf: url, encoding: .utf8)) ?? ""

    /// Import result (router, node manager, warnings).
    static func imported() throws -> ConfigParseResult {
        try ClashConfigParser().parseWithWarnings(rawString: text)
    }

    /// Every node with its `interop:` expectations, in profile order.
    static let nodes: [InteropNode] = {
        guard let result = try? imported(),
              let proxies = (try? YAMLParser.parse(text))?.mapping?["proxies"]?.sequence
        else { return [] }
        return proxies.compactMap { item -> InteropNode? in
            guard let name = item.string(for: "name"),
                  let node = result.nodeManager.node(id: name)
            else { return nil }
            let expect = item.mapping?["interop"]
            return InteropNode(
                name: name,
                node: node,
                expectsUDP: expect?.bool(for: "udp", default: false) ?? false,
                expectsHalfClose: expect?.bool(for: "half-close", default: false) ?? false,
                checksReference: expect?.bool(for: "reference", default: true) ?? true,
                hasSingboxTwin: expect?.bool(for: "singbox", default: true) ?? true,
                knownIssues: expect?.mapping?["known-issue"]?.mapping?.compactMapValues(\.string) ?? [:]
            )
        }
    }()

    /// Nodes to exercise (all, or `PRIZMX_INTEROP_NODES`).
    static var selectedNodes: [InteropNode] {
        guard let filter = InteropEnvironment.nodeFilter else { return nodes }
        return nodes.filter { filter.contains($0.name) }
    }

    /// Raw proxy entries' names, for checks that every entry imported.
    static var declaredNames: [String] {
        ((try? YAMLParser.parse(text))?.mapping?["proxies"]?.sequence ?? []).compactMap { $0.string(for: "name") }
    }
}
