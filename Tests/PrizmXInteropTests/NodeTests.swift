import Foundation
import Testing

/// Every profile node against its real server, with real requests to
/// targets that only a working proxy can reach. Needs `Interop/run.sh`.
///
/// Serialized: the node selection (engine group and mihomo) is global.
@Suite("Interop nodes", .enabled(if: InteropEnvironment.enabled), .serialized)
struct NodeTests {
    /// Correctness pass: each applicable scenario once, small sizes.
    static let scenarios: [InteropScenario] = [
        .httpPing,
        .httpDownload(bytes: 64 * 1024),
        .httpDownload(bytes: 4 * 1024 * 1024),
        .httpsDownload(bytes: 1024 * 1024),
        .httpUpload(bytes: 1024 * 1024),
        .tcpEcho(bytes: 256 * 1024),
        .tcpHalfClose(bytes: 20_000),
        .dnsQuery,
        .udpEcho(bytes: 1200),
    ]

    /// Reference pass on mihomo: proves the server side of each node works,
    /// so a PrizmX failure on a node mihomo passes is ours.
    static let referenceScenarios: [InteropScenario] = [
        .httpDownload(bytes: 1024 * 1024),
        .httpsDownload(bytes: 256 * 1024),
        .httpUpload(bytes: 256 * 1024),
    ]

    @Test(arguments: InteropProfile.selectedNodes)
    func prizmx(node: InteropNode) async throws {
        try await run(Self.scenarios, node: node, route: .prizmx)
        // A few connections in parallel through the same node.
        let report = try await LoadRunner.run(
            .httpDownload(bytes: 256 * 1024),
            node: node,
            route: .prizmx,
            plan: LoadPlan(concurrency: 8, iterations: 2)
        )
        #expect(report.failures == 0, "parallel downloads: \(report.firstError ?? "")")
    }

    @Test(arguments: InteropProfile.selectedNodes.filter(\.checksReference))
    func reference(node: InteropNode) async throws {
        try await run(Self.referenceScenarios, node: node, route: .reference)
    }

    private func run(_ scenarios: [InteropScenario], node: InteropNode, route: InteropRoute) async throws {
        let port = try await InteropHarness.shared.prepare(node, route: route)
        let http = ProxyHTTPClient(proxyPort: port)
        defer { http.invalidate() }
        for scenario in scenarios where scenario.routes.contains(route) && scenario.applies(node) {
            let context = ScenarioContext(node: node, route: route, http: http, seed: .random(in: 0...UInt64.max))
            if let reason = node.knownIssues[scenario.family] {
                // Reported as a known issue; flags itself once it passes.
                await withKnownIssue(Comment(rawValue: reason)) {
                    _ = try await scenario.run(context)
                }
                continue
            }
            do {
                _ = try await scenario.run(context)
            } catch {
                Issue.record("\(scenario.name) via \(route.rawValue): \(error)")
            }
        }
    }
}
