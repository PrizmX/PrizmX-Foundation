import Foundation
import Testing

/// Load runs over the same scenarios and nodes (`PRIZMX_INTEROP_LOAD=1`).
///
///   PRIZMX_LOAD_CONCURRENCY  workers per run (8)
///   PRIZMX_LOAD_ITERATIONS   runs per worker (4)
///   PRIZMX_LOAD_BYTES        payload per run (8 MiB)
///   PRIZMX_LOAD_SCENARIOS    download,https,upload,ping,tcp (download,upload)
///   PRIZMX_LOAD_ROUTES       prizmx,reference (both)
///   PRIZMX_LOAD_REPORT       JSON report path (Interop/.generated/load-report.json)
///
/// Reports print per node; the JSON keeps every `LoadReport` for comparing
/// runs (PrizmX vs mihomo, or before / after a change).
@Suite("Interop load", .enabled(if: InteropEnvironment.loadEnabled), .serialized)
struct LoadTests {
    static var environment: [String: String] { InteropEnvironment.environment }

    static var scenarios: [InteropScenario] {
        let bytes = environment["PRIZMX_LOAD_BYTES"].flatMap(Int.init) ?? 8 * 1024 * 1024
        let names = (environment["PRIZMX_LOAD_SCENARIOS"] ?? "download,upload").split(separator: ",")
        return names.compactMap { name -> InteropScenario? in
            switch name.trimmingCharacters(in: .whitespaces) {
            case "download": .httpDownload(bytes: bytes)
            case "https": .httpsDownload(bytes: bytes)
            case "upload": .httpUpload(bytes: bytes)
            case "ping": .httpPing
            case "tcp": .tcpEcho(bytes: bytes)
            default: nil
            }
        }
    }

    static var routes: [InteropRoute] {
        (environment["PRIZMX_LOAD_ROUTES"] ?? "prizmx,reference")
            .split(separator: ",")
            .compactMap { InteropRoute(rawValue: $0.trimmingCharacters(in: .whitespaces)) }
    }

    @Test func loadReport() async throws {
        let plan = LoadPlan.fromEnvironment
        var reports: [LoadReport] = []
        for node in InteropProfile.selectedNodes {
            for route in Self.routes where route == .prizmx || node.checksReference {
                for scenario in Self.scenarios where scenario.routes.contains(route) && scenario.applies(node) {
                    let report = try await LoadRunner.run(scenario, node: node, route: route, plan: plan)
                    print("LOAD \(report)")
                    if report.failures > 0 {
                        Issue.record("\(report): \(report.firstError ?? "")")
                    }
                    reports.append(report)
                }
            }
        }
        let path = Self.environment["PRIZMX_LOAD_REPORT"]
            ?? InteropEnvironment.directory.appendingPathComponent(".generated/load-report.json").path
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(reports).write(to: URL(fileURLWithPath: path))
        print("LOAD report written to \(path)")
    }
}
