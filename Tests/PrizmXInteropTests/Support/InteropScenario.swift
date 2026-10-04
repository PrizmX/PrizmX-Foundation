import Foundation
import Testing
@testable import PrizmXNodes
@testable import PrizmXProtocols

/// What a scenario run gets: the node, the route, an HTTP client already
/// pointed at that route's proxy, and a per-run seed for payloads.
struct ScenarioContext: Sendable {
    let node: InteropNode
    let route: InteropRoute
    let http: ProxyHTTPClient
    let seed: UInt64
}

/// One kind of real traffic through a node. Correctness tests run each once
/// with small sizes; `LoadRunner` runs the same scenario concurrently and
/// repeatedly. New protocols need no new scenarios: they are new nodes.
struct InteropScenario: Sendable, CustomTestStringConvertible {
    let name: String
    /// `http`, `https`, `tcp`, `half-close` or `udp` (keys of `known-issue:`).
    let family: String
    /// Routes that can carry it (stream / UDP scenarios are PrizmX only).
    let routes: Set<InteropRoute>
    /// Whether the node is expected to support it.
    let applies: @Sendable (InteropNode) -> Bool
    let run: @Sendable (ScenarioContext) async throws -> TransferSample

    var testDescription: String { name }
}

extension InteropScenario {
    static func httpDownload(bytes: Int) -> InteropScenario {
        InteropScenario(name: "http-download-\(bytes)", family: "http", routes: [.prizmx, .reference], applies: { _ in true }) {
            try await $0.http.download(bytes: bytes, seed: $0.seed)
        }
    }

    /// End-to-end TLS to `https://web.test` inside the proxy tunnel.
    static func httpsDownload(bytes: Int) -> InteropScenario {
        InteropScenario(name: "https-download-\(bytes)", family: "https", routes: [.prizmx, .reference], applies: { _ in true }) {
            try await $0.http.download(bytes: bytes, seed: $0.seed, tls: true)
        }
    }

    static func httpUpload(bytes: Int) -> InteropScenario {
        InteropScenario(name: "http-upload-\(bytes)", family: "http", routes: [.prizmx, .reference], applies: { _ in true }) {
            try await $0.http.upload(bytes: bytes, seed: $0.seed)
        }
    }

    static let httpPing = InteropScenario(name: "http-ping", family: "http", routes: [.prizmx, .reference], applies: { _ in true }) {
        try await $0.http.ping()
    }

    /// A real DNS query to `dns.test` over the node's UDP relay.
    static let dnsQuery = InteropScenario(name: "udp-dns", family: "udp", routes: [.prizmx], applies: { $0.expectsUDP }) { context in
        let outbound = try #require(try NodeFactory.makeDatagramOutbound(from: context.node.node, to: InteropEnvironment.dnsTarget))
        try await outbound.open()
        defer { Task { await outbound.close() } }
        let id = UInt16(truncatingIfNeeded: context.seed)
        let query = DNSWire.makeQuery(id: id, domain: "probe-\(context.seed).test")
        let start = ContinuousClock.now
        try await outbound.send(query, to: InteropEnvironment.dnsTarget)
        let reply = try await withInteropTimeout(.seconds(5), cancel: { await outbound.close() }) {
            try await outbound.receive()
        }
        let records = DNSWire.aRecords(in: try #require(reply), expectedID: id)
        guard records.map(\.address) == [InteropEnvironment.dnsAnswer] else {
            throw InteropHTTPError.badReply("DNS answer \(records)")
        }
        return TransferSample(bytes: query.count, duration: ContinuousClock.now - start)
    }

    /// Datagrams up to a typical MTU payload, echoed back.
    static func udpEcho(bytes: Int) -> InteropScenario {
        InteropScenario(name: "udp-echo-\(bytes)", family: "udp", routes: [.prizmx], applies: { $0.expectsUDP }) { context in
            let target = InteropEnvironment.echoTarget
            let outbound = try #require(try NodeFactory.makeDatagramOutbound(from: context.node.node, to: target))
            try await outbound.open()
            defer { Task { await outbound.close() } }
            var pattern = PayloadPattern(seed: context.seed)
            let payload = pattern.next(bytes)
            let start = ContinuousClock.now
            try await outbound.send(payload, to: target)
            let reply = try await withInteropTimeout(.seconds(5), cancel: { await outbound.close() }) {
                try await outbound.receive()
            }
            guard reply == payload else { throw InteropHTTPError.badReply("UDP echo of \(reply?.count ?? 0) bytes") }
            return TransferSample(bytes: bytes, duration: ContinuousClock.now - start)
        }
    }

    /// Full-duplex stream: upload while reading the echo back.
    static func tcpEcho(bytes: Int) -> InteropScenario {
        InteropScenario(name: "tcp-echo-\(bytes)", family: "tcp", routes: [.prizmx], applies: { _ in true }) { context in
            let connection = try NodeFactory.makeConnection(from: context.node.node, to: InteropEnvironment.echoTarget)
            try await connection.open()
            defer { Task { await connection.close() } }
            var pattern = PayloadPattern(seed: context.seed)
            let payload = pattern.next(bytes)
            let start = ContinuousClock.now
            async let upload: Void = connection.writeAll(payload)
            var check = PayloadPattern(seed: context.seed)
            var received = 0
            while received < bytes {
                let chunk = try await withInteropTimeout(.seconds(10), cancel: { await connection.close() }) {
                    try await connection.readData(upTo: 64 * 1024)
                }
                guard !chunk.isEmpty else { break }
                if let offset = check.firstMismatch(in: chunk) {
                    throw InteropHTTPError.mismatch(offset: received + offset)
                }
                received += chunk.count
            }
            try await upload
            guard received == bytes else { throw InteropHTTPError.shortBody(expected: bytes, actual: received) }
            return TransferSample(bytes: bytes * 2, duration: ContinuousClock.now - start)
        }
    }

    /// `closeWrite` must reach the target as EOF: it closes, and the
    /// downlink delivers everything and then EOF.
    static func tcpHalfClose(bytes: Int) -> InteropScenario {
        InteropScenario(name: "tcp-half-close", family: "half-close", routes: [.prizmx], applies: { $0.expectsHalfClose }) { context in
            let connection = try NodeFactory.makeConnection(from: context.node.node, to: InteropEnvironment.echoTarget)
            try await connection.open()
            defer { Task { await connection.close() } }
            var pattern = PayloadPattern(seed: context.seed)
            let payload = pattern.next(bytes)
            let start = ContinuousClock.now
            try await connection.writeAll(payload)
            await connection.closeWrite()
            var received = Data()
            while true {
                let chunk = try await withInteropTimeout(.seconds(10), cancel: { await connection.close() }) {
                    try await connection.readData(upTo: 64 * 1024)
                }
                if chunk.isEmpty { break }
                received.append(chunk)
            }
            guard received == payload else { throw InteropHTTPError.shortBody(expected: bytes, actual: received.count) }
            return TransferSample(bytes: bytes, duration: ContinuousClock.now - start)
        }
    }
}

// MARK: - Load

/// How hard `LoadRunner` drives a scenario.
struct LoadPlan: Sendable, Codable {
    /// Parallel workers.
    var concurrency: Int
    /// Runs per worker.
    var iterations: Int

    /// `PRIZMX_LOAD_CONCURRENCY` / `PRIZMX_LOAD_ITERATIONS`.
    static var fromEnvironment: LoadPlan {
        let environment = InteropEnvironment.environment
        return LoadPlan(
            concurrency: environment["PRIZMX_LOAD_CONCURRENCY"].flatMap(Int.init) ?? 8,
            iterations: environment["PRIZMX_LOAD_ITERATIONS"].flatMap(Int.init) ?? 4
        )
    }
}

/// Aggregate of one scenario × node × route under a plan.
struct LoadReport: Sendable, Codable, CustomStringConvertible {
    var node: String
    var route: InteropRoute
    var scenario: String
    var plan: LoadPlan
    var runs: Int
    var failures: Int
    var firstError: String?
    var bytes: Int
    var wallSeconds: Double
    var latencyMillis: Percentiles

    struct Percentiles: Sendable, Codable {
        var p50: Double
        var p90: Double
        var p99: Double
        var max: Double

        init(_ samples: [Double]) {
            let sorted = samples.sorted()
            func at(_ q: Double) -> Double {
                guard !sorted.isEmpty else { return 0 }
                return sorted[min(sorted.count - 1, Int(Double(sorted.count - 1) * q))]
            }
            p50 = at(0.5); p90 = at(0.9); p99 = at(0.99); max = sorted.last ?? 0
        }
    }

    var megabitsPerSecond: Double {
        wallSeconds > 0 ? Double(bytes) * 8 / wallSeconds / 1_000_000 : 0
    }

    var description: String {
        let throughput = String(format: "%.1f", megabitsPerSecond)
        let latency = String(format: "p50 %.1f / p99 %.1f ms", latencyMillis.p50, latencyMillis.p99)
        return "\(node) [\(route.rawValue)] \(scenario) ×\(runs): \(throughput) Mbit/s, \(latency), failures \(failures)"
    }
}

enum LoadRunner {
    /// Runs `scenario` `plan.concurrency × plan.iterations` times on `route`.
    /// Failures are counted, not thrown, so a report shows the error rate.
    static func run(
        _ scenario: InteropScenario,
        node: InteropNode,
        route: InteropRoute,
        plan: LoadPlan
    ) async throws -> LoadReport {
        let port = try await InteropHarness.shared.prepare(node, route: route)
        let http = ProxyHTTPClient(proxyPort: port, maxConnections: plan.concurrency)
        defer { http.invalidate() }

        let start = ContinuousClock.now
        let outcomes = await withTaskGroup(of: [Result<TransferSample, Error>].self) { group in
            for worker in 0..<plan.concurrency {
                group.addTask {
                    var results: [Result<TransferSample, Error>] = []
                    for iteration in 0..<plan.iterations {
                        let seed = UInt64(worker) << 32 | UInt64(iteration)
                        let context = ScenarioContext(node: node, route: route, http: http, seed: seed)
                        do {
                            results.append(.success(try await scenario.run(context)))
                        } catch {
                            results.append(.failure(error))
                        }
                    }
                    return results
                }
            }
            var all: [Result<TransferSample, Error>] = []
            for await results in group { all += results }
            return all
        }
        let wall = ContinuousClock.now - start

        let samples = outcomes.compactMap { try? $0.get() }
        let errors = outcomes.compactMap { outcome -> Error? in
            if case .failure(let error) = outcome { return error }
            return nil
        }
        return LoadReport(
            node: node.name,
            route: route,
            scenario: scenario.name,
            plan: plan,
            runs: outcomes.count,
            failures: errors.count,
            firstError: errors.first.map { "\($0)" },
            bytes: samples.reduce(0) { $0 + $1.bytes },
            wallSeconds: wall.seconds,
            latencyMillis: .init(samples.map { $0.duration.seconds * 1000 })
        )
    }
}

extension Duration {
    var seconds: Double {
        Double(components.seconds) + Double(components.attoseconds) / 1e18
    }
}
