import Darwin
import Foundation
import PrizmXConfig
import PrizmXCore
import PrizmXNodes
import PrizmXProtocols
import os

/// Whose client carries a scenario's traffic.
enum InteropRoute: String, Sendable, Codable, CaseIterable {
    /// PrizmX: HTTP through the engine's mixed-port; stream and UDP
    /// scenarios through the node's outbound directly.
    case prizmx
    /// mihomo with the same node selected (HTTP only).
    case reference
}

/// The engine and mixed-port built from `profile.yaml`, shared by all tests
/// in the process, plus node selection on both routes.
actor InteropHarness {
    static let shared = InteropHarness()

    private var engine: Engine?
    private var server: MixedPortServer?
    private(set) var mixedPort: UInt16 = 0

    /// Starts the engine and mixed-port once.
    func start() async throws -> Engine {
        if let engine { return engine }
        let result = try InteropProfile.imported()
        let engine = Engine(router: result.router, nodeManager: result.nodeManager)
        let port = try Self.freeLoopbackPort()
        let server = MixedPortServer(engine: engine, port: port)
        try await server.start()
        self.engine = engine
        self.server = server
        mixedPort = port
        return engine
    }

    /// HTTP proxy port for `route`, with `node` selected on it.
    func prepare(_ node: InteropNode, route: InteropRoute) async throws -> UInt16 {
        switch route {
        case .prizmx:
            let engine = try await start()
            try engine.nodeManager.select(nodeID: node.name, inGroup: InteropEnvironment.group)
            return mixedPort
        case .reference:
            try await Self.selectReference(node.name)
            return InteropEnvironment.referenceProxyPort
        }
    }

    /// `PUT /proxies/Interop` on mihomo's controller.
    private static func selectReference(_ name: String) async throws {
        let base = "http://127.0.0.1:\(InteropEnvironment.referenceControllerPort)"
        var request = URLRequest(url: URL(string: "\(base)/proxies/\(InteropEnvironment.group)")!)
        request.httpMethod = "PUT"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: ["name": name])
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        let (data, response) = try await URLSession(configuration: configuration).data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 204 else {
            throw InteropHTTPError.badReply("mihomo select \(name): \(String(decoding: data, as: UTF8.self))")
        }
    }

    /// An unused 127.0.0.1 TCP port (bind to 0, read it back, release).
    private static func freeLoopbackPort() throws -> UInt16 {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.EMFILE) }
        defer { close(fd) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        address.sin_port = 0
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { generic -> Int32 in
                guard bind(fd, generic, length) == 0 else { return -1 }
                return getsockname(fd, generic, &length)
            }
        }
        guard bound == 0 else { throw POSIXError(.EADDRINUSE) }
        return UInt16(bigEndian: address.sin_port)
    }
}

/// Runs `body`; past `limit` it calls `cancel`, which must unblock `body`
/// (close the connection a read is parked on), and the failure is reported
/// as `InteropTimeout`.
func withInteropTimeout<T: Sendable>(
    _ limit: Duration,
    cancel: @escaping @Sendable () async -> Void,
    _ body: () async throws -> T
) async throws -> T {
    let fired = OSAllocatedUnfairLock(initialState: false)
    let timer = Task {
        try await Task.sleep(for: limit)
        fired.withLock { $0 = true }
        await cancel()
    }
    defer { timer.cancel() }
    do {
        let value = try await body()
        if fired.withLock({ $0 }) { throw InteropTimeout(limit: limit, underlying: nil) }
        return value
    } catch let error as InteropTimeout {
        throw error
    } catch {
        if fired.withLock({ $0 }) { throw InteropTimeout(limit: limit, underlying: error) }
        throw error
    }
}

struct InteropTimeout: Error, CustomStringConvertible {
    let limit: Duration
    let underlying: Error?
    var description: String { "timed out after \(limit)" + (underlying.map { " (\($0))" } ?? "") }
}
