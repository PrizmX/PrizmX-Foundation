import Foundation
import os
import Testing
@testable import PrizmXCore
import PrizmXProtocols

/// Inbound whose `read()` ignores task cancellation, like NW / SwiftTCP.
final class ScriptedInbound: InboundStream, @unchecked Sendable {
    let endpoint: Endpoint
    private let lock = NSLock()
    private var queue: [Data?] = []
    private var waiter: CheckedContinuation<Data?, Never>?
    private(set) var written = Data()
    private(set) var closed = false
    private(set) var writeClosed = false
    let halfClose: Bool
    var supportsHalfClose: Bool { halfClose }

    init(endpoint: Endpoint, halfClose: Bool = false) {
        self.endpoint = endpoint
        self.halfClose = halfClose
    }

    /// Delivers `data`; `nil` = EOF.
    func feed(_ data: Data?) {
        lock.lock()
        if let waiter {
            self.waiter = nil
            lock.unlock()
            waiter.resume(returning: data)
            return
        }
        queue.append(data)
        lock.unlock()
    }

    func read() async throws -> Data? {
        await withCheckedContinuation { continuation in
            lock.lock()
            if !queue.isEmpty {
                let next = queue.removeFirst()
                lock.unlock()
                continuation.resume(returning: next)
                return
            }
            waiter = continuation
            lock.unlock()
        }
    }

    func write(_ data: Data) async throws {
        lock.withLock { written.append(data) }
    }

    func close() async {
        lock.withLock { closed = true }
        feed(nil)
    }

    func closeWrite() async {
        lock.withLock { writeClosed = true }
    }
}

private let ipTarget = Endpoint(host: .ipv4(IPv4Address(93, 184, 216, 34)), port: 22)

@Test func sniffTimesOutOnSilentClientAndKeepsLateBytes() async throws {
    let inbound = ScriptedInbound(endpoint: ipTarget)
    let started = ContinuousClock.now
    let prepared = await EngineTCPRelay.prepare(stream: inbound, budget: .milliseconds(100))
    let elapsed = ContinuousClock.now - started
    #expect(elapsed < .seconds(1))
    #expect(prepared.endpoint == ipTarget)

    // Bytes that arrive after the budget reach the relay (not swallowed by
    // the abandoned sniff read).
    inbound.feed(Data("late".utf8))
    let first = try await prepared.stream.read()
    #expect(first == Data("late".utf8))
}

@Test func sniffGivesUpOnSSHBannerImmediately() async throws {
    let inbound = ScriptedInbound(endpoint: ipTarget)
    let banner = Data("SSH-2.0-OpenSSH_9.6\r\n".utf8)
    inbound.feed(banner)
    let started = ContinuousClock.now
    let prepared = await EngineTCPRelay.prepare(stream: inbound, budget: .seconds(5))
    #expect(ContinuousClock.now - started < .seconds(1))
    #expect(prepared.endpoint == ipTarget)
    #expect(try await prepared.stream.read() == banner)
}

@Test func sniffKeepsIPEndpointForIPLiteralHost() async throws {
    for host in ["192.168.1.1", "192.168.1.1:8080", "[::1]", "[::1]:8080"] {
        let inbound = ScriptedInbound(endpoint: Endpoint(host: .ipv4(IPv4Address(192, 168, 1, 1)), port: 80))
        let request = Data("GET / HTTP/1.1\r\nHost: \(host)\r\n\r\n".utf8)
        inbound.feed(request)
        let prepared = await EngineTCPRelay.prepare(stream: inbound, budget: .seconds(2))
        #expect(prepared.endpoint == inbound.endpoint, "\(host)")
        #expect(try await prepared.stream.read() == request)
    }
}

@Test func sniffUsesDomainHost() async throws {
    let inbound = ScriptedInbound(endpoint: Endpoint(host: .ipv4(IPv4Address(1, 2, 3, 4)), port: 80))
    inbound.feed(Data("GET / HTTP/1.1\r\nHost: Example.COM:80\r\n\r\n".utf8))
    let prepared = await EngineTCPRelay.prepare(stream: inbound, budget: .seconds(2))
    #expect(prepared.endpoint == Endpoint(domain: "example.com", port: 80))
}

@Test func sniffPreservesEOFSeenDuringSniff() async throws {
    let inbound = ScriptedInbound(endpoint: ipTarget)
    inbound.feed(Data("GE".utf8))
    inbound.feed(nil)
    let prepared = await EngineTCPRelay.prepare(stream: inbound, budget: .seconds(2))
    #expect(try await prepared.stream.read() == Data("GE".utf8))
    #expect(try await prepared.stream.read() == nil)
}
