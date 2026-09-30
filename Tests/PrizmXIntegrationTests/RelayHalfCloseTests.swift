import Foundation
import os
import Testing
@testable import PrizmXCore
import PrizmXProtocols

/// Outbound whose `read` blocks until fed or closed (closing unblocks it).
final class ScriptedOutbound: OutboundConnection, @unchecked Sendable {
    let endpoint = Endpoint(domain: "remote.example", port: 443)
    let halfClose: Bool
    var supportsHalfClose: Bool { halfClose }
    var state: OutboundConnectionState { lock.withLock { closed ? .closed : .established } }
    private let lock = NSLock()
    private var queue: [Data] = []
    private var waiter: CheckedContinuation<Data, Never>?
    private(set) var received = Data()
    private(set) var closed = false
    private(set) var writeClosed = false

    init(halfClose: Bool) { self.halfClose = halfClose }

    /// Empty `data` = EOF.
    func feed(_ data: Data) {
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

    func open() async throws {}

    func write(_ buffer: UnsafeRawBufferPointer) async throws -> Int {
        lock.withLock { received.append(contentsOf: buffer) }
        return buffer.count
    }

    func read(into buffer: UnsafeMutableRawBufferPointer) async throws -> Int {
        let data: Data = await withCheckedContinuation { continuation in
            lock.lock()
            if !queue.isEmpty {
                let next = queue.removeFirst()
                lock.unlock()
                continuation.resume(returning: next)
                return
            }
            if closed {
                lock.unlock()
                continuation.resume(returning: Data())
                return
            }
            waiter = continuation
            lock.unlock()
        }
        let count = min(buffer.count, data.count)
        data.withUnsafeBytes { raw in
            buffer.copyMemory(from: UnsafeRawBufferPointer(rebasing: raw.prefix(count)))
        }
        return count
    }

    func close() async {
        lock.withLock { closed = true }
        feed(Data())
    }

    func closeWrite() async {
        lock.withLock { writeClosed = true }
    }
}

private let target = Endpoint(host: .ipv4(IPv4Address(10, 0, 0, 1)), port: 80)

@Test func inboundEOFHalfClosesOutboundAndKeepsDownlink() async throws {
    let inbound = ScriptedInbound(endpoint: target, halfClose: true)
    let outbound = ScriptedOutbound(halfClose: true)
    inbound.feed(Data("request".utf8))
    inbound.feed(nil)
    let splice = Task {
        await EngineTCPRelay.splice(inbound: inbound, outbound: outbound) { _, _ in }
    }
    // Upload finished: outbound got FIN, not a full close.
    for _ in 0..<200 where !outbound.writeClosed {
        try await Task.sleep(for: .milliseconds(5))
    }
    #expect(outbound.writeClosed)
    #expect(!outbound.closed)
    #expect(outbound.received == Data("request".utf8))

    // The response still reaches the client after the client's FIN.
    outbound.feed(Data("response".utf8))
    outbound.feed(Data())
    let snapshot = await splice.value
    #expect(inbound.written == Data("response".utf8))
    #expect(snapshot.up == 7)
    #expect(snapshot.down == 8)
    #expect(inbound.writeClosed)
    #expect(outbound.closed)
}

@Test func inboundEOFClosesOutboundWithoutHalfCloseSupport() async throws {
    let inbound = ScriptedInbound(endpoint: target)
    let outbound = ScriptedOutbound(halfClose: false)
    inbound.feed(Data("x".utf8))
    inbound.feed(nil)
    _ = await EngineTCPRelay.splice(inbound: inbound, outbound: outbound) { _, _ in }
    #expect(outbound.closed)
    #expect(!outbound.writeClosed)
    #expect(inbound.closed)
}
