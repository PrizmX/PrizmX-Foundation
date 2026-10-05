import Foundation
import Testing
import os
@testable import PrizmXProtocols

private final class StubCore: AnyTLSSessionCore, @unchecked Sendable {
    private let store = OSAllocatedUnfairLock(initialState: ([AnyTLSFrame](), [UInt32]()))

    var frames: [AnyTLSFrame] { store.withLock { $0.0 } }
    var closedStreams: [UInt32] { store.withLock { $0.1 } }

    func send(_ frame: AnyTLSFrame) async throws {
        store.withLock { $0.0.append(frame) }
    }

    func closeStream(_ id: UInt32) async {
        store.withLock { $0.1.append(id) }
    }
}

private let testTarget = Endpoint(domain: "www.google.com", port: 443)
private let testIdentity = AnyTLSServerIdentity(
    server: Endpoint(domain: "node.example.com", port: 443),
    password: "secret",
    sni: "cdn.example.com"
)

@Test func streamReadReturnsIngestedData() async throws {
    let core = StubCore()
    let stream = AnyTLSSessionStream(id: 7, target: testTarget, core: core)
    stream.ingest(Data("hello".utf8))
    let data = try await stream.readData()
    #expect(data == Data("hello".utf8))
}

@Test func streamReadWaitsThenReceives() async throws {
    let core = StubCore()
    let stream = AnyTLSSessionStream(id: 7, target: testTarget, core: core)
    let reader = Task { try await stream.readData() }
    try await Task.sleep(for: .milliseconds(50))
    stream.ingest(Data("late".utf8))
    #expect(try await reader.value == Data("late".utf8))
}

@Test func streamFinEndsReads() async throws {
    let core = StubCore()
    let stream = AnyTLSSessionStream(id: 7, target: testTarget, core: core)
    stream.finishInput()
    #expect(try await stream.readData() == nil)
}

@Test func streamFailureFailsPendingAndFutureReads() async throws {
    let core = StubCore()
    let stream = AnyTLSSessionStream(id: 7, target: testTarget, core: core)
    stream.fail(OutboundError.unreachable(testIdentity.server))
    await #expect(throws: OutboundError.self) {
        _ = try await stream.readData()
    }
}

@Test func streamAckSuccessAndError() async throws {
    let core = StubCore()
    let ok = AnyTLSSessionStream(id: 1, target: testTarget, core: core)
    ok.acknowledge(errorMessage: nil)
    try await ok.waitAck(timeout: .seconds(1))

    let bad = AnyTLSSessionStream(id: 2, target: testTarget, core: core)
    bad.acknowledge(errorMessage: "target unreachable")
    await #expect(throws: AnyTLSError.self) {
        try await bad.waitAck(timeout: .seconds(1))
    }
}

@Test func streamCloseFinsOnlyThisStream() async throws {
    let core = StubCore()
    let stream = AnyTLSSessionStream(id: 9, target: testTarget, core: core)
    await stream.close()
    #expect(core.closedStreams == [9])
    // Idempotent
    await stream.close()
    #expect(core.closedStreams == [9])
}

@Test func streamReadAfterCloseEnds() async throws {
    let core = StubCore()
    let stream = AnyTLSSessionStream(id: 10, target: testTarget, core: core)
    await stream.close()
    // Nothing ingests or finishes a closed stream: a read that lost the race
    // with close() used to park forever.
    let result = OSAllocatedUnfairLock<(done: Bool, data: Data?)>(initialState: (false, nil))
    _ = Task {
        let data = try await stream.readData()
        result.withLock { $0 = (true, data) }
    }
    try await Task.sleep(for: .milliseconds(100))
    #expect(result.withLock { $0.done })
    #expect(result.withLock { $0.data } == nil)
}

@Test func poolBusySessionDoesNotTakeASecondStream() async throws {
    let pool = AnyTLSSessionPool()
    let calls = CallCounter()
    await pool.setEstablishForTesting { identity in
        calls.increment()
        return AnyTLSSession.makeForTesting(identity: identity)
    }
    _ = try await pool.openStream(identity: testIdentity, to: testTarget)
    _ = try await pool.openStream(identity: testIdentity, to: testTarget)
    #expect(calls.value == 2)
    #expect(await pool.sessionCount(for: testIdentity) == 2)
    #expect(await pool.idleCount(for: testIdentity) == 0)
}

@Test func poolReusesNewestIdleSession() async throws {
    let pool = AnyTLSSessionPool()
    await pool.setEstablishForTesting { identity in
        AnyTLSSession.makeForTesting(identity: identity)
    }
    let first = try await pool.openStream(identity: testIdentity, to: testTarget)
    await first.close()
    try await Task.sleep(for: .milliseconds(30))
    #expect(await pool.idleCount(for: testIdentity) == 1)
    _ = try await pool.openStream(identity: testIdentity, to: testTarget)
    #expect(await pool.sessionCount(for: testIdentity) == 1)
    #expect(await pool.idleCount(for: testIdentity) == 0)
}

@Test func poolEvictsTerminatedSession() async throws {
    let pool = AnyTLSSessionPool()
    await pool.setEstablishForTesting { identity in
        AnyTLSSession.makeForTesting(identity: identity)
    }
    let first = try await pool.openStream(identity: testIdentity, to: testTarget)
    #expect(await pool.sessionCount(for: testIdentity) == 1)
    await first.close()
    try await Task.sleep(for: .milliseconds(30))
    #expect(await pool.idleCount(for: testIdentity) == 1)
    // Terminate the idle session; next open must dial again.
    await pool.reset()
    _ = try await pool.openStream(identity: testIdentity, to: testTarget)
    #expect(await pool.sessionCount(for: testIdentity) == 1)
}

private final class CallCounter: @unchecked Sendable {
    private let count = OSAllocatedUnfairLock(initialState: 0)
    var value: Int { count.withLock { $0 } }
    func increment() { count.withLock { $0 += 1 } }
}

// MARK: - Backpressure / SYNACK failure

@Test func streamSignalsBackpressureAtCapAndResumesAfterDrain() async throws {
    let core = StubCore()
    let stream = AnyTLSSessionStream(id: 3, target: testTarget, core: core)
    #expect(!stream.ingest(Data(count: 1024)))
    #expect(stream.ingest(Data(count: AnyTLSSessionStream.receiveBufferLimit)))

    let drained = OSAllocatedUnfairLock(initialState: false)
    let waiter = Task {
        await stream.waitUntilDrained()
        drained.withLock { $0 = true }
    }
    try await Task.sleep(for: .milliseconds(50))
    #expect(!drained.withLock { $0 })

    let data = try await stream.readData()
    #expect(data?.count == 1024 + AnyTLSSessionStream.receiveBufferLimit)
    await waiter.value
    #expect(drained.withLock { $0 })
    #expect(stream.bufferedByteCount == 0)
}

@Test func streamCloseReleasesBackpressureWaiter() async throws {
    let core = StubCore()
    let stream = AnyTLSSessionStream(id: 4, target: testTarget, core: core)
    #expect(stream.ingest(Data(count: AnyTLSSessionStream.receiveBufferLimit)))
    let waiter = Task { await stream.waitUntilDrained() }
    try await Task.sleep(for: .milliseconds(20))
    await stream.close()
    await waiter.value
}

@Test func synAckErrorWakesBlockedReaderAndRefusesWrites() async throws {
    let core = StubCore()
    let stream = AnyTLSSessionStream(id: 5, target: testTarget, core: core)
    let reader = Task { try await stream.readData() }
    try await Task.sleep(for: .milliseconds(30))
    stream.acknowledge(errorMessage: "dial tcp: refused")
    await #expect(throws: AnyTLSError.self) {
        _ = try await reader.value
    }
    let scratch = UnsafeMutableRawBufferPointer.allocate(byteCount: 3, alignment: 8)
    defer { scratch.deallocate() }
    scratch.copyBytes(from: [1, 2, 3] as [UInt8])
    let raw = UnsafeRawBufferPointer(scratch)
    await #expect(throws: AnyTLSError.self) {
        try await stream.write(raw)
    }
    #expect(core.frames.isEmpty)
}

// MARK: - Pool idle cleanup under reentrancy

private final class Gate: @unchecked Sendable {
    private let state = OSAllocatedUnfairLock<(open: Bool, waiters: [CheckedContinuation<Void, Never>])>(
        initialState: (false, [])
    )

    func wait() async {
        await withCheckedContinuation { continuation in
            let resumeNow = state.withLock { box -> Bool in
                if box.open { return true }
                box.waiters.append(continuation)
                return false
            }
            if resumeNow { continuation.resume() }
        }
    }

    var hasWaiter: Bool { state.withLock { !$0.waiters.isEmpty } }

    func open() {
        let waiters = state.withLock { box -> [CheckedContinuation<Void, Never>] in
            box.open = true
            defer { box.waiters.removeAll() }
            return box.waiters
        }
        for waiter in waiters { waiter.resume() }
    }
}

@Test func idleCleanupDoesNotClobberConcurrentPoolChanges() async throws {
    let pool = AnyTLSSessionPool()
    let now = ContinuousClock.now
    let older = AnyTLSSession.makeForTesting(identity: testIdentity)
    let newer = AnyTLSSession.makeForTesting(identity: testIdentity)
    await pool.insertIdleForTesting(newer, identity: testIdentity, idleSince: now)
    await pool.insertIdleForTesting(older, identity: testIdentity, idleSince: now)
    #expect(await pool.nextSeqForTesting(testIdentity) == 2)

    // The first probe suspends; meanwhile the pool hands `newer` out and a
    // third session is created.
    let gate = Gate()
    newer.probeOverrideForTesting = {
        await gate.wait()
        return true
    }
    let cleanup = Task { await pool.idleCleanup() }
    while !gate.hasWaiter { try await Task.sleep(for: .milliseconds(5)) }

    let taken = await pool.takeIdleForTesting(testIdentity)
    #expect(taken === newer)
    let third = AnyTLSSession.makeForTesting(identity: testIdentity)
    await pool.insertIdleForTesting(third, identity: testIdentity, idleSince: now)
    gate.open()
    await cleanup.value

    #expect(await pool.nextSeqForTesting(testIdentity) == 3)
    #expect(await pool.idleCount(for: testIdentity) == 2)
    // The taken session must not be resurrected into the idle list.
    #expect(await pool.takeIdleForTesting(testIdentity) !== newer)
    #expect(await pool.takeIdleForTesting(testIdentity) !== newer)
}
