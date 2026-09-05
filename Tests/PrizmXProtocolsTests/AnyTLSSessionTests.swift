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
