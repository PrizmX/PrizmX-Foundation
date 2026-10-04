import Foundation
import os
import Testing
@testable import PrizmXCore

@Suite("Relay pipe")
struct RelayPipeTests {
    private struct Boom: Error {}

    @Test func deliversInOrderThenEnds() async throws {
        let pipe = RelayPipe(capacity: 1024)
        let producer = Task {
            for index in 0..<50 {
                _ = await pipe.push(Data([UInt8(index)]))
            }
            pipe.finish()
        }
        var seen: [UInt8] = []
        while let chunk = try await pipe.pop() { seen += chunk }
        await producer.value
        #expect(seen == (0..<50).map(UInt8.init))
    }

    @Test func producerWaitsWhileFull() async throws {
        let pipe = RelayPipe(capacity: 4)
        let pushed = OSAllocatedUnfairLock(initialState: 0)
        let producer = Task {
            for _ in 0..<3 {
                _ = await pipe.push(Data(count: 4))
                pushed.withLock { $0 += 1 }
            }
            pipe.finish()
        }
        try await Task.sleep(for: .milliseconds(50))
        // The first push fills the pipe and parks until a pop frees space.
        #expect(pushed.withLock { $0 } == 0)
        var total = 0
        while let chunk = try await pipe.pop() { total += chunk.count }
        await producer.value
        #expect(total == 12)
        #expect(pushed.withLock { $0 } == 3)
    }

    @Test func errorSurfacesAfterQueuedData() async throws {
        let pipe = RelayPipe(capacity: 1024)
        _ = await pipe.push(Data([1]))
        pipe.finish(throwing: Boom())
        #expect(try await pipe.pop() == Data([1]))
        await #expect(throws: Boom.self) { try await pipe.pop() }
    }

    @Test func cancelReleasesABlockedProducer() async throws {
        let pipe = RelayPipe(capacity: 1)
        let producer = Task { () -> [Bool] in
            [await pipe.push(Data([1])), await pipe.push(Data([2]))]
        }
        try await Task.sleep(for: .milliseconds(50))
        // The first push fills the pipe and parks; cancelling drops its data.
        pipe.cancel()
        #expect(await producer.value == [false, false])
    }
}
