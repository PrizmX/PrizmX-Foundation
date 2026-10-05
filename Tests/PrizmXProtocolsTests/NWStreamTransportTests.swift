import Foundation
import Network
import Testing
import os
@testable import PrizmXProtocols

@Suite("NWStreamTransport")
struct NWStreamTransportTests {

    @Test func closeCancelsASocketThePeerFailed() async throws {
        let target = Endpoint(domain: "example.com", port: 443)
        let transport = NWStreamTransport(queueLabel: "prizmx.test.transport", endpoint: target, errorPeer: target)
        let cancelled = OSAllocatedUnfairLock(initialState: false)
        // Loopback port 1: refused, so the socket never carries data.
        let nw = NWConnection(host: "127.0.0.1", port: 1, using: .tcp)
        nw.stateUpdateHandler = { state in
            if case .cancelled = state { cancelled.withLock { $0 = true } }
        }
        nw.start(queue: transport.queue)
        transport.attach(nw)
        transport.markEstablished()
        // What the post-ready state handler does on `.failed`: the socket
        // stays attached so reads can drain it.
        transport.markClosed()
        try transport.ensureReadable()

        await transport.close()
        #expect(transport.connection == nil)
        #expect(throws: OutboundError.self) { try transport.ensureReadable() }
        for _ in 0..<50 where !cancelled.withLock({ $0 }) {
            try await Task.sleep(for: .milliseconds(20))
        }
        #expect(cancelled.withLock { $0 })
    }
}
