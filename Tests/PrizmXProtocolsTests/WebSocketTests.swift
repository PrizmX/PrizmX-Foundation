import Foundation
import os
import Testing
@testable import PrizmXProtocols

/// In-memory `ByteStream` playing a WebSocket server: answers the upgrade
/// with a valid 101, then echoes each client frame's payload back unmasked.
private final class LoopbackServer: ByteStream, @unchecked Sendable {
    private let state = OSAllocatedUnfairLock(initialState: State())
    private struct State {
        var requests: [String] = []
        var outbound: [Data] = []
        var waiters: [CheckedContinuation<Data?, Never>] = []
    }

    var requests: [String] { state.withLock { $0.requests } }

    func send(_ data: Data) async throws {
        if data.starts(with: Data("GET ".utf8)) {
            let text = String(decoding: data, as: UTF8.self)
            let key = text.components(separatedBy: "\r\n")
                .first { $0.hasPrefix("Sec-WebSocket-Key: ") }!
                .dropFirst("Sec-WebSocket-Key: ".count)
            let accept = HTTPUpgradeHandshake.accept(for: String(key))
            state.withLock { $0.requests.append(text) }
            deliver(Data("HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: \(accept)\r\n\r\n".utf8))
            return
        }
        // Unmask the client frame and echo it as a server (unmasked) frame.
        let bytes = [UInt8](data)
        var length = Int(bytes[1] & 0x7F)
        var offset = 2
        if length == 126 {
            length = Int(bytes[2]) << 8 | Int(bytes[3])
            offset = 4
        }
        let mask = Array(bytes[offset..<(offset + 4)])
        let payload: [UInt8] = bytes[(offset + 4)...].enumerated().map { $0.element ^ mask[$0.offset & 3] }
        var reply: [UInt8] = [0x82]
        if payload.count < 126 {
            reply.append(UInt8(payload.count))
        } else {
            reply += [126, UInt8(payload.count >> 8), UInt8(payload.count & 0xFF)]
        }
        deliver(Data(reply + payload))
    }

    func deliver(_ data: Data) {
        let waiter = state.withLock { current -> CheckedContinuation<Data?, Never>? in
            if current.waiters.isEmpty {
                current.outbound.append(data)
                return nil
            }
            return current.waiters.removeFirst()
        }
        waiter?.resume(returning: data)
    }

    func receive() async throws -> Data? {
        await withCheckedContinuation { continuation in
            let ready = state.withLock { current -> Data? in
                if !current.outbound.isEmpty { return current.outbound.removeFirst() }
                current.waiters.append(continuation)
                return nil
            }
            if let ready { continuation.resume(returning: ready) }
        }
    }

    func finishWriting() async {}
}

@Suite("WebSocket transport")
struct WebSocketTests {

    @Test func frameHeaderEncodesLengthAndMask() {
        let small = WebSocketStream.frame(opcode: 0x2, payload: Data([1, 2, 3]), maskKey: 0x0102_0304)
        let expectedSmall: [UInt8] = [0x82, 0x83, 1, 2, 3, 4, 0, 0, 0]
        #expect(Array(small) == expectedSmall)

        let medium = WebSocketStream.frame(opcode: 0x2, payload: Data(count: 300), maskKey: 0)
        let expectedMedium: [UInt8] = [0x82, 0xFE, 0x01, 0x2C]
        #expect(Array(medium.prefix(4)) == expectedMedium)
        #expect(medium.count == 4 + 4 + 300)

        let large = WebSocketStream.frame(opcode: 0x2, payload: Data(count: 70_000), maskKey: 0)
        let expectedLarge: [UInt8] = [0x82, 0xFF, 0, 0, 0, 0, 0, 0x01, 0x11, 0x70]
        #expect(Array(large.prefix(10)) == expectedLarge)
    }

    @Test func maskMatchesBytewiseXOR() {
        let mask: [UInt8] = [0xA1, 0xB2, 0xC3, 0xD4]
        let input = (0..<37).map { UInt8($0 * 7 & 0xFF) }
        var output = input
        output.withUnsafeMutableBytes { WebSocketStream.applyMask(mask, to: $0) }
        let expected: [UInt8] = input.enumerated().map { $0.element ^ mask[$0.offset & 3] }
        #expect(output == expected)
    }

    @Test func acceptTokenMatchesRFC6455Example() {
        #expect(HTTPUpgradeHandshake.accept(for: "dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
    }

    @Test func xrayEarlyDataQueryBecomesHeader() {
        let settings = WebSocketSettings.parsing(path: "/ws?ed=2048&x=1", headers: ["Host": "cdn.example"])
        #expect(settings.path == "/ws?x=1")
        #expect(settings.maxEarlyData == 2048)
        #expect(settings.earlyDataHeaderName == "Sec-WebSocket-Protocol")
        #expect(settings.host == "cdn.example")
        #expect(settings.headers.isEmpty)
    }

    @Test func roundTripsThroughLoopbackServer() async throws {
        let server = LoopbackServer()
        let stream = WebSocketStream(lower: server, settings: WebSocketSettings(path: "/p"), host: "h.example")
        try await stream.connect()
        #expect(server.requests.first?.hasPrefix("GET /p HTTP/1.1\r\nHost: h.example\r\n") == true)

        let payload = Data((0..<1000).map { UInt8($0 & 0xFF) })
        try await stream.send(payload)
        var echoed = Data()
        while echoed.count < payload.count {
            echoed.append(try #require(try await stream.receive()))
        }
        #expect(echoed == payload)
    }

    @Test func earlyDataRidesInTheUpgradeRequest() async throws {
        let server = LoopbackServer()
        let settings = WebSocketSettings(path: "/ed", maxEarlyData: 4, earlyDataHeaderName: "Sec-WebSocket-Protocol")
        let stream = WebSocketStream(lower: server, settings: settings, host: "h.example")
        try await stream.connect()
        #expect(server.requests.isEmpty, "upgrade waits for the first write")

        try await stream.send(Data("hello!".utf8))
        let request = try #require(server.requests.first)
        #expect(request.contains("Sec-WebSocket-Protocol: aGVsbA\r\n"))
        // Only the bytes beyond the early-data budget go out as a frame.
        #expect(try await stream.receive() == Data("o!".utf8))
    }
}
