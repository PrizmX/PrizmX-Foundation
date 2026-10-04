import Foundation
import os
import Testing
@testable import PrizmXProtocols

/// Scripted lower stream: records sends, replays queued downlink chunks.
private final class ScriptedStream: ByteStream, @unchecked Sendable {
    private let state = OSAllocatedUnfairLock(initialState: (sent: [Data](), replies: [Data]()))

    init(replies: [Data] = []) {
        state.withLock { $0.replies = replies }
    }

    var sent: [Data] { state.withLock { $0.sent } }

    func send(_ data: Data) async throws {
        state.withLock { $0.sent.append(data) }
    }

    func receive() async throws -> Data? {
        state.withLock { current -> Data? in
            current.replies.isEmpty ? nil : current.replies.removeFirst()
        }
    }

    func finishWriting() async {}
}

@Suite("Shadowsocks plugins")
struct ShadowsocksPluginTests {

    @Test func obfsTLSClientHelloMatchesTemplate() {
        let ticket = Data((0..<100).map { UInt8($0) })
        let hello = [UInt8](SimpleObfsTLSStream.clientHello(ticket: ticket, host: "cdn.example"))
        #expect(hello.count == 100 + 11 + 217)
        #expect(Array(hello[0..<3]) == [0x16, 0x03, 0x01])
        #expect(Int(hello[3]) << 8 | Int(hello[4]) == hello.count - 5)
        #expect(hello[5] == 0x01)
        #expect(Int(hello[7]) << 8 | Int(hello[8]) == hello.count - 9)
        // obfs-server reads the session ticket right after the 138-byte header.
        #expect(Array(hello[138..<140]) == [0x00, 0x23])
        #expect(Int(hello[140]) << 8 | Int(hello[141]) == ticket.count)
        #expect(Array(hello[142..<242]) == Array(ticket))
        #expect(Array(hello[242..<244]) == [0x00, 0x00])
        #expect(String(decoding: hello[251..<262], as: UTF8.self) == "cdn.example")
        #expect(Int(hello[136]) << 8 | Int(hello[137]) == hello.count - 138)
    }

    @Test func obfsTLSStripsServerPreambleAndRecords() async throws {
        var first = Data([0x16, 0x03, 0x01]) + Data(count: 93)      // ServerHello (96)
        first += Data([0x14, 0x03, 0x03, 0x00, 0x01, 0x01])         // ChangeCipherSpec
        first += Data([0x16, 0x03, 0x03, 0x00, 0x03, 0x61, 0x62])   // first record, split
        let second = Data([0x63, 0x17, 0x03, 0x03, 0x00, 0x02, 0x64, 0x65])
        let lower = ScriptedStream(replies: [first, second])
        let stream = SimpleObfsTLSStream(lower: lower, host: "h")
        #expect(try await stream.receive() == Data("abc".utf8))
        #expect(try await stream.receive() == Data("de".utf8))
        #expect(try await stream.receive() == nil)
    }

    @Test func obfsTLSWrapsLaterWritesInRecords() async throws {
        let lower = ScriptedStream()
        let stream = SimpleObfsTLSStream(lower: lower, host: "h")
        try await stream.send(Data("hello".utf8))
        try await stream.send(Data(count: SimpleObfsTLSStream.maxRecordPayload + 1))
        let later = [UInt8](lower.sent[1])
        #expect(Array(later[0..<5]) == [0x17, 0x03, 0x03, 0x40, 0x00])
        #expect(Array(later[(5 + 16384)..<(5 + 16384 + 5)]) == [0x17, 0x03, 0x03, 0x00, 0x01])
    }

    @Test func obfsHTTPRequestAndResponse() async throws {
        let reply = Data("HTTP/1.1 101 Switching Protocols\r\nServer: nginx\r\n\r\nPAY".utf8)
        let lower = ScriptedStream(replies: [reply, Data("LOAD".utf8)])
        let stream = SimpleObfsHTTPStream(
            lower: lower,
            settings: SimpleObfsSettings(mode: .http, host: "cdn.example"),
            port: 8388
        )
        try await stream.send(Data("body".utf8))
        try await stream.send(Data("raw".utf8))
        let request = String(decoding: lower.sent[0], as: UTF8.self)
        #expect(request.hasPrefix("GET / HTTP/1.1\r\nHost: cdn.example:8388\r\n"))
        #expect(request.contains("Upgrade: websocket\r\n"))
        #expect(request.hasSuffix("Content-Length: 4\r\n\r\nbody"))
        #expect(lower.sent[1] == Data("raw".utf8))
        #expect(try await stream.receive() == Data("PAY".utf8))
        #expect(try await stream.receive() == Data("LOAD".utf8))
    }

    @Test func muxCoolFramesOneSession() async throws {
        let keep = Data([0x00, 0x04, 0x00, 0x00, 0x02, 0x01, 0x00, 0x02, 0x68, 0x69])
        let keepAlive = Data([0x00, 0x04, 0x00, 0x00, 0x04, 0x00])
        let end = Data([0x00, 0x04, 0x00, 0x00, 0x03, 0x00])
        let lower = ScriptedStream(replies: [keepAlive + keep.prefix(5), keep.dropFirst(5) + end])
        let stream = MuxCoolStream(lower: lower)
        try await stream.send(Data("ab".utf8))
        let opening: [UInt8] = [
            0x00, 0x0C, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 127, 0, 0, 1,
            0x00, 0x04, 0x00, 0x00, 0x02, 0x01, 0x00, 0x02, 0x61, 0x62,
        ]
        #expect([UInt8](lower.sent[0]) == opening)
        #expect(try await stream.receive() == Data("hi".utf8))
        #expect(try await stream.receive() == nil)
    }
}
