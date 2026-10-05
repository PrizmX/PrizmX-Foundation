import Foundation
import os
import Testing
@testable import PrizmXProtocols

/// Scripted peer: records sent bytes, replays pushed chunks to `receive`.
private final class ScriptedPeer: ByteStream, @unchecked Sendable {
    private let state = OSAllocatedUnfairLock(initialState: (sent: Data(), queue: [Data?](), waiter: CheckedContinuation<Data?, Never>?.none))

    var sent: Data { state.withLock { $0.sent } }

    func send(_ data: Data) async throws {
        state.withLock { $0.sent.append(data) }
    }

    func push(_ data: Data?) {
        let waiter = state.withLock { current -> CheckedContinuation<Data?, Never>? in
            if let waiter = current.waiter {
                current.waiter = nil
                return waiter
            }
            current.queue.append(data)
            return nil
        }
        waiter?.resume(returning: data)
    }

    func receive() async throws -> Data? {
        await withCheckedContinuation { continuation in
            let ready = state.withLock { current -> Data?? in
                if !current.queue.isEmpty { return .some(current.queue.removeFirst()) }
                current.waiter = continuation
                return .none
            }
            if case .some(let data) = ready { continuation.resume(returning: data) }
        }
    }

    func finishWriting() async {}

    /// (type, flags, stream, payload length) of every frame after the preface.
    var frames: [(UInt8, UInt8, UInt32, Int)] {
        var bytes = [UInt8](sent.dropFirst(HTTP2.preface.count))
        var result: [(UInt8, UInt8, UInt32, Int)] = []
        while bytes.count >= 9 {
            let length = Int(bytes[0]) << 16 | Int(bytes[1]) << 8 | Int(bytes[2])
            let stream = UInt32(bytes[5]) << 24 | UInt32(bytes[6]) << 16 | UInt32(bytes[7]) << 8 | UInt32(bytes[8])
            result.append((bytes[3], bytes[4], stream, length))
            bytes.removeFirst(9 + length)
        }
        return result
    }
}

@Suite("gRPC transport")
struct GRPCTests {

    @Test func pathsFollowXray() {
        #expect(GRPCSettings(serviceName: "GunService").path == "/GunService/Tun")
        #expect(GRPCSettings(serviceName: "").path == "//Tun")
        #expect(GRPCSettings(serviceName: "/my/sample/path1|path2").path == "/my/sample/path1")
        #expect(GRPCSettings(serviceName: "a b").path == "/a%20b/Tun")
    }

    @Test func hunksRoundTripWithLongVarintsAndUnknownFields() throws {
        let payload = Data((0..<300).map { UInt8($0 & 0xFF) })
        let encoded = GunHunk.encode(payload)
        #expect(Array(encoded.prefix(8)) == [0x00, 0, 0, 0x01, 0x2F, 0x0A, 0xAC, 0x02])
        var decoder = GunHunk.Decoder()
        #expect(try decoder.feed(encoded.prefix(100)) == [])
        #expect(try decoder.feed(encoded.dropFirst(100)) == [payload])
        // Field 2 (varint) before field 1 is skipped.
        let message: [UInt8] = [0x10, 0x05, 0x0A, 0x02, 0x68, 0x69]
        #expect(try GunHunk.Decoder.hunkData(Data(message)) == Data("hi".utf8))
    }

    @Test func rejectsNegativeVarintLength() {
        // Field 1, length varint 0xFF×9 0x01 decodes to a negative Int.
        let message: [UInt8] = [0x0A] + [UInt8](repeating: 0xFF, count: 9) + [0x01, 0x68]
        #expect(throws: TransportError.protocolViolation("protobuf length")) {
            try GunHunk.Decoder.hunkData(Data(message))
        }
    }

    @Test func gracefulGoAwayLetsTheStreamFinish() async throws {
        let peer = ScriptedPeer()
        let stream = GRPCStream(lower: peer)
        try await stream.connect(settings: GRPCSettings(serviceName: "Gun"), authority: "s.example", tls: true)
        // GOAWAY(last stream 2^31-1, NO_ERROR), then stream 1 keeps going.
        peer.push(HTTP2.frame(.goAway, stream: 0, payload: Data([0x7F, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0])))
        peer.push(HTTP2.frame(.data, stream: 1, payload: GunHunk.encode(Data("late".utf8))))
        peer.push(HTTP2.frame(.headers, flags: HTTP2.flagEndHeaders | HTTP2.flagEndStream, stream: 1, payload: Data()))
        #expect(try await stream.receive() == Data("late".utf8))
        #expect(try await stream.receive() == nil)
    }

    @Test func goAwayExcludingTheStreamFails() async throws {
        let peer = ScriptedPeer()
        let stream = GRPCStream(lower: peer)
        try await stream.connect(settings: GRPCSettings(serviceName: "Gun"), authority: "s.example", tls: true)
        peer.push(HTTP2.frame(.goAway, stream: 0, payload: Data([0, 0, 0, 0, 0, 0, 0, 0])))
        await #expect(throws: TransportError.self) { try await stream.receive() }
    }

    @Test func hpackIntegersUsePrefixContinuation() {
        var block = Data()
        HTTP2.appendInteger(10, prefixBits: 7, to: &block)
        HTTP2.appendInteger(1337, prefixBits: 5, to: &block)
        #expect(Array(block) == [10, 31, 154, 10])   // RFC 7541 C.1.2
    }

    @Test func respectsPeerWindowAndDeliversData() async throws {
        let peer = ScriptedPeer()
        let stream = GRPCStream(lower: peer)
        try await stream.connect(settings: GRPCSettings(serviceName: "Gun"), authority: "s.example", tls: true)
        #expect(peer.sent.starts(with: HTTP2.preface))

        // Peer: initial stream window 16 bytes.
        peer.push(HTTP2.frame(.settings, stream: 0, payload: Data([0, 4, 0, 0, 0, 16])))
        try await Task.sleep(for: .milliseconds(50))
        #expect(peer.frames.contains { $0.0 == HTTP2.FrameType.settings.rawValue && $0.1 == HTTP2.flagAck })

        let sending = Task { try await stream.send(Data(count: 40)) }   // 47-byte gRPC message
        try await Task.sleep(for: .milliseconds(50))
        var data = peer.frames.filter { $0.0 == HTTP2.FrameType.data.rawValue }
        #expect(data.map(\.3) == [16])
        peer.push(HTTP2.windowUpdate(stream: GRPCStream.streamID, increment: 100))
        try await sending.value
        data = peer.frames.filter { $0.0 == HTTP2.FrameType.data.rawValue }
        #expect(data.map(\.3) == [16, 31])

        // Response headers, one hunk, then trailers ending the stream.
        peer.push(HTTP2.frame(.headers, flags: HTTP2.flagEndHeaders, stream: 1, payload: HTTP2.headerBlock([(":status", "200")])))
        peer.push(HTTP2.frame(.data, stream: 1, payload: GunHunk.encode(Data("pong".utf8))))
        peer.push(HTTP2.frame(.headers, flags: HTTP2.flagEndHeaders | HTTP2.flagEndStream, stream: 1, payload: Data()))
        #expect(try await stream.receive() == Data("pong".utf8))
        #expect(try await stream.receive() == nil)
    }
}
