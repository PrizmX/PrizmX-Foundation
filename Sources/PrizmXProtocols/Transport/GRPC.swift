import Foundation
import os

/// gRPC transport options ("gun", Clash `grpc-opts`, Xray / sing-box `grpc`).
public struct GRPCSettings: Sendable, Hashable {
    /// `grpc-service-name`. A name starting with `/` is a full custom path
    /// (`/a/b/Tun|TunMulti`, Xray), otherwise the path is `/<name>/Tun`.
    public var serviceName: String

    public init(serviceName: String = "") {
        self.serviceName = serviceName
    }

    /// The HTTP/2 `:path` of the Tun stream (Xray `getServiceName` /
    /// `getTunStreamName`).
    var path: String {
        func escape(_ part: Substring) -> String {
            String(part).addingPercentEncoding(withAllowedCharacters: .urlPathAllowed.subtracting(["/"])) ?? String(part)
        }
        guard serviceName.hasPrefix("/") else {
            return "/\(escape(Substring(serviceName)))/Tun"
        }
        let last = serviceName.lastIndex(of: "/")!
        let lastOffset = max(serviceName.distance(from: serviceName.startIndex, to: last), 1)
        let service = serviceName.dropFirst().prefix(lastOffset - 1)
            .split(separator: "/", omittingEmptySubsequences: false).map(escape).joined(separator: "/")
        let tun = serviceName[serviceName.index(after: last)...].split(separator: "|", omittingEmptySubsequences: false).first ?? ""
        return "/\(service)/\(escape(tun))"
    }
}

// MARK: - HTTP/2 framing

enum HTTP2 {
    static let preface = Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)

    enum FrameType: UInt8 {
        case data = 0x0, headers = 0x1, priority = 0x2, rstStream = 0x3, settings = 0x4
        case pushPromise = 0x5, ping = 0x6, goAway = 0x7, windowUpdate = 0x8, continuation = 0x9
    }

    static let flagEndStream: UInt8 = 0x1
    static let flagAck: UInt8 = 0x1
    static let flagEndHeaders: UInt8 = 0x4
    static let flagPadded: UInt8 = 0x8
    static let flagPriority: UInt8 = 0x20

    static let settingsInitialWindowSize: UInt16 = 0x4
    static let settingsMaxFrameSize: UInt16 = 0x5
    static let settingsEnablePush: UInt16 = 0x2

    static func frame(_ type: FrameType, flags: UInt8 = 0, stream: UInt32, payload: Data = Data()) -> Data {
        var frame = Data(capacity: 9 + payload.count)
        let length = payload.count
        frame.append(contentsOf: [UInt8(length >> 16 & 0xFF), UInt8(length >> 8 & 0xFF), UInt8(length & 0xFF)])
        frame.append(type.rawValue)
        frame.append(flags)
        frame.append(contentsOf: withUnsafeBytes(of: (stream & 0x7FFF_FFFF).bigEndian) { Array($0) })
        frame.append(payload)
        return frame
    }

    static func settings(_ pairs: [(UInt16, UInt32)]) -> Data {
        var payload = Data()
        for (id, value) in pairs {
            payload.append(contentsOf: withUnsafeBytes(of: id.bigEndian) { Array($0) })
            payload.append(contentsOf: withUnsafeBytes(of: value.bigEndian) { Array($0) })
        }
        return frame(.settings, stream: 0, payload: payload)
    }

    static func windowUpdate(stream: UInt32, increment: UInt32) -> Data {
        frame(.windowUpdate, stream: stream, payload: Data(withUnsafeBytes(of: (increment & 0x7FFF_FFFF).bigEndian) { Array($0) }))
    }

    /// HPACK header block of literals without indexing (new names), so the
    /// peer's dynamic table never changes and needs no tracking here.
    static func headerBlock(_ headers: [(String, String)]) -> Data {
        var block = Data()
        for (name, value) in headers {
            block.append(0x00)
            appendString(name, to: &block)
            appendString(value, to: &block)
        }
        return block
    }

    private static func appendString(_ text: String, to block: inout Data) {
        let bytes = Array(text.utf8)
        appendInteger(bytes.count, prefixBits: 7, to: &block)
        block.append(contentsOf: bytes)
    }

    /// RFC 7541 §5.1 integer with an N-bit prefix (Huffman bit clear).
    static func appendInteger(_ value: Int, prefixBits: Int, to block: inout Data) {
        let limit = (1 << prefixBits) - 1
        if value < limit {
            block.append(UInt8(value))
            return
        }
        block.append(UInt8(limit))
        var rest = value - limit
        while rest >= 128 {
            block.append(UInt8(rest & 0x7F | 0x80))
            rest >>= 7
        }
        block.append(UInt8(rest))
    }
}

// MARK: - gun messages

/// gRPC message framing around gun's `Hunk { bytes data = 1; }`.
enum GunHunk {
    /// `[0][length BE32][0x0A][varint size][data]`.
    static func encode(_ data: Data) -> Data {
        var message = Data([0x0A])
        var size = data.count
        while size >= 0x80 {
            message.append(UInt8(size & 0x7F | 0x80))
            size >>= 7
        }
        message.append(UInt8(size))
        message.append(data)
        var framed = Data([0x00])
        framed.append(contentsOf: withUnsafeBytes(of: UInt32(message.count).bigEndian) { Array($0) })
        framed.append(message)
        return framed
    }

    /// Incremental decoder of gRPC messages to hunk payloads.
    struct Decoder {
        private var buffer = Data()

        mutating func feed(_ chunk: Data) throws -> [Data] {
            buffer.append(chunk)
            var hunks: [Data] = []
            while buffer.count >= 5 {
                let bytes = buffer.startIndex
                guard buffer[bytes] == 0 else { throw TransportError.protocolViolation("compressed gRPC message") }
                let length = buffer[(bytes + 1)..<(bytes + 5)].reduce(0) { $0 << 8 | Int($1) }
                guard buffer.count >= 5 + length else { break }
                let message = buffer.subdata(in: (bytes + 5)..<(bytes + 5 + length))
                buffer.removeFirst(5 + length)
                if let data = try Self.hunkData(message), !data.isEmpty {
                    hunks.append(data)
                }
            }
            return hunks
        }

        /// Field 1 of the protobuf message; unknown fields are skipped.
        static func hunkData(_ message: Data) throws -> Data? {
            let bytes = [UInt8](message)
            var offset = 0
            var result: Data?
            func varint() throws -> Int {
                var value = 0
                var shift = 0
                while true {
                    guard offset < bytes.count, shift < 64 else { throw TransportError.protocolViolation("protobuf varint") }
                    let byte = bytes[offset]
                    offset += 1
                    value |= Int(byte & 0x7F) << shift
                    if byte & 0x80 == 0 { return value }
                    shift += 7
                }
            }
            while offset < bytes.count {
                let key = try varint()
                switch key & 0x7 {
                case 0:
                    _ = try varint()
                case 1:
                    offset += 8
                case 2:
                    let length = try varint()
                    guard offset + length <= bytes.count else { throw TransportError.protocolViolation("protobuf length") }
                    if key >> 3 == 1 {
                        result = Data(bytes[offset..<(offset + length)])
                    }
                    offset += length
                case 5:
                    offset += 4
                default:
                    throw TransportError.protocolViolation("protobuf wire type")
                }
            }
            return result
        }
    }
}

// MARK: - Stream

/// One gun stream (`/<service>/Tun`) on its own HTTP/2 connection.
///
/// A background task parses every frame, so window updates, pings and
/// settings are handled even while nobody reads; received data is handed
/// to `receive` and only then credited back to the peer, so flow control
/// still bounds what is buffered.
final class GRPCStream: ByteStream, @unchecked Sendable {
    static let streamID: UInt32 = 1
    /// Receive window we grant (stream and connection).
    static let receiveWindow: UInt32 = 4 << 20
    /// Largest DATA frame we accept from the peer.
    static let maxReceiveFrame: UInt32 = 1 << 16

    private struct State {
        // Send side, adjusted by the peer.
        var connectionWindow = 65_535
        var streamWindow = 65_535
        var peerInitialWindow = 65_535
        var peerMaxFrame = 16_384
        var windowWaiter: CheckedContinuation<Void, Never>?
        // Receive side.
        var chunks: [Data] = []
        var ended = false
        var failure: Error?
        var reader: CheckedContinuation<Data?, Error>?
        var uncredited = 0
    }

    private let lower: any ByteStream
    private let state = OSAllocatedUnfairLock(initialState: State())
    private var frameTask: Task<Void, Never>?
    private var sentEndStream = false
    // Frame task only.
    private var decoder = GunHunk.Decoder()
    /// DATA bytes received but not handed out as hunk payload (gRPC and
    /// protobuf framing, padding, partial messages), credited right away;
    /// payload is credited when `receive` hands it out.
    private var framingBalance = 0

    init(lower: any ByteStream) {
        self.lower = lower
    }

    deinit {
        frameTask?.cancel()
    }

    /// Preface, settings, connection window and the request headers.
    func connect(settings: GRPCSettings, authority: String, tls: Bool) async throws {
        var opening = HTTP2.preface
        opening.append(HTTP2.settings([
            (HTTP2.settingsEnablePush, 0),
            (HTTP2.settingsInitialWindowSize, Self.receiveWindow),
            (HTTP2.settingsMaxFrameSize, Self.maxReceiveFrame),
        ]))
        opening.append(HTTP2.windowUpdate(stream: 0, increment: Self.receiveWindow - 65_535))
        let headers = HTTP2.headerBlock([
            (":method", "POST"),
            (":scheme", tls ? "https" : "http"),
            (":path", settings.path),
            (":authority", authority),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
            ("user-agent", "grpc-go/1.65.0"),
        ])
        opening.append(HTTP2.frame(.headers, flags: HTTP2.flagEndHeaders, stream: Self.streamID, payload: headers))
        try await lower.send(opening)
        frameTask = Task { [weak self] in await self?.readFrames() }
    }

    // MARK: Send

    func send(_ data: Data) async throws {
        var message = GunHunk.encode(data)[...]
        while !message.isEmpty {
            let allowance = await reserve(upTo: message.count)
            let piece = message.prefix(allowance)
            message = message.dropFirst(allowance)
            try await lower.send(HTTP2.frame(.data, stream: Self.streamID, payload: Data(piece)))
        }
    }

    /// Waits for send window and returns how many bytes may go in one frame.
    private func reserve(upTo count: Int) async -> Int {
        while true {
            let granted: Int? = state.withLock { current in
                let available = min(current.connectionWindow, current.streamWindow, current.peerMaxFrame)
                guard available > 0 || current.failure != nil || current.ended else { return nil }
                let take = max(1, min(count, available))
                current.connectionWindow -= take
                current.streamWindow -= take
                return take
            }
            if let granted { return granted }
            await withCheckedContinuation { continuation in
                let wake = state.withLock { current -> Bool in
                    if min(current.connectionWindow, current.streamWindow) > 0 || current.failure != nil || current.ended {
                        return true
                    }
                    current.windowWaiter = continuation
                    return false
                }
                if wake { continuation.resume() }
            }
        }
    }

    /// gRPC half-close: an empty DATA frame ending the stream.
    func finishWriting() async {
        guard !sentEndStream else { return }
        sentEndStream = true
        try? await lower.send(HTTP2.frame(.data, flags: HTTP2.flagEndStream, stream: Self.streamID))
    }

    // MARK: Receive

    func receive() async throws -> Data? {
        let next: Result<Data?, Error>? = state.withLock { current in
            if !current.chunks.isEmpty { return .success(current.chunks.removeFirst()) }
            if let failure = current.failure { return .failure(failure) }
            if current.ended { return .success(nil) }
            return nil
        }
        let data: Data?
        if let next {
            data = try next.get()
        } else {
            data = try await withCheckedThrowingContinuation { continuation in
                let ready: Result<Data?, Error>? = state.withLock { current in
                    if !current.chunks.isEmpty { return .success(current.chunks.removeFirst()) }
                    if let failure = current.failure { return .failure(failure) }
                    if current.ended { return .success(nil) }
                    current.reader = continuation
                    return nil
                }
                if let ready { continuation.resume(with: ready) }
            }
        }
        if let data { await credit(data.count) }
        return data
    }

    /// Hands consumed bytes back to the peer in batches.
    private func credit(_ count: Int) async {
        let increment: Int = state.withLock { current in
            current.uncredited += count
            guard current.uncredited >= Int(Self.receiveWindow / 4) else { return 0 }
            defer { current.uncredited = 0 }
            return current.uncredited
        }
        guard increment > 0 else { return }
        var frames = HTTP2.windowUpdate(stream: 0, increment: UInt32(increment))
        frames.append(HTTP2.windowUpdate(stream: Self.streamID, increment: UInt32(increment)))
        try? await lower.send(frames)
    }

    private func deliver(_ chunk: Data) {
        let reader = state.withLock { current -> CheckedContinuation<Data?, Error>? in
            if let reader = current.reader {
                current.reader = nil
                return reader
            }
            current.chunks.append(chunk)
            return nil
        }
        reader?.resume(returning: chunk)
    }

    private func end(_ failure: Error?) {
        let (reader, waiter) = state.withLock { current -> (CheckedContinuation<Data?, Error>?, CheckedContinuation<Void, Never>?) in
            if current.failure == nil, !current.ended {
                if let failure { current.failure = failure } else { current.ended = true }
            }
            defer { current.reader = nil; current.windowWaiter = nil }
            return (current.reader, current.windowWaiter)
        }
        waiter?.resume()
        guard let reader else { return }
        if let failure {
            reader.resume(throwing: failure)
        } else {
            reader.resume(returning: nil)
        }
    }

    // MARK: Frames

    private func readFrames() async {
        var buffer = Data()
        do {
            while !Task.isCancelled {
                while buffer.count >= 9 {
                    let head = [UInt8](buffer.prefix(9))
                    let length = Int(head[0]) << 16 | Int(head[1]) << 8 | Int(head[2])
                    guard buffer.count >= 9 + length else { break }
                    let payload = buffer.subdata(in: (buffer.startIndex + 9)..<(buffer.startIndex + 9 + length))
                    buffer.removeFirst(9 + length)
                    let stream = (UInt32(head[5]) << 24 | UInt32(head[6]) << 16 | UInt32(head[7]) << 8 | UInt32(head[8])) & 0x7FFF_FFFF
                    if try await handle(type: head[3], flags: head[4], stream: stream, payload: payload) {
                        return
                    }
                }
                guard let chunk = try await lower.receive() else {
                    end(nil)
                    return
                }
                buffer.append(chunk)
            }
        } catch {
            end(error)
        }
    }

    /// Returns `true` once the stream is over.
    private func handle(type: UInt8, flags: UInt8, stream: UInt32, payload: Data) async throws -> Bool {
        switch HTTP2.FrameType(rawValue: type) {
        case .data:
            guard stream == Self.streamID else { return false }
            var body = payload
            if flags & HTTP2.flagPadded != 0, let pad = body.first {
                body = body.dropFirst().dropLast(Int(pad))
            }
            let hunks = try decoder.feed(Data(body))
            framingBalance += payload.count - hunks.reduce(0) { $0 + $1.count }
            if framingBalance > 0 {
                await credit(framingBalance)
                framingBalance = 0
            }
            for hunk in hunks {
                deliver(hunk)
            }
            if flags & HTTP2.flagEndStream != 0 {
                end(nil)
                return true
            }
        case .headers, .continuation:
            if stream == Self.streamID, flags & HTTP2.flagEndStream != 0 {
                // Trailers (or a trailers-only error reply) end the stream.
                end(nil)
                return true
            }
        case .settings:
            guard flags & HTTP2.flagAck == 0 else { return false }
            let bytes = [UInt8](payload)
            var index = 0
            while index + 6 <= bytes.count {
                let id = UInt16(bytes[index]) << 8 | UInt16(bytes[index + 1])
                let value = Int(bytes[index + 2]) << 24 | Int(bytes[index + 3]) << 16 | Int(bytes[index + 4]) << 8 | Int(bytes[index + 5])
                state.withLock { current in
                    if id == HTTP2.settingsInitialWindowSize {
                        current.streamWindow += value - current.peerInitialWindow
                        current.peerInitialWindow = value
                    } else if id == HTTP2.settingsMaxFrameSize {
                        current.peerMaxFrame = value
                    }
                }
                index += 6
            }
            try await lower.send(HTTP2.frame(.settings, flags: HTTP2.flagAck, stream: 0))
            wakeSender()
        case .ping:
            if flags & HTTP2.flagAck == 0 {
                try await lower.send(HTTP2.frame(.ping, flags: HTTP2.flagAck, stream: 0, payload: payload))
            }
        case .windowUpdate:
            let bytes = [UInt8](payload)
            guard bytes.count == 4 else { return false }
            let increment = Int(UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])) & 0x7FFF_FFFF
            state.withLock { current in
                if stream == 0 {
                    current.connectionWindow += increment
                } else if stream == Self.streamID {
                    current.streamWindow += increment
                }
            }
            wakeSender()
        case .rstStream:
            if stream == Self.streamID {
                end(TransportError.protocolViolation("stream reset"))
                return true
            }
        case .goAway:
            end(nil)
            return true
        case .priority, .pushPromise, nil:
            break
        }
        return false
    }

    private func wakeSender() {
        let waiter = state.withLock { current -> CheckedContinuation<Void, Never>? in
            guard min(current.connectionWindow, current.streamWindow) > 0 else { return nil }
            defer { current.windowWaiter = nil }
            return current.windowWaiter
        }
        waiter?.resume()
    }
}
