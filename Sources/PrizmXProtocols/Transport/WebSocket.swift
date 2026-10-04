import CryptoKit
import Foundation
import os

/// WebSocket transport options (Clash `ws-opts`, sing-box / Xray `ws`).
public struct WebSocketSettings: Sendable, Hashable {
    /// Request path (with query). Always starts with `/`.
    public var path: String
    /// `Host` header; `nil` falls back to the TLS server name, then the
    /// server address.
    public var host: String?
    /// Extra request headers (a `Host` entry here is moved to `host`).
    public var headers: [String: String]
    /// Bytes of the first uplink write carried in the handshake (0 = off).
    public var maxEarlyData: Int
    /// Header that carries early data (base64url). Empty puts it at the end
    /// of the path instead (v2fly semantics).
    public var earlyDataHeaderName: String

    public init(
        path: String = "/",
        host: String? = nil,
        headers: [String: String] = [:],
        maxEarlyData: Int = 0,
        earlyDataHeaderName: String = ""
    ) {
        var headers = headers
        var host = host
        if let key = headers.keys.first(where: { $0.lowercased() == "host" }) {
            let value = headers.removeValue(forKey: key)
            if host?.isEmpty ?? true { host = value }
        }
        self.path = path.hasPrefix("/") ? path : "/" + path
        self.host = host?.isEmpty == true ? nil : host
        self.headers = headers
        self.maxEarlyData = max(0, maxEarlyData)
        self.earlyDataHeaderName = earlyDataHeaderName
    }

    /// Xray-style `?ed=2048` in the path: strips it and turns it into
    /// `Sec-WebSocket-Protocol` early data unless early data is already set.
    public static func parsing(
        path: String,
        host: String? = nil,
        headers: [String: String] = [:],
        maxEarlyData: Int = 0,
        earlyDataHeaderName: String = ""
    ) -> WebSocketSettings {
        var path = path.isEmpty ? "/" : path
        var maxEarlyData = maxEarlyData
        var headerName = earlyDataHeaderName
        if var components = URLComponents(string: path),
           let items = components.queryItems,
           let ed = items.first(where: { $0.name == "ed" }) {
            let rest = items.filter { $0.name != "ed" }
            components.queryItems = rest.isEmpty ? nil : rest
            path = components.string ?? path
            if maxEarlyData == 0, let value = ed.value.flatMap(Int.init), value > 0 {
                maxEarlyData = value
                if headerName.isEmpty { headerName = "Sec-WebSocket-Protocol" }
            }
        }
        return WebSocketSettings(
            path: path,
            host: host,
            headers: headers,
            maxEarlyData: maxEarlyData,
            earlyDataHeaderName: headerName
        )
    }
}

/// HTTP upgrade transport (sing-box / Xray `httpupgrade`): a WebSocket-style
/// `GET` + `101 Switching Protocols`, then the raw stream with no framing.
public struct HTTPUpgradeSettings: Sendable, Hashable {
    public var path: String
    public var host: String?
    public var headers: [String: String]

    public init(path: String = "/", host: String? = nil, headers: [String: String] = [:]) {
        let normalized = WebSocketSettings(path: path, host: host, headers: headers)
        self.path = normalized.path
        self.host = normalized.host
        self.headers = normalized.headers
    }
}

/// Errors from the HTTP-based transports (WebSocket, HTTP upgrade, gRPC).
@frozen
public enum TransportError: Error, Equatable, Sendable {
    /// The server did not switch protocols (status code, 0 if unparsable).
    case upgradeRejected(Int)
    /// `Sec-WebSocket-Accept` does not match the key we sent.
    case badAccept
    /// A frame violates the framing protocol.
    case protocolViolation(String)
}

// MARK: - Handshake

enum HTTPUpgradeHandshake {
    static let webSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    /// `GET` upgrade request head.
    static func request(
        path: String,
        host: String,
        headers: [String: String],
        key: String?,
        extra: [(String, String)] = []
    ) -> Data {
        var head = "GET \(path) HTTP/1.1\r\nHost: \(host)\r\n"
        head += "Connection: Upgrade\r\nUpgrade: websocket\r\n"
        if let key {
            head += "Sec-WebSocket-Key: \(key)\r\nSec-WebSocket-Version: 13\r\n"
        }
        for (name, value) in extra {
            head += "\(name): \(value)\r\n"
        }
        if !headers.keys.contains(where: { $0.lowercased() == "user-agent" }) {
            head += "User-Agent: Mozilla/5.0\r\n"
        }
        for (name, value) in headers.sorted(by: { $0.key < $1.key }) {
            head += "\(name): \(value)\r\n"
        }
        head += "\r\n"
        return Data(head.utf8)
    }

    static func accept(for key: String) -> String {
        let digest = Insecure.SHA1.hash(data: Data((key + webSocketGUID).utf8))
        return Data(digest).base64EncodedString()
    }

    /// Reads the response head from `lower` (leftover bytes go to
    /// `overflow`) and checks for `101`, plus the accept token for WebSocket.
    static func readResponse(
        from lower: any ByteStream,
        overflow: DirectBuffer,
        expectedAccept: String?
    ) async throws {
        let delimiter = Array("\r\n\r\n".utf8)
        var head = Data()
        while true {
            guard let chunk = try await lower.receive() else {
                throw TransportError.upgradeRejected(0)
            }
            head.append(chunk)
            if let range = head.firstRange(of: delimiter) {
                overflow.append(head[range.upperBound...])
                head = head[..<range.lowerBound]
                break
            }
            guard head.count < 16 * 1024 else { throw TransportError.upgradeRejected(0) }
        }
        let lines = String(decoding: head, as: UTF8.self).components(separatedBy: "\r\n")
        let status = lines.first?.split(separator: " ", maxSplits: 2) ?? []
        let code = status.count >= 2 ? Int(status[1]) ?? 0 : 0
        guard code == 101 else { throw TransportError.upgradeRejected(code) }
        guard let expectedAccept else { return }
        let accept = lines.dropFirst().first { $0.lowercased().hasPrefix("sec-websocket-accept:") }
        let value = accept.map { String($0.dropFirst("sec-websocket-accept:".count)).trimmingCharacters(in: .whitespaces) }
        guard value == expectedAccept else { throw TransportError.badAccept }
    }

    /// RFC 4648 §5 base64url without padding (Go `RawURLEncoding`).
    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

// MARK: - WebSocket stream

/// RFC 6455 client framing over `lower`: binary frames out (masked), data
/// frames in; pings are answered, a close frame ends the stream.
///
/// With early data on, the upgrade waits for the first uplink write so its
/// first `maxEarlyData` bytes ride in the request (saves one round trip).
final class WebSocketStream: ByteStream, @unchecked Sendable {
    private let lower: any ByteStream
    private let settings: WebSocketSettings
    private let host: String
    private let handshakeTask = OSAllocatedUnfairLock<Task<Void, Error>?>(initialState: nil)
    private let inbound = DirectBuffer()
    private var closed = false

    init(lower: any ByteStream, settings: WebSocketSettings, host: String) {
        self.lower = lower
        self.settings = settings
        self.host = host
    }

    /// Upgrades now unless early data defers it to the first write.
    func connect() async throws {
        guard settings.maxEarlyData == 0 else { return }
        try await handshake(earlyData: Data())
    }

    func send(_ data: Data) async throws {
        let early = data.prefix(settings.maxEarlyData)
        let carried = try await handshake(earlyData: Data(early))
        let payload = carried ? data.dropFirst(early.count) : data
        if payload.isEmpty { return }
        try await lower.send(Self.frame(opcode: 0x2, payload: payload))
    }

    func receive() async throws -> Data? {
        try await handshake(earlyData: Data())
        while true {
            if let payload = try nextFrame() {
                return payload
            }
            if closed { return nil }
            guard let chunk = try await lower.receive() else {
                guard inbound.readableByteCount == 0 else {
                    throw TransportError.protocolViolation("truncated frame")
                }
                return nil
            }
            inbound.append(chunk)
        }
    }

    /// WebSocket cannot half-close: a close frame tears down both ways on
    /// common servers, so the uplink just stops.
    func finishWriting() async {}

    // MARK: Handshake

    /// Starts the upgrade once (with `earlyData` if this call starts it) and
    /// waits for it; concurrent callers share the same task. Returns `true`
    /// when this call's `earlyData` went out with the request.
    @discardableResult
    private func handshake(earlyData: Data) async throws -> Bool {
        let (task, started) = handshakeTask.withLock { current -> (Task<Void, Error>, Bool) in
            if let current { return (current, false) }
            let task = Task { try await self.upgrade(earlyData: earlyData) }
            current = task
            return (task, true)
        }
        try await task.value
        return started && !earlyData.isEmpty
    }

    private func upgrade(earlyData: Data) async throws {
        let key = Data((0..<16).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
        var path = settings.path
        var extra: [(String, String)] = []
        if !earlyData.isEmpty {
            let encoded = HTTPUpgradeHandshake.base64URL(earlyData)
            if settings.earlyDataHeaderName.isEmpty {
                path += encoded
            } else {
                extra.append((settings.earlyDataHeaderName, encoded))
            }
        }
        try await lower.send(HTTPUpgradeHandshake.request(
            path: path,
            host: host,
            headers: settings.headers,
            key: key,
            extra: extra
        ))
        try await HTTPUpgradeHandshake.readResponse(
            from: lower,
            overflow: inbound,
            expectedAccept: HTTPUpgradeHandshake.accept(for: key)
        )
    }

    // MARK: Framing

    /// One client frame: FIN set, masked with a random key.
    static func frame(opcode: UInt8, payload: Data, maskKey: UInt32 = .random(in: .min ... .max)) -> Data {
        let count = payload.count
        var head: [UInt8] = [0x80 | opcode]
        switch count {
        case 0..<126:
            head.append(0x80 | UInt8(count))
        case 126...0xFFFF:
            head.append(0x80 | 126)
            head.append(UInt8(count >> 8))
            head.append(UInt8(count & 0xFF))
        default:
            head.append(0x80 | 127)
            for shift in stride(from: 56, through: 0, by: -8) {
                head.append(UInt8(truncatingIfNeeded: UInt64(count) >> UInt64(shift)))
            }
        }
        let mask = withUnsafeBytes(of: maskKey.bigEndian) { Array($0) }
        head.append(contentsOf: mask)

        var frame = Data(count: head.count + count)
        frame.withUnsafeMutableBytes { raw in
            raw.copyBytes(from: head)
            let body = UnsafeMutableRawBufferPointer(rebasing: raw[head.count...])
            payload.withUnsafeBytes { body.copyMemory(from: $0) }
            applyMask(mask, to: body)
        }
        return frame
    }

    /// XORs `body` with the repeating 4-byte `mask` (8 bytes per step).
    static func applyMask(_ mask: [UInt8], to body: UnsafeMutableRawBufferPointer) {
        guard !body.isEmpty else { return }
        var wide: UInt64 = 0
        for index in 0..<8 {
            wide |= UInt64(mask[index & 3]) << UInt64(index * 8)
        }
        let words = body.count / 8
        for index in 0..<words {
            let offset = index * 8
            let value = body.loadUnaligned(fromByteOffset: offset, as: UInt64.self)
            body.storeBytes(of: value ^ wide.littleEndian, toByteOffset: offset, as: UInt64.self)
        }
        for offset in (words * 8)..<body.count {
            body[offset] ^= mask[offset & 3]
        }
    }

    /// Consumes buffered frames until one carries data; `nil` when more
    /// bytes are needed (or a close frame was seen).
    private func nextFrame() throws -> Data? {
        while !closed {
            let raw = inbound.readableBytes
            guard raw.count >= 2 else { return nil }
            let opcode = raw[0] & 0x0F
            let masked = raw[1] & 0x80 != 0
            var length = Int(raw[1] & 0x7F)
            var offset = 2
            if length == 126 {
                guard raw.count >= 4 else { return nil }
                length = Int(raw[2]) << 8 | Int(raw[3])
                offset = 4
            } else if length == 127 {
                guard raw.count >= 10 else { return nil }
                let wide = loadUInt64BE(raw, offset: 2)
                guard wide <= UInt64(Int32.max) else {
                    throw TransportError.protocolViolation("frame too large")
                }
                length = Int(wide)
                offset = 10
            }
            let mask = masked ? Array(raw[offset..<min(offset + 4, raw.count)]) : []
            if masked { offset += 4 }
            guard raw.count >= offset + length else { return nil }

            var payload = Data(raw[offset..<(offset + length)])
            if masked {
                payload.withUnsafeMutableBytes { Self.applyMask(mask, to: $0) }
            }
            inbound.consume(offset + length)

            switch opcode {
            case 0x0, 0x1, 0x2:
                if !payload.isEmpty { return payload }
            case 0x8:
                closed = true
            case 0x9:
                let pong = Self.frame(opcode: 0xA, payload: payload)
                Task { [lower] in try? await lower.send(pong) }
            case 0xA:
                break
            default:
                throw TransportError.protocolViolation("opcode \(opcode)")
            }
        }
        return nil
    }
}

// MARK: - HTTP upgrade stream

/// `httpupgrade`: one upgrade exchange, then `lower` untouched.
final class HTTPUpgradeStream: ByteStream, @unchecked Sendable {
    private let lower: any ByteStream
    private let overflow = DirectBuffer()

    init(lower: any ByteStream) {
        self.lower = lower
    }

    func connect(settings: HTTPUpgradeSettings, host: String) async throws {
        try await lower.send(HTTPUpgradeHandshake.request(
            path: settings.path,
            host: host,
            headers: settings.headers,
            key: nil
        ))
        try await HTTPUpgradeHandshake.readResponse(from: lower, overflow: overflow, expectedAccept: nil)
    }

    func send(_ data: Data) async throws {
        try await lower.send(data)
    }

    func receive() async throws -> Data? {
        if overflow.readableByteCount > 0 {
            defer { overflow.clear() }
            return Data(overflow.readableBytes)
        }
        return try await lower.receive()
    }

    func finishWriting() async {
        await lower.finishWriting()
    }
}
