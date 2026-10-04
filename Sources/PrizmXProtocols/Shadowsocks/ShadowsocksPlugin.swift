import Foundation

/// SIP003 plugins Shadowsocks servers commonly run.
public enum ShadowsocksPlugin: Sendable, Hashable {
    /// simple-obfs (`obfs-local`): HTTP or TLS camouflage on the TCP stream.
    case obfs(SimpleObfsSettings)
    /// v2ray-plugin in websocket mode (optionally TLS), with its single
    /// mux.cool session when `mux` is on (the plugin's default).
    case v2ray(webSocket: WebSocketSettings, tls: TLSSettings?, mux: Bool = true)
}

/// simple-obfs client options (Clash `plugin-opts`).
public struct SimpleObfsSettings: Sendable, Hashable {
    public enum Mode: String, Sendable, Hashable {
        case http
        case tls
    }

    public var mode: Mode
    /// `Host` header (http) or SNI (tls).
    public var host: String
    /// Request URI for http mode.
    public var path: String

    public init(mode: Mode, host: String = "bing.com", path: String = "/") {
        self.mode = mode
        self.host = host.isEmpty ? "bing.com" : host
        self.path = path.hasPrefix("/") ? path : "/" + path
    }
}

// MARK: - HTTP mode

/// simple-obfs `http`: the first uplink write rides as the body of a
/// websocket-looking `GET`; the server's reply starts with an HTTP head.
/// Everything after that is the raw stream.
final class SimpleObfsHTTPStream: ByteStream, @unchecked Sendable {
    private let lower: any ByteStream
    private let settings: SimpleObfsSettings
    private let port: UInt16
    private var requestSent = false
    private var responseHead: Data? = Data()

    init(lower: any ByteStream, settings: SimpleObfsSettings, port: UInt16) {
        self.lower = lower
        self.settings = settings
        self.port = port
    }

    func send(_ data: Data) async throws {
        guard !requestSent else {
            try await lower.send(data)
            return
        }
        requestSent = true
        try await lower.send(Self.request(settings: settings, port: port, body: data))
    }

    func receive() async throws -> Data? {
        while var head = responseHead {
            guard let chunk = try await lower.receive() else { return nil }
            head.append(chunk)
            if let end = head.firstRange(of: Data("\r\n\r\n".utf8)) {
                responseHead = nil
                let rest = Data(head[end.upperBound...])
                if !rest.isEmpty { return rest }
            } else {
                guard head.count < 16 * 1024 else { throw TransportError.upgradeRejected(0) }
                responseHead = head
            }
        }
        return try await lower.receive()
    }

    /// obfs-server drops both directions on the client's FIN.
    func finishWriting() async {}

    /// obfs-local's request head (`obfs_http.c`), with `body` appended.
    static func request(settings: SimpleObfsSettings, port: UInt16, body: Data) -> Data {
        let host = port == 80 ? settings.host : "\(settings.host):\(port)"
        let key = Data((0..<16).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
        var head = "GET \(settings.path) HTTP/1.1\r\n"
        head += "Host: \(host)\r\n"
        head += "User-Agent: curl/7.\(Int.random(in: 0..<51)).\(Int.random(in: 0..<2))\r\n"
        head += "Upgrade: websocket\r\n"
        head += "Connection: Upgrade\r\n"
        head += "Sec-WebSocket-Key: \(key)\r\n"
        head += "Content-Length: \(body.count)\r\n\r\n"
        return Data(head.utf8) + body
    }
}

// MARK: - TLS mode

/// simple-obfs `tls`: the first uplink write hides in the session-ticket
/// extension of a fake TLS 1.2 ClientHello, later writes in application-data
/// records. The server's first flight is a fake ServerHello and
/// ChangeCipherSpec before its first record.
final class SimpleObfsTLSStream: ByteStream, @unchecked Sendable {
    /// obfs-server rejects records above 2^14 bytes.
    static let maxRecordPayload = 1 << 14
    /// ServerHello (96) + ChangeCipherSpec (6) ahead of the first record.
    static let serverPreambleByteCount = 96 + 6

    private let lower: any ByteStream
    private let host: String
    private var helloSent = false
    private var preambleLeft = serverPreambleByteCount
    private let inbound = DirectBuffer()

    init(lower: any ByteStream, host: String) {
        self.lower = lower
        self.host = host
    }

    func send(_ data: Data) async throws {
        var wire = Data()
        var offset = data.startIndex
        while offset < data.endIndex {
            let end = min(offset + Self.maxRecordPayload, data.endIndex)
            let piece = data[offset..<end]
            if helloSent {
                wire.append(contentsOf: [0x17, 0x03, 0x03, UInt8(piece.count >> 8), UInt8(piece.count & 0xFF)])
                wire.append(piece)
            } else {
                helloSent = true
                wire.append(Self.clientHello(ticket: Data(piece), host: host))
            }
            offset = end
        }
        if !wire.isEmpty {
            try await lower.send(wire)
        }
    }

    func receive() async throws -> Data? {
        while true {
            if let payload = try nextRecord() { return payload }
            guard let chunk = try await lower.receive() else {
                guard inbound.readableByteCount == 0 else {
                    throw TransportError.protocolViolation("truncated obfs record")
                }
                return nil
            }
            inbound.append(chunk)
        }
    }

    /// obfs-server drops both directions on the client's FIN.
    func finishWriting() async {}

    /// Strips the preamble, then returns the next complete record payload.
    private func nextRecord() throws -> Data? {
        while true {
            if preambleLeft > 0 {
                let skip = min(preambleLeft, inbound.readableByteCount)
                if skip == 0 { return nil }
                if preambleLeft == Self.serverPreambleByteCount, inbound.readableBytes[0] != 0x16 {
                    throw TransportError.protocolViolation("obfs server hello")
                }
                inbound.consume(skip)
                preambleLeft -= skip
                continue
            }
            let raw = inbound.readableBytes
            guard raw.count >= 5 else { return nil }
            let length = Int(raw[3]) << 8 | Int(raw[4])
            guard raw.count >= 5 + length else { return nil }
            let payload = Data(raw[5..<(5 + length)])
            inbound.consume(5 + length)
            if !payload.isEmpty { return payload }
        }
    }

    /// The `obfs_tls.c` ClientHello: fixed header, session ticket carrying
    /// `ticket`, SNI `host`, then the fixed extension block.
    static func clientHello(ticket: Data, host: String) -> Data {
        let hostBytes = Array(host.utf8)
        let total = ticket.count + hostBytes.count + 217
        var hello: [UInt8] = [0x16, 0x03, 0x01]
        hello += uint16(total - 5)
        hello += [0x01, 0x00]
        hello += uint16(total - 9)
        hello += [0x03, 0x03]
        hello += withUnsafeBytes(of: UInt32(Date().timeIntervalSince1970).bigEndian) { Array($0) }
        hello += (0..<28).map { _ in UInt8.random(in: 0...255) }
        hello.append(32)
        hello += (0..<32).map { _ in UInt8.random(in: 0...255) }
        hello += [0x00, 0x38]
        hello += [
            0xC0, 0x2C, 0xC0, 0x30, 0x00, 0x9F, 0xCC, 0xA9, 0xCC, 0xA8, 0xCC, 0xAA, 0xC0, 0x2B, 0xC0, 0x2F,
            0x00, 0x9E, 0xC0, 0x24, 0xC0, 0x28, 0x00, 0x6B, 0xC0, 0x23, 0xC0, 0x27, 0x00, 0x67, 0xC0, 0x0A,
            0xC0, 0x14, 0x00, 0x39, 0xC0, 0x09, 0xC0, 0x13, 0x00, 0x33, 0x00, 0x9D, 0x00, 0x9C, 0x00, 0x3D,
            0x00, 0x3C, 0x00, 0x35, 0x00, 0x2F, 0x00, 0xFF,
        ]
        hello += [0x01, 0x00]
        hello += uint16(ticket.count + hostBytes.count + 79)
        // Session ticket.
        hello += [0x00, 0x23]
        hello += uint16(ticket.count)
        hello += ticket
        // Server name.
        hello += [0x00, 0x00]
        hello += uint16(hostBytes.count + 5)
        hello += uint16(hostBytes.count + 3)
        hello.append(0x00)
        hello += uint16(hostBytes.count)
        hello += hostBytes
        // EC point formats, groups, signature algorithms, EtM, EMS.
        hello += [0x00, 0x0B, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]
        hello += [0x00, 0x0A, 0x00, 0x0A, 0x00, 0x08, 0x00, 0x1D, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18]
        hello += [
            0x00, 0x0D, 0x00, 0x20, 0x00, 0x1E, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02,
            0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01,
            0x02, 0x02, 0x02, 0x03,
        ]
        hello += [0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00]
        return Data(hello)
    }

    private static func uint16(_ value: Int) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]
    }
}

// MARK: - v2ray-plugin mux

/// One mux.cool session (v2ray `common/mux`), as v2ray-plugin's client
/// opens it: a `New` frame for session 0 → `127.0.0.1:0` rides with the
/// first write, every write is a `Keep` frame with data, and only data for
/// the session comes back up. The server side of v2ray-plugin demuxes
/// unconditionally, so this layer is required whenever its `mux` is on.
final class MuxCoolStream: ByteStream, @unchecked Sendable {
    private enum Status: UInt8 {
        case new = 0x01
        case keep = 0x02
        case end = 0x03
        case keepAlive = 0x04
    }

    private static let optionData: UInt8 = 0x01
    private static let maxFrameData = 0xFFFF

    private let lower: any ByteStream
    private var opened = false
    private var ended = false
    private let inbound = DirectBuffer()

    init(lower: any ByteStream) {
        self.lower = lower
    }

    func send(_ data: Data) async throws {
        var wire = Data()
        if !opened {
            opened = true
            // [len][id 0][New][no data][TCP][port 0][IPv4 127.0.0.1]
            wire.append(contentsOf: [0x00, 0x0C, 0x00, 0x00, Status.new.rawValue, 0x00, 0x01, 0x00, 0x00, 0x01, 127, 0, 0, 1])
        }
        var offset = data.startIndex
        while offset < data.endIndex {
            let end = min(offset + Self.maxFrameData, data.endIndex)
            let count = end - offset
            wire.append(contentsOf: [0x00, 0x04, 0x00, 0x00, Status.keep.rawValue, Self.optionData])
            wire.append(contentsOf: [UInt8(count >> 8), UInt8(count & 0xFF)])
            wire.append(data[offset..<end])
            offset = end
        }
        if !wire.isEmpty {
            try await lower.send(wire)
        }
    }

    func receive() async throws -> Data? {
        while !ended {
            if let payload = try nextFrame() { return payload }
            if ended { break }
            guard let chunk = try await lower.receive() else {
                guard inbound.readableByteCount == 0 else {
                    throw TransportError.protocolViolation("truncated mux frame")
                }
                return nil
            }
            inbound.append(chunk)
        }
        return nil
    }

    /// An `End` frame closes the session both ways: no half-close.
    func finishWriting() async {}

    /// Next data payload from buffered frames; `nil` when more bytes are
    /// needed or the session ended.
    private func nextFrame() throws -> Data? {
        while true {
            let raw = inbound.readableBytes
            guard raw.count >= 2 else { return nil }
            let metaLength = Int(raw[0]) << 8 | Int(raw[1])
            guard metaLength >= 4, metaLength <= 512 else {
                throw TransportError.protocolViolation("mux metadata length \(metaLength)")
            }
            guard raw.count >= 2 + metaLength else { return nil }
            let status = raw[2 + 2]
            let hasData = raw[2 + 3] & Self.optionData != 0
            var frameEnd = 2 + metaLength
            var payload = Data()
            if hasData {
                guard raw.count >= frameEnd + 2 else { return nil }
                let dataLength = Int(raw[frameEnd]) << 8 | Int(raw[frameEnd + 1])
                guard raw.count >= frameEnd + 2 + dataLength else { return nil }
                payload = Data(raw[(frameEnd + 2)..<(frameEnd + 2 + dataLength)])
                frameEnd += 2 + dataLength
            }
            inbound.consume(frameEnd)
            switch Status(rawValue: status) {
            case .end:
                ended = true
                return payload.isEmpty ? nil : payload
            case .new, .keep:
                if !payload.isEmpty { return payload }
            case .keepAlive, nil:
                continue
            }
        }
    }
}
