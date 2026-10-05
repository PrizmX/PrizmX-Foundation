import Foundation
import os

/// ShadowsocksR obfuscation (`obfs`), client side.
///
/// Wire format follows shadowsocksr-libev `src/obfs` (http_simple.c,
/// tls1.2_ticket.c) and the Python client in `shadowsocks/obfsplugin`.
/// `tls1.2_ticket_fastauth` is the same client as `tls1.2_ticket_auth`.
@frozen
public enum SSRObfsKind: String, Sendable, Hashable, CaseIterable {
    case plain
    case httpSimple = "http_simple"
    case httpPost = "http_post"
    case tls12TicketAuth = "tls1.2_ticket_auth"
    case tls12TicketFastauth = "tls1.2_ticket_fastauth"

    /// Bytes this layer adds per frame. Add it to the protocol overhead
    /// before building `SSRContext` (auth_chain reports the sum).
    public var overhead: Int {
        switch self {
        case .plain, .httpSimple, .httpPost: 0
        case .tls12TicketAuth, .tls12TicketFastauth: 5
        }
    }
}

/// Client obfs, the layer closest to the socket. Plaintext is framed by the
/// protocol plugin, then the stream cipher, then this layer.
enum SSRObfs {
    /// `key` is `EVP_BytesToKey(password)` — tls1.2_ticket_auth HMACs with
    /// it. `headLength` is libev `server.head_len` (address-header size,
    /// default 30); a random 0...63 is added on top, matching
    /// `http_simple_client_encode`.
    static func stream(
        _ kind: SSRObfsKind,
        lower: any ByteStream,
        host: String,
        port: UInt16,
        param: String = "",
        key: [UInt8] = [],
        headLength: Int = 30
    ) -> any ByteStream {
        switch kind {
        case .plain:
            return SSRPlainStream(lower: lower, host: host, port: port, param: param)
        case .httpSimple:
            return SSRHTTPSimpleStream(lower: lower, host: host, port: port, param: param, headLength: headLength)
        case .httpPost:
            return SSRHTTPPostStream(lower: lower, host: host, port: port, param: param, headLength: headLength)
        case .tls12TicketAuth, .tls12TicketFastauth:
            return SSRTLSTicketAuthStream(lower: lower, host: host, port: port, param: param, key: key)
        }
    }
}

// MARK: - plain

/// No framing. `origin` in the obfs slot is this, not a protocol plugin.
final class SSRPlainStream: ByteStream, @unchecked Sendable {
    private let lower: any ByteStream

    init(lower: any ByteStream, host: String, port: UInt16, param: String) {
        self.lower = lower
        _ = (host, port, param)
    }

    func send(_ data: Data) async throws {
        try await lower.send(data)
    }

    func receive() async throws -> Data? {
        try await lower.receive()
    }

    func finishWriting() async {
        await lower.finishWriting()
    }
}

// MARK: - http_simple / http_post

/// `obfs-param`: comma-separated hosts, optional `#` custom header block.
enum SSRObfsParam {
    static func parse(_ raw: String) -> (hosts: [String], body: String?) {
        let hash = raw.firstIndex(of: "#")
        let hostPart = hash.map { String(raw[..<$0]) } ?? raw
        let body = hash.map { unescape(String(raw[raw.index(after: $0)...])) }
        var hosts = hostPart.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        if hosts.isEmpty { hosts = [""] }
        return (hosts, body)
    }

    /// libev's body scan: `\n` and a raw newline become CRLF, `\\` becomes
    /// `\`, an unknown escape keeps the backslash.
    static func unescape(_ body: String) -> String {
        var out = ""
        var escaped = false
        for character in body {
            if escaped {
                if character == "\\" {
                    out.append("\\")
                } else if character == "n" {
                    out.append("\r\n")
                } else {
                    out.append("\\")
                    out.append(character)
                }
                escaped = false
            } else if character == "\\" {
                escaped = true
            } else if character == "\n" {
                out.append("\r")
                out.append(character)
            } else {
                out.append(character)
            }
        }
        return out
    }
}

enum SSRHTTPObfs {
    /// libev `g_useragent` (the Python client uses the same twelve).
    static let userAgents = [
        "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/44.0",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/27.0.1453.93 Chrome/27.0.1453.93 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:35.0) Gecko/20100101 Firefox/35.0",
        "Mozilla/5.0 (compatible; WOW64; MSIE 10.0; Windows NT 6.2)",
        "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C)",
        "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Linux; Android 4.4; Nexus 5 Build/BuildID) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
    ]

    static let boundaryAlphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

    /// `head_len + (xorshift & 0x3F)`, capped at the buffer.
    static func headCount(_ count: Int, headLength: Int) -> Int {
        guard count > 0 else { return 0 }
        let budget = min(max(headLength, 0), count)
        let room = count - budget
        let jitter = room == 0 ? 0 : Int.random(in: 0...min(63, room))
        return budget + jitter
    }

    static func percentEncode(_ data: [UInt8]) -> String {
        let hex = Array("0123456789abcdef")
        var out = ""
        out.reserveCapacity(data.count * 3)
        for byte in data {
            out.append("%")
            out.append(hex[Int(byte >> 4)])
            out.append(hex[Int(byte & 0x0F)])
        }
        return out
    }

    static func randomBoundary() -> String {
        String((0..<32).map { _ in boundaryAlphabet[Int.random(in: 0..<boundaryAlphabet.count)] })
    }

    /// libev `http_simple_client_encode` / `http_post_client_encode`.
    /// `customBody` replaces the stock header block when `obfs-param`
    /// carries a `#` section.
    static func request(
        post: Bool,
        head: [UInt8],
        remainder: [UInt8],
        host: String,
        port: UInt16,
        userAgent: String,
        boundary: String,
        customBody: String?
    ) -> [UInt8] {
        let hostPort = port == 80 ? host : "\(host):\(port)"
        var text = "\(post ? "POST" : "GET") /\(percentEncode(head)) HTTP/1.1\r\nHost: \(hostPort)\r\n"
        if let customBody {
            text += customBody + "\r\n\r\n"
        } else {
            text += "User-Agent: \(userAgent)\r\n"
            text += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            text += "Accept-Language: en-US,en;q=0.8\r\n"
            text += "Accept-Encoding: gzip, deflate\r\n"
            if post {
                text += "Content-Type: multipart/form-data; boundary=\(boundary)\r\n"
            }
            text += "DNT: 1\r\nConnection: keep-alive\r\n\r\n"
        }
        return Array(text.utf8) + remainder
    }
}

/// HTTP camouflage. The first uplink write is a GET (or POST) whose path is
/// a percent-encoded prefix of the encrypted stream; everything after the
/// response head is the raw stream. A split response head is buffered —
/// libev drops it, which fails a truncated read.
class SSRHTTPObfsStream: ByteStream, @unchecked Sendable {
    private let lower: any ByteStream
    private let host: String
    private let port: UInt16
    private let param: String
    private let headLength: Int
    fileprivate let post: Bool
    private var headerSent = false
    /// `nil` once the response head has been consumed.
    private var responseHead: Data? = Data()

    fileprivate init(lower: any ByteStream, host: String, port: UInt16, param: String, headLength: Int, post: Bool) {
        self.lower = lower
        self.host = host
        self.port = port
        self.param = param
        self.headLength = headLength
        self.post = post
    }

    func send(_ data: Data) async throws {
        guard !headerSent else {
            try await lower.send(data)
            return
        }
        headerSent = true
        let bytes = [UInt8](data)
        let headCount = SSRHTTPObfs.headCount(bytes.count, headLength: headLength)
        let source = param.isEmpty ? host : param
        let parsed = SSRObfsParam.parse(source)
        let chosen = parsed.hosts[Int.random(in: 0..<parsed.hosts.count)]
        let agent = SSRHTTPObfs.userAgents[Int.random(in: 0..<SSRHTTPObfs.userAgents.count)]
        let wire = SSRHTTPObfs.request(
            post: post,
            head: Array(bytes.prefix(headCount)),
            remainder: Array(bytes.dropFirst(headCount)),
            host: chosen,
            port: port,
            userAgent: agent,
            boundary: SSRHTTPObfs.randomBoundary(),
            customBody: parsed.body
        )
        try await lower.send(Data(wire))
    }

    func receive() async throws -> Data? {
        guard responseHead != nil else {
            return try await lower.receive()
        }
        while var head = responseHead {
            guard let chunk = try await lower.receive() else {
                if head.isEmpty { return nil }
                throw TransportError.protocolViolation("truncated obfs response")
            }
            head.append(chunk)
            if let end = head.firstRange(of: Data("\r\n\r\n".utf8)) {
                responseHead = nil
                let rest = Data(head[end.upperBound...])
                if !rest.isEmpty { return rest }
                return try await lower.receive()
            }
            guard head.count <= 16 * 1024 else {
                throw TransportError.protocolViolation("obfs response too long")
            }
            responseHead = head
        }
        return try await lower.receive()
    }

    func finishWriting() async {
        await lower.finishWriting()
    }
}

final class SSRHTTPSimpleStream: SSRHTTPObfsStream, @unchecked Sendable {
    init(lower: any ByteStream, host: String, port: UInt16, param: String, headLength: Int = 30) {
        super.init(lower: lower, host: host, port: port, param: param, headLength: headLength, post: false)
    }
}

final class SSRHTTPPostStream: SSRHTTPObfsStream, @unchecked Sendable {
    init(lower: any ByteStream, host: String, port: UInt16, param: String, headLength: Int = 30) {
        super.init(lower: lower, host: host, port: port, param: param, headLength: headLength, post: true)
    }
}

// MARK: - tls1.2_ticket_auth

enum SSRTLSTicketAuth {
    /// TLS record cap. SSR chunks stay far below this; anything larger is
    /// a corrupt length, not a reason to wait.
    static let maxRecord = 18_432
    static let maxHandshake = 8_192

    static let cipherSuites: [UInt8] = [
        0x00, 0x1C, 0xC0, 0x2B, 0xC0, 0x2F, 0xCC, 0xA9, 0xCC, 0xA8, 0xCC, 0x14, 0xCC, 0x13, 0xC0, 0x0A,
        0xC0, 0x14, 0xC0, 0x09, 0xC0, 0x13, 0x00, 0x9C, 0x00, 0x35, 0x00, 0x2F, 0x00, 0x0A, 0x01, 0x00,
    ]

    /// Extensions that follow the session ticket, identical in libev and
    /// the Python client.
    static let tailExtensions: [UInt8] = [
        0x00, 0x0D, 0x00, 0x16, 0x00, 0x14, 0x06, 0x01, 0x06, 0x03, 0x05, 0x01, 0x05, 0x03, 0x04, 0x01,
        0x04, 0x03, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01, 0x02, 0x03, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x75, 0x50, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x02, 0x01,
        0x00, 0x00, 0x0A, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18,
    ]

    /// A host whose last byte is a digit is sent with an empty SNI
    /// (`tls1.2_ticket.c`).
    static func sniHost(_ host: String) -> String {
        guard let last = host.utf8.last, last >= UInt8(ascii: "0"), last <= UInt8(ascii: "9") else {
            return host
        }
        return ""
    }

    static func hmac10(_ key: [UInt8], _ data: [UInt8]) -> [UInt8]? {
        guard !key.isEmpty else { return nil }
        return Array(SSRBytes.hmac(key, data, sha1: true).prefix(10))
    }

    static func macEquals(_ mac: some Collection<UInt8>, key: [UInt8], data: [UInt8]) -> Bool {
        guard let expect = hmac10(key, data), mac.count == expect.count else { return false }
        return Array(mac) == expect
    }

    /// `[time BE][18 random][HMAC-SHA1-10]`, keyed by `key || clientID`.
    static func authData(unixTime: UInt32, random: [UInt8], key: [UInt8], clientID: [UInt8]) -> [UInt8] {
        var data = [
            UInt8(truncatingIfNeeded: unixTime >> 24),
            UInt8(truncatingIfNeeded: unixTime >> 16),
            UInt8(truncatingIfNeeded: unixTime >> 8),
            UInt8(truncatingIfNeeded: unixTime),
        ]
        data += padded(random, count: 18)
        data += hmac10(key + clientID, data) ?? Array(repeating: 0, count: 10)
        return data
    }

    /// ClientHello. Record version is TLS 1.0 (`03 01`); the inner version
    /// is TLS 1.2. The 32-byte random is auth data, the session id is
    /// `clientID`, and the session-ticket extension carries `ticket`.
    static func clientHello(
        unixTime: UInt32,
        random: [UInt8],
        clientID: [UInt8],
        ticket: [UInt8],
        host: String,
        key: [UInt8]
    ) -> [UInt8] {
        let identity = padded(clientID, count: 32)
        let auth = authData(unixTime: unixTime, random: random, key: key, clientID: identity)
        var ext: [UInt8] = [0xFF, 0x01, 0x00, 0x01, 0x00]
        ext += sniExtension(Array(sniHost(host).utf8))
        ext += [0x00, 0x17, 0x00, 0x00]
        ext += [0x00, 0x23] + SSRBytes.be16(ticket.count) + ticket
        ext += tailExtensions

        var body: [UInt8] = [0x03, 0x03]
        body += auth
        body.append(0x20)
        body += identity
        body += cipherSuites
        body += SSRBytes.be16(ext.count)
        body += ext

        var handshake: [UInt8] = [0x01, 0x00]
        handshake += SSRBytes.be16(body.count)
        handshake += body

        return [0x16, 0x03, 0x01] + SSRBytes.be16(handshake.count) + handshake
    }

    /// ChangeCipherSpec + Finished, then the buffered application records.
    /// The 10-byte HMAC covers the 33 bytes ahead of it.
    static func clientFinish(random: [UInt8], key: [UInt8], clientID: [UInt8], records: [UInt8]) -> [UInt8] {
        var head: [UInt8] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03, 0x00, 0x20]
        head += padded(random, count: 22)
        head += hmac10(key + clientID, head) ?? Array(repeating: 0, count: 10)
        return head + records
    }

    /// Application-data records. Under 1024 bytes stays one record; longer
    /// writes are split the way libev splits (`% 4096 + 100` while more
    /// than 2048 bytes remain).
    static func appRecords(_ data: [UInt8], chunkLength: (Int) -> Int = { _ in Int.random(in: 0..<4096) + 100 }) -> [UInt8] {
        guard !data.isEmpty else { return [] }
        if data.count < 1024 {
            return record(data)
        }
        var out: [UInt8] = []
        var start = 0
        while data.count - start > 2048 {
            let remaining = data.count - start
            var len = chunkLength(remaining)
            if len < 1 { len = 1 }
            if len > remaining { len = remaining }
            out += record(Array(data[start..<(start + len)]))
            start += len
        }
        if start < data.count {
            out += record(Array(data[start...]))
        }
        return out
    }

    /// End offset of a verified server handshake, or `nil` when more bytes
    /// are required. HMAC failure is `SSRError.obfsRejected`; a length or
    /// record the server never sends is `TransportError.protocolViolation`.
    ///
    /// The trailing HMAC covers the handshake through Finished only. A read
    /// that already contains the next application-data record must not fold
    /// those bytes into the MAC (the server appends them after the MAC).
    static func inspect(_ bytes: [UInt8], macKey: [UInt8]) throws -> Int? {
        guard let first = bytes.first else { return nil }
        guard first == 0x16 else {
            throw TransportError.protocolViolation("obfs server hello")
        }
        guard bytes.count >= 3 else { return nil }
        guard bytes[1] == 0x03, bytes[2] == 0x03 else {
            throw TransportError.protocolViolation("obfs server hello")
        }
        guard bytes.count >= 5 else { return nil }
        let firstLength = u16(bytes, 3)
        guard firstLength <= maxRecord else {
            throw TransportError.protocolViolation("obfs record length \(firstLength)")
        }
        // Auth data sits at a fixed offset inside ServerHello (86-byte
        // record on the wire). A shorter first record cannot be one.
        guard firstLength >= 71 else {
            throw TransportError.protocolViolation("obfs server hello")
        }
        if bytes.count >= 6, bytes[5] != 0x02 {
            throw TransportError.protocolViolation("obfs server hello")
        }
        if bytes.count >= 44, bytes[43] != 0x20 {
            throw TransportError.protocolViolation("obfs server hello")
        }
        if bytes.count >= 43,
           !macEquals(bytes[33..<43], key: macKey, data: Array(bytes[11..<33])) {
            throw SSRError.obfsRejected
        }

        var offset = 0
        var sawCCS = false
        while bytes.count >= offset + 5 {
            if offset > maxHandshake {
                throw TransportError.protocolViolation("obfs handshake too long")
            }
            let type = bytes[offset]
            let length = u16(bytes, offset + 3)
            guard length <= maxRecord else {
                throw TransportError.protocolViolation("obfs record length \(length)")
            }
            let frame = 5 + length
            guard bytes.count >= offset + frame else { break }
            if !sawCCS {
                if type == 0x16 {
                    offset += frame
                    continue
                }
                if type == 0x14 {
                    guard length == 1, bytes[offset + 5] == 0x01 else {
                        throw TransportError.protocolViolation("obfs change cipher spec")
                    }
                    sawCCS = true
                    offset += frame
                    continue
                }
                throw TransportError.protocolViolation("obfs handshake record")
            }
            guard type == 0x16 else {
                throw TransportError.protocolViolation("obfs finished")
            }
            offset += frame
            guard offset >= 10, offset <= bytes.count else {
                throw TransportError.protocolViolation("obfs finished")
            }
            let mac = bytes[(offset - 10)..<offset]
            guard macEquals(mac, key: macKey, data: Array(bytes[..<(offset - 10)])) else {
                throw SSRError.obfsRejected
            }
            return offset
        }
        if bytes.count > maxHandshake {
            throw TransportError.protocolViolation("obfs handshake too long")
        }
        return nil
    }

    static func record(_ payload: [UInt8]) -> [UInt8] {
        let count = min(payload.count, 0xFFFF)
        return [0x17, 0x03, 0x03, UInt8(count >> 8), UInt8(count & 0xFF)] + payload
    }

    private static func sniExtension(_ host: [UInt8]) -> [UInt8] {
        var name: [UInt8] = [0x00]
        name += SSRBytes.be16(host.count)
        name += host
        var ext: [UInt8] = [0x00, 0x00]
        ext += SSRBytes.be16(name.count + 2)
        ext += SSRBytes.be16(name.count)
        ext += name
        return ext
    }

    private static func padded(_ bytes: [UInt8], count: Int) -> [UInt8] {
        var out = Array(bytes.prefix(count))
        if out.count < count {
            out += Array(repeating: 0, count: count - out.count)
        }
        return out
    }

    private static func u16(_ bytes: [UInt8], _ offset: Int) -> Int {
        guard offset >= 0, bytes.count >= offset + 2 else { return 0 }
        return Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
    }
}

/// Fake TLS 1.2 session-ticket handshake. The first `send` emits only the
/// ClientHello and holds the payload; `receive` checks the server flight,
/// then writes ChangeCipherSpec + Finished + the held records before
/// returning application data. Later writes are application-data records.
final class SSRTLSTicketAuthStream: ByteStream, @unchecked Sendable {
    private struct State {
        var helloSent = false
        var handshakeDone = false
        var pending: [UInt8] = []
    }

    private let lower: any ByteStream
    private let host: String
    private let param: String
    private let key: [UInt8]
    private let clientID: [UInt8]
    private let writeLock = AsyncMutex()
    private let state = OSAllocatedUnfairLock(initialState: State())
    private let inbound = DirectBuffer()

    init(lower: any ByteStream, host: String, port: UInt16, param: String, key: [UInt8]) {
        self.lower = lower
        self.host = host
        self.param = param
        self.key = key
        self.clientID = SSRBytes.random(32)
        _ = port
    }

    private var macKey: [UInt8] { key + clientID }

    func send(_ data: Data) async throws {
        let bytes = [UInt8](data)
        let wire = state.withLock { current -> [UInt8]? in
            if current.handshakeDone {
                return SSRTLSTicketAuth.appRecords(bytes)
            }
            current.pending += SSRTLSTicketAuth.appRecords(bytes)
            if !current.helloSent {
                current.helloSent = true
                return clientHello()
            }
            return nil
        }
        guard let wire, !wire.isEmpty else { return }
        await writeLock.acquire()
        defer { writeLock.release() }
        try await lower.send(Data(wire))
    }

    func receive() async throws -> Data? {
        while true {
            if state.withLock({ $0.handshakeDone }) {
                if let payload = try nextAppRecord() { return payload }
            } else if let end = try SSRTLSTicketAuth.inspect(buffered(), macKey: macKey) {
                try await completeHandshake(end: end)
                continue
            }
            guard let chunk = try await lower.receive() else {
                return try endOfStream()
            }
            inbound.append(chunk)
        }
    }

    func finishWriting() async {
        await lower.finishWriting()
    }

    private func clientHello() -> [UInt8] {
        let source = param.isEmpty ? host : param
        let hosts = source.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        let chosen = hosts.isEmpty ? "" : hosts[Int.random(in: 0..<hosts.count)]
        let ticketLen = Int.random(in: 0..<164) * 2 + 64
        let now = UInt32(truncatingIfNeeded: Int(Date().timeIntervalSince1970))
        return SSRTLSTicketAuth.clientHello(
            unixTime: now,
            random: SSRBytes.random(18),
            clientID: clientID,
            ticket: SSRBytes.random(ticketLen),
            host: chosen,
            key: key
        )
    }

    /// Server flight is done. Send CCS + Finished + held records before any
    /// later `send` can emit an application-data record.
    private func completeHandshake(end: Int) async throws {
        await writeLock.acquire()
        defer { writeLock.release() }
        guard end >= 0, end <= inbound.readableByteCount else {
            throw TransportError.protocolViolation("obfs finished")
        }
        let pending = state.withLock { current -> [UInt8] in
            let queued = current.pending
            current.pending = []
            current.handshakeDone = true
            return queued
        }
        let finish = SSRTLSTicketAuth.clientFinish(
            random: SSRBytes.random(22),
            key: key,
            clientID: clientID,
            records: pending
        )
        inbound.consume(end)
        try await lower.send(Data(finish))
    }

    private func endOfStream() throws -> Data? {
        let (done, helloSent) = state.withLock { ($0.handshakeDone, $0.helloSent) }
        if done {
            if inbound.readableByteCount == 0 { return nil }
            throw TransportError.protocolViolation("truncated obfs record")
        }
        if !helloSent, inbound.readableByteCount == 0 { return nil }
        throw TransportError.protocolViolation("truncated obfs record")
    }

    private func nextAppRecord() throws -> Data? {
        while true {
            let count = inbound.readableByteCount
            guard count >= 5 else { return nil }
            let raw = inbound.readableBytes
            let type = raw[0]
            let versionOK = raw[1] == 0x03 && raw[2] == 0x03
            let length = Int(raw[3]) << 8 | Int(raw[4])
            guard type == 0x17, versionOK else {
                throw TransportError.protocolViolation("obfs application data")
            }
            guard length <= SSRTLSTicketAuth.maxRecord else {
                throw TransportError.protocolViolation("obfs record length \(length)")
            }
            guard count >= 5 + length else { return nil }
            let payload = Array(raw[5..<(5 + length)])
            inbound.consume(5 + length)
            if !payload.isEmpty { return Data(payload) }
        }
    }

    private func buffered() -> [UInt8] {
        Array(inbound.readableBytes)
    }
}
