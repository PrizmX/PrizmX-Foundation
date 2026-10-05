import CryptoKit
import Foundation
import os
import Testing
@testable import PrizmXProtocols

/// Scripted lower stream: records sends, replays queued downlink chunks.
private final class SSRScriptedStream: ByteStream, @unchecked Sendable {
    private let state = OSAllocatedUnfairLock(initialState: (sent: [Data](), replies: [Data](), finished: false))

    var sent: [Data] { state.withLock { $0.sent } }
    var finished: Bool { state.withLock { $0.finished } }

    func enqueue(_ data: Data) {
        state.withLock { $0.replies.append(data) }
    }

    func send(_ data: Data) async throws {
        state.withLock { $0.sent.append(data) }
    }

    func receive() async throws -> Data? {
        state.withLock { current -> Data? in
            current.replies.isEmpty ? nil : current.replies.removeFirst()
        }
    }

    func finishWriting() async {
        state.withLock { $0.finished = true }
    }
}

private func ssrHex(_ hex: String) -> [UInt8] {
    var out: [UInt8] = []
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        out.append(UInt8(hex[index..<next], radix: 16)!)
        index = next
    }
    return out
}

private func ssrHexString(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

/// Python `obfs_tls.server_encode` flight, so the parser is checked against
/// an independent builder. HMAC key is `key || clientID`.
private func ssrServerFlight(
    key: [UInt8],
    clientID: [UInt8],
    time: UInt32,
    random18: [UInt8],
    finishRandom: [UInt8],
    ticket: [UInt8]?,
    app: [UInt8]
) -> [UInt8] {
    var auth = [
        UInt8(truncatingIfNeeded: time >> 24),
        UInt8(truncatingIfNeeded: time >> 16),
        UInt8(truncatingIfNeeded: time >> 8),
        UInt8(truncatingIfNeeded: time),
    ] + random18
    let macKey = SymmetricKey(data: key + clientID)
    auth += Array(HMAC<Insecure.SHA1>.authenticationCode(for: auth, using: macKey).prefix(10))
    var body: [UInt8] = [0x03, 0x03] + auth + [0x20] + clientID
    body += [0xC0, 0x2F, 0x00, 0x00, 0x05, 0xFF, 0x01, 0x00, 0x01, 0x00]
    let hello = [0x02, 0x00] + SSRBytes.be16(body.count) + body
    var wire: [UInt8] = [0x16, 0x03, 0x03] + SSRBytes.be16(hello.count) + hello
    if let ticket {
        let payload = [0x04, 0x00] + SSRBytes.be16(ticket.count) + ticket
        wire += [0x16, 0x03, 0x03] + SSRBytes.be16(payload.count) + payload
    }
    wire += [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]
    let finishLen = finishRandom.count + 10
    wire += [0x16, 0x03, 0x03] + SSRBytes.be16(finishLen) + finishRandom
    wire += Array(HMAC<Insecure.SHA1>.authenticationCode(for: wire, using: macKey).prefix(10))
    if !app.isEmpty {
        wire += [0x17, 0x03, 0x03] + SSRBytes.be16(app.count) + app
    }
    return wire
}

@Suite("SSRObfs")
struct SSRObfsTests {
    // Python obfs_tls vectors: key 00..0f, client id 00..1f, ticket 0xAB×64,
    // host cdn.example, client time 0x66000001, client random 00..11.
    private static let helloHex = "160301010501000101030366000001000102030405060708090a0b0c0d0e0f101102dc6e85adb8c62607d620000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f001cc02bc02fcca9cca8cc14cc13c00ac014c009c013009c0035002f000a0100009cff0100010000000010000e00000b63646e2e6578616d706c650017000000230040abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab000d0016001406010603050105030401040303010303020102030005000501000000000012000075500000000b00020100000a0006000400170018"
    // Server time 0x66000002, server random 0x5A×18, finish payload 0x22×22.
    private static let serverHex = "16030300510200004d0303660000025a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0814e3e3da9fbdd50b3620000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fc02f000005ff0100010014030300010116030300202222222222222222222222222222222222222222222250bf9ee65411499bd1b7"
    // Same flight plus a 64-byte session ticket and a 40-byte Finished.
    private static let serverTicketHex = "16030300510200004d0303660000025a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0814e3e3da9fbdd50b3620000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fc02f000005ff010001001603030044040000401111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111114030300010116030300283333333333333333333333333333333333333333333333333333333333338ccadb7fabc36fd7a1c3"

    private let key = (0..<16).map { UInt8($0) }
    private let clientID = (0..<32).map { UInt8($0) }

    @Test func overheadAndAliases() {
        #expect(SSRObfsKind.plain.overhead == 0)
        #expect(SSRObfsKind.httpSimple.overhead == 0)
        #expect(SSRObfsKind.httpPost.overhead == 0)
        #expect(SSRObfsKind.tls12TicketAuth.overhead == 5)
        #expect(SSRObfsKind.tls12TicketFastauth.overhead == 5)
        #expect(SSRObfsKind(rawValue: "tls1.2_ticket_fastauth") == .tls12TicketFastauth)
        #expect(SSRObfsKind(rawValue: "tls1.2_ticket_auth")?.rawValue == "tls1.2_ticket_auth")
        #expect(SSRObfsKind(rawValue: "http_simple") == .httpSimple)
        #expect(SSRObfsKind(rawValue: "not-an-obfs") == nil)
    }

    @Test func plainForwardsBothDirections() async throws {
        let lower = SSRScriptedStream()
        lower.enqueue(Data([0x00, 0xFF]))
        let stream = SSRPlainStream(lower: lower, host: "h", port: 1, param: "")
        try await stream.send(Data([1, 2, 3]))
        await stream.finishWriting()
        #expect(lower.sent == [Data([1, 2, 3])])
        #expect(try await stream.receive() == Data([0x00, 0xFF]))
        #expect(try await stream.receive() == nil)
        #expect(lower.finished)
    }

    @Test func httpRequestMatchesLibevTemplate() {
        let wire = SSRHTTPObfs.request(
            post: false,
            head: [0x00, 0xFF],
            remainder: [0x10, 0x11],
            host: "example.com",
            port: 8388,
            userAgent: "TestAgent",
            boundary: "",
            customBody: nil
        )
        let text = "GET /%00%ff HTTP/1.1\r\nHost: example.com:8388\r\nUser-Agent: TestAgent\r\n"
            + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            + "Accept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\n"
            + "DNT: 1\r\nConnection: keep-alive\r\n\r\n"
        #expect(wire == Array(text.utf8) + [0x10, 0x11])

        let boundary = String(repeating: "A", count: 32)
        let onEighty = SSRHTTPObfs.request(
            post: true,
            head: [],
            remainder: [],
            host: "example.com",
            port: 80,
            userAgent: "TestAgent",
            boundary: boundary,
            customBody: nil
        )
        let post = String(decoding: onEighty, as: UTF8.self)
        #expect(post.hasPrefix("POST / HTTP/1.1\r\nHost: example.com\r\n"))
        #expect(post.contains("Content-Type: multipart/form-data; boundary=\(String(repeating: "A", count: 32))\r\n"))
    }

    @Test func httpParamUnescapeMatchesLibev() {
        let parsed = SSRObfsParam.parse("a.com,b.com#X: 1\\nY: 2")
        #expect(parsed.hosts == ["a.com", "b.com"])
        #expect(parsed.body == "X: 1\r\nY: 2")
        #expect(SSRObfsParam.unescape("raw\nline") == "raw\r\nline")
        #expect(SSRObfsParam.parse("#only").hosts == [""])
    }

    @Test func httpSimpleRoundTripsPrefixAndStripsServerHead() async throws {
        let payload = (0..<200).map { UInt8($0) }
        let reply = Data("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nServer: nginx\r\n\r\n".utf8)
        let lower = SSRScriptedStream()
        lower.enqueue(Data(reply.prefix(18)))
        lower.enqueue(Data(reply.dropFirst(18)) + Data("BODY".utf8))
        lower.enqueue(Data([0xAB]))
        let stream = SSRHTTPSimpleStream(lower: lower, host: "ignored.example", port: 8388, param: "", headLength: 30)
        try await stream.send(Data(payload))
        try await stream.send(Data([9]))
        let wire = lower.sent[0]
        let decoded = try decodeHTTP(wire, method: "GET")
        #expect(decoded.head.count >= 30 && decoded.head.count <= 93)
        #expect(decoded.head + decoded.tail == payload)
        #expect(lower.sent[1] == Data([9]))
        let header = String(decoding: wire.prefix(decoded.headerEnd), as: UTF8.self)
        #expect(header.contains("Host: ignored.example:8388\r\n"))
        #expect(SSRHTTPObfs.userAgents.contains { header.contains($0) })
        #expect(try await stream.receive() == Data("BODY".utf8))
        #expect(try await stream.receive() == Data([0xAB]))
    }

    @Test func httpPostCustomBodyAndPort80() async throws {
        let lower = SSRScriptedStream()
        let stream = SSRHTTPPostStream(
            lower: lower,
            host: "fallback.example",
            port: 80,
            param: "cdn.example#X-Test: a\\nX-Next: b",
            headLength: 30
        )
        try await stream.send(Data([0x01, 0x02]))
        let text = String(decoding: lower.sent[0], as: UTF8.self)
        #expect(text.hasPrefix("POST /%01%02 HTTP/1.1\r\nHost: cdn.example\r\n"))
        #expect(text.contains("X-Test: a\r\nX-Next: b\r\n\r\n"))
        #expect(!text.contains("User-Agent:"))
        #expect(!text.contains(":80"))
    }

    @Test func httpRejectsTruncatedAndOversizedResponse() async throws {
        let missing = SSRScriptedStream()
        missing.enqueue(Data("HTTP/1.1 200 OK\r\n".utf8))
        let truncated = SSRHTTPSimpleStream(lower: missing, host: "h", port: 1, param: "")
        await #expect(throws: TransportError.protocolViolation("truncated obfs response")) {
            try await truncated.receive()
        }

        let huge = SSRScriptedStream()
        huge.enqueue(Data(repeating: 0x41, count: 16 * 1024 + 1))
        let oversized = SSRHTTPSimpleStream(lower: huge, host: "h", port: 1, param: "")
        await #expect(throws: TransportError.protocolViolation("obfs response too long")) {
            try await oversized.receive()
        }

        let binary = SSRScriptedStream()
        binary.enqueue(Data([0xFF, 0xFE, 0x00]))
        let garbage = SSRHTTPSimpleStream(lower: binary, host: "h", port: 1, param: "")
        await #expect(throws: TransportError.protocolViolation("truncated obfs response")) {
            try await garbage.receive()
        }
    }

    @Test func tlsClientHelloMatchesPythonVector() {
        let hello = SSRTLSTicketAuth.clientHello(
            unixTime: 0x6600_0001,
            random: (0..<18).map { UInt8($0) },
            clientID: clientID,
            ticket: Array(repeating: 0xAB, count: 64),
            host: "cdn.example",
            key: key
        )
        #expect(hello.count == 266)
        #expect(ssrHexString(hello) == Self.helloHex)
        #expect(Array(hello[0..<3]) == [0x16, 0x03, 0x01])
        #expect(Array(hello[9..<11]) == [0x03, 0x03])
        #expect(Array(hello[44..<76]) == clientID)
    }

    @Test func tlsEmptySNIWhenHostEndsWithDigit() {
        let hello = SSRTLSTicketAuth.clientHello(
            unixTime: 1,
            random: Array(repeating: 0, count: 18),
            clientID: clientID,
            ticket: [1],
            host: "1.2.3.4",
            key: key
        )
        #expect(Data(hello).range(of: Data("1.2.3.4".utf8)) == nil)
        #expect(Data(hello).range(of: Data([0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00])) != nil)
    }

    @Test func tlsClientFinishHMACMatchesPython() {
        let finish = SSRTLSTicketAuth.clientFinish(
            random: Array(repeating: 0x44, count: 22),
            key: key,
            clientID: clientID,
            records: [0x17, 0x03, 0x03, 0x00, 0x01, 0x99]
        )
        #expect(Array(finish[0..<6]) == [0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
        #expect(ssrHexString(Array(finish[33..<43])) == "60d2dece79c8f672fe7c")
        #expect(Array(finish.suffix(6)) == [0x17, 0x03, 0x03, 0x00, 0x01, 0x99])
    }

    @Test func tlsAppRecordsSplitLikeLibev() {
        let one = SSRTLSTicketAuth.appRecords(Array(repeating: 1, count: 100))
        #expect(Array(one[0..<5]) == [0x17, 0x03, 0x03, 0x00, 100])
        let split = SSRTLSTicketAuth.appRecords(Array(repeating: 2, count: 2049), chunkLength: { _ in 100 })
        #expect(Array(split[0..<5]) == [0x17, 0x03, 0x03, 0x00, 100])
        #expect(Array(split[105..<110]) == [0x17, 0x03, 0x03, 0x07, 0x9D])
        #expect(split.count == 5 + 100 + 5 + 1949)
    }

    @Test func tlsServerFlightFixedVectors() throws {
        let macKey = key + clientID
        let server = ssrHex(Self.serverHex)
        #expect(try SSRTLSTicketAuth.inspect(server, macKey: macKey) == 129)
        let withApp = server + [0x17, 0x03, 0x03, 0x00, 0x02, 0x6F, 0x6B]
        #expect(try SSRTLSTicketAuth.inspect(withApp, macKey: macKey) == 129)
        #expect(try SSRTLSTicketAuth.inspect(ssrHex(Self.serverTicketHex), macKey: macKey) == 210)
        #expect(try SSRTLSTicketAuth.inspect(Array(server.prefix(40)), macKey: macKey) == nil)
        #expect(try SSRTLSTicketAuth.inspect([], macKey: macKey) == nil)

        var badAuth = server
        badAuth[33] ^= 0xFF
        #expect(throws: SSRError.obfsRejected) {
            try SSRTLSTicketAuth.inspect(badAuth, macKey: macKey)
        }
        var badTail = server
        badTail[128] ^= 0xFF
        #expect(throws: SSRError.obfsRejected) {
            try SSRTLSTicketAuth.inspect(badTail, macKey: macKey)
        }
        #expect(throws: TransportError.protocolViolation("obfs server hello")) {
            try SSRTLSTicketAuth.inspect([0x00, 0x03, 0x03], macKey: macKey)
        }
        #expect(throws: TransportError.protocolViolation("obfs record length 65535")) {
            try SSRTLSTicketAuth.inspect([0x16, 0x03, 0x03, 0xFF, 0xFF], macKey: macKey)
        }
        #expect(throws: TransportError.protocolViolation("obfs server hello")) {
            try SSRTLSTicketAuth.inspect([0x16, 0x03, 0x01, 0x00, 0x51], macKey: macKey)
        }
    }

    @Test func tlsStreamCompletesHandshakeAndUnwrapsRecords() async throws {
        let lower = SSRScriptedStream()
        let stream = SSRTLSTicketAuthStream(lower: lower, host: "cdn.example", port: 443, param: "", key: key)
        try await stream.send(Data("hello".utf8))
        let hello = [UInt8](lower.sent[0])
        #expect(Array(hello.prefix(3)) == [0x16, 0x03, 0x01])
        #expect(!Data(hello).contains(Data("hello".utf8)))
        let id = Array(hello[44..<76])
        let flight = ssrServerFlight(
            key: key,
            clientID: id,
            time: 0x6600_0002,
            random18: Array(repeating: 0x5A, count: 18),
            finishRandom: Array(repeating: 0x22, count: 22),
            ticket: nil,
            app: Array("ok".utf8)
        )
        lower.enqueue(Data(flight.prefix(20)))
        lower.enqueue(Data(flight.dropFirst(20).prefix(40)))
        lower.enqueue(Data(flight.dropFirst(60)))
        lower.enqueue(Data([0x17, 0x03, 0x03, 0x00, 0x01]))
        lower.enqueue(Data([0x21, 0x17, 0x03, 0x03, 0x00, 0x00, 0x17, 0x03, 0x03, 0x00, 0x01, 0x22]))
        #expect(try await stream.receive() == Data("ok".utf8))
        let finish = [UInt8](lower.sent[1])
        #expect(Array(finish.prefix(11)) == [0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03, 0x00, 0x20])
        let macKey = SymmetricKey(data: key + id)
        let expect = Array(HMAC<Insecure.SHA1>.authenticationCode(for: finish.prefix(33), using: macKey).prefix(10))
        #expect(Array(finish[33..<43]) == expect)
        #expect(Data(finish).range(of: Data([0x17, 0x03, 0x03, 0x00, 0x05]) + Data("hello".utf8)) != nil)
        #expect(try await stream.receive() == Data([0x21]))
        #expect(try await stream.receive() == Data([0x22]))
        try await stream.send(Data("Z".utf8))
        #expect([UInt8](lower.sent[2]) == [0x17, 0x03, 0x03, 0x00, 0x01, 0x5A])
        await stream.finishWriting()
        #expect(lower.finished)
    }

    @Test func tlsStreamRejectsBadHandshakeAndTruncation() async throws {
        let bad = SSRScriptedStream()
        bad.enqueue(Data([0x15, 0x03, 0x03, 0x00, 0x00]))
        let wrongType = SSRTLSTicketAuthStream(lower: bad, host: "h", port: 1, param: "", key: key)
        try await wrongType.send(Data([1]))
        await #expect(throws: TransportError.protocolViolation("obfs server hello")) {
            try await wrongType.receive()
        }

        let short = SSRScriptedStream()
        short.enqueue(Data([0x16, 0x03, 0x03, 0x00, 0x51, 0x02, 0x00]))
        let truncated = SSRTLSTicketAuthStream(lower: short, host: "h", port: 1, param: "", key: key)
        try await truncated.send(Data([1]))
        await #expect(throws: TransportError.protocolViolation("truncated obfs record")) {
            try await truncated.receive()
        }

        let lower = SSRScriptedStream()
        let stream = SSRTLSTicketAuthStream(lower: lower, host: "h", port: 1, param: "cdn.example,1.2.3.4", key: key)
        try await stream.send(Data("x".utf8))
        let id = Array([UInt8](lower.sent[0])[44..<76])
        var flight = ssrServerFlight(
            key: key,
            clientID: id,
            time: 1,
            random18: Array(repeating: 3, count: 18),
            finishRandom: Array(repeating: 4, count: 22),
            ticket: Array(repeating: 9, count: 64),
            app: [0x61]
        )
        flight[33] ^= 0x01
        lower.enqueue(Data(flight))
        await #expect(throws: SSRError.obfsRejected) {
            try await stream.receive()
        }
    }

    @Test func tlsStreamRejectsMalformedApplicationData() async throws {
        let lower = SSRScriptedStream()
        let stream = SSRTLSTicketAuthStream(lower: lower, host: "h", port: 443, param: "", key: key)
        try await stream.send(Data([7]))
        let id = Array([UInt8](lower.sent[0])[44..<76])
        let flight = ssrServerFlight(
            key: key,
            clientID: id,
            time: 2,
            random18: Array(repeating: 1, count: 18),
            finishRandom: Array(repeating: 2, count: 30),
            ticket: nil,
            app: []
        )
        lower.enqueue(Data(flight))
        lower.enqueue(Data([0x17, 0x03, 0x03, 0xFF, 0xFF, 0x00]))
        await #expect(throws: TransportError.protocolViolation("obfs record length 65535")) {
            try await stream.receive()
        }

        let typed = SSRScriptedStream()
        let other = SSRTLSTicketAuthStream(lower: typed, host: "h", port: 1, param: "", key: key)
        try await other.send(Data([7]))
        let otherID = Array([UInt8](typed.sent[0])[44..<76])
        typed.enqueue(Data(ssrServerFlight(
            key: key,
            clientID: otherID,
            time: 2,
            random18: Array(repeating: 1, count: 18),
            finishRandom: Array(repeating: 2, count: 22),
            ticket: nil,
            app: []
        )))
        typed.enqueue(Data([0x15, 0x03, 0x03, 0x00, 0x01, 0x00]))
        await #expect(throws: TransportError.protocolViolation("obfs application data")) {
            try await other.receive()
        }
    }

    private func decodeHTTP(_ wire: Data, method: String) throws -> (head: [UInt8], tail: [UInt8], headerEnd: Int) {
        let marker = Data(" HTTP/1.1\r\n".utf8)
        let separator = Data("\r\n\r\n".utf8)
        guard let line = wire.range(of: marker), let end = wire.range(of: separator) else {
            throw TransportError.protocolViolation("test request")
        }
        let prefix = Data("\(method) /".utf8)
        #expect(wire.prefix(prefix.count) == prefix)
        let encoded = wire[prefix.count..<line.lowerBound]
        guard encoded.count.isMultiple(of: 3) else {
            throw TransportError.protocolViolation("test request")
        }
        var head: [UInt8] = []
        var index = encoded.startIndex
        while index < encoded.endIndex {
            guard encoded[index] == UInt8(ascii: "%") else {
                throw TransportError.protocolViolation("test request")
            }
            let high = encoded[encoded.index(index, offsetBy: 1)]
            let low = encoded[encoded.index(index, offsetBy: 2)]
            head.append(UInt8(hexNibble(high) << 4 | hexNibble(low)))
            index = encoded.index(index, offsetBy: 3)
        }
        return (head, Array(wire[end.upperBound...]), wire.distance(from: wire.startIndex, to: end.upperBound))
    }

    private func hexNibble(_ byte: UInt8) -> UInt8 {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): byte - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): byte - UInt8(ascii: "a") + 10
        default: 0
        }
    }
}

