import Foundation
import Testing
import PrizmXCore
import PrizmXProtocols

@Test func mixedPortClassifiesSOCKSVersusHTTP() {
    #expect(MixedPortParser.kind(firstByte: 0x05) == .socks5)
    #expect(MixedPortParser.kind(firstByte: UInt8(ascii: "C")) == .http)
}

@Test func mixedPortParsesHTTPConnect() throws {
    let request = Data("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".utf8)
    let parsed = try MixedPortParser.parseHTTP(request)
    #expect(parsed.0.host == "example.com")
    #expect(parsed.0.port == 443)
    #expect(parsed.0.command == .connect)
}

@Test func mixedPortRewritesAbsoluteFormGET() throws {
    let request = Data("GET http://example.com/foo?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8)
    let parsed = try MixedPortParser.parseHTTP(request)
    #expect(parsed.0.host == "example.com")
    #expect(parsed.0.port == 80)
    #expect(parsed.0.command == .forward)
    let preface = String(data: parsed.0.preface, encoding: .utf8) ?? ""
    #expect(preface.hasPrefix("GET /foo?q=1 HTTP/1.1"))
}

@Test func mixedPortHTTPNeedsMoreUntilHeadersEnd() {
    let partial = Data("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com".utf8)
    #expect(throws: MixedPortParser.ParseError.needMore) {
        _ = try MixedPortParser.parseHTTP(partial)
    }
}

@Test func mixedPortParsesSOCKS5DomainRequest() throws {
    let greeting = Data([0x05, 0x01, 0x00])
    #expect(try MixedPortParser.parseSOCKSGreeting(greeting) == 3)
    var request = Data([0x05, 0x01, 0x00, 0x03, 11])
    request.append(contentsOf: Array("example.com".utf8))
    request.append(contentsOf: [0x01, 0xBB])
    let parsed = try MixedPortParser.parseSOCKSRequest(request)
    #expect(parsed.0.host == "example.com")
    #expect(parsed.0.port == 443)
}

@Test func mixedPortParsesSOCKS5IPv4Request() throws {
    let request = Data([0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x35])
    let parsed = try MixedPortParser.parseSOCKSRequest(request)
    #expect(parsed.0.host == "1.1.1.1")
    #expect(parsed.0.port == 53)
}
