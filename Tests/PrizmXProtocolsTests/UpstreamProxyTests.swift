import Foundation
import Testing
@testable import PrizmXProtocols

@Suite("HTTP CONNECT")
struct HTTPConnectTests {

    @Test func requestCarriesAuthorityBasicAuthAndHeaders() {
        let request = HTTPConnectOutboundConnection.request(
            target: Endpoint(domain: "example.com", port: 443),
            credentials: ProxyCredentials(username: "user", password: "pass"),
            headers: ["User-Agent": "PrizmX", "Host": "ignored"]
        )
        #expect(String(decoding: request, as: UTF8.self) == """
        CONNECT example.com:443 HTTP/1.1\r
        Host: example.com:443\r
        Proxy-Authorization: Basic dXNlcjpwYXNz\r
        User-Agent: PrizmX\r
        \r

        """)
    }

    @Test func bracketsIPv6Authority() {
        let target = Endpoint(host: .ipv6(IPv6Address(high: 0x2001_0db8_0000_0000, low: 1)), port: 8443)
        let request = HTTPConnectOutboundConnection.request(target: target, credentials: nil, headers: [:])
        #expect(String(decoding: request, as: UTF8.self).hasPrefix("CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n"))
    }

    @Test func acceptsOnly2xxReplies() throws {
        try HTTPConnectOutboundConnection.checkReply(Array("HTTP/1.1 200 Connection established\r\n\r\n".utf8))
        try HTTPConnectOutboundConnection.checkReply(Array("HTTP/1.0 200\r\n\r\n".utf8))
        #expect(throws: ProxyHandshakeError.httpStatus(407)) {
            try HTTPConnectOutboundConnection.checkReply(Array("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".utf8))
        }
        #expect(throws: ProxyHandshakeError.malformedResponse) {
            try HTTPConnectOutboundConnection.checkReply(Array("SSH-2.0-OpenSSH\r\n\r\n".utf8))
        }
    }
}

@Suite("SOCKS5")
struct SOCKS5Tests {

    @Test func connectRequestUsesSOCKSAddress() throws {
        let request = try SOCKS5OutboundConnection.request(
            command: .connect,
            target: Endpoint(domain: "a.io", port: 80)
        )
        #expect(request == [0x05, 0x01, 0x00, 0x03, 4, 0x61, 0x2E, 0x69, 0x6F, 0x00, 0x50])
    }

    @Test func authRequestFollowsRFC1929() throws {
        let request = try SOCKS5OutboundConnection.authRequest(ProxyCredentials(username: "ab", password: "c"))
        #expect(request == [0x01, 2, 0x61, 0x62, 1, 0x63])
    }

    @Test func unspecifiedRelayAddressMeansServer() {
        let server = Endpoint(domain: "proxy.example", port: 1080)
        let any = Endpoint(host: .ipv4(.any), port: 40000)
        #expect(SOCKS5DatagramOutbound.relay(bound: any, server: server) == Endpoint(domain: "proxy.example", port: 40000))
        let explicit = Endpoint(host: .ipv4(IPv4Address(10, 0, 0, 2)), port: 40000)
        #expect(SOCKS5DatagramOutbound.relay(bound: explicit, server: server) == explicit)
    }

    @Test func udpPayloadStripsHeaderAndDropsFragments() {
        let packet = Data([0, 0, 0, 0x01, 8, 8, 8, 8, 0, 53, 0xAB, 0xCD])
        #expect(SOCKS5DatagramOutbound.payload(of: packet) == Data([0xAB, 0xCD]))
        var fragment = packet
        fragment[2] = 1
        #expect(SOCKS5DatagramOutbound.payload(of: fragment) == nil)
    }
}
