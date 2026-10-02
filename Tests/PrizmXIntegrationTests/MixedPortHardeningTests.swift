import Foundation
import Testing
@testable import PrizmXCore
import PrizmXNodes
@testable import PrizmXProtocols
import PrizmXRules

@Test func forwardRewriteKeepsPercentEncodingAndDropsProxyHeaders() throws {
    let request = Data((
        "GET http://a.example:8080/p%2Fq/%E4%B8%AD?x=%20y HTTP/1.1\r\n"
            + "Host: a.example:8080\r\nProxy-Connection: keep-alive\r\n"
            + "Proxy-Authorization: Basic dTpw\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n"
    ).utf8)
    let (parsed, leftover) = try MixedPortParser.parseHTTP(request)
    #expect(parsed.host == "a.example")
    #expect(parsed.port == 8080)
    #expect(parsed.proxyAuthorization == "Basic dTpw")
    #expect(parsed.body == .none)
    #expect(leftover.isEmpty)
    let head = String(decoding: parsed.preface, as: UTF8.self)
    #expect(head.hasPrefix("GET /p%2Fq/%E4%B8%AD?x=%20y HTTP/1.1\r\n"))
    #expect(!head.lowercased().contains("proxy-"))
    #expect(!head.contains("keep-alive"))
    #expect(head.hasSuffix("Connection: close\r\n\r\n"))
    #expect(head.contains("Accept: */*\r\n"))
}

/// Keep-alive proxy connection: the second request names another origin
/// and must never be forwarded to the first one.
@Test func forwardStreamStopsAfterFirstRequest() async throws {
    let first = "POST http://a.example/upload HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\n\r\n"
    let second = "GET http://b.example/secret HTTP/1.1\r\nHost: b.example\r\n\r\n"
    let wire = Data((first + "hello" + second).utf8)
    let (parsed, leftover) = try MixedPortParser.parseHTTP(wire)
    #expect(parsed.body == .length(5))
    let inbound = ScriptedInbound(endpoint: Endpoint(domain: "a.example", port: 80))
    inbound.feed(leftover)
    inbound.feed(nil)
    let stream = HTTPForwardInbound(inner: inbound, head: parsed.preface, body: parsed.body)
    var forwarded = Data()
    while let chunk = try await stream.read() { forwarded.append(chunk) }
    let text = String(decoding: forwarded, as: UTF8.self)
    #expect(text.hasPrefix("POST /upload HTTP/1.1\r\n"))
    #expect(text.hasSuffix("\r\n\r\nhello"))
    #expect(!text.contains("b.example"))
    #expect(!stream.supportsHalfClose)
}

@Test func chunkedFramerFindsBodyEnd() throws {
    var framer = HTTPBodyFramer(.chunked)
    let body = Data("4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: 1\r\n\r\n".utf8)
    let next = Data("GET / HTTP/1.1\r\n".utf8)
    // Feed byte-by-byte-ish pieces to exercise state across reads.
    var consumed = 0
    for piece in stride(from: 0, to: body.count, by: 7) {
        let slice = body.subdata(in: piece..<min(piece + 7, body.count))
        consumed += try framer.consume(slice)
    }
    #expect(consumed == body.count)
    #expect(framer.isComplete)
    #expect(try framer.consume(next) == 0)

    var bad = HTTPBodyFramer(.chunked)
    #expect(throws: MixedPortParser.ParseError.self) { _ = try bad.consume(Data("zz\r\n".utf8)) }
}

@Test func upgradeRequestPassesThrough() throws {
    let request = Data("GET http://ws.example/chat HTTP/1.1\r\nHost: ws.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".utf8)
    let (parsed, _) = try MixedPortParser.parseHTTP(request)
    #expect(parsed.body == .passthrough)
    let head = String(decoding: parsed.preface, as: UTF8.self)
    #expect(head.contains("Connection: Upgrade\r\n"))
    #expect(!head.contains("Connection: close"))
}

@Test func socksUserPassParses() throws {
    var message = Data([0x01, 0x04])
    message.append(contentsOf: Array("user".utf8))
    message.append(0x04)
    message.append(contentsOf: Array("pass".utf8))
    message.append(0x05)
    let parsed = try MixedPortParser.parseSOCKSUserPass(message)
    #expect(parsed.credentials == "user:pass")
    #expect(parsed.consumed == 11)
    #expect(throws: MixedPortParser.ParseError.needMore) {
        _ = try MixedPortParser.parseSOCKSUserPass(message.prefix(5))
    }
    #expect(MixedPortParser.socksMethods(Data([0x05, 0x02, 0x00, 0x02])) == [0x00, 0x02])
}

@Test func mixedPortAccessPolicy() {
    let open = MixedPortAccess()
    #expect(!open.requiresAuthentication)
    for source in ["127.0.0.1", "10.1.2.3", "172.20.0.5", "192.168.1.9", "100.100.1.1", "169.254.3.3",
                   "::1", "fd00::1", "fe80::1%en0", "::ffff:192.168.1.2"] {
        #expect(open.acceptsSource(source), "\(source)")
    }
    for source in ["8.8.8.8", "172.32.0.1", "2001:db8::1", "::ffff:8.8.8.8", ""] {
        #expect(!open.acceptsSource(source), "\(source)")
    }

    let auth = MixedPortAccess(authentication: ["alice:secret"])
    #expect(auth.needsAuthentication(from: "192.168.1.2"))
    #expect(!auth.needsAuthentication(from: "127.0.0.1"))
    #expect(!auth.needsAuthentication(from: "::1"))
    #expect(auth.accepts(credentials: MixedPortParser.basicCredentials("Basic YWxpY2U6c2VjcmV0")))
    #expect(!auth.accepts(credentials: MixedPortParser.basicCredentials("Basic YWxpY2U6d3Jvbmc=")))
    #expect(!auth.accepts(credentials: nil))

    for target in ["127.0.0.1", "127.9.9.9", "::1", "localhost", "LOCALHOST.", "api.localhost", "0.0.0.0"] {
        #expect(MixedPortAccess.isLoopbackTarget(host: target), "\(target)")
    }
    #expect(!MixedPortAccess.isLoopbackTarget(host: "example.com"))
    #expect(!MixedPortAccess.isLoopbackTarget(host: "10.0.0.1"))
}

@Test func headerEndSearchesIncrementally() {
    let data = Data("GET / HTTP/1.1\r\nHost: a\r\n\r\n".utf8)
    #expect(MixedPortParser.headerEnd(in: data, from: 0) != nil)
    #expect(MixedPortParser.headerEnd(in: data, from: data.count - 4) != nil)
    #expect(MixedPortParser.headerEnd(in: data.prefix(data.count - 1), from: -3) == nil)
}

@Test func thisHostCoversLoopbackUnspecifiedAndMappedForms() throws {
    #expect(Endpoint.Host.ipv4(IPv4Address(127, 9, 9, 9)).isThisHost)
    #expect(Endpoint.Host.ipv4(IPv4Address(0, 0, 0, 0)).isThisHost)
    #expect(Endpoint.Host.ipv6(.loopback).isThisHost)
    #expect(Endpoint.Host.ipv6(try #require(IPv6Address(parsing: "::ffff:127.0.0.1"))).isThisHost)
    #expect(!Endpoint.Host.ipv4(IPv4Address(192, 168, 1, 1)).isThisHost)
    #expect(!Endpoint.Host.domain("localhost").isThisHost)
}

/// Allow LAN: a name that lands on this host (sniffed `Host: localhost`, a
/// hosts entry, or DNS answering 127.0.0.1) must not be dialed for a LAN
/// client, while a local client keeps reaching it.
@Test func remoteClientDirectDialNeverReachesThisHost() async throws {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("prizmx-hosts-\(UUID().uuidString)")
    try "127.0.0.1 lan-target.test\n".write(to: url, atomically: true, encoding: .utf8)
    defer { try? FileManager.default.removeItem(at: url) }
    let engine = Engine(router: Router(default: .direct), nodeManager: NodeManager(nodes: [], groups: []))

    try await SystemHosts.$pathOverride.withValue(url.path) {
        for target in [Endpoint(domain: "lan-target.test", port: 9), Endpoint(host: .ipv4(.loopback), port: 9)] {
            let remote = try await engine.resolveAndDispatch(target: target, remoteClient: true)
            let direct = try #require(remote.connection as? DirectOutboundConnection)
            #expect(direct.refusesThisHost)
            do {
                try await direct.open()
                Issue.record("dialed \(target) for a remote client")
            } catch OutboundError.unreachable {
            } catch {
                Issue.record("expected unreachable, got \(error)")
            }
        }
        let local = try await engine.resolveAndDispatch(target: Endpoint(domain: "lan-target.test", port: 9))
        #expect((local.connection as? DirectOutboundConnection)?.refusesThisHost == false)
    }
}
