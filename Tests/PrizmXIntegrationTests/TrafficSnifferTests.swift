import Foundation
import Testing
import PrizmXCore
import PrizmXNodes
import PrizmXProtocols
import PrizmXRules

@Test func sniffExtractsHTTPHost() {
    let request = Data("GET / HTTP/1.1\r\nHost: www.Example.com\r\nUser-Agent: x\r\n\r\n".utf8)
    #expect(TrafficSniffer.sniff(request) == .hostname("www.example.com"))
}

@Test func sniffStripsPortFromHTTPHost() {
    let request = Data("POST /x HTTP/1.1\r\nHost: api.example.com:8443\r\n\r\n".utf8)
    #expect(TrafficSniffer.sniff(request) == .hostname("api.example.com"))
}

@Test func sniffHTTPNeedsCompleteHeaders() {
    let partial = Data("GET / HTTP/1.1\r\nHost: example.com".utf8)
    #expect(TrafficSniffer.sniff(partial) == .needMore)
}

@Test func sniffExtractsTLSSNI() {
    let hello = tlsClientHello(sni: "www.google.com")
    #expect(TrafficSniffer.sniff(hello) == .hostname("www.google.com"))
}

@Test func sniffTLSNeedsFullRecord() {
    let hello = tlsClientHello(sni: "www.google.com")
    #expect(TrafficSniffer.sniff(Data(hello.prefix(8))) == .needMore)
}

@Test func sniffUnknownBinaryIsNone() {
    #expect(TrafficSniffer.sniff(Data([0x00, 0x01, 0x02, 0x03])) == .none)
}

@Test func engineTCPRelaySniffsHTTPHostOnIPDestination() async {
    let router = Router(
        rules: [RouteRule(.domainSuffix("example.com"), policy: .reject)],
        default: .direct
    )
    let engine = Engine(router: router, nodeManager: NodeManager(nodes: [], groups: []))
    let stream = ChunkInboundStream(
        endpoint: Endpoint(host: .ipv4(IPv4Address(1, 1, 1, 1)), port: 80),
        chunks: [Data("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n".utf8)]
    )
    await EngineTCPRelay.pipe(stream: stream, engine: engine)
    #expect(stream.closed)
}

private func tlsClientHello(sni: String) -> Data {
    let hostname = Array(sni.utf8)
    var serverName = Data()
    serverName.append(0x00) // host_name
    serverName.append(UInt8(hostname.count >> 8))
    serverName.append(UInt8(hostname.count & 0xFF))
    serverName.append(contentsOf: hostname)
    var sniList = Data()
    sniList.append(UInt8(serverName.count >> 8))
    sniList.append(UInt8(serverName.count & 0xFF))
    sniList.append(serverName)
    var extensionBody = Data()
    extensionBody.append(contentsOf: [0x00, 0x00]) // server_name
    extensionBody.append(UInt8(sniList.count >> 8))
    extensionBody.append(UInt8(sniList.count & 0xFF))
    extensionBody.append(sniList)

    var hello = Data()
    hello.append(contentsOf: [0x03, 0x03]) // client version
    hello.append(Data(repeating: 0x11, count: 32)) // random
    hello.append(0x00) // session id
    hello.append(contentsOf: [0x00, 0x02, 0x00, 0x2F]) // one cipher
    hello.append(contentsOf: [0x01, 0x00]) // compression
    hello.append(UInt8(extensionBody.count >> 8))
    hello.append(UInt8(extensionBody.count & 0xFF))
    hello.append(extensionBody)

    var handshake = Data([0x01])
    let helloLen = hello.count
    handshake.append(UInt8((helloLen >> 16) & 0xFF))
    handshake.append(UInt8((helloLen >> 8) & 0xFF))
    handshake.append(UInt8(helloLen & 0xFF))
    handshake.append(hello)

    var record = Data([0x16, 0x03, 0x01])
    record.append(UInt8(handshake.count >> 8))
    record.append(UInt8(handshake.count & 0xFF))
    record.append(handshake)
    return record
}

private final class ChunkInboundStream: InboundStream, @unchecked Sendable {
    let endpoint: Endpoint
    private var chunks: [Data]
    private(set) var closed = false

    init(endpoint: Endpoint, chunks: [Data]) {
        self.endpoint = endpoint
        self.chunks = chunks
    }

    func read() async throws -> Data? {
        guard !chunks.isEmpty else { return nil }
        return chunks.removeFirst()
    }

    func write(_ data: Data) async throws {}
    func close() async { closed = true }
}
