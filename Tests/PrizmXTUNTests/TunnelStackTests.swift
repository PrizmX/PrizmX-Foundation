import Foundation
import Testing
@testable import PrizmXTUN
import PrizmXProtocols

@Test func ipv4CodecRoundTripAndChecksum() throws {
    let payload = Data([0x00, 0x50, 0x01, 0xBB, 0x00, 0x00, 0x00, 0x00])
    let encoded = payload.withUnsafeBytes { raw in
        IPv4Codec.encode(
            source: IPv4Address(198, 18, 0, 1),
            destination: IPv4Address(1, 1, 1, 1),
            protocolNumber: 6,
            payload: raw
        )
    }
    let parsed = try encoded.withUnsafeBytes { try IPv4Header.parse($0) }
    #expect(parsed.source == IPv4Address(198, 18, 0, 1))
    #expect(parsed.destination == IPv4Address(1, 1, 1, 1))
    #expect(parsed.protocolNumber == 6)
    #expect(Int(parsed.totalLength) == encoded.count)

    let header = encoded.prefix(20)
    let checksumOK = header.withUnsafeBytes { raw -> Bool in
        InternetChecksum.compute(raw) == 0
    }
    #expect(checksumOK)
}

@Test func tcpSegmentRoundTrip() throws {
    let outbound = TCPSegment(
        sourcePort: 443,
        destinationPort: 52_000,
        sequence: 100,
        acknowledgement: 200,
        flags: [.syn, .ack],
        window: 32_768,
        payload: Data()
    )
    let packet = outbound.encode(
        source: IPv4Address(1, 1, 1, 1),
        destination: IPv4Address(198, 18, 0, 1)
    )
    let parsed = try packet.withUnsafeBytes { try RawIPPacket($0) }
    let segment = try #require(TCPSegment.parse(ipPayload: parsed.payload!))
    #expect(segment.sourcePort == 443)
    #expect(segment.destinationPort == 52_000)
    #expect(segment.sequence == 100)
    #expect(segment.flags.contains(.syn) && segment.flags.contains(.ack))
}

@Test func fakeIPAllocatesAndResolvesDomain() {
    let pool = FakeIPAllocator(capacity: 32)
    let first = pool.allocate(domain: "www.baidu.com")
    let again = pool.allocate(domain: "WWW.BAIDU.COM")
    #expect(first == again)
    #expect(pool.domain(for: first) == "www.baidu.com")
    #expect(pool.contains(first))
    #expect(!pool.contains(IPv4Address(8, 8, 8, 8)))
}

@Test func fakeIPAllocatesIPv6AndResolvesDomain() {
    let pool = FakeIPAllocator(capacity: 32)
    let first = pool.allocateIPv6(domain: "www.google.com")
    let again = pool.allocateIPv6(domain: "WWW.GOOGLE.COM")
    #expect(first == again)
    #expect(first.high == FakeIPAllocator.network6.high)
    #expect(first.low >= 3)
    #expect(pool.domain(for: first) == "www.google.com")
    #expect(pool.contains(first))
    #expect(!pool.contains(IPv6Address.loopback))
}

@Test func dnsFakeIPResponseContainsAllocatedAddress() throws {
    var query = Data()
    query.append(contentsOf: [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    query.append(3)
    query.append(contentsOf: Array("www".utf8))
    query.append(7)
    query.append(contentsOf: Array("example".utf8))
    query.append(3)
    query.append(contentsOf: Array("com".utf8))
    query.append(0)
    query.append(contentsOf: [0x00, 0x01, 0x00, 0x01])

    let parsed = try #require(DNSMessage.parseQuestion(query))
    #expect(parsed.question.name == "www.example.com")
    #expect(parsed.question.type == 1)
    let ip = IPv4Address(198, 18, 0, 10)
    let response = DNSMessage.response(id: parsed.id, question: parsed.question, ipv4: ip)
    #expect(response[0] == 0x12 && response[1] == 0x34)
    #expect(response.suffix(4) == Data([198, 18, 0, 10]))
}

@Test func dnsAAAAQueryGetsNODATAWithoutAddress() throws {
    var query = Data()
    query.append(contentsOf: [0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    query.append(7)
    query.append(contentsOf: Array("example".utf8))
    query.append(3)
    query.append(contentsOf: Array("com".utf8))
    query.append(0)
    query.append(contentsOf: [0x00, 0x1C, 0x00, 0x01]) // AAAA IN

    let parsed = try #require(DNSMessage.parseQuestion(query))
    #expect(parsed.question.type == 28)
    let nodata = DNSMessage.response(id: parsed.id, question: parsed.question)
    #expect(nodata[6] == 0 && nodata[7] == 0) // ANCOUNT 0

    let answer = DNSMessage.response(
        id: parsed.id,
        question: parsed.question,
        ipv6: .loopback
    )
    #expect(answer[6] == 0 && answer[7] == 1)
    #expect(answer.suffix(16) == Data(repeating: 0, count: 15) + Data([1]))
}
