import Foundation
import Testing
@testable import PrizmXTUN
import PrizmXProtocols
import PrizmXRules

@Suite(.serialized)
struct SwiftTCPStackTests {
    @Test func acceptsTCPSynAndEmitsSynAck() async throws {
        final class OutputBox: @unchecked Sendable {
            var packets: [Data] = []
        }
        let box = OutputBox()
        let stack = TUNStack(fakeIP: nil) { packets in
            box.packets.append(contentsOf: packets)
        }
        await stack.start()

        let syn = TCPSegment(
            sourcePort: 12_345,
            destinationPort: 80,
            sequence: 1,
            acknowledgement: 0,
            flags: .syn,
            window: 65_535,
            payload: Data()
        )
        let packet = syn.encode(
            source: IPv4Address(198, 18, 0, 1),
            destination: IPv4Address(1, 1, 1, 1)
        )
        await stack.input(packets: [packet])
        // ingest drains on a separate task; wait for the SYN-ACK to land.
        let deadline = ContinuousClock.now + .seconds(2)
        while box.packets.isEmpty, ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(10))
        }

        #expect(!box.packets.isEmpty)
        let reply = box.packets[0]
        let parsed = try reply.withUnsafeBytes { try RawIPPacket($0) }
        let segment = try #require(parsed.payload.flatMap { TCPSegment.parse(ipPayload: $0) })
        #expect(segment.flags.contains(.syn) && segment.flags.contains(.ack))
        #expect(segment.sourcePort == 80)
        #expect(segment.destinationPort == 12_345)
        #expect(parsed.ipv4Header.source == IPv4Address(1, 1, 1, 1))

        await stack.stop()
    }

    @Test func fakeDNSReturnsAllocatedAddress() async {
        final class OutputBox: @unchecked Sendable {
            var packets: [Data] = []
        }
        let box = OutputBox()
        let pool = FakeIPAllocator()
        let stack = TUNStack(fakeIP: pool) { packets in
            box.packets.append(contentsOf: packets)
        }
        await stack.start()

        await stack.input(packets: [dnsQueryPacket(name: "www.example.com")])
        #expect(!box.packets.isEmpty)
        #expect(pool.count == 1)

        await stack.stop()
    }

    @Test func fakeDNSAllocatesFakeIPWhenPolicyIsDirect() async throws {
        final class OutputBox: @unchecked Sendable {
            var packets: [Data] = []
        }
        let box = OutputBox()
        let pool = FakeIPAllocator()
        let stack = TUNStack(fakeIP: pool, dnsPolicy: { _ in .direct }) { packets in
            box.packets.append(contentsOf: packets)
        }
        await stack.start()

        await stack.input(packets: [dnsQueryPacket(name: "www.example.com")])
        #expect(pool.count == 1)
        let parsed = try box.packets[0].withUnsafeBytes { try RawIPPacket($0) }
        let udp = try #require(parsed.payload.flatMap { UDPDatagram.parse(ipPayload: $0) })
        #expect(udp.payload[6] == 0 && udp.payload[7] == 1) // ANCOUNT 1
        #expect(udp.payload.suffix(4).starts(with: [198, 18]))

        await stack.stop()
    }

    @Test func fakeDNSReturnsNODATAWhenPolicyIsReject() async throws {
        final class OutputBox: @unchecked Sendable {
            var packets: [Data] = []
        }
        let box = OutputBox()
        let pool = FakeIPAllocator()
        let stack = TUNStack(fakeIP: pool, dnsPolicy: { _ in .reject }) { packets in
            box.packets.append(contentsOf: packets)
        }
        await stack.start()

        await stack.input(packets: [dnsQueryPacket(name: "ads.example")])
        #expect(pool.count == 0)
        #expect(!box.packets.isEmpty)
        let parsed = try box.packets[0].withUnsafeBytes { try RawIPPacket($0) }
        let udp = try #require(parsed.payload.flatMap { UDPDatagram.parse(ipPayload: $0) })
        #expect(udp.payload[6] == 0 && udp.payload[7] == 0) // ANCOUNT 0

        await stack.stop()
    }

    @Test func yieldsUDPDatagrams() async throws {
        let stack = TUNStack(fakeIP: nil) { _ in }
        await stack.start()
        let stream = await stack.udpDatagrams()
        let payload = Data([0x01, 0x02, 0x03, 0x04])
        let packet = UDPDatagram(
            sourcePort: 50_000,
            destinationPort: 443,
            payload: payload
        ).encode(
            source: IPv4Address(198, 18, 0, 1),
            destination: IPv4Address(1, 1, 1, 1)
        )
        await stack.input(packets: [packet])
        var iterator = stream.makeAsyncIterator()
        let received = try #require(await iterator.next())
        #expect(received.destination.port == 443)
        #expect(received.source.port == 50_000)
        #expect(received.payload == payload)
        await stack.stop()
    }
}

/// Builds a UDP-encapsulated A-record query from a fake client to FakeDNS.
private func dnsQueryPacket(name: String) -> Data {
    var query = Data()
    query.append(contentsOf: [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    for label in name.split(separator: ".") {
        query.append(UInt8(label.count))
        query.append(contentsOf: Array(label.utf8))
    }
    query.append(0)
    query.append(contentsOf: [0x00, 0x01, 0x00, 0x01]) // A IN
    return UDPDatagram(sourcePort: 53_000, destinationPort: 53, payload: query)
        .encode(source: IPv4Address(198, 18, 0, 1), destination: FakeIPAllocator.dns)
}
