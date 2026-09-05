import Foundation
import Testing
@testable import PrizmXTUN
import PrizmXProtocols

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

        var query = Data()
        query.append(contentsOf: [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        query.append(3); query.append(contentsOf: Array("www".utf8))
        query.append(7); query.append(contentsOf: Array("example".utf8))
        query.append(3); query.append(contentsOf: Array("com".utf8))
        query.append(0)
        query.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
        let datagram = UDPDatagram(sourcePort: 53_000, destinationPort: 53, payload: query)
            .encode(source: IPv4Address(198, 18, 0, 1), destination: FakeIPAllocator.dns)
        await stack.input(packets: [datagram])
        #expect(!box.packets.isEmpty)
        #expect(pool.count == 1)

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
