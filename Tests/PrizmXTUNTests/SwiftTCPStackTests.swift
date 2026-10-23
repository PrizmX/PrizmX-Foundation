import Foundation
import Testing
@testable import PrizmXProtocols
@testable import PrizmXTUN
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

    @Test func fakeDNSReturnsSystemHostsInsteadOfFakeIP() async throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("prizmx-hosts-\(UUID().uuidString)")
        try "127.0.0.1 dev.example.test\n".write(to: url, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: url) }

        final class OutputBox: @unchecked Sendable {
            var packets: [Data] = []
        }
        let box = OutputBox()
        let pool = FakeIPAllocator()
        let stack = TUNStack(fakeIP: pool, dnsPolicy: { _ in .proxy(targetGroup: "Proxy") }) { packets in
            box.packets.append(contentsOf: packets)
        }
        await stack.start()
        await SystemHosts.$pathOverride.withValue(url.path) {
            await stack.input(packets: [dnsQueryPacket(name: "dev.example.test")])
        }
        #expect(pool.count == 0)
        let parsed = try box.packets[0].withUnsafeBytes { try RawIPPacket($0) }
        let udp = try #require(parsed.payload.flatMap { UDPDatagram.parse(ipPayload: $0) })
        #expect(udp.payload[6] == 0 && udp.payload[7] == 1)
        #expect(udp.payload.suffix(4) == Data([127, 0, 0, 1]))
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

    @Test func resetFlowsResetsOpenFlowsAndKeepsTheStack() async throws {
        let output = OutputLog()
        let stack = TUNStack(fakeIP: nil) { output.append($0) }
        await stack.start()
        let connections = await stack.tcpConnections()
        let datagrams = await stack.udpDatagrams()
        let app = IPv4Address(198, 18, 0, 1)
        let server = IPv4Address(1, 1, 1, 1)

        await stack.input(packets: [
            TCPSegment(
                sourcePort: 12_345, destinationPort: 80, sequence: 1, acknowledgement: 0,
                flags: .syn, window: 65_535, payload: Data()
            ).encode(source: app, destination: server),
        ])
        let synAck = try #require(await output.waitForSegment { $0.flags.contains(.syn) })
        await stack.input(packets: [
            TCPSegment(
                sourcePort: 12_345, destinationPort: 80, sequence: 2, acknowledgement: synAck.sequence &+ 1,
                flags: .ack, window: 65_535, payload: Data()
            ).encode(source: app, destination: server),
            UDPDatagram(sourcePort: 50_000, destinationPort: 443, payload: Data([1]))
                .encode(source: app, destination: server),
        ])
        var tcp = connections.makeAsyncIterator()
        let stream = try #require(await tcp.next())
        var udp = datagrams.makeAsyncIterator()
        _ = try #require(await udp.next())

        let reset = await stack.resetFlows()
        #expect(reset.tcp == 1)
        #expect(reset.udp == 1)
        // The app gets a RST; the relay's read fails instead of reaching EOF.
        #expect(await output.waitForSegment { $0.flags.contains(.rst) && $0.destinationPort == 12_345 } != nil)
        await #expect(throws: TUNStreamError.closed) { try await stream.read() }
        await stack.stop()
    }
}

/// Packets the stack wrote toward the app, appended from any thread.
private final class OutputLog: @unchecked Sendable {
    private let lock = NSLock()
    private var packets: [Data] = []

    func append(_ batch: [Data]) {
        lock.withLock { packets += batch }
    }

    /// The first TCP segment that matches, waiting up to 2 s for it.
    func waitForSegment(_ match: (TCPSegment) -> Bool) async -> TCPSegment? {
        let deadline = ContinuousClock.now + .seconds(2)
        repeat {
            let segments = lock.withLock { packets }.compactMap { packet in
                packet.withUnsafeBytes { bytes -> TCPSegment? in
                    guard let raw = try? RawIPPacket(bytes), case .tcp = raw.transport else { return nil }
                    return raw.payload.flatMap { TCPSegment.parse(ipPayload: $0) }
                }
            }
            if let hit = segments.first(where: match) { return hit }
            try? await Task.sleep(for: .milliseconds(10))
        } while ContinuousClock.now < deadline
        return nil
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
