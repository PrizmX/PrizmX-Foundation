import Foundation
import Testing
@testable import PrizmXTUN
import PrizmXProtocols
import SwiftTCP

// MARK: - FakeIP LRU

@Test func fakeIPDefaultsToWholePool() {
    let pool = FakeIPAllocator()
    for index in 0..<5000 {
        _ = pool.allocate(domain: "host\(index).example")
    }
    // The old FIFO cap (4096) would have dropped the first names.
    #expect(pool.count == 5000)
    #expect(pool.domain(for: pool.allocate(domain: "host0.example")) == "host0.example")
    #expect(FakeIPAllocator.poolSize == 65_532)
}

@Test func fakeIPRecyclesLeastRecentlyUsed() {
    let pool = FakeIPAllocator(capacity: 16)
    var addresses: [IPv4Address] = []
    for index in 0..<16 {
        addresses.append(pool.allocate(domain: "d\(index)"))
    }
    // Refresh d0 via a DNS hit and d1 via a flow lookup.
    #expect(pool.allocate(domain: "d0") == addresses[0])
    #expect(pool.domain(for: addresses[1]) == "d1")

    let fresh = pool.allocate(domain: "new")
    // d2 was the least recently used, so its address is recycled.
    #expect(fresh == addresses[2])
    #expect(pool.domain(for: addresses[0]) == "d0")
    #expect(pool.domain(for: addresses[1]) == "d1")
    #expect(pool.allocate(domain: "d2") != addresses[2])
}

@Test func fakeIPSkipsAddressesPinnedByLiveFlows() {
    let pool = FakeIPAllocator(capacity: 16)
    var addresses: [IPv4Address] = []
    for index in 0..<16 {
        addresses.append(pool.allocate(domain: "d\(index)"))
    }
    pool.retain(addresses[0])
    let fresh = pool.allocate(domain: "new")
    #expect(fresh != addresses[0])
    #expect(pool.domain(for: addresses[0]) == "d0")
    pool.release(addresses[0])
}

// MARK: - Mailbox: half-close and UDP/TCP separation

private struct NullByteStream: TCPByteStream {
    func send(flow: FlowKey, data: Data) async -> Int { data.count }
    func close(flow: FlowKey) async {}
    func creditAppReceive(flow: FlowKey, bytes: Int) async {}
}

private func makeFlow() -> FlowKey {
    FlowKey(
        src: IPAddress(v4: 0xC612_0001),
        srcPort: 50_000,
        dst: IPAddress(v4: 0x0101_0101),
        dstPort: 443
    )
}

@Test func peerFinishedEndsReadsAfterBufferedData() async throws {
    let mailbox = TUNMailbox(fakeIP: nil) { _ in }
    mailbox.attach(byteStream: NullByteStream())
    let (streams, continuation) = AsyncStream.makeStream(of: TUNTCPStream.self)
    mailbox.setTCPContinuation(continuation)
    let flow = makeFlow()
    mailbox.onEstablished(flow: flow)
    var iterator = streams.makeAsyncIterator()
    let stream = try #require(await iterator.next())
    mailbox.onData(flow: flow, data: Data("tail".utf8))
    mailbox.onPeerFinished(flow: flow)
    #expect(await stream.read() == Data("tail".utf8))
    #expect(await stream.read() == nil)
    #expect(stream.supportsHalfClose)
}

@Test func udpSessionCloseDoesNotFinishTCPFlowOnSameTuple() async throws {
    let mailbox = TUNMailbox(fakeIP: nil) { _ in }
    mailbox.attach(byteStream: NullByteStream())
    let (streams, continuation) = AsyncStream.makeStream(of: TUNTCPStream.self)
    mailbox.setTCPContinuation(continuation)
    let closed = LockedFlows()
    mailbox.setUDPClosedHandler { closed.append($0) }
    let flow = makeFlow()
    mailbox.onEstablished(flow: flow)
    var iterator = streams.makeAsyncIterator()
    let stream = try #require(await iterator.next())

    mailbox.onUDPSessionClosed(flow: flow, reason: .expired)
    #expect(closed.values == [flow])
    // The TCP stream is still open: data still arrives.
    mailbox.onData(flow: flow, data: Data("still".utf8))
    #expect(await stream.read() == Data("still".utf8))
}

private final class LockedFlows: @unchecked Sendable {
    private let lock = NSLock()
    private var flows: [FlowKey] = []
    var values: [FlowKey] { lock.withLock { flows } }
    func append(_ flow: FlowKey) { lock.withLock { flows.append(flow) } }
}

// MARK: - DNS forwarding helpers

@Test func dnsForwarderRecognizesFakeIPReverseNames() {
    #expect(DNSForwarder.isFakeIPReverseName("5.0.18.198.in-addr.arpa"))
    #expect(DNSForwarder.isFakeIPReverseName("5.0.18.198.IN-ADDR.ARPA."))
    #expect(!DNSForwarder.isFakeIPReverseName("1.1.168.192.in-addr.arpa"))
    #expect(DNSForwarder.isFakeIPReverseName(
        "3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.7.4.6.9.1.9.1.4.1.5.4.1.1.d.f.ip6.arpa"
    ))
    #expect(DNSForwarder.isAnswer(Data([0x12, 0x34, 0x81]), to: Data([0x12, 0x34, 0x01])))
    #expect(!DNSForwarder.isAnswer(Data([0x12, 0x35, 0x81]), to: Data([0x12, 0x34, 0x01])))
    #expect(!DNSForwarder.isAnswer(Data([0x12, 0x34, 0x01]), to: Data([0x12, 0x34, 0x01])))
}

// MARK: - HTTPS / SVCB stay local in FakeIP mode

private final class CapturedPackets: @unchecked Sendable {
    private let lock = NSLock()
    private var packets: [Data] = []
    func append(_ batch: [Data]) { lock.lock(); packets += batch; lock.unlock() }
    var all: [Data] { lock.lock(); defer { lock.unlock() }; return packets }
}

private func dnsQueryPacket(name: String, type: UInt16, id: UInt16) -> Data {
    var dns: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xFF), 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    for label in name.split(separator: ".") {
        dns.append(UInt8(label.utf8.count))
        dns += Array(label.utf8)
    }
    dns += [0, UInt8(type >> 8), UInt8(type & 0xFF), 0x00, 0x01]
    let udpLength = 8 + dns.count
    var udp: [UInt8] = [0xD4, 0x31, 0x00, 0x35, UInt8(udpLength >> 8), UInt8(udpLength & 0xFF), 0, 0]
    udp += dns
    let total = 20 + udp.count
    var ip: [UInt8] = [0x45, 0, UInt8(total >> 8), UInt8(total & 0xFF), 0, 1, 0x40, 0, 64, 17, 0, 0,
                       198, 18, 0, 1, 198, 18, 0, 2]
    var sum: UInt32 = 0
    for index in stride(from: 0, to: 20, by: 2) { sum += UInt32(ip[index]) << 8 | UInt32(ip[index + 1]) }
    while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
    let checksum = ~UInt16(sum)
    ip[10] = UInt8(checksum >> 8)
    ip[11] = UInt8(checksum & 0xFF)
    return Data(ip + udp)
}

@Test(arguments: [UInt16(65), UInt16(64)])
func fakeIPModeAnswersHTTPSAndSVCBLocallyWithNODATA(type: UInt16) async throws {
    let captured = CapturedPackets()
    // A forwardable upstream: the old path sent HTTPS here and only fell
    // back after its timeout, advertising h3 when it answered.
    let dns = DNSClient(settings: .bootstrap(physicalIPs: ["192.0.2.1"]), persistenceURL: nil)
    let stack = TUNStack(fakeIP: FakeIPAllocator(), dns: dns, onOutput: { captured.append($0) })
    await stack.start()
    await stack.input(packets: [dnsQueryPacket(name: "www.example.com", type: type, id: 0x4242)])

    let replies = captured.all.filter { $0.count > 28 && $0[9] == 17 }
    let reply = try #require(replies.first, "expected an immediate local reply")
    let dnsReply = reply.dropFirst(28)
    #expect(dnsReply[dnsReply.startIndex] == 0x42 && dnsReply[dnsReply.startIndex + 1] == 0x42)
    #expect(dnsReply[dnsReply.startIndex + 6] == 0 && dnsReply[dnsReply.startIndex + 7] == 0) // ANCOUNT 0
    await stack.stop()
}

@Test func otherQueryTypesNeverStallFakeDNSAnswers() async throws {
    let captured = CapturedPackets()
    let dns = DNSClient(settings: .bootstrap(physicalIPs: ["192.0.2.1"]), persistenceURL: nil)
    // Neither a slow policy walk nor the (unreachable) upstream may hold
    // the packet path that answers A queries.
    let stack = TUNStack(
        fakeIP: FakeIPAllocator(),
        dns: dns,
        dnsPolicy: { _ in
            try? await Task.sleep(for: .seconds(5))
            return .direct
        },
        onOutput: { captured.append($0) }
    )
    await stack.start()
    let started = ContinuousClock.now
    await stack.input(packets: [
        dnsQueryPacket(name: "_ldap._tcp.example.com", type: 33, id: 0x0001), // SRV
        dnsQueryPacket(name: "4.3.2.1.in-addr.arpa", type: 12, id: 0x0002), // PTR
    ])
    #expect(ContinuousClock.now - started < .seconds(1))
    await stack.stop()
}
