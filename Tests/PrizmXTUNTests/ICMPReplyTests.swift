import Foundation
import Testing
import PrizmXProtocols
@testable import PrizmXTUN

@Test func ipv4PortUnreachableLooksLikeICMP() {
    let packet = ICMPReply.portUnreachable(
        client: IPv4Address(198, 18, 0, 10),
        destination: IPv4Address(198, 18, 0, 20),
        sourcePort: 443,
        destinationPort: 443
    )
    #expect(packet.count == 56)
    #expect(packet[0] >> 4 == 4)
    #expect(packet[9] == 1)
    #expect(packet[20] == 3)
    #expect(packet[21] == 3)
    #expect(ICMPReply.internetChecksum(packet.prefix(20)) == 0)
}

@Test func ipv6UnreachableLooksLikeICMPv6() throws {
    var original = Data(count: 40)
    original[0] = 0x60
    original[7] = 64
    original[6] = 17
    let reply = try #require(ICMPReply.ipv6Unreachable(original: original))
    #expect(reply[0] >> 4 == 6)
    #expect(reply[6] == 58)
    #expect(reply[40] == 1)
    #expect(reply[41] == 3)
}

/// IPv6 TCP segment from `[fd00::2]:51000` to `[2606:4700::1111]:443`.
private func ipv6TCP(flags: UInt8, seq: UInt32, ack: UInt32 = 0, payload: Int = 0) -> Data {
    var packet = Data(count: 60 + payload)
    packet[0] = 0x60
    packet[4] = UInt8((20 + payload) >> 8)
    packet[5] = UInt8((20 + payload) & 0xFF)
    packet[6] = 6
    packet[7] = 64
    packet[8] = 0xfd
    packet[23] = 2
    packet.replaceSubrange(24..<28, with: [0x26, 0x06, 0x47, 0x00])
    packet[38] = 0x11
    packet[39] = 0x11
    packet.replaceSubrange(40..<44, with: [0xC7, 0x38, 0x01, 0xBB])
    for index in 0..<4 {
        packet[44 + index] = UInt8(truncatingIfNeeded: seq >> (24 - 8 * index))
        packet[48 + index] = UInt8(truncatingIfNeeded: ack >> (24 - 8 * index))
    }
    packet[52] = 5 << 4
    packet[53] = flags
    return packet
}

private func uint32(_ data: Data, at offset: Int) -> UInt32 {
    (0..<4).reduce(0) { $0 << 8 | UInt32(data[offset + $1]) }
}

/// macOS keeps retrying a SYN that got ICMPv6 unreachable; a RST fails it now.
@Test func ipv6TCPConnectIsResetFromItsDestination() throws {
    let syn = ipv6TCP(flags: 0x02, seq: 1_000)
    let reply = try #require(ICMPReply.ipv6Refusal(original: syn))
    #expect(reply.count == 60)
    #expect(reply[6] == 6)
    #expect(reply.subdata(in: 8..<24) == syn.subdata(in: 24..<40))
    #expect(reply.subdata(in: 24..<40) == syn.subdata(in: 8..<24))
    #expect(reply.subdata(in: 40..<42) == syn.subdata(in: 42..<44))
    #expect(reply.subdata(in: 42..<44) == syn.subdata(in: 40..<42))
    #expect(uint32(reply, at: 44) == 0)
    #expect(uint32(reply, at: 48) == 1_001)
    #expect(reply[53] == 0x14)
    let checksum = ICMPReply.ipv6Checksum(
        source: reply.subdata(in: 8..<24),
        destination: reply.subdata(in: 24..<40),
        nextHeader: 6,
        payload: reply.subdata(in: 40..<60)
    )
    #expect(checksum == 0)
}

@Test func ipv6ResetFollowsTheSegmentItAnswers() throws {
    let data = ipv6TCP(flags: 0x18, seq: 5, ack: 77, payload: 10)
    let reply = try #require(ICMPReply.ipv6Refusal(original: data))
    #expect(uint32(reply, at: 44) == 77)
    #expect(reply[53] == 0x04)
    // A RST is never answered; UDP still gets ICMPv6 unreachable.
    #expect(ICMPReply.ipv6Refusal(original: ipv6TCP(flags: 0x04, seq: 1)) == nil)
    var udp = Data(count: 48)
    udp[0] = 0x60
    udp[6] = 17
    let unreachable = try #require(ICMPReply.ipv6Refusal(original: udp))
    #expect(unreachable[6] == 58)
}

/// A dropped IPv6 UDP flow (QUIC to a node without UDP) fails at once.
@Test func ipv6PortUnreachableQuotesTheDroppedDatagram() {
    let client = FakeIPAllocator.gateway6
    let server = IPv6Address(high: 0x2606_4700_4700_0000, low: 0x1111)
    let reply = ICMPReply.ipv6PortUnreachable(client: client, destination: server, sourcePort: 50_000, destinationPort: 443)
    #expect(reply[6] == 58)
    #expect(reply[40] == 1)
    #expect(reply[41] == 4)
    // Quoted datagram: client → server, UDP 50000 → 443.
    #expect(reply.subdata(in: 24..<40) == reply.subdata(in: 48 + 8..<48 + 24))
    #expect(reply[48 + 6] == 17)
    #expect(UInt16(reply[88]) << 8 | UInt16(reply[89]) == 50_000)
    #expect(UInt16(reply[90]) << 8 | UInt16(reply[91]) == 443)
    let checksum = ICMPReply.ipv6Checksum(
        source: reply.subdata(in: 8..<24),
        destination: reply.subdata(in: 24..<40),
        nextHeader: 58,
        payload: reply.subdata(in: 40..<reply.count)
    )
    #expect(checksum == 0)
}
