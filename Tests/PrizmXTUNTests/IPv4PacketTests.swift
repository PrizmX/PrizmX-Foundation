import Testing
@testable import PrizmXTUN

/// Constructs a minimal valid IPv4 packet (20-byte header + payload).
private func makeIPv4Packet(
    protocolNumber: UInt8 = 6,
    source: [UInt8] = [10, 0, 0, 1],
    destination: [UInt8] = [1, 1, 1, 1],
    payload: [UInt8]
) -> [UInt8] {
    let totalLength = UInt16(20 + payload.count)
    var packet: [UInt8] = []
    packet.reserveCapacity(Int(totalLength))
    packet.append(0x45)  // version=4, IHL=5
    packet.append(0x00)  // DSCP/ECN
    packet.append(UInt8(totalLength >> 8))
    packet.append(UInt8(totalLength & 0xFF))
    packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00])  // id / flags / fragment
    packet.append(64)  // TTL
    packet.append(protocolNumber)
    packet.append(contentsOf: [0x00, 0x00])  // checksum (not validated by this stub)
    packet.append(contentsOf: source)
    packet.append(contentsOf: destination)
    packet.append(contentsOf: payload)
    return packet
}

@Test func parsesTCPHeaderAndPorts() throws {
    // TCP: the first 4 payload bytes are the source/destination ports.
    let packetBytes = makeIPv4Packet(
        protocolNumber: 6,
        payload: [0x00, 0x50, 0x01, 0xBB, 0xFF]
    )
    let packet = try packetBytes.withUnsafeBytes { raw in
        try RawIPPacket(raw)
    }

    #expect(packet.ipv4Header.version == 4)
    #expect(packet.ipv4Header.headerLength == 20)
    #expect(packet.ipv4Header.totalLength == 25)
    #expect(packet.ipv4Header.protocolNumber == 6)
    #expect(packet.ipv4Header.source == .init(10, 0, 0, 1))
    #expect(packet.ipv4Header.destination == .init(1, 1, 1, 1))
    #expect(packet.transport == .tcp(sourcePort: 80, destinationPort: 443))
    #expect(packet.payload?.count == 5)

    let flow = try #require(packet.flowTuple)
    #expect(flow.sourcePort == 80)
    #expect(flow.destinationPort == 443)
    #expect(flow.sourceAddress == .init(10, 0, 0, 1))
    // Reversed five-tuple.
    #expect(flow.reversed.destinationPort == 80)
    #expect(flow.reversed.sourceAddress == .init(1, 1, 1, 1))
}

@Test func parsesUDPHeaderAndPorts() throws {
    let packetBytes = makeIPv4Packet(
        protocolNumber: 17,
        payload: [0x00, 0x35, 0xE1, 0x40]
    )
    let packet = try packetBytes.withUnsafeBytes { raw in
        try RawIPPacket(raw)
    }
    #expect(packet.transport == .udp(sourcePort: 53, destinationPort: 57664))
    #expect(packet.flowTuple?.protocolNumber == 17)
}

@Test func nonTransportProtocolYieldsOther() throws {
    let packetBytes = makeIPv4Packet(protocolNumber: 1, payload: [0x08, 0x00])
    let packet = try packetBytes.withUnsafeBytes { raw in
        try RawIPPacket(raw)
    }
    #expect(packet.transport == .other(protocolNumber: 1))
    #expect(packet.flowTuple == nil)
}

@Test func truncatedPacketThrows() {
    let packetBytes = makeIPv4Packet(payload: [0x00, 0x50, 0x01, 0xBB, 0xFF])
    let truncated = Array(packetBytes.dropLast(10))
    #expect(throws: TUNPacketError.self) {
        try truncated.withUnsafeBytes { raw in
            try RawIPPacket(raw)
        }
    }
}

@Test func unsupportedVersionThrows() {
    var packetBytes = makeIPv4Packet(payload: [0x00, 0x50, 0x01, 0xBB])
    packetBytes[0] = 0x65  // version=6
    #expect(throws: TUNPacketError.self) {
        try packetBytes.withUnsafeBytes { raw in
            try RawIPPacket(raw)
        }
    }
}

@Test func emptyBufferThrows() {
    let empty = UnsafeRawBufferPointer(start: nil, count: 0)
    #expect(throws: TUNPacketError.self) {
        try RawIPPacket(empty)
    }
}
