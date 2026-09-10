import Foundation
@testable import PrizmXTUN
import PrizmXProtocols

// Legacy packet crafting/parsing helpers. These were the production wire
// format before the SwiftTCP migration; only tests use them now, so they
// live in the test target instead of the shipped library.

// MARK: - IPv4 header / raw packet

/// IPv4 header (fixed 20 bytes + optional options, up to 60 bytes).
struct IPv4Header: Equatable, Sendable {
    let version: UInt8
    let headerLength: Int
    let totalLength: UInt16
    let protocolNumber: UInt8
    let source: IPv4Address
    let destination: IPv4Address

    /// Parses an IPv4 header from the start of a packet. Does not validate the
    /// header checksum (usually offloaded to the NIC / TUN).
    static func parse(_ packet: UnsafeRawBufferPointer) throws -> IPv4Header {
        guard packet.count >= 20 else {
            throw TUNPacketError.truncated(expected: 20, actual: packet.count)
        }
        let versionAndIHL = packet[0]
        let version = versionAndIHL >> 4
        guard version == 4 else {
            throw TUNPacketError.unsupportedIPVersion(version)
        }
        let headerLength = Int(versionAndIHL & 0x0F) << 2
        guard (20...60).contains(headerLength) else {
            throw TUNPacketError.invalidHeaderLength(headerLength)
        }
        guard packet.count >= headerLength else {
            throw TUNPacketError.truncated(expected: headerLength, actual: packet.count)
        }
        let totalLength = UInt16(packet[2]) << 8 | UInt16(packet[3])
        return IPv4Header(
            version: version,
            headerLength: headerLength,
            totalLength: totalLength,
            protocolNumber: packet[9],
            source: IPv4Address(packet[12], packet[13], packet[14], packet[15]),
            destination: IPv4Address(packet[16], packet[17], packet[18], packet[19])
        )
    }
}

/// A zero-copy view of a raw IP packet.
struct RawIPPacket: @unchecked Sendable {

    /// Transport-layer information (ports are parsed only for TCP / UDP).
    enum Transport: Hashable, Sendable {
        case tcp(sourcePort: UInt16, destinationPort: UInt16)
        case udp(sourcePort: UInt16, destinationPort: UInt16)
        case other(protocolNumber: UInt8)
    }

    let ipv4Header: IPv4Header
    let bytes: UnsafeRawBufferPointer
    let transport: Transport

    init(_ buffer: UnsafeRawBufferPointer) throws {
        let header = try IPv4Header.parse(buffer)

        // A totalLength of 0 treats the whole buffer as the packet (the
        // lenient behavior of some stacks).
        let totalLength = header.totalLength
        if totalLength > 0 {
            guard totalLength >= header.headerLength else {
                throw TUNPacketError.invalidTotalLength(totalLength)
            }
            guard Int(totalLength) <= buffer.count else {
                throw TUNPacketError.truncated(
                    expected: Int(totalLength), actual: buffer.count
                )
            }
        }

        var transport: Transport = .other(protocolNumber: header.protocolNumber)
        let tcp = IPProtocolNumber.tcp.rawValue
        let udp = IPProtocolNumber.udp.rawValue
        if header.protocolNumber == tcp || header.protocolNumber == udp {
            let portOffset = header.headerLength
            guard buffer.count >= portOffset + 4 else {
                throw TUNPacketError.truncated(
                    expected: portOffset + 4, actual: buffer.count
                )
            }
            let sourcePort = UInt16(buffer[portOffset]) << 8
                | UInt16(buffer[portOffset + 1])
            let destinationPort = UInt16(buffer[portOffset + 2]) << 8
                | UInt16(buffer[portOffset + 3])
            transport = header.protocolNumber == tcp
                ? .tcp(sourcePort: sourcePort, destinationPort: destinationPort)
                : .udp(sourcePort: sourcePort, destinationPort: destinationPort)
        }

        self.ipv4Header = header
        self.bytes = buffer
        self.transport = transport
    }

    /// Zero-copy view of the IP payload (transport-layer segment), truncated to
    /// `totalLength`. Returns `nil` when there is no payload.
    var payload: UnsafeRawBufferPointer? {
        let start = ipv4Header.headerLength
        let end: Int
        if ipv4Header.totalLength > 0 {
            end = min(Int(ipv4Header.totalLength), bytes.count)
        } else {
            end = bytes.count
        }
        guard end > start else { return nil }
        return UnsafeRawBufferPointer(rebasing: bytes[start..<end])
    }

    /// The IPv4 five-tuple (used as a NAT / session-table key). Returns `nil`
    /// for non-TCP / non-UDP packets.
    var flowTuple: FlowTuple? {
        switch transport {
        case .tcp(let sourcePort, let destinationPort),
             .udp(let sourcePort, let destinationPort):
            return FlowTuple(
                protocolNumber: ipv4Header.protocolNumber,
                sourceAddress: ipv4Header.source,
                destinationAddress: ipv4Header.destination,
                sourcePort: sourcePort,
                destinationPort: destinationPort
            )
        case .other:
            return nil
        }
    }
}

/// An IPv4 flow five-tuple — the key of a NAT / session table.
struct FlowTuple: Hashable, Sendable {
    let protocolNumber: UInt8
    let sourceAddress: IPv4Address
    let destinationAddress: IPv4Address
    let sourcePort: UInt16
    let destinationPort: UInt16

    /// The reverse flow (server -> client direction).
    var reversed: FlowTuple {
        FlowTuple(
            protocolNumber: protocolNumber,
            sourceAddress: destinationAddress,
            destinationAddress: sourceAddress,
            sourcePort: destinationPort,
            destinationPort: sourcePort
        )
    }
}

// MARK: - TCP segment

struct TCPFlags: OptionSet, Sendable {
    let rawValue: UInt8
    static let fin = TCPFlags(rawValue: 0x01)
    static let syn = TCPFlags(rawValue: 0x02)
    static let rst = TCPFlags(rawValue: 0x04)
    static let psh = TCPFlags(rawValue: 0x08)
    static let ack = TCPFlags(rawValue: 0x10)
}

/// Parsed TCP header + payload view. Payload is a copy so it outlives the TUN buffer.
struct TCPSegment: Sendable {
    var sourcePort: UInt16
    var destinationPort: UInt16
    var sequence: UInt32
    var acknowledgement: UInt32
    var flags: TCPFlags
    var window: UInt16
    var payload: Data

    static func parse(ipPayload: UnsafeRawBufferPointer) -> TCPSegment? {
        guard ipPayload.count >= 20 else { return nil }
        let dataOffset = Int(ipPayload[12] >> 4) * 4
        guard dataOffset >= 20, ipPayload.count >= dataOffset else { return nil }
        let payload: Data
        if ipPayload.count > dataOffset {
            payload = Data(ipPayload[dataOffset..<ipPayload.count])
        } else {
            payload = Data()
        }
        return TCPSegment(
            sourcePort: UInt16(ipPayload[0]) << 8 | UInt16(ipPayload[1]),
            destinationPort: UInt16(ipPayload[2]) << 8 | UInt16(ipPayload[3]),
            sequence: loadUInt32(ipPayload, 4),
            acknowledgement: loadUInt32(ipPayload, 8),
            flags: TCPFlags(rawValue: ipPayload[13] & 0x3F),
            window: UInt16(ipPayload[14]) << 8 | UInt16(ipPayload[15]),
            payload: payload
        )
    }

    func encode(
        source: IPv4Address,
        destination: IPv4Address
    ) -> Data {
        let headerLength = 20
        var tcp = Data(count: headerLength + payload.count)
        tcp.withUnsafeMutableBytes { raw in
            raw[0] = UInt8(truncatingIfNeeded: sourcePort >> 8)
            raw[1] = UInt8(truncatingIfNeeded: sourcePort)
            raw[2] = UInt8(truncatingIfNeeded: destinationPort >> 8)
            raw[3] = UInt8(truncatingIfNeeded: destinationPort)
            storeUInt32(sequence, at: 4, in: raw)
            storeUInt32(acknowledgement, at: 8, in: raw)
            raw[12] = UInt8((headerLength / 4) << 4)
            raw[13] = flags.rawValue
            raw[14] = UInt8(truncatingIfNeeded: window >> 8)
            raw[15] = UInt8(truncatingIfNeeded: window)
            raw[16] = 0
            raw[17] = 0
            raw[18] = 0
            raw[19] = 0
            if !payload.isEmpty {
                payload.withUnsafeBytes { bytes in
                    raw.baseAddress!.advanced(by: headerLength)
                        .copyMemory(from: bytes.baseAddress!, byteCount: payload.count)
                }
            }
            let checksum = tcpChecksum(
                source: source,
                destination: destination,
                tcp: UnsafeRawBufferPointer(raw)
            )
            raw[16] = UInt8(truncatingIfNeeded: checksum >> 8)
            raw[17] = UInt8(truncatingIfNeeded: checksum)
        }
        return tcp.withUnsafeBytes { bytes in
            IPv4Codec.encode(
                source: source,
                destination: destination,
                protocolNumber: IPProtocolNumber.tcp.rawValue,
                payload: bytes
            )
        }
    }
}

private func loadUInt32(_ buffer: UnsafeRawBufferPointer, _ offset: Int) -> UInt32 {
    (UInt32(buffer[offset]) << 24)
        | (UInt32(buffer[offset + 1]) << 16)
        | (UInt32(buffer[offset + 2]) << 8)
        | UInt32(buffer[offset + 3])
}

private func storeUInt32(_ value: UInt32, at offset: Int, in raw: UnsafeMutableRawBufferPointer) {
    raw[offset] = UInt8(truncatingIfNeeded: value >> 24)
    raw[offset + 1] = UInt8(truncatingIfNeeded: value >> 16)
    raw[offset + 2] = UInt8(truncatingIfNeeded: value >> 8)
    raw[offset + 3] = UInt8(truncatingIfNeeded: value)
}

private func tcpChecksum(
    source: IPv4Address,
    destination: IPv4Address,
    tcp: UnsafeRawBufferPointer
) -> UInt16 {
    var total: UInt32 = 0
    total += source.rawValue >> 16
    total += source.rawValue & 0xFFFF
    total += destination.rawValue >> 16
    total += destination.rawValue & 0xFFFF
    total += UInt32(IPProtocolNumber.tcp.rawValue)
    total += UInt32(tcp.count)
    total = InternetChecksum.sum(tcp, initial: total)
    return InternetChecksum.fold(total)
}

// MARK: - UDP datagram parse (test-side; production only encodes)

extension UDPDatagram {
    static func parse(ipPayload: UnsafeRawBufferPointer) -> UDPDatagram? {
        guard ipPayload.count >= 8 else { return nil }
        let length = Int(UInt16(ipPayload[4]) << 8 | UInt16(ipPayload[5]))
        let payloadEnd = length > 0 ? min(length, ipPayload.count) : ipPayload.count
        guard payloadEnd >= 8 else { return nil }
        return UDPDatagram(
            sourcePort: UInt16(ipPayload[0]) << 8 | UInt16(ipPayload[1]),
            destinationPort: UInt16(ipPayload[2]) << 8 | UInt16(ipPayload[3]),
            payload: Data(ipPayload[8..<payloadEnd])
        )
    }
}
