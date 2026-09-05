import PrizmXProtocols

/// IP layer protocol numbers (only the ones commonly used by proxy / TUN
/// scenarios).
@frozen
public enum IPProtocolNumber: UInt8, Sendable, CaseIterable {
    case icmp = 1
    case tcp = 6
    case udp = 17
    case icmpv6 = 58
}

/// Raw IP packet parsing errors.
@frozen
public enum TUNPacketError: Error, Equatable, Sendable {
    /// The buffer is shorter than the header declares (or the minimum header).
    case truncated(expected: Int, actual: Int)
    /// Unsupported IP version (currently only 4 is supported; IPv6 is a
    /// future stub).
    case unsupportedIPVersion(UInt8)
    /// Invalid IHL field (legal range is 20...60 bytes).
    case invalidHeaderLength(Int)
    /// totalLength is smaller than the header length.
    case invalidTotalLength(UInt16)
}

/// IPv4 header (fixed 20 bytes + optional options, up to 60 bytes).
///
/// Parsed as a pure value-type copy (~24 bytes) that does not retain the
/// original buffer, so it can be safely stored long-term.
@frozen
public struct IPv4Header: Equatable, Sendable {

    /// IP version, always 4.
    public let version: UInt8
    /// Total header length in bytes (20...60, including options).
    public let headerLength: Int
    /// Total IP packet (header + payload) length in bytes (host byte order).
    public let totalLength: UInt16
    /// Upper-layer protocol number (see `IPProtocolNumber`).
    public let protocolNumber: UInt8
    /// Source address.
    public let source: IPv4Address
    /// Destination address.
    public let destination: IPv4Address

    public init(
        version: UInt8,
        headerLength: Int,
        totalLength: UInt16,
        protocolNumber: UInt8,
        source: IPv4Address,
        destination: IPv4Address
    ) {
        self.version = version
        self.headerLength = headerLength
        self.totalLength = totalLength
        self.protocolNumber = protocolNumber
        self.source = source
        self.destination = destination
    }

    /// Parses an IPv4 header from the start of a packet. Does not validate the
    /// header checksum (usually offloaded to the NIC / TUN).
    @inlinable
    public static func parse(_ packet: UnsafeRawBufferPointer) throws -> IPv4Header {
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
            source: IPv4Address(
                packet[12], packet[13], packet[14], packet[15]
            ),
            destination: IPv4Address(
                packet[16], packet[17], packet[18], packet[19]
            )
        )
    }
}

/// A **zero-copy view** of a raw IP packet read from a TUN device.
///
/// - Important: `bytes` points into the caller's buffer; its validity is fully
///   determined by the caller. The view does not retain or copy any data. Copy
///   the payload if it must outlive the buffer.
///   (Hence it is marked `@unchecked Sendable`: the type system cannot verify
///   the ownership and lifetime of memory behind raw pointers; that
///   responsibility rests with the caller per this documentation.)
@frozen
public struct RawIPPacket: @unchecked Sendable {

    /// Transport-layer information (ports are parsed only for TCP / UDP).
    @frozen
    public enum Transport: Hashable, Sendable {
        case tcp(sourcePort: UInt16, destinationPort: UInt16)
        case udp(sourcePort: UInt16, destinationPort: UInt16)
        case other(protocolNumber: UInt8)
    }

    /// The parsed IPv4 header (a value copy, safe to store).
    public let ipv4Header: IPv4Header
    /// Zero-copy view of the whole IP packet (including the header).
    public let bytes: UnsafeRawBufferPointer
    /// Transport-layer summary.
    public let transport: Transport

    /// Parses and wraps a raw IP packet.
    ///
    /// - Parameter buffer: A buffer pointing to the complete IP packet
    ///   (starting at the first byte of the IP header). Some implementations
    ///   prepend a 4-byte address-family prefix to TUN packets; callers should
    ///   strip it first.
    public init(_ buffer: UnsafeRawBufferPointer) throws {
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
    public var payload: UnsafeRawBufferPointer? {
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
    public var flowTuple: FlowTuple? {
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
@frozen
public struct FlowTuple: Hashable, Sendable {
    public let protocolNumber: UInt8
    public let sourceAddress: IPv4Address
    public let destinationAddress: IPv4Address
    public let sourcePort: UInt16
    public let destinationPort: UInt16

    public init(
        protocolNumber: UInt8,
        sourceAddress: IPv4Address,
        destinationAddress: IPv4Address,
        sourcePort: UInt16,
        destinationPort: UInt16
    ) {
        self.protocolNumber = protocolNumber
        self.sourceAddress = sourceAddress
        self.destinationAddress = destinationAddress
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
    }

    /// The reverse flow (server -> client direction).
    public var reversed: FlowTuple {
        FlowTuple(
            protocolNumber: protocolNumber,
            sourceAddress: destinationAddress,
            destinationAddress: sourceAddress,
            sourcePort: destinationPort,
            destinationPort: sourcePort
        )
    }
}
