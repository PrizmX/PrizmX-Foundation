import Foundation
import PrizmXProtocols

/// IPv4 ICMP / IPv6 ICMPv6 replies so dropped UDP/QUIC fails fast and
/// Happy Eyeballs can fall back to TCP / IPv4.
enum ICMPReply {
    static let tunnelIPv4 = IPv4Address(198, 18, 0, 1)
    /// Unique-local address advertised on the utun.
    static let tunnelIPv6: [UInt8] = [
        0xfd, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ]

    /// ICMP type 3 code 3 (port unreachable) for a dropped UDP datagram.
    static func portUnreachable(
        client: IPv4Address,
        destination: IPv4Address,
        sourcePort: UInt16,
        destinationPort: UInt16
    ) -> Data {
        var inner = Data(count: 28)
        inner[0] = 0x45
        inner[8] = 64
        inner[9] = 17
        writeUInt16(28, into: &inner, at: 2)
        writeIPv4(client, into: &inner, at: 12)
        writeIPv4(destination, into: &inner, at: 16)
        writeUInt16(internetChecksum(inner), into: &inner, at: 10)
        writeUInt16(sourcePort, into: &inner, at: 20)
        writeUInt16(destinationPort, into: &inner, at: 22)
        writeUInt16(8, into: &inner, at: 24)

        var icmp = Data(count: 8)
        icmp[0] = 3
        icmp[1] = 3
        icmp.append(inner)
        writeUInt16(internetChecksum(icmp), into: &icmp, at: 2)

        var ip = Data(count: 20)
        ip[0] = 0x45
        ip[8] = 64
        ip[9] = 1
        writeUInt16(UInt16(20 + icmp.count), into: &ip, at: 2)
        writeIPv4(tunnelIPv4, into: &ip, at: 12)
        writeIPv4(client, into: &ip, at: 16)
        writeUInt16(internetChecksum(ip), into: &ip, at: 10)
        ip.append(icmp)
        return ip
    }

    /// ICMPv6 Destination Unreachable (type 1): code 3 address unreachable,
    /// code 4 port unreachable.
    static func ipv6Unreachable(original: Data, code: UInt8 = 3) -> Data? {
        guard original.count >= 40, original[0] >> 4 == 6 else { return nil }
        let client = original.subdata(in: 8..<24)
        let quoted = original.prefix(min(original.count, 1232))

        var icmp = Data()
        icmp.append(1)
        icmp.append(code)
        icmp.append(contentsOf: [0, 0, 0, 0, 0, 0])
        icmp.append(quoted)
        let checksum = icmpv6Checksum(source: Data(tunnelIPv6), destination: client, icmp: icmp)
        icmp[2] = UInt8(truncatingIfNeeded: checksum >> 8)
        icmp[3] = UInt8(truncatingIfNeeded: checksum)

        var ip = Data(count: 40)
        ip[0] = 0x60
        writeUInt16(UInt16(icmp.count), into: &ip, at: 4)
        ip[6] = 58
        ip[7] = 64
        for offset in 0..<16 { ip[8 + offset] = tunnelIPv6[offset] }
        ip.replaceSubrange(24..<40, with: client)
        ip.append(icmp)
        return ip
    }

    /// ICMPv6 port unreachable (type 1 code 4) for a dropped UDP datagram,
    /// quoting a rebuilt IPv6 + UDP header (the IPv6 `portUnreachable`).
    static func ipv6PortUnreachable(
        client: IPv6Address,
        destination: IPv6Address,
        sourcePort: UInt16,
        destinationPort: UInt16
    ) -> Data {
        var original = Data(count: 48)
        original[0] = 0x60
        writeUInt16(8, into: &original, at: 4)
        original[6] = 17
        original[7] = 64
        writeIPv6(client, into: &original, at: 8)
        writeIPv6(destination, into: &original, at: 24)
        writeUInt16(sourcePort, into: &original, at: 40)
        writeUInt16(destinationPort, into: &original, at: 42)
        writeUInt16(8, into: &original, at: 44)
        // A 48-byte IPv6 packet always yields a reply.
        return ipv6Unreachable(original: original, code: 4) ?? Data()
    }

    /// Refuses IPv6 the tunnel does not carry. TCP gets a RST: macOS takes
    /// ICMPv6 unreachable as a soft error and retries the SYN for seconds,
    /// while a RST fails the connect at once (apps then use IPv4).
    /// Anything else gets ICMPv6 unreachable.
    static func ipv6Refusal(original: Data) -> Data? {
        guard original.count >= 40, original[0] >> 4 == 6 else { return nil }
        if original[6] == 6 { return ipv6Reset(original: original) }
        return ipv6Unreachable(original: original)
    }

    /// TCP RST answering `original` (RFC 9293 §3.10.7.1), from its
    /// destination. Nil for a RST, which is never answered, or a TCP header
    /// that is cut short.
    static func ipv6Reset(original: Data) -> Data? {
        let packet = Data(original)
        guard packet.count >= 60, packet[0] >> 4 == 6, packet[6] == 6 else { return nil }
        let flags = packet[53]
        let rst: UInt8 = 0x04, syn: UInt8 = 0x02, fin: UInt8 = 0x01, ack: UInt8 = 0x10
        guard flags & rst == 0 else { return nil }
        let headerLength = Int(packet[52] >> 4) * 4
        let payloadLength = Int(UInt16(packet[4]) << 8 | UInt16(packet[5]))
        guard headerLength >= 20, payloadLength >= headerLength, packet.count >= 40 + payloadLength else {
            return nil
        }
        func readUInt32(at offset: Int) -> UInt32 {
            (0..<4).reduce(0) { $0 << 8 | UInt32(packet[offset + $1]) }
        }

        var tcp = Data(count: 20)
        tcp.replaceSubrange(0..<2, with: packet[42..<44])
        tcp.replaceSubrange(2..<4, with: packet[40..<42])
        if flags & ack != 0 {
            // <SEQ=SEG.ACK><CTL=RST>
            writeUInt32(readUInt32(at: 48), into: &tcp, at: 4)
            tcp[13] = rst
        } else {
            // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
            var length = UInt32(payloadLength - headerLength)
            if flags & syn != 0 { length += 1 }
            if flags & fin != 0 { length += 1 }
            writeUInt32(readUInt32(at: 44) &+ length, into: &tcp, at: 8)
            tcp[13] = rst | ack
        }
        tcp[12] = 5 << 4
        let source = packet.subdata(in: 24..<40)
        let destination = packet.subdata(in: 8..<24)
        let checksum = ipv6Checksum(source: source, destination: destination, nextHeader: 6, payload: tcp)
        writeUInt16(checksum, into: &tcp, at: 16)

        var ip = Data(count: 40)
        ip[0] = 0x60
        writeUInt16(UInt16(tcp.count), into: &ip, at: 4)
        ip[6] = 6
        ip[7] = 64
        ip.replaceSubrange(8..<24, with: source)
        ip.replaceSubrange(24..<40, with: destination)
        ip.append(tcp)
        return ip
    }

    private static func writeIPv6(_ address: IPv6Address, into data: inout Data, at offset: Int) {
        for index in 0..<8 {
            data[offset + index] = UInt8(truncatingIfNeeded: address.high >> (56 - 8 * index))
            data[offset + 8 + index] = UInt8(truncatingIfNeeded: address.low >> (56 - 8 * index))
        }
    }

    private static func writeUInt32(_ value: UInt32, into data: inout Data, at offset: Int) {
        for index in 0..<4 {
            data[offset + index] = UInt8(truncatingIfNeeded: value >> (24 - 8 * index))
        }
    }

    private static func writeUInt16(_ value: UInt16, into data: inout Data, at offset: Int) {
        data[offset] = UInt8(truncatingIfNeeded: value >> 8)
        data[offset + 1] = UInt8(truncatingIfNeeded: value)
    }

    private static func writeIPv4(_ address: IPv4Address, into data: inout Data, at offset: Int) {
        let raw = address.rawValue
        data[offset] = UInt8(truncatingIfNeeded: raw >> 24)
        data[offset + 1] = UInt8(truncatingIfNeeded: raw >> 16)
        data[offset + 2] = UInt8(truncatingIfNeeded: raw >> 8)
        data[offset + 3] = UInt8(truncatingIfNeeded: raw)
    }

    static func internetChecksum(_ data: Data) -> UInt16 {
        data.withUnsafeBytes { InternetChecksum.compute($0) }
    }

    private static func icmpv6Checksum(source: Data, destination: Data, icmp: Data) -> UInt16 {
        ipv6Checksum(source: source, destination: destination, nextHeader: 58, payload: icmp)
    }

    /// Upper-layer checksum over the IPv6 pseudo-header (RFC 8200 §8.1).
    static func ipv6Checksum(source: Data, destination: Data, nextHeader: UInt8, payload: Data) -> UInt16 {
        var sum = Data()
        sum.append(source)
        sum.append(destination)
        let length = UInt32(payload.count)
        sum.append(UInt8(truncatingIfNeeded: length >> 24))
        sum.append(UInt8(truncatingIfNeeded: length >> 16))
        sum.append(UInt8(truncatingIfNeeded: length >> 8))
        sum.append(UInt8(truncatingIfNeeded: length))
        sum.append(contentsOf: [0, 0, 0, nextHeader])
        sum.append(payload)
        return internetChecksum(sum)
    }
}
