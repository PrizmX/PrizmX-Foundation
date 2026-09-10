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

    /// ICMPv6 Destination Unreachable / Address Unreachable (type 1 code 3).
    static func ipv6Unreachable(original: Data) -> Data? {
        guard original.count >= 40, original[0] >> 4 == 6 else { return nil }
        let client = original.subdata(in: 8..<24)
        let quoted = original.prefix(min(original.count, 1232))

        var icmp = Data()
        icmp.append(1)
        icmp.append(3)
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
        var sum = Data()
        sum.append(source)
        sum.append(destination)
        let length = UInt32(icmp.count)
        sum.append(UInt8(truncatingIfNeeded: length >> 24))
        sum.append(UInt8(truncatingIfNeeded: length >> 16))
        sum.append(UInt8(truncatingIfNeeded: length >> 8))
        sum.append(UInt8(truncatingIfNeeded: length))
        sum.append(contentsOf: [0, 0, 0, 58])
        sum.append(icmp)
        return internetChecksum(sum)
    }
}
