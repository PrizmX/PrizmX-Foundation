import Foundation
import PrizmXProtocols

struct UDPDatagram: Sendable {
    var sourcePort: UInt16
    var destinationPort: UInt16
    var payload: Data

    func encode(source: IPv4Address, destination: IPv4Address) -> Data {
        let length = 8 + payload.count
        var udp = Data(count: length)
        udp.withUnsafeMutableBytes { raw in
            raw[0] = UInt8(truncatingIfNeeded: sourcePort >> 8)
            raw[1] = UInt8(truncatingIfNeeded: sourcePort)
            raw[2] = UInt8(truncatingIfNeeded: destinationPort >> 8)
            raw[3] = UInt8(truncatingIfNeeded: destinationPort)
            raw[4] = UInt8(truncatingIfNeeded: length >> 8)
            raw[5] = UInt8(truncatingIfNeeded: length)
            raw[6] = 0
            raw[7] = 0
            if !payload.isEmpty {
                payload.withUnsafeBytes { bytes in
                    raw.baseAddress!.advanced(by: 8)
                        .copyMemory(from: bytes.baseAddress!, byteCount: payload.count)
                }
            }
            var total: UInt32 = 0
            total += source.rawValue >> 16
            total += source.rawValue & 0xFFFF
            total += destination.rawValue >> 16
            total += destination.rawValue & 0xFFFF
            total += UInt32(IPProtocolNumber.udp.rawValue)
            total += UInt32(length)
            total = InternetChecksum.sum(UnsafeRawBufferPointer(raw), initial: total)
            let checksum = InternetChecksum.fold(total)
            // A UDP checksum of 0 means "not used"; transmit 0xFFFF instead.
            let stored = checksum == 0 ? 0xFFFF : checksum
            raw[6] = UInt8(truncatingIfNeeded: stored >> 8)
            raw[7] = UInt8(truncatingIfNeeded: stored)
        }
        return udp.withUnsafeBytes { bytes in
            IPv4Codec.encode(
                source: source,
                destination: destination,
                protocolNumber: IPProtocolNumber.udp.rawValue,
                payload: bytes
            )
        }
    }

    func encode(source: IPv6Address, destination: IPv6Address) -> Data {
        let udpLength = 8 + payload.count
        var udp = Data(count: udpLength)
        udp[0] = UInt8(truncatingIfNeeded: sourcePort >> 8)
        udp[1] = UInt8(truncatingIfNeeded: sourcePort)
        udp[2] = UInt8(truncatingIfNeeded: destinationPort >> 8)
        udp[3] = UInt8(truncatingIfNeeded: destinationPort)
        udp[4] = UInt8(truncatingIfNeeded: udpLength >> 8)
        udp[5] = UInt8(truncatingIfNeeded: udpLength)
        if !payload.isEmpty {
            udp.replaceSubrange(8..<udpLength, with: payload)
        }
        var pseudo = Data()
        appendIPv6(source, into: &pseudo)
        appendIPv6(destination, into: &pseudo)
        pseudo.append(contentsOf: [
            0, 0,
            UInt8(truncatingIfNeeded: udpLength >> 8),
            UInt8(truncatingIfNeeded: udpLength),
            0, 0, 0, 17,
        ])
        let checksum = udp.withUnsafeBytes { raw -> UInt16 in
            var total = InternetChecksum.sum(pseudo.withUnsafeBytes { $0 })
            total = InternetChecksum.sum(UnsafeRawBufferPointer(raw), initial: total)
            let folded = InternetChecksum.fold(total)
            return folded == 0 ? 0xFFFF : folded
        }
        udp[6] = UInt8(truncatingIfNeeded: checksum >> 8)
        udp[7] = UInt8(truncatingIfNeeded: checksum)

        var ip = Data(count: 40)
        ip[0] = 0x60
        ip[4] = UInt8(truncatingIfNeeded: udpLength >> 8)
        ip[5] = UInt8(truncatingIfNeeded: udpLength)
        ip[6] = 17
        ip[7] = 64
        var offset = 8
        appendIPv6(source, into: &ip, at: &offset)
        appendIPv6(destination, into: &ip, at: &offset)
        ip.append(udp)
        return ip
    }
}

private func appendIPv6(_ address: IPv6Address, into data: inout Data) {
    var offset = data.count
    data.append(contentsOf: repeatElement(0, count: 16))
    appendIPv6(address, into: &data, at: &offset)
}

private func appendIPv6(_ address: IPv6Address, into data: inout Data, at offset: inout Int) {
    func write64(_ value: UInt64) {
        for shift in [56, 48, 40, 32, 24, 16, 8, 0] {
            data[offset] = UInt8(truncatingIfNeeded: value >> shift)
            offset += 1
        }
    }
    write64(address.high)
    write64(address.low)
}
