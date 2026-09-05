import Foundation
import PrizmXProtocols

struct UDPDatagram: Sendable {
    var sourcePort: UInt16
    var destinationPort: UInt16
    var payload: Data

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
}
