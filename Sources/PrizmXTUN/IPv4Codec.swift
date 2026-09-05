import Foundation
import PrizmXProtocols

/// Builds IPv4 datagrams (20-byte header, no options) with a correct checksum.
enum IPv4Codec {
    static let headerLength = 20
    static let defaultTTL: UInt8 = 64

    static func encode(
        source: IPv4Address,
        destination: IPv4Address,
        protocolNumber: UInt8,
        identification: UInt16 = 0,
        payload: UnsafeRawBufferPointer
    ) -> Data {
        let total = headerLength + payload.count
        var packet = Data(count: total)
        packet.withUnsafeMutableBytes { raw in
            raw[0] = 0x45
            raw[1] = 0x00
            raw[2] = UInt8(truncatingIfNeeded: total >> 8)
            raw[3] = UInt8(truncatingIfNeeded: total)
            raw[4] = UInt8(truncatingIfNeeded: identification >> 8)
            raw[5] = UInt8(truncatingIfNeeded: identification)
            raw[6] = 0x40 // DF
            raw[7] = 0x00
            raw[8] = defaultTTL
            raw[9] = protocolNumber
            raw[10] = 0
            raw[11] = 0
            store(source, at: 12, in: raw)
            store(destination, at: 16, in: raw)
            if payload.count > 0,
               let destinationPointer = raw.baseAddress?.advanced(by: headerLength),
               let sourcePointer = payload.baseAddress
            {
                destinationPointer.copyMemory(from: sourcePointer, byteCount: payload.count)
            }
            let checksum = InternetChecksum.compute(UnsafeRawBufferPointer(rebasing: raw.prefix(headerLength)))
            raw[10] = UInt8(truncatingIfNeeded: checksum >> 8)
            raw[11] = UInt8(truncatingIfNeeded: checksum)
        }
        return packet
    }

    private static func store(_ address: IPv4Address, at offset: Int, in raw: UnsafeMutableRawBufferPointer) {
        let value = address.rawValue
        raw[offset] = UInt8(truncatingIfNeeded: value >> 24)
        raw[offset + 1] = UInt8(truncatingIfNeeded: value >> 16)
        raw[offset + 2] = UInt8(truncatingIfNeeded: value >> 8)
        raw[offset + 3] = UInt8(truncatingIfNeeded: value)
    }
}
