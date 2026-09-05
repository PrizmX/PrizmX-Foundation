import Foundation
import PrizmXProtocols

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
