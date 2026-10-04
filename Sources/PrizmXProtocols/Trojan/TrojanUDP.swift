import Foundation

/// Trojan UDP ASSOCIATE packets, carried on the TLS stream after the request
/// header:
/// `[SOCKS5 ATYP/ADDR/PORT][uint16 length][\r\n][payload]`.
public struct TrojanUDPFraming: DatagramStreamFraming {
    /// Largest payload one packet can carry (`uint16` length field).
    public static let maxPayloadLength = 0xFFFF

    private var leftover = Data()

    public init() {}

    public func encode(_ payload: Data, to destination: Endpoint) throws -> Data {
        guard payload.count <= Self.maxPayloadLength else {
            throw TrojanError.truncated(expected: Self.maxPayloadLength, actual: payload.count)
        }
        let address: [UInt8]
        do {
            address = try ShadowsocksAddress.encode(destination)
        } catch {
            throw TrojanError.invalidAddress(destination)
        }
        var packet = Data(capacity: address.count + 4 + payload.count)
        packet.append(contentsOf: address)
        packet.append(UInt8(truncatingIfNeeded: payload.count >> 8))
        packet.append(UInt8(truncatingIfNeeded: payload.count))
        packet.append(contentsOf: TrojanHeader.crlf)
        packet.append(payload)
        return packet
    }

    public mutating func decode(_ chunk: Data) throws -> [Data] {
        leftover.append(chunk)
        var datagrams: [Data] = []
        while let (payload, consumed) = try Self.parse(leftover) {
            datagrams.append(payload)
            leftover.removeSubrange(leftover.startIndex..<(leftover.startIndex + consumed))
        }
        return datagrams
    }

    /// One complete packet at the start of `buffer`: payload and bytes
    /// consumed, or `nil` when more bytes are needed.
    static func parse(_ buffer: Data) throws -> (Data, Int)? {
        try buffer.withUnsafeBytes { raw -> (Data, Int)? in
            guard let addressCount = try addressByteCount(raw) else { return nil }
            let header = addressCount + 4
            guard raw.count >= header else { return nil }
            guard raw[addressCount + 2] == 0x0D, raw[addressCount + 3] == 0x0A else {
                throw TrojanError.malformedUDPPacket
            }
            let length = Int(raw[addressCount]) << 8 | Int(raw[addressCount + 1])
            guard raw.count >= header + length else { return nil }
            return (Data(raw[header..<(header + length)]), header + length)
        }
    }

    /// Size of the SOCKS5 address at the start, or `nil` when truncated.
    private static func addressByteCount(_ raw: UnsafeRawBufferPointer) throws -> Int? {
        guard let type = raw.first else { return nil }
        switch type {
        case 0x01: return 1 + 4 + 2
        case 0x04: return 1 + 16 + 2
        case 0x03:
            guard raw.count >= 2 else { return nil }
            return 1 + 1 + Int(raw[1]) + 2
        default:
            throw TrojanError.malformedUDPPacket
        }
    }
}
