import Foundation
import PrizmXProtocols

/// Minimal DNS codec for FakeIP (one question, A / AAAA answers).
enum DNSMessage {
    struct Question: Sendable {
        var name: String
        var type: UInt16
        var qClass: UInt16
    }

    static func parseQuestion(_ data: Data) -> (id: UInt16, question: Question)? {
        guard data.count >= 12 else { return nil }
        let id = UInt16(data[0]) << 8 | UInt16(data[1])
        var offset = 12
        guard let name = decodeName(data, offset: &offset), offset + 4 <= data.count else {
            return nil
        }
        let type = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
        let classValue = UInt16(data[offset + 2]) << 8 | UInt16(data[offset + 3])
        return (id, Question(name: name, type: type, qClass: classValue))
    }

    /// A record when `ipv4` is set; AAAA when `ipv6` is set. Otherwise NODATA
    /// (Clash `dns.ipv6: false` / proxied names with IPv4-only FakeIP).
    static func response(
        id: UInt16,
        question: Question,
        ipv4: IPv4Address? = nil,
        ipv6: IPv6Address? = nil,
        ttl: UInt32 = 30
    ) -> Data {
        var data = Data()
        data.append(UInt8(truncatingIfNeeded: id >> 8))
        data.append(UInt8(truncatingIfNeeded: id))
        data.append(0x81) // QR + RD + RA later
        data.append(0x80) // RA
        data.append(contentsOf: [0x00, 0x01]) // QDCOUNT
        let answerA = question.type == 1 && ipv4 != nil
        let answerAAAA = question.type == 28 && ipv6 != nil
        data.append(contentsOf: (answerA || answerAAAA) ? [0x00, 0x01] : [0x00, 0x00]) // ANCOUNT
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // NS / AR
        appendName(question.name, into: &data)
        appendUInt16(question.type, into: &data)
        appendUInt16(question.qClass, into: &data)
        if answerA, let ipv4 {
            data.append(contentsOf: [0xC0, 0x0C]) // pointer to QNAME
            appendUInt16(1, into: &data)
            appendUInt16(1, into: &data)
            appendUInt32(ttl, into: &data)
            appendUInt16(4, into: &data)
            let raw = ipv4.rawValue
            data.append(UInt8(truncatingIfNeeded: raw >> 24))
            data.append(UInt8(truncatingIfNeeded: raw >> 16))
            data.append(UInt8(truncatingIfNeeded: raw >> 8))
            data.append(UInt8(truncatingIfNeeded: raw))
        } else if answerAAAA, let ipv6 {
            data.append(contentsOf: [0xC0, 0x0C])
            appendUInt16(28, into: &data)
            appendUInt16(1, into: &data)
            appendUInt32(ttl, into: &data)
            appendUInt16(16, into: &data)
            appendIPv6(ipv6, into: &data)
        }
        return data
    }

    private static func appendIPv6(_ address: IPv6Address, into data: inout Data) {
        func append64(_ value: UInt64) {
            for shift in [56, 48, 40, 32, 24, 16, 8, 0] {
                data.append(UInt8(truncatingIfNeeded: value >> shift))
            }
        }
        append64(address.high)
        append64(address.low)
    }

    private static func decodeName(_ data: Data, offset: inout Int) -> String? {
        var labels: [String] = []
        var hops = 0
        var cursor = offset
        var jumped = false
        while cursor < data.count, hops < 16 {
            let length = Int(data[cursor])
            if length == 0 {
                if !jumped { offset = cursor + 1 }
                return labels.joined(separator: ".")
            }
            if length & 0xC0 == 0xC0 {
                guard cursor + 1 < data.count else { return nil }
                let pointer = Int(length & 0x3F) << 8 | Int(data[cursor + 1])
                if !jumped { offset = cursor + 2 }
                cursor = pointer
                jumped = true
                hops += 1
                continue
            }
            guard length < 64, cursor + 1 + length <= data.count else { return nil }
            let label = String(decoding: data[(cursor + 1)..<(cursor + 1 + length)], as: UTF8.self)
            labels.append(label)
            cursor += 1 + length
            if !jumped { offset = cursor }
        }
        return nil
    }

    private static func appendName(_ name: String, into data: inout Data) {
        for label in name.split(separator: ".") {
            let bytes = Array(label.utf8)
            data.append(UInt8(bytes.count))
            data.append(contentsOf: bytes)
        }
        data.append(0)
    }

    private static func appendUInt16(_ value: UInt16, into data: inout Data) {
        data.append(UInt8(truncatingIfNeeded: value >> 8))
        data.append(UInt8(truncatingIfNeeded: value))
    }

    private static func appendUInt32(_ value: UInt32, into data: inout Data) {
        data.append(UInt8(truncatingIfNeeded: value >> 24))
        data.append(UInt8(truncatingIfNeeded: value >> 16))
        data.append(UInt8(truncatingIfNeeded: value >> 8))
        data.append(UInt8(truncatingIfNeeded: value))
    }
}
