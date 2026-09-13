import Foundation

/// Shared minimal DNS wire codec used by the UDP and DoH nameserver transports.
public enum DNSWire {
    public static let typeA: UInt16 = 1
    public static let typePTR: UInt16 = 12
    public static let typeAAAA: UInt16 = 28

    /// One A answer with its TTL.
    public struct Record: Sendable, Equatable {
        public var address: IPv4Address
        public var ttl: UInt32
    }

    /// One AAAA answer with its TTL.
    public struct AAAARecord: Sendable, Equatable {
        public var address: IPv6Address
        public var ttl: UInt32
    }

    static func makeQuery(id queryID: UInt16, domain: String, type: UInt16 = typeA) -> Data {
        var data = Data()
        data.append(UInt8(truncatingIfNeeded: queryID >> 8))
        data.append(UInt8(truncatingIfNeeded: queryID))
        data.append(contentsOf: [0x01, 0x00]) // RD
        data.append(contentsOf: [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) // QD=1
        for label in domain.split(separator: ".") {
            let bytes = Array(label.utf8)
            // RFC 1035 caps a label at 63 bytes; an over-long label would trap
            // the UInt8 conversion. Clamp it — the resulting name simply
            // fails to resolve, which is the correct fate for invalid input.
            let clamped = bytes.prefix(63)
            data.append(UInt8(clamped.count))
            data.append(contentsOf: clamped)
        }
        data.append(0)
        data.append(UInt8(truncatingIfNeeded: type >> 8))
        data.append(UInt8(truncatingIfNeeded: type))
        data.append(contentsOf: [0x00, 0x01]) // IN
        return data
    }

    /// Base64url (no padding) query parameter for RFC 8484 GET requests.
    static func base64url(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func aRecords(in data: Data, expectedID: UInt16) -> [Record] {
        guard data.count >= 12 else { return [] }
        let id = UInt16(data[0]) << 8 | UInt16(data[1])
        guard id == expectedID else { return [] }
        let questionCount = Int(data[4]) << 8 | Int(data[5])
        let answerCount = Int(data[6]) << 8 | Int(data[7])
        guard answerCount > 0 else { return [] }
        var offset = 12
        for _ in 0..<questionCount {
            guard let next = skipName(data, offset), next + 4 <= data.count else { return [] }
            offset = next + 4
        }
        var results: [Record] = []
        var cursor = offset
        for _ in 0..<answerCount {
            guard let nameEnd = skipName(data, cursor), nameEnd + 10 <= data.count else { break }
            let type = Int(data[nameEnd]) << 8 | Int(data[nameEnd + 1])
            let ttl = UInt32(data[nameEnd + 4]) << 24 | UInt32(data[nameEnd + 5]) << 16
                | UInt32(data[nameEnd + 6]) << 8 | UInt32(data[nameEnd + 7])
            let length = Int(data[nameEnd + 8]) << 8 | Int(data[nameEnd + 9])
            let rdata = nameEnd + 10
            guard rdata + length <= data.count else { break }
            if type == Int(typeA), length == 4 {
                results.append(
                    Record(
                        address: IPv4Address(data[rdata], data[rdata + 1], data[rdata + 2], data[rdata + 3]),
                        ttl: ttl
                    )
                )
            }
            cursor = rdata + length
        }
        return results
    }

    static func ptrNames(in data: Data, expectedID: UInt16) -> [String] {
        guard data.count >= 12 else { return [] }
        let id = UInt16(data[0]) << 8 | UInt16(data[1])
        guard id == expectedID else { return [] }
        let questionCount = Int(data[4]) << 8 | Int(data[5])
        let answerCount = Int(data[6]) << 8 | Int(data[7])
        guard answerCount > 0 else { return [] }
        var offset = 12
        for _ in 0..<questionCount {
            guard let next = skipName(data, offset), next + 4 <= data.count else { return [] }
            offset = next + 4
        }
        var results: [String] = []
        var cursor = offset
        for _ in 0..<answerCount {
            guard let nameEnd = skipName(data, cursor), nameEnd + 10 <= data.count else { break }
            let type = Int(data[nameEnd]) << 8 | Int(data[nameEnd + 1])
            let length = Int(data[nameEnd + 8]) << 8 | Int(data[nameEnd + 9])
            let rdata = nameEnd + 10
            guard rdata + length <= data.count else { break }
            if type == Int(typePTR), let name = readName(data, rdata)?.0, !name.isEmpty {
                results.append(name)
            }
            cursor = rdata + length
        }
        return results
    }

    static func aaaaRecords(in data: Data, expectedID: UInt16) -> [AAAARecord] {
        guard data.count >= 12 else { return [] }
        let id = UInt16(data[0]) << 8 | UInt16(data[1])
        guard id == expectedID else { return [] }
        let questionCount = Int(data[4]) << 8 | Int(data[5])
        let answerCount = Int(data[6]) << 8 | Int(data[7])
        guard answerCount > 0 else { return [] }
        var offset = 12
        for _ in 0..<questionCount {
            guard let next = skipName(data, offset), next + 4 <= data.count else { return [] }
            offset = next + 4
        }
        var results: [AAAARecord] = []
        var cursor = offset
        for _ in 0..<answerCount {
            guard let nameEnd = skipName(data, cursor), nameEnd + 10 <= data.count else { break }
            let type = Int(data[nameEnd]) << 8 | Int(data[nameEnd + 1])
            let ttl = UInt32(data[nameEnd + 4]) << 24 | UInt32(data[nameEnd + 5]) << 16
                | UInt32(data[nameEnd + 6]) << 8 | UInt32(data[nameEnd + 7])
            let length = Int(data[nameEnd + 8]) << 8 | Int(data[nameEnd + 9])
            let rdata = nameEnd + 10
            guard rdata + length <= data.count else { break }
            if type == Int(typeAAAA), length == 16 {
                results.append(AAAARecord(address: ipv6(data, at: rdata), ttl: ttl))
            }
            cursor = rdata + length
        }
        return results
    }

    private static func ipv6(_ data: Data, at offset: Int) -> IPv6Address {
        func word(_ index: Int) -> UInt64 {
            var value: UInt64 = 0
            for byte in 0..<8 {
                value = (value << 8) | UInt64(data[offset + index + byte])
            }
            return value
        }
        return IPv6Address(high: word(0), low: word(8))
    }

    /// Decode a DNS name at `offset`, following compression pointers.
    static func readName(_ data: Data, _ offset: Int) -> (String, Int)? {
        var labels: [String] = []
        var cursor = offset
        var hops = 0
        var consumed = offset
        var jumped = false
        while cursor < data.count, hops < 16 {
            let length = Int(data[cursor])
            if length == 0 {
                if !jumped { consumed = cursor + 1 }
                return (labels.joined(separator: "."), consumed)
            }
            if length & 0xC0 == 0xC0 {
                guard cursor + 1 < data.count else { return nil }
                let pointer = (length & 0x3F) << 8 | Int(data[cursor + 1])
                if !jumped {
                    consumed = cursor + 2
                    jumped = true
                }
                cursor = pointer
                hops += 1
                continue
            }
            guard length < 64, cursor + 1 + length <= data.count else { return nil }
            let start = cursor + 1
            labels.append(String(decoding: data[start..<(start + length)], as: UTF8.self))
            cursor = start + length
            hops += 1
        }
        return nil
    }

    private static func skipName(_ data: Data, _ offset: Int) -> Int? {
        var cursor = offset
        var hops = 0
        while cursor < data.count, hops < 16 {
            let length = Int(data[cursor])
            if length == 0 { return cursor + 1 }
            if length & 0xC0 == 0xC0 {
                guard cursor + 1 < data.count else { return nil }
                return cursor + 2
            }
            guard length < 64, cursor + 1 + length <= data.count else { return nil }
            cursor += 1 + length
            hops += 1
        }
        return nil
    }
}
