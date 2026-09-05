import Foundation

/// Shared minimal DNS wire codec (one A question) used by the UDP and DoH
/// nameserver transports.
public enum DNSWire {
    /// One A answer with its TTL.
    public struct Record: Sendable, Equatable {
        public var address: IPv4Address
        public var ttl: UInt32
    }

    static func makeQuery(id queryID: UInt16, domain: String) -> Data {
        var data = Data()
        data.append(UInt8(truncatingIfNeeded: queryID >> 8))
        data.append(UInt8(truncatingIfNeeded: queryID))
        data.append(contentsOf: [0x01, 0x00]) // RD
        data.append(contentsOf: [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) // QD=1
        for label in domain.split(separator: ".") {
            let bytes = Array(label.utf8)
            data.append(UInt8(bytes.count))
            data.append(contentsOf: bytes)
        }
        data.append(0)
        data.append(contentsOf: [0x00, 0x01, 0x00, 0x01]) // A IN
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
            if type == 1, length == 4 {
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
