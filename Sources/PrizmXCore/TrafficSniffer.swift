import Foundation

/// Clash-style protocol sniff: recover a hostname from the first TCP bytes
/// (HTTP `Host` or TLS ClientHello SNI) so domain rules match IP destinations.
public enum TrafficSniff: Sendable, Equatable {
    case hostname(String)
    case needMore
    case none
}

public enum TrafficSniffer: Sendable {
    public static let maxPrefix = 16 * 1024

    public static func sniff(_ data: Data) -> TrafficSniff {
        if data.isEmpty { return .needMore }
        if data.count > maxPrefix { return .none }
        let first = data[data.startIndex]
        if first == 0x16 {
            return sniffTLS(data)
        }
        if first >= 0x41 && first <= 0x5A {
            return sniffHTTP(data)
        }
        return .none
    }

    private static func sniffHTTP(_ data: Data) -> TrafficSniff {
        guard let headerEnd = data.range(of: Data([0x0D, 0x0A, 0x0D, 0x0A])) else {
            return .needMore
        }
        guard let text = String(data: data[..<headerEnd.lowerBound], encoding: .ascii) else {
            return .none
        }
        for line in text.split(separator: "\r\n") {
            let pair = line.split(separator: ":", maxSplits: 1)
            guard pair.count == 2, pair[0].lowercased() == "host" else { continue }
            var host = pair[1].trimmingCharacters(in: .whitespaces)
            if host.hasPrefix("["), let close = host.firstIndex(of: "]") {
                host = String(host[host.index(after: host.startIndex)..<close])
            } else if let colon = host.lastIndex(of: ":"), host[..<colon].contains(":") == false {
                host = String(host[..<colon])
            }
            host = host.lowercased()
            return host.isEmpty ? .none : .hostname(host)
        }
        return .none
    }

    private static func sniffTLS(_ data: Data) -> TrafficSniff {
        var reader = Reader(data)
        guard let contentType = reader.u8(), contentType == 0x16 else { return .none }
        guard reader.u8() != nil, reader.u8() != nil else { return .needMore }
        guard let recordLen = reader.u16() else { return .needMore }
        guard reader.remaining >= Int(recordLen) else { return .needMore }
        guard let handshake = reader.u8(), handshake == 0x01 else { return .none }
        guard reader.u24() != nil else { return .needMore }
        guard reader.skip(2 + 32) else { return .needMore } // version + random
        guard let sidLen = reader.u8(), reader.skip(Int(sidLen)) else { return .needMore }
        guard let cipherLen = reader.u16(), reader.skip(Int(cipherLen)) else { return .needMore }
        guard let compLen = reader.u8(), reader.skip(Int(compLen)) else { return .needMore }
        if reader.remaining == 0 { return .none }
        guard let extLen = reader.u16(), reader.remaining >= Int(extLen) else { return .needMore }
        let extEnd = reader.offset + Int(extLen)
        while reader.offset + 4 <= extEnd {
            guard let extType = reader.u16(), let length = reader.u16() else { return .needMore }
            guard reader.offset + Int(length) <= extEnd else { return .none }
            if extType == 0 {
                guard let body = reader.slice(Int(length)) else { return .none }
                return parseSNI(body)
            }
            guard reader.skip(Int(length)) else { return .none }
        }
        return .none
    }

    private static func parseSNI(_ data: Data) -> TrafficSniff {
        var reader = Reader(data)
        guard let listLen = reader.u16(), reader.remaining >= Int(listLen) else { return .none }
        while reader.remaining >= 3 {
            guard let nameType = reader.u8(), let nameLen = reader.u16() else { return .none }
            guard let name = reader.slice(Int(nameLen)) else { return .none }
            if nameType == 0 {
                guard let host = String(data: name, encoding: .ascii)?.lowercased(), !host.isEmpty else {
                    return .none
                }
                return .hostname(host)
            }
        }
        return .none
    }
}

private struct Reader {
    let data: Data
    var offset: Int = 0

    init(_ data: Data) {
        self.data = data
    }

    var remaining: Int { data.count - offset }

    mutating func u8() -> UInt8? {
        guard offset < data.count else { return nil }
        let value = data[offset]
        offset += 1
        return value
    }

    mutating func u16() -> UInt16? {
        guard let high = u8(), let low = u8() else { return nil }
        return UInt16(high) << 8 | UInt16(low)
    }

    mutating func u24() -> Int? {
        guard let high = u8(), let mid = u8(), let low = u8() else { return nil }
        return Int(high) << 16 | Int(mid) << 8 | Int(low)
    }

    mutating func skip(_ count: Int) -> Bool {
        guard count >= 0, remaining >= count else { return false }
        offset += count
        return true
    }

    mutating func slice(_ count: Int) -> Data? {
        guard count >= 0, remaining >= count else { return nil }
        let value = data.subdata(in: offset..<(offset + count))
        offset += count
        return value
    }
}
