import Foundation

/// Failures while decoding a v2ray / Mihomo `geosite.dat` protobuf.
public enum GeositeDatError: Error, Equatable, Sendable {
    case truncated
}

/// Decoder for v2ray `GeoSiteList` (`geosite.dat`).
///
/// Domain types: `Plain` → keyword, `Domain` → suffix, `Full` → exact.
/// `Regex` entries are skipped (the matcher has no regex engine).
public enum GeositeDatParser: Sendable {
    /// When `includeTags` is non-empty, only those lists are compiled
    /// (lowercase). `nil` compiles every tag in the file.
    public static func parse(data: Data, includeTags: Set<String>? = nil) throws -> GeositeMatcher {
        let wanted = includeTags.map { Set($0.map { $0.lowercased() }) }
        var reader = ProtoReader(data)
        var groups: [String: GeositeGroup] = [:]
        while let field = try reader.next() {
            guard field.number == 1, case .bytes(let blob) = field.value else { continue }
            guard let parsed = try parseSite(blob, include: wanted) else { continue }
            groups[parsed.tag] = parsed.group
        }
        return GeositeMatcher(groups: groups)
    }

    private static func parseSite(
        _ data: Data,
        include: Set<String>?
    ) throws -> (tag: String, group: GeositeGroup)? {
        var reader = ProtoReader(data)
        var tag = ""
        var exact: [String] = []
        var suffixes: [String] = []
        var keywords: [String] = []
        while let field = try reader.next() {
            switch (field.number, field.value) {
            case (1, .bytes(let bytes)):
                tag = String(decoding: bytes, as: UTF8.self).lowercased()
            case (2, .bytes(let bytes)):
                if let include, !tag.isEmpty, !include.contains(tag) { continue }
                switch try parseDomain(bytes) {
                case .exact(let value): exact.append(value)
                case .suffix(let value): suffixes.append(value)
                case .keyword(let value): keywords.append(value)
                case .skip: break
                }
            default:
                break
            }
        }
        if let include, !include.contains(tag) { return nil }
        guard !tag.isEmpty else { return nil }
        return (tag, GeositeGroup(exact: exact, suffixes: suffixes, keywords: keywords))
    }

    private enum DomainKind {
        case exact(String)
        case suffix(String)
        case keyword(String)
        case skip
    }

    private static func parseDomain(_ data: Data) throws -> DomainKind {
        var reader = ProtoReader(data)
        var type: UInt64 = 0
        var value = ""
        while let field = try reader.next() {
            switch (field.number, field.value) {
            case (1, .varint(let raw)):
                type = raw
            case (2, .bytes(let bytes)):
                value = String(decoding: bytes, as: UTF8.self)
            default:
                break
            }
        }
        guard !value.isEmpty else { return .skip }
        switch type {
        case 0: return .keyword(value)
        case 2: return .suffix(value)
        case 3: return .exact(value)
        default: return .skip
        }
    }
}

// MARK: - Minimal protobuf reader (varint + length-delimited)

private struct ProtoReader {
    enum Value {
        case varint(UInt64)
        case bytes(Data)
        case fixed32(UInt32)
        case fixed64(UInt64)
    }

    struct Field {
        var number: Int
        var value: Value
    }

    private let data: Data
    private var offset = 0

    init(_ data: Data) {
        self.data = data
    }

    mutating func next() throws -> Field? {
        guard offset < data.count else { return nil }
        let tag = try readVarint()
        let number = Int(tag >> 3)
        switch tag & 7 {
        case 0:
            return Field(number: number, value: .varint(try readVarint()))
        case 1:
            let value = try readFixed(byteCount: 8)
            return Field(number: number, value: .fixed64(value))
        case 2:
            let length = Int(try readVarint())
            let bytes = try readBytes(length)
            return Field(number: number, value: .bytes(bytes))
        case 5:
            let value = try readFixed(byteCount: 4)
            return Field(number: number, value: .fixed32(UInt32(truncatingIfNeeded: value)))
        default:
            throw GeositeDatError.truncated
        }
    }

    private mutating func readVarint() throws -> UInt64 {
        var result: UInt64 = 0
        var shift = 0
        while offset < data.count, shift < 64 {
            let byte = data[offset]
            offset += 1
            result |= UInt64(byte & 0x7F) << shift
            if byte & 0x80 == 0 { return result }
            shift += 7
        }
        throw GeositeDatError.truncated
    }

    private mutating func readBytes(_ count: Int) throws -> Data {
        guard count >= 0, offset + count <= data.count else { throw GeositeDatError.truncated }
        let slice = data.subdata(in: offset..<(offset + count))
        offset += count
        return slice
    }

    private mutating func readFixed(byteCount: Int) throws -> UInt64 {
        let bytes = try readBytes(byteCount)
        var value: UInt64 = 0
        for (index, byte) in bytes.enumerated() {
            value |= UInt64(byte) << (8 * index)
        }
        return value
    }
}
