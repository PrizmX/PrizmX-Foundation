import Foundation
import PrizmXProtocols

// MARK: - Errors

public enum GeoIPError: Error, Equatable, Sendable {
    case fileTooSmall
    case metadataNotFound
    case invalidMetadata
    case unsupportedRecordSize(Int)
    case truncated
}

// MARK: - Decoded MMDB value (country records are maps of strings)

enum MMDBValue: Sendable {
    case string(String)
    case uint(UInt64)
    case int(Int32)
    case boolean(Bool)
    case double(Double)
    case float(Float)
    case bytes(Data)
    case map([String: MMDBValue])
    case array([MMDBValue])

    var string: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    var map: [String: MMDBValue]? {
        if case .map(let value) = self { return value }
        return nil
    }

    var isoCode: String? {
        if let direct = string { return direct }
        if let nested = map?["country"]?.map?["iso_code"]?.string { return nested }
        if let nested = map?["registered_country"]?.map?["iso_code"]?.string { return nested }
        return map?["iso_code"]?.string
    }
}

// MARK: - Matcher

/// Memory-mapped MaxMind DB reader. `lookup` walks the binary tree (one bit per
/// node) then decodes the data record; a country query is typically a few
/// hundred nanoseconds to a couple of microseconds.
public final class GeoIPMatcher: Sendable {
    private let data: Data
    private let nodeCount: UInt32
    private let recordSize: Int
    private let nodeByteCount: Int
    private let treeByteCount: Int
    private let ipVersion: Int
    /// Node to start IPv4 lookups from (0 for IPv4 DBs; after `::/96` for IPv6 DBs).
    private let ipv4StartNode: UInt32

    public convenience init(contentsOf url: URL) throws {
        let mapped = try Data(contentsOf: url, options: [.mappedIfSafe])
        try self.init(data: mapped)
    }

    public init(data: Data) throws {
        guard data.count > 128 else { throw GeoIPError.fileTooSmall }
        self.data = data

        let metadata = try Self.readMetadata(data)
        guard let nodeCount = metadata["node_count"]?.uint.flatMap({ UInt32(exactly: $0) }),
              let recordSize = metadata["record_size"]?.uint.map(Int.init),
              let ipVersion = metadata["ip_version"]?.uint.map(Int.init)
        else {
            throw GeoIPError.invalidMetadata
        }
        guard recordSize == 24 || recordSize == 28 || recordSize == 32 else {
            throw GeoIPError.unsupportedRecordSize(recordSize)
        }

        self.nodeCount = nodeCount
        self.recordSize = recordSize
        self.nodeByteCount = recordSize * 2 / 8
        self.treeByteCount = Int(nodeCount) * nodeByteCount
        self.ipVersion = ipVersion

        guard treeByteCount + 16 < data.count else { throw GeoIPError.truncated }

        var start: UInt32 = 0
        if ipVersion == 6 {
            start = Self.walkZeros(
                data: data,
                from: 0,
                bits: 96,
                nodeCount: nodeCount,
                recordSize: recordSize,
                nodeByteCount: nodeByteCount
            ) ?? 0
        }
        self.ipv4StartNode = start
    }

    /// Returns the ISO country code (e.g. `"CN"`) or `nil` when the address is
    /// missing / unparsable.
    public func lookup(ip: String) -> String? {
        if let address = IPv4Address(parsing: ip) { return lookup(ipv4: address) }
        if let address = IPv6Address(parsing: ip) { return lookup(ipv6: address) }
        return nil
    }

    public func lookup(ipv4 address: IPv4Address) -> String? {
        let start = ipVersion == 4 ? 0 : ipv4StartNode
        return walk(startNode: start, bitCount: 32) { index in
            UInt8(truncatingIfNeeded: (address.rawValue >> (31 - index)) & 1)
        }
    }

    public func lookup(ipv6 address: IPv6Address) -> String? {
        walk(startNode: 0, bitCount: 128) { index in
            if index < 64 {
                return UInt8(truncatingIfNeeded: (address.high >> (63 - index)) & 1)
            }
            return UInt8(truncatingIfNeeded: (address.low >> (63 - (index - 64))) & 1)
        }
    }

    private func walk(startNode: UInt32, bitCount: Int, bitAt: (Int) -> UInt8) -> String? {
        data.withUnsafeBytes { buffer -> String? in
            var node = startNode
            for index in 0..<bitCount {
                let record = Self.readRecord(
                    buffer: buffer,
                    node: node,
                    side: bitAt(index),
                    recordSize: recordSize,
                    nodeByteCount: nodeByteCount
                )
                if record < nodeCount {
                    node = record
                    continue
                }
                if record == nodeCount { return nil }
                let fileOffset = Int(record - nodeCount) + treeByteCount
                return Self.decodeCountryCode(
                    buffer: buffer,
                    fileOffset: fileOffset,
                    sectionStart: treeByteCount + 16
                )
            }
            return nil
        }
    }

    // MARK: Tree

    private static func readRecord(
        buffer: UnsafeRawBufferPointer,
        node: UInt32,
        side: UInt8,
        recordSize: Int,
        nodeByteCount: Int
    ) -> UInt32 {
        let base = Int(node) * nodeByteCount
        switch recordSize {
        case 24:
            let offset = base + Int(side) * 3
            return uint24(buffer, offset)
        case 32:
            let offset = base + Int(side) * 4
            return uint32(buffer, offset)
        case 28:
            let middle = buffer[base + 3]
            if side == 0 {
                return (UInt32(middle >> 4) << 24) | uint24(buffer, base)
            }
            return (UInt32(middle & 0x0F) << 24) | uint24(buffer, base + 4)
        default:
            return 0
        }
    }

    private static func walkZeros(
        data: Data,
        from start: UInt32,
        bits: Int,
        nodeCount: UInt32,
        recordSize: Int,
        nodeByteCount: Int
    ) -> UInt32? {
        data.withUnsafeBytes { buffer -> UInt32? in
            var node = start
            for _ in 0..<bits {
                let record = readRecord(
                    buffer: buffer,
                    node: node,
                    side: 0,
                    recordSize: recordSize,
                    nodeByteCount: nodeByteCount
                )
                if record < nodeCount {
                    node = record
                } else {
                    return start
                }
            }
            return node
        }
    }

    // MARK: Metadata

    private static let metadataMarker = Data([0xAB, 0xCD, 0xEF]) + Data("MaxMind.com".utf8)

    private static func readMetadata(_ data: Data) throws -> [String: MMDBValue] {
        let start = max(0, data.count - 128 * 1024)
        guard let range = data.range(
            of: metadataMarker,
            options: .backwards,
            in: start..<data.count
        ) else {
            throw GeoIPError.metadataNotFound
        }
        let markerEnd = range.upperBound
        let map = data.withUnsafeBytes { buffer in
            decodeValue(buffer: buffer, fileOffset: markerEnd, sectionStart: markerEnd)?.map
        }
        guard let map, !map.isEmpty else { throw GeoIPError.invalidMetadata }
        return map
    }

    // MARK: Country-code decoder (avoids allocating the full value tree)

    private static func decodeCountryCode(
        buffer: UnsafeRawBufferPointer,
        fileOffset: Int,
        sectionStart: Int
    ) -> String? {
        var cursor = fileOffset
        return readCountryCode(buffer: buffer, cursor: &cursor, sectionStart: sectionStart, depth: 0)?
            .uppercased()
    }

    private static func readCountryCode(
        buffer: UnsafeRawBufferPointer,
        cursor: inout Int,
        sectionStart: Int,
        depth: Int
    ) -> String? {
        guard depth < 16, cursor < buffer.count else { return nil }
        let control = buffer[cursor]
        cursor += 1
        var type = Int(control >> 5)
        var size = Int(control & 0x1F)
        if type == 0 {
            guard cursor < buffer.count else { return nil }
            type = Int(buffer[cursor]) + 7
            cursor += 1
        }
        if type == 1 {
            let pointer = decodePointer(control: control, buffer: buffer, cursor: &cursor)
            return decodeCountryCode(
                buffer: buffer,
                fileOffset: sectionStart + Int(pointer),
                sectionStart: sectionStart
            )
        }
        if type != 14 {
            size = payloadSize(size, buffer: buffer, cursor: &cursor)
        }
        switch type {
        case 2:
            return readString(buffer, cursor: &cursor, count: size)
        case 7:
            var country: String?
            var registered: String?
            var iso: String?
            for _ in 0..<size {
                guard let key = readStringField(buffer: buffer, cursor: &cursor, sectionStart: sectionStart)
                else {
                    skipValue(buffer: buffer, cursor: &cursor)
                    skipValue(buffer: buffer, cursor: &cursor)
                    continue
                }
                if key == "country" {
                    country = readCountryCode(
                        buffer: buffer, cursor: &cursor, sectionStart: sectionStart, depth: depth + 1
                    )
                } else if key == "registered_country" {
                    registered = readCountryCode(
                        buffer: buffer, cursor: &cursor, sectionStart: sectionStart, depth: depth + 1
                    )
                } else if key == "iso_code" {
                    iso = readStringField(buffer: buffer, cursor: &cursor, sectionStart: sectionStart)
                } else {
                    skipValue(buffer: buffer, cursor: &cursor)
                }
            }
            return country ?? registered ?? iso
        default:
            skipPayload(type: type, size: size, buffer: buffer, cursor: &cursor)
            return nil
        }
    }

    private static func readStringField(
        buffer: UnsafeRawBufferPointer,
        cursor: inout Int,
        sectionStart: Int
    ) -> String? {
        guard cursor < buffer.count else { return nil }
        let control = buffer[cursor]
        cursor += 1
        var type = Int(control >> 5)
        var size = Int(control & 0x1F)
        if type == 0 {
            guard cursor < buffer.count else { return nil }
            type = Int(buffer[cursor]) + 7
            cursor += 1
        }
        if type == 1 {
            let pointer = decodePointer(control: control, buffer: buffer, cursor: &cursor)
            var nested = sectionStart + Int(pointer)
            return readStringField(buffer: buffer, cursor: &nested, sectionStart: sectionStart)
        }
        if type != 14 {
            size = payloadSize(size, buffer: buffer, cursor: &cursor)
        }
        guard type == 2 else {
            skipPayload(type: type, size: size, buffer: buffer, cursor: &cursor)
            return nil
        }
        return readString(buffer, cursor: &cursor, count: size)
    }

    private static func skipValue(buffer: UnsafeRawBufferPointer, cursor: inout Int) {
        guard cursor < buffer.count else { return }
        let control = buffer[cursor]
        cursor += 1
        var type = Int(control >> 5)
        var size = Int(control & 0x1F)
        if type == 0 {
            guard cursor < buffer.count else { return }
            type = Int(buffer[cursor]) + 7
            cursor += 1
        }
        if type == 1 {
            _ = decodePointer(control: control, buffer: buffer, cursor: &cursor)
            return
        }
        if type != 14 {
            size = payloadSize(size, buffer: buffer, cursor: &cursor)
        }
        skipPayload(type: type, size: size, buffer: buffer, cursor: &cursor)
    }

    private static func skipPayload(
        type: Int,
        size: Int,
        buffer: UnsafeRawBufferPointer,
        cursor: inout Int
    ) {
        switch type {
        case 2, 4, 5, 6, 8, 9, 10:
            cursor += size
        case 3:
            cursor += 8
        case 7:
            for _ in 0..<size {
                skipValue(buffer: buffer, cursor: &cursor)
                skipValue(buffer: buffer, cursor: &cursor)
            }
        case 11:
            for _ in 0..<size { skipValue(buffer: buffer, cursor: &cursor) }
        case 14:
            break
        case 15:
            cursor += 4
        default:
            break
        }
    }

    // MARK: Data decoder

    private static func decodeValue(
        buffer: UnsafeRawBufferPointer,
        fileOffset: Int,
        sectionStart: Int,
        depth: Int = 0
    ) -> MMDBValue? {
        guard depth < 64, fileOffset >= 0, fileOffset < buffer.count else { return nil }
        var cursor = fileOffset
        guard let decoded = decodeField(buffer: buffer, cursor: &cursor, sectionStart: sectionStart, depth: depth)
        else { return nil }
        return decoded
    }

    private static func decodeField(
        buffer: UnsafeRawBufferPointer,
        cursor: inout Int,
        sectionStart: Int,
        depth: Int
    ) -> MMDBValue? {
        guard cursor < buffer.count else { return nil }
        let control = buffer[cursor]
        cursor += 1
        var type = Int(control >> 5)
        var size = Int(control & 0x1F)
        if type == 0 {
            guard cursor < buffer.count else { return nil }
            type = Int(buffer[cursor]) + 7
            cursor += 1
        }

        if type == 1 {
            let pointer = decodePointer(control: control, buffer: buffer, cursor: &cursor)
            return decodeValue(
                buffer: buffer,
                fileOffset: sectionStart + Int(pointer),
                sectionStart: sectionStart,
                depth: depth + 1
            )
        }

        if type != 14 {
            size = payloadSize(size, buffer: buffer, cursor: &cursor)
        }

        switch type {
        case 2:
            return .string(readString(buffer, cursor: &cursor, count: size))
        case 3:
            return .double(readDouble(buffer, cursor: &cursor))
        case 4:
            return .bytes(readData(buffer, cursor: &cursor, count: size))
        case 5, 6, 9, 10:
            return .uint(readUInt(buffer, cursor: &cursor, count: size))
        case 8:
            return .int(readInt32(buffer, cursor: &cursor, count: size))
        case 7:
            var map: [String: MMDBValue] = [:]
            map.reserveCapacity(size)
            for _ in 0..<size {
                guard let key = decodeField(buffer: buffer, cursor: &cursor, sectionStart: sectionStart, depth: depth + 1)?.string,
                      let value = decodeField(buffer: buffer, cursor: &cursor, sectionStart: sectionStart, depth: depth + 1)
                else { return nil }
                map[key] = value
            }
            return .map(map)
        case 11:
            var items: [MMDBValue] = []
            items.reserveCapacity(size)
            for _ in 0..<size {
                guard let item = decodeField(buffer: buffer, cursor: &cursor, sectionStart: sectionStart, depth: depth + 1)
                else { return nil }
                items.append(item)
            }
            return .array(items)
        case 14:
            return .boolean(size != 0)
        case 15:
            return .float(readFloat(buffer, cursor: &cursor))
        default:
            return nil
        }
    }

    private static func decodePointer(control: UInt8, buffer: UnsafeRawBufferPointer, cursor: inout Int) -> UInt32 {
        let size = Int((control >> 3) & 0b11)
        let low = UInt32(control & 0b111)
        switch size {
        case 0:
            let next = UInt32(buffer[cursor]); cursor += 1
            return (low << 8) | next
        case 1:
            let value = (low << 16) | (UInt32(buffer[cursor]) << 8) | UInt32(buffer[cursor + 1])
            cursor += 2
            return value + 2048
        case 2:
            let value = (low << 24)
                | (UInt32(buffer[cursor]) << 16)
                | (UInt32(buffer[cursor + 1]) << 8)
                | UInt32(buffer[cursor + 2])
            cursor += 3
            return value + 526_336
        default:
            let value = uint32(buffer, cursor)
            cursor += 4
            return value
        }
    }

    private static func payloadSize(_ raw: Int, buffer: UnsafeRawBufferPointer, cursor: inout Int) -> Int {
        switch raw {
        case 29:
            let extra = Int(buffer[cursor]); cursor += 1
            return 29 + extra
        case 30:
            let extra = Int(buffer[cursor]) << 8 | Int(buffer[cursor + 1])
            cursor += 2
            return 285 + extra
        case 31:
            let extra = Int(buffer[cursor]) << 16 | Int(buffer[cursor + 1]) << 8 | Int(buffer[cursor + 2])
            cursor += 3
            return 65_821 + extra
        default:
            return raw
        }
    }

    private static func uint24(_ buffer: UnsafeRawBufferPointer, _ offset: Int) -> UInt32 {
        (UInt32(buffer[offset]) << 16) | (UInt32(buffer[offset + 1]) << 8) | UInt32(buffer[offset + 2])
    }

    private static func uint32(_ buffer: UnsafeRawBufferPointer, _ offset: Int) -> UInt32 {
        (UInt32(buffer[offset]) << 24)
            | (UInt32(buffer[offset + 1]) << 16)
            | (UInt32(buffer[offset + 2]) << 8)
            | UInt32(buffer[offset + 3])
    }

    private static func readString(_ buffer: UnsafeRawBufferPointer, cursor: inout Int, count: Int) -> String {
        let slice = UnsafeRawBufferPointer(rebasing: buffer[cursor..<(cursor + count)])
        cursor += count
        return String(decoding: slice, as: UTF8.self)
    }

    private static func readData(_ buffer: UnsafeRawBufferPointer, cursor: inout Int, count: Int) -> Data {
        let slice = Data(buffer[cursor..<(cursor + count)])
        cursor += count
        return slice
    }

    private static func readUInt(_ buffer: UnsafeRawBufferPointer, cursor: inout Int, count: Int) -> UInt64 {
        var value: UInt64 = 0
        for _ in 0..<count {
            value = (value << 8) | UInt64(buffer[cursor])
            cursor += 1
        }
        return value
    }

    private static func readInt32(_ buffer: UnsafeRawBufferPointer, cursor: inout Int, count: Int) -> Int32 {
        if count == 0 { return 0 }
        if count == 4 {
            let raw = uint32(buffer, cursor)
            cursor += 4
            return Int32(bitPattern: raw)
        }
        return Int32(truncatingIfNeeded: readUInt(buffer, cursor: &cursor, count: count))
    }

    private static func readDouble(_ buffer: UnsafeRawBufferPointer, cursor: inout Int) -> Double {
        var raw: UInt64 = 0
        for _ in 0..<8 {
            raw = (raw << 8) | UInt64(buffer[cursor])
            cursor += 1
        }
        return Double(bitPattern: raw)
    }

    private static func readFloat(_ buffer: UnsafeRawBufferPointer, cursor: inout Int) -> Float {
        let raw = uint32(buffer, cursor)
        cursor += 4
        return Float(bitPattern: raw)
    }
}

private extension MMDBValue {
    var uint: UInt64? {
        if case .uint(let value) = self { return value }
        return nil
    }
}

// MARK: - Test / fixture writer (IPv4, 24-bit records)

/// Builds a tiny IPv4 GeoIP MMDB for tests and fixtures.
enum MMDBWriter {
    static func build(records: [(address: IPv4Address, prefix: UInt8, country: String)]) -> Data {
        let root = TreeNode()
        for record in records {
            insert(root: root, address: record.address, prefix: record.prefix, country: record.country)
        }

        var nodes: [TreeNode] = []
        flatten(root, into: &nodes)
        let nodeCount = UInt32(nodes.count)

        var payloads: [String: Int] = [:]
        var dataSection = Data()
        for record in records {
            if payloads[record.country] == nil {
                payloads[record.country] = dataSection.count
                dataSection.append(encodeCountry(record.country))
            }
        }

        var tree = Data()
        tree.reserveCapacity(nodes.count * 6)
        for node in nodes {
            writeRecord(edge: node.left, nodeCount: nodeCount, payloads: payloads, into: &tree)
            writeRecord(edge: node.right, nodeCount: nodeCount, payloads: payloads, into: &tree)
        }

        var file = Data()
        file.append(tree)
        file.append(Data(repeating: 0, count: 16))
        file.append(dataSection)
        file.append(contentsOf: [0xAB, 0xCD, 0xEF])
        file.append(contentsOf: Array("MaxMind.com".utf8))
        file.append(encodeMetadata(nodeCount: nodeCount))
        return file
    }

    private final class TreeNode {
        var left: Edge = .empty
        var right: Edge = .empty
        var index = 0
    }

    private enum Edge {
        case empty
        case node(TreeNode)
        case data(String)
    }

    private static func insert(root: TreeNode, address: IPv4Address, prefix: UInt8, country: String) {
        var node = root
        let bits = Int(prefix)
        guard bits > 0 else { return }
        for bitIndex in 0..<bits {
            let bit = (address.rawValue >> (31 - bitIndex)) & 1
            if bitIndex == bits - 1 {
                if bit == 0 { node.left = .data(country) } else { node.right = .data(country) }
                return
            }
            if bit == 0 {
                node = descend(&node.left)
            } else {
                node = descend(&node.right)
            }
        }
    }

    private static func descend(_ edge: inout Edge) -> TreeNode {
        switch edge {
        case .node(let child):
            return child
        case .empty:
            let child = TreeNode()
            edge = .node(child)
            return child
        case .data(let country):
            let child = TreeNode()
            child.left = .data(country)
            child.right = .data(country)
            edge = .node(child)
            return child
        }
    }

    private static func flatten(_ node: TreeNode, into nodes: inout [TreeNode]) {
        node.index = nodes.count
        nodes.append(node)
        if case .node(let child) = node.left { flatten(child, into: &nodes) }
        if case .node(let child) = node.right { flatten(child, into: &nodes) }
    }

    private static func writeRecord(
        edge: Edge,
        nodeCount: UInt32,
        payloads: [String: Int],
        into data: inout Data
    ) {
        let value: UInt32
        switch edge {
        case .empty:
            value = nodeCount
        case .node(let child):
            value = UInt32(child.index)
        case .data(let country):
            let offset = UInt32(payloads[country] ?? 0)
            value = nodeCount + 16 + offset
        }
        data.append(UInt8(truncatingIfNeeded: value >> 16))
        data.append(UInt8(truncatingIfNeeded: value >> 8))
        data.append(UInt8(truncatingIfNeeded: value))
    }

    private static func encodeCountry(_ code: String) -> Data {
        var data = Data()
        appendMapCount(1, into: &data)
        appendString("country", into: &data)
        appendMapCount(1, into: &data)
        appendString("iso_code", into: &data)
        appendString(code, into: &data)
        return data
    }

    private static func encodeMetadata(nodeCount: UInt32) -> Data {
        var data = Data()
        appendMapCount(8, into: &data)
        appendString("node_count", into: &data)
        appendUInt(UInt64(nodeCount), type: 6, into: &data)
        appendString("record_size", into: &data)
        appendUInt(24, type: 5, into: &data)
        appendString("ip_version", into: &data)
        appendUInt(4, type: 5, into: &data)
        appendString("database_type", into: &data)
        appendString("PrizmX-Test", into: &data)
        appendString("binary_format_major_version", into: &data)
        appendUInt(2, type: 5, into: &data)
        appendString("binary_format_minor_version", into: &data)
        appendUInt(0, type: 5, into: &data)
        appendString("build_epoch", into: &data)
        appendUInt(0, type: 9, into: &data)
        appendString("description", into: &data)
        appendMapCount(1, into: &data)
        appendString("en", into: &data)
        appendString("PrizmX test GeoIP", into: &data)
        return data
    }

    private static func appendMapCount(_ count: Int, into data: inout Data) {
        appendControl(type: 7, size: count, into: &data)
    }

    private static func appendString(_ string: String, into data: inout Data) {
        let bytes = Array(string.utf8)
        appendControl(type: 2, size: bytes.count, into: &data)
        data.append(contentsOf: bytes)
    }

    private static func appendUInt(_ value: UInt64, type: Int, into data: inout Data) {
        var bytes: [UInt8] = []
        var remaining = value
        if remaining == 0 {
            appendControl(type: type, size: 0, into: &data)
            return
        }
        while remaining > 0 {
            bytes.insert(UInt8(truncatingIfNeeded: remaining), at: 0)
            remaining >>= 8
        }
        appendControl(type: type, size: bytes.count, into: &data)
        data.append(contentsOf: bytes)
    }

    private static func appendControl(type: Int, size: Int, into data: inout Data) {
        if type < 8 {
            if size < 29 {
                data.append(UInt8((type << 5) | size))
            } else if size < 29 + 256 {
                data.append(UInt8((type << 5) | 29))
                data.append(UInt8(size - 29))
            } else {
                data.append(UInt8((type << 5) | 30))
                let extra = size - 285
                data.append(UInt8(extra >> 8))
                data.append(UInt8(truncatingIfNeeded: extra))
            }
            return
        }
        // Extended type: first byte type=0, second byte type-7.
        if size < 29 {
            data.append(UInt8(size))
        } else {
            data.append(29)
            data.append(UInt8(size - 29))
        }
        data.append(UInt8(type - 7))
    }
}
