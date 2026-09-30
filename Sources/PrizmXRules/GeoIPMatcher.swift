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
    /// missing / unparsable. Multi-code records return their first code.
    public func lookup(ip: String) -> String? {
        if let address = IPv4Address(parsing: ip) { return lookup(ipv4: address) }
        if let address = IPv6Address(parsing: ip) { return lookup(ipv6: address) }
        return nil
    }

    public func lookup(ipv4 address: IPv4Address) -> String? {
        lookupCodes(ipv4: address).first
    }

    public func lookup(ipv6 address: IPv6Address) -> String? {
        lookupCodes(ipv6: address).first
    }

    /// All codes for the address. MetaCubeX `geoip.metadb` records can be an
    /// array of codes (an IP in several lists); MaxMind records yield one.
    public func lookupCodes(ipv4 address: IPv4Address) -> [String] {
        let start = ipVersion == 4 ? 0 : ipv4StartNode
        return walk(startNode: start, bitCount: 32) { index in
            UInt8(truncatingIfNeeded: (address.rawValue >> (31 - index)) & 1)
        }
    }

    public func lookupCodes(ipv6 address: IPv6Address) -> [String] {
        walk(startNode: 0, bitCount: 128) { index in
            if index < 64 {
                return UInt8(truncatingIfNeeded: (address.high >> (63 - index)) & 1)
            }
            return UInt8(truncatingIfNeeded: (address.low >> (63 - (index - 64))) & 1)
        }
    }

    /// `code` must be uppercase (rules normalize at compile time).
    public func matches(ipv4 address: IPv4Address, code: String) -> Bool {
        lookupCodes(ipv4: address).contains(code)
    }

    public func matches(ipv6 address: IPv6Address, code: String) -> Bool {
        lookupCodes(ipv6: address).contains(code)
    }

    private func walk(startNode: UInt32, bitCount: Int, bitAt: (Int) -> UInt8) -> [String] {
        data.withUnsafeBytes { buffer -> [String] in
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
                if record == nodeCount { return [] }
                let fileOffset = Int(record - nodeCount) + treeByteCount
                var cursor = MMDBCursor(buffer: buffer, offset: fileOffset, sectionStart: treeByteCount + 16)
                return (Self.readCountryCodes(&cursor, depth: 0) ?? []).map { $0.uppercased() }
            }
            return []
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
        let markerEnd = range.upperBound - data.startIndex
        let map = data.withUnsafeBytes { buffer -> [String: MMDBValue]? in
            var cursor = MMDBCursor(buffer: buffer, offset: markerEnd, sectionStart: markerEnd)
            return decodeField(&cursor, depth: 0)?.map
        }
        guard let map, !map.isEmpty else { throw GeoIPError.invalidMetadata }
        return map
    }

    // MARK: Decoding (every read bounds-checked; pointer chains depth-limited)

    /// Nesting + pointer-follow ceiling. Real country records are ~3 deep; a
    /// self-referencing pointer in a corrupt file stops here.
    private static let maxDepth = 32

    /// Country codes without building the full value tree: a string, an
    /// array of strings (MetaCubeX metadb), or a MaxMind country map.
    static func readCountryCodes(_ cursor: inout MMDBCursor, depth: Int) -> [String]? {
        guard depth < maxDepth, let field = cursor.control() else { return nil }
        switch field {
        case .pointer(let target):
            var nested = cursor.at(target)
            return readCountryCodes(&nested, depth: depth + 1)
        case .value(let type, let size):
            switch type {
            case 2:
                return cursor.string(count: size).map { [$0] }
            case 11:
                var codes: [String] = []
                for _ in 0..<size {
                    guard let item = readCountryCodes(&cursor, depth: depth + 1) else { return nil }
                    codes.append(contentsOf: item)
                }
                return codes
            case 7:
                var country: [String]?
                var registered: [String]?
                var iso: [String]?
                for _ in 0..<size {
                    guard let key = readStringField(&cursor, depth: depth + 1) else { return nil }
                    switch key {
                    case "country":
                        country = readCountryCodes(&cursor, depth: depth + 1)
                    case "registered_country":
                        registered = readCountryCodes(&cursor, depth: depth + 1)
                    case "iso_code":
                        iso = readStringField(&cursor, depth: depth + 1).map { [$0] }
                    default:
                        guard skipValue(&cursor, depth: depth + 1) else { return nil }
                    }
                }
                return country ?? registered ?? iso
            default:
                return cursor.skipPayload(type: type, size: size) ? [] : nil
            }
        }
    }

    private static func readStringField(_ cursor: inout MMDBCursor, depth: Int) -> String? {
        guard depth < maxDepth, let field = cursor.control() else { return nil }
        switch field {
        case .pointer(let target):
            var nested = cursor.at(target)
            return readStringField(&nested, depth: depth + 1)
        case .value(let type, let size):
            guard type == 2 else {
                _ = cursor.skipPayload(type: type, size: size)
                return nil
            }
            return cursor.string(count: size)
        }
    }

    /// Skips one value; `false` when the data is truncated or too deep.
    private static func skipValue(_ cursor: inout MMDBCursor, depth: Int) -> Bool {
        guard depth < maxDepth, let field = cursor.control() else { return false }
        switch field {
        case .pointer:
            return true
        case .value(let type, let size):
            switch type {
            case 7:
                for _ in 0..<size {
                    guard skipValue(&cursor, depth: depth + 1), skipValue(&cursor, depth: depth + 1) else {
                        return false
                    }
                }
                return true
            case 11:
                for _ in 0..<size where !skipValue(&cursor, depth: depth + 1) {
                    return false
                }
                return true
            default:
                return cursor.skipPayload(type: type, size: size)
            }
        }
    }

    private static func decodeField(_ cursor: inout MMDBCursor, depth: Int) -> MMDBValue? {
        guard depth < maxDepth, let field = cursor.control() else { return nil }
        let type: Int
        let size: Int
        switch field {
        case .pointer(let target):
            var nested = cursor.at(target)
            return decodeField(&nested, depth: depth + 1)
        case .value(let fieldType, let fieldSize):
            type = fieldType
            size = fieldSize
        }
        switch type {
        case 2:
            return cursor.string(count: size).map(MMDBValue.string)
        case 3:
            return cursor.uint(count: 8).map { .double(Double(bitPattern: $0)) }
        case 4:
            return cursor.bytes(count: size).map { .bytes(Data($0)) }
        case 5, 6, 9, 10:
            guard size <= 16 else { return nil }
            return cursor.uint(count: min(size, 8), skipping: max(0, size - 8)).map(MMDBValue.uint)
        case 8:
            guard size <= 4 else { return nil }
            return cursor.uint(count: size).map { .int(Int32(truncatingIfNeeded: $0)) }
        case 7:
            var map: [String: MMDBValue] = [:]
            for _ in 0..<size {
                guard let key = decodeField(&cursor, depth: depth + 1)?.string,
                      let value = decodeField(&cursor, depth: depth + 1)
                else { return nil }
                map[key] = value
            }
            return .map(map)
        case 11:
            var items: [MMDBValue] = []
            for _ in 0..<size {
                guard let item = decodeField(&cursor, depth: depth + 1) else { return nil }
                items.append(item)
            }
            return .array(items)
        case 14:
            return .boolean(size != 0)
        case 15:
            return cursor.uint(count: 4).map { .float(Float(bitPattern: UInt32(truncatingIfNeeded: $0))) }
        default:
            return nil
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
}

/// Bounds-checked reader over the mapped file. `UnsafeRawBufferPointer`
/// subscripts are unchecked in release builds, so every access goes through
/// `byte()` / `bytes(count:)`.
struct MMDBCursor {
    enum Field {
        /// Absolute file offset the pointer refers to.
        case pointer(Int)
        case value(type: Int, size: Int)
    }

    let buffer: UnsafeRawBufferPointer
    var offset: Int
    let sectionStart: Int

    func at(_ target: Int) -> MMDBCursor {
        MMDBCursor(buffer: buffer, offset: target, sectionStart: sectionStart)
    }

    mutating func byte() -> UInt8? {
        guard offset >= 0, offset < buffer.count else { return nil }
        let value = buffer[offset]
        offset += 1
        return value
    }

    mutating func bytes(count: Int) -> UnsafeRawBufferPointer? {
        guard count >= 0, offset >= 0, offset <= buffer.count, buffer.count - offset >= count else { return nil }
        let slice = UnsafeRawBufferPointer(rebasing: buffer[offset..<(offset + count)])
        offset += count
        return slice
    }

    mutating func skip(_ count: Int) -> Bool {
        bytes(count: count) != nil
    }

    /// Big-endian unsigned integer of `count` (≤ 8) bytes after `skipping` leading bytes.
    mutating func uint(count: Int, skipping: Int = 0) -> UInt64? {
        guard count <= 8, skip(skipping), let raw = bytes(count: count) else { return nil }
        var value: UInt64 = 0
        for byte in raw { value = (value << 8) | UInt64(byte) }
        return value
    }

    mutating func string(count: Int) -> String? {
        bytes(count: count).map { String(decoding: $0, as: UTF8.self) }
    }

    /// Control byte + extended type + size (or pointer target).
    mutating func control() -> Field? {
        guard let control = byte() else { return nil }
        var type = Int(control >> 5)
        if type == 1 {
            let size = Int((control >> 3) & 0b11)
            let low = UInt64(control & 0b111)
            let target: UInt64
            switch size {
            case 0:
                guard let next = uint(count: 1) else { return nil }
                target = (low << 8) | next
            case 1:
                guard let next = uint(count: 2) else { return nil }
                target = ((low << 16) | next) + 2048
            case 2:
                guard let next = uint(count: 3) else { return nil }
                target = ((low << 24) | next) + 526_336
            default:
                guard let next = uint(count: 4) else { return nil }
                target = next
            }
            return .pointer(sectionStart + Int(target))
        }
        var size = Int(control & 0x1F)
        if type == 0 {
            guard let extended = byte() else { return nil }
            type = Int(extended) + 7
        }
        if type != 14 {
            switch size {
            case 29:
                guard let extra = uint(count: 1) else { return nil }
                size = 29 + Int(extra)
            case 30:
                guard let extra = uint(count: 2) else { return nil }
                size = 285 + Int(extra)
            case 31:
                guard let extra = uint(count: 3) else { return nil }
                size = 65_821 + Int(extra)
            default:
                break
            }
        }
        return .value(type: type, size: size)
    }

    /// Skips a scalar payload; containers are handled by the caller.
    mutating func skipPayload(type: Int, size: Int) -> Bool {
        switch type {
        case 2, 4, 5, 6, 8, 9, 10: return skip(size)
        case 3: return skip(8)
        case 14: return true
        case 15: return skip(4)
        case 7, 11: return false
        default: return false
        }
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
