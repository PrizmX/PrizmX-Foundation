import Foundation

// MARK: - VLESS v0 constants

/// VLESS version 0 (Xray / V2Ray) TCP request and response framing.
///
/// Request:
/// `[version 1][uuid 16][addon len 1][addons N][command 1][port 2 BE][atype 1][addr …]`
///
/// Response:
/// `[version 1][addon len 1][addons N]` then a raw byte stream (TCP).
///
/// Address types differ from SOCKS5: domain is `0x02`, IPv6 is `0x03`.
/// Port is written **before** the address (`PortThenAddress`).
public enum VLESS {
    /// Current protocol version byte.
    public static let version: UInt8 = 0x00
    /// Raw UUID size in bytes.
    public static let userIDByteCount = 16
}

// MARK: - Errors

@frozen
public enum VLESSError: Error, Equatable, Sendable {
    /// `uuid` string is not a 16-byte RFC 4122 UUID.
    case invalidUserID(String)
    /// Destination cannot be encoded (empty / overlong domain).
    case invalidAddress(Endpoint)
    /// Addon protobuf payload exceeds the 1-byte length prefix (255).
    case addonTooLarge(Int)
    /// Peer sent a version other than `0x00`.
    case unsupportedVersion(UInt8)
    /// Buffer shorter than the header / addon section requires.
    case truncated(expected: Int, actual: Int)
    /// Address type byte is not IPv4 / domain / IPv6.
    case invalidAddressType(UInt8)
    /// Command byte is not TCP / UDP.
    case invalidCommand(UInt8)
}

// MARK: - Command / address type

@frozen
public enum VLESSCommand: UInt8, Hashable, Sendable, Codable {
    /// TCP stream. Body is an unframed byte stream.
    case tcp = 0x01
    /// UDP datagrams. Body is `[2-byte BE length][payload]` records.
    case udp = 0x02
}

@frozen
public enum VLESSAddressType: UInt8, Hashable, Sendable {
    case ipv4 = 0x01
    case domain = 0x02
    case ipv6 = 0x03
}

// MARK: - UUID (16-byte raw buffer)

public enum VLESSUserID {
    /// Parses a hyphenated UUID, a 32-char hex string, or `{uuid}` form into
    /// the RFC 4122 16-byte layout used on the wire.
    public static func parse(_ string: String) throws -> UUID {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        let unbraced = trimmed.replacingOccurrences(of: "{", with: "")
            .replacingOccurrences(of: "}", with: "")
        if let uuid = UUID(uuidString: unbraced) {
            return uuid
        }

        let hex = unbraced.filter { $0 != "-" }
        guard hex.count == 32 else {
            throw VLESSError.invalidUserID(string)
        }

        var bytes = [UInt8]()
        bytes.reserveCapacity(16)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else {
                throw VLESSError.invalidUserID(string)
            }
            bytes.append(byte)
            index = next
        }
        return uuid(fromRawBytes: bytes)
    }

    /// 16-byte RFC 4122 buffer (time-low … node), matching Xray `ID.Bytes()`.
    public static func rawBytes(_ uuid: UUID) -> [UInt8] {
        let value = uuid.uuid
        return [
            value.0, value.1, value.2, value.3,
            value.4, value.5, value.6, value.7,
            value.8, value.9, value.10, value.11,
            value.12, value.13, value.14, value.15,
        ]
    }

    public static func uuid(fromRawBytes bytes: [UInt8]) -> UUID {
        precondition(bytes.count == VLESS.userIDByteCount)
        return UUID(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }
}

// MARK: - Request header

/// Client request header for VLESS v0.
public struct VLESSHeader: Sendable, Equatable {
    public var version: UInt8
    public var userID: UUID
    /// Protobuf `Addons` payload **without** the length prefix. Empty → a single `0x00` on the wire.
    public var addons: Data
    public var command: VLESSCommand
    public var destination: Endpoint

    public init(
        userID: UUID,
        destination: Endpoint,
        command: VLESSCommand = .tcp,
        addons: Data = Data(),
        version: UInt8 = VLESS.version
    ) {
        self.version = version
        self.userID = userID
        self.addons = addons
        self.command = command
        self.destination = destination
    }

    public init(
        uuid: String,
        destination: Endpoint,
        command: VLESSCommand = .tcp,
        addons: Data = Data()
    ) throws {
        try self.init(
            userID: VLESSUserID.parse(uuid),
            destination: destination,
            command: command,
            addons: addons
        )
    }

    /// Packed size of the request header, including a 1-byte addon length.
    public var encodedByteCount: Int {
        1 + VLESS.userIDByteCount + 1 + addons.count + 1 + Self.addressPortByteCount(of: destination)
    }

    /// Encodes the header into a single contiguous `Data` (one allocation).
    public func encode() throws -> Data {
        guard addons.count <= 255 else {
            throw VLESSError.addonTooLarge(addons.count)
        }
        let count = encodedByteCount
        var data = Data(count: count)
        let written = try data.withUnsafeMutableBytes { try encode(into: $0) }
        if written != count {
            data.removeSubrange(written...)
        }
        return data
    }

    /// Writes the header into `output`. Returns the number of bytes written.
    @discardableResult
    public func encode(into output: UnsafeMutableRawBufferPointer) throws -> Int {
        guard addons.count <= 255 else {
            throw VLESSError.addonTooLarge(addons.count)
        }
        let count = encodedByteCount
        guard output.count >= count else {
            throw VLESSError.truncated(expected: count, actual: output.count)
        }

        var offset = 0
        output[offset] = version
        offset += 1

        let id = VLESSUserID.rawBytes(userID)
        for byte in id {
            output[offset] = byte
            offset += 1
        }

        output[offset] = UInt8(addons.count)
        offset += 1
        if !addons.isEmpty {
            addons.copyBytes(
                to: UnsafeMutableRawBufferPointer(
                    rebasing: output[offset..<(offset + addons.count)]
                )
            )
            offset += addons.count
        }

        output[offset] = command.rawValue
        offset += 1

        offset += try Self.encodeAddressPort(destination, into: UnsafeMutableRawBufferPointer(rebasing: output[offset...]))
        return offset
    }

    /// Parses a complete request header. Extra trailing bytes are ignored.
    public static func decode(_ data: Data) throws -> VLESSHeader {
        try data.withUnsafeBytes { try decode($0) }
    }

    public static func decode(_ buffer: UnsafeRawBufferPointer) throws -> VLESSHeader {
        // version + uuid + addonLen
        let minimum = 1 + VLESS.userIDByteCount + 1
        guard buffer.count >= minimum else {
            throw VLESSError.truncated(expected: minimum, actual: buffer.count)
        }
        var offset = 0
        let version = buffer[offset]
        offset += 1

        let idBytes = Array(buffer[offset..<(offset + VLESS.userIDByteCount)])
        offset += VLESS.userIDByteCount
        let userID = VLESSUserID.uuid(fromRawBytes: idBytes)

        let addonLength = Int(buffer[offset])
        offset += 1
        guard buffer.count >= offset + addonLength + 1 else {
            throw VLESSError.truncated(
                expected: offset + addonLength + 1,
                actual: buffer.count
            )
        }
        let addons: Data
        if addonLength == 0 {
            addons = Data()
        } else {
            addons = Data(buffer[offset..<(offset + addonLength)])
            offset += addonLength
        }

        guard let command = VLESSCommand(rawValue: buffer[offset]) else {
            throw VLESSError.invalidCommand(buffer[offset])
        }
        offset += 1

        let rest = UnsafeRawBufferPointer(rebasing: buffer[offset...])
        let (destination, consumed) = try decodeAddressPort(rest)
        _ = consumed

        return VLESSHeader(
            userID: userID,
            destination: destination,
            command: command,
            addons: addons,
            version: version
        )
    }

    // MARK: PortThenAddress

    public static func addressPortByteCount(of endpoint: Endpoint) -> Int {
        2 + 1 + addressValueByteCount(of: endpoint)
    }

    public static func addressValueByteCount(of endpoint: Endpoint) -> Int {
        switch endpoint.host {
        case .ipv4: return 4
        case .ipv6: return 16
        case .domain(let domain): return 1 + domain.utf8.count
        }
    }

    @discardableResult
    public static func encodeAddressPort(
        _ endpoint: Endpoint,
        into output: UnsafeMutableRawBufferPointer
    ) throws -> Int {
        let count = addressPortByteCount(of: endpoint)
        guard output.count >= count else {
            throw VLESSError.truncated(expected: count, actual: output.count)
        }

        output[0] = UInt8(truncatingIfNeeded: endpoint.port >> 8)
        output[1] = UInt8(truncatingIfNeeded: endpoint.port)

        switch endpoint.host {
        case .ipv4(let address):
            output[2] = VLESSAddressType.ipv4.rawValue
            output[3] = UInt8(truncatingIfNeeded: address.rawValue >> 24)
            output[4] = UInt8(truncatingIfNeeded: address.rawValue >> 16)
            output[5] = UInt8(truncatingIfNeeded: address.rawValue >> 8)
            output[6] = UInt8(truncatingIfNeeded: address.rawValue)
        case .ipv6(let address):
            output[2] = VLESSAddressType.ipv6.rawValue
            output.storeBytes(of: address.high.bigEndian, toByteOffset: 3, as: UInt64.self)
            output.storeBytes(of: address.low.bigEndian, toByteOffset: 11, as: UInt64.self)
        case .domain(let domain):
            let utf8 = Array(domain.utf8)
            guard (1...255).contains(utf8.count) else {
                throw VLESSError.invalidAddress(endpoint)
            }
            output[2] = VLESSAddressType.domain.rawValue
            output[3] = UInt8(utf8.count)
            for (index, byte) in utf8.enumerated() {
                output[4 + index] = byte
            }
        }
        return count
    }

    public static func decodeAddressPort(
        _ buffer: UnsafeRawBufferPointer
    ) throws -> (Endpoint, Int) {
        guard buffer.count >= 3 else {
            throw VLESSError.truncated(expected: 3, actual: buffer.count)
        }
        let port = UInt16(buffer[0]) << 8 | UInt16(buffer[1])
        guard let type = VLESSAddressType(rawValue: buffer[2]) else {
            throw VLESSError.invalidAddressType(buffer[2])
        }

        switch type {
        case .ipv4:
            guard buffer.count >= 7 else {
                throw VLESSError.truncated(expected: 7, actual: buffer.count)
            }
            let address = IPv4Address(buffer[3], buffer[4], buffer[5], buffer[6])
            return (Endpoint(host: .ipv4(address), port: port), 7)
        case .ipv6:
            guard buffer.count >= 19 else {
                throw VLESSError.truncated(expected: 19, actual: buffer.count)
            }
            // Offset 3 is not 8-byte aligned; assemble integers from bytes.
            let high = loadUInt64BE(buffer, offset: 3)
            let low = loadUInt64BE(buffer, offset: 11)
            return (Endpoint(host: .ipv6(IPv6Address(high: high, low: low)), port: port), 19)
        case .domain:
            guard buffer.count >= 4 else {
                throw VLESSError.truncated(expected: 4, actual: buffer.count)
            }
            let length = Int(buffer[3])
            let total = 4 + length
            guard length > 0 else {
                throw VLESSError.invalidAddress(Endpoint(domain: "", port: port))
            }
            guard buffer.count >= total else {
                throw VLESSError.truncated(expected: total, actual: buffer.count)
            }
            let slice = UnsafeRawBufferPointer(rebasing: buffer[4..<total])
            let domain = String(decoding: slice.bindMemory(to: UInt8.self), as: UTF8.self)
            return (Endpoint(domain: domain, port: port), total)
        }
    }
}

@inline(__always)
private func loadUInt64BE(_ buffer: UnsafeRawBufferPointer, offset: Int) -> UInt64 {
    var value: UInt64 = 0
    for index in 0..<8 {
        value = (value << 8) | UInt64(buffer[offset + index])
    }
    return value
}

// MARK: - Response header

/// Server response header: version + length-prefixed addons, then raw payload.
public struct VLESSResponseHeader: Sendable, Equatable {
    public var version: UInt8
    public var addons: Data

    public init(version: UInt8 = VLESS.version, addons: Data = Data()) {
        self.version = version
        self.addons = addons
    }

    public var encodedByteCount: Int { 2 + addons.count }

    public func encode() throws -> Data {
        guard addons.count <= 255 else {
            throw VLESSError.addonTooLarge(addons.count)
        }
        var data = Data(count: encodedByteCount)
        data[0] = version
        data[1] = UInt8(addons.count)
        if !addons.isEmpty {
            data.replaceSubrange(2..<(2 + addons.count), with: addons)
        }
        return data
    }

    /// Consumes a complete response header from the front of `buffer`.
    /// Returns `nil` when more bytes are required.
    public static func consume(
        _ buffer: UnsafeRawBufferPointer
    ) throws -> (VLESSResponseHeader, Int)? {
        guard buffer.count >= 2 else { return nil }
        let version = buffer[0]
        let addonLength = Int(buffer[1])
        let total = 2 + addonLength
        guard buffer.count >= total else { return nil }
        guard version == VLESS.version else {
            throw VLESSError.unsupportedVersion(version)
        }
        let addons: Data
        if addonLength == 0 {
            addons = Data()
        } else {
            addons = Data(buffer[2..<total])
        }
        return (VLESSResponseHeader(version: version, addons: addons), total)
    }
}
