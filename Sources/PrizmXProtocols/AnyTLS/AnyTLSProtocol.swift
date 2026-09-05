import CryptoKit
import Foundation

/// AnyTLS session-layer commands (`anytls-go` protocol versions 1 and 2).
@frozen
public enum AnyTLSCommand: UInt8, Hashable, Sendable {
    case waste = 0
    case syn = 1
    case psh = 2
    case fin = 3
    case settings = 4
    case alert = 5
    case updatePaddingScheme = 6
    case synAck = 7
    case heartRequest = 8
    case heartResponse = 9
    case serverSettings = 10
}

@frozen
public enum AnyTLSError: Error, Equatable, Sendable {
    /// Destination cannot be encoded as a SOCKS5 address.
    case invalidAddress(Endpoint)
    /// Buffer shorter than a frame / auth blob requires.
    case truncated(expected: Int, actual: Int)
    /// Server sent `cmdAlert` with a UTF-8 message.
    case alert(String)
    /// `cmdSYNACK` carried an error payload.
    case streamFailed(String)
}

/// Default padding scheme shipped by anytls-go (packet 0 is a fixed 30-byte pad).
public enum AnyTLSPadding {
    public static let defaultScheme =
        "stop=8\n"
        + "0=30-30\n"
        + "1=100-400\n"
        + "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n"
        + "3=9-9,500-1000\n"
        + "4=500-1000\n"
        + "5=500-1000\n"
        + "6=500-1000\n"
        + "7=500-1000\n"

    /// Packet-0 padding length from the default scheme (`0=30-30`).
    public static let packet0ByteCount = 30

    /// Lowercase MD5 hex of `defaultScheme` (`padding-md5` in `cmdSettings`).
    public static var defaultSchemeMD5Hex: String {
        let digest = Insecure.MD5.hash(data: Data(defaultScheme.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}

/// Authentication blob sent immediately after the TLS 1.3 handshake:
/// `[SHA256(password) 32][padding0 length 2 BE][padding0]`.
public struct AnyTLSAuth: Sendable, Equatable {
    public var passwordSHA256: [UInt8]
    public var padding: [UInt8]

    public init(password: String, paddingByteCount: Int = AnyTLSPadding.packet0ByteCount) {
        let digest = SHA256.hash(data: Data(password.utf8))
        self.passwordSHA256 = Array(digest)
        self.padding = [UInt8](repeating: 0, count: max(0, paddingByteCount))
    }

    public init(passwordSHA256: [UInt8], padding: [UInt8]) {
        self.passwordSHA256 = passwordSHA256
        self.padding = padding
    }

    public var encodedByteCount: Int { 32 + 2 + padding.count }

    public func encode() -> [UInt8] {
        var bytes = [UInt8]()
        bytes.reserveCapacity(encodedByteCount)
        bytes.append(contentsOf: passwordSHA256)
        let length = UInt16(truncatingIfNeeded: padding.count).bigEndian
        withUnsafeBytes(of: length) { bytes.append(contentsOf: $0) }
        bytes.append(contentsOf: padding)
        return bytes
    }
}

/// 7-byte session frame plus payload.
public struct AnyTLSFrame: Sendable, Equatable {
    public static let headerByteCount = 7

    public var command: AnyTLSCommand
    public var streamID: UInt32
    public var payload: Data

    public init(command: AnyTLSCommand, streamID: UInt32 = 0, payload: Data = Data()) {
        self.command = command
        self.streamID = streamID
        self.payload = payload
    }

    public var encodedByteCount: Int { Self.headerByteCount + payload.count }

    public func encode() -> Data {
        var data = Data(count: encodedByteCount)
        data.withUnsafeMutableBytes { raw in
            raw[0] = command.rawValue
            raw[1] = UInt8(truncatingIfNeeded: streamID >> 24)
            raw[2] = UInt8(truncatingIfNeeded: streamID >> 16)
            raw[3] = UInt8(truncatingIfNeeded: streamID >> 8)
            raw[4] = UInt8(truncatingIfNeeded: streamID)
            let length = UInt16(truncatingIfNeeded: payload.count)
            raw[5] = UInt8(truncatingIfNeeded: length >> 8)
            raw[6] = UInt8(truncatingIfNeeded: length)
            if !payload.isEmpty {
                payload.withUnsafeBytes { body in
                    raw.baseAddress!.advanced(by: Self.headerByteCount)
                        .copyMemory(from: body.baseAddress!, byteCount: body.count)
                }
            }
        }
        return data
    }

    /// Returns `nil` when `buffer` does not yet contain a complete frame.
    public static func consume(_ buffer: UnsafeRawBufferPointer) -> (AnyTLSFrame, Int)? {
        guard buffer.count >= headerByteCount else { return nil }
        let length = Int(buffer[5]) << 8 | Int(buffer[6])
        let total = headerByteCount + length
        guard buffer.count >= total else { return nil }
        let command = AnyTLSCommand(rawValue: buffer[0]) ?? .waste
        let streamID = UInt32(buffer[1]) << 24
            | UInt32(buffer[2]) << 16
            | UInt32(buffer[3]) << 8
            | UInt32(buffer[4])
        let payload: Data
        if length == 0 {
            payload = Data()
        } else {
            payload = Data(buffer[headerByteCount..<total])
        }
        return (AnyTLSFrame(command: command, streamID: streamID, payload: payload), total)
    }
}

/// Client `cmdSettings` body (`v=2` UTF-8 key=value lines).
public enum AnyTLSSettings {
    public static let protocolVersion = 2
    public static let clientName = "prizmx/1.0"

    public static func clientBody(paddingMD5Hex: String = AnyTLSPadding.defaultSchemeMD5Hex) -> Data {
        let text = "v=\(protocolVersion)\nclient=\(clientName)\npadding-md5=\(paddingMD5Hex)\n"
        return Data(text.utf8)
    }
}
