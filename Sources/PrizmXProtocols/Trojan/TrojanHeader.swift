import Foundation

/// Trojan command byte (SOCKS5 CONNECT / UDP ASSOCIATE).
@frozen
public enum TrojanCommand: UInt8, Hashable, Sendable, Codable {
    /// TCP CONNECT (`0x01`). Subsequent payload is a raw byte stream.
    case connect = 0x01
    /// UDP ASSOCIATE (`0x03`). Subsequent payload is Trojan UDP packets.
    case udpAssociate = 0x03
}

@frozen
public enum TrojanError: Error, Equatable, Sendable {
    /// Destination cannot be encoded as a SOCKS5 address.
    case invalidAddress(Endpoint)
    /// Buffer shorter than the header requires.
    case truncated(expected: Int, actual: Int)
    /// Command byte is not CONNECT / UDP ASSOCIATE.
    case invalidCommand(UInt8)
}

/// Trojan request header (after the TLS handshake, before payload).
///
/// Wire layout:
/// `[hex(SHA224(password)) 56][\r\n][CMD 1][SOCKS5 ATYP/ADDR/PORT][\r\n]`
public struct TrojanHeader: Sendable, Equatable {
    public static let crlf: [UInt8] = [0x0D, 0x0A]
    public static let hashHexByteCount = SHA224.hexDigestByteCount

    public var passwordHashHex: [UInt8]
    public var command: TrojanCommand
    public var destination: Endpoint

    public init(password: String, destination: Endpoint, command: TrojanCommand = .connect) {
        self.passwordHashHex = SHA224.hexDigest(Array(password.utf8))
        self.command = command
        self.destination = destination
    }

    public init(passwordHashHex: [UInt8], destination: Endpoint, command: TrojanCommand = .connect) {
        self.passwordHashHex = passwordHashHex
        self.command = command
        self.destination = destination
    }

    public var encodedByteCount: Int {
        let addressCount = (try? ShadowsocksAddress.encodedByteCount(of: destination)) ?? 0
        return Self.hashHexByteCount + 2 + 1 + addressCount + 2
    }

    public func encode() throws -> [UInt8] {
        guard passwordHashHex.count == Self.hashHexByteCount else {
            throw TrojanError.truncated(
                expected: Self.hashHexByteCount,
                actual: passwordHashHex.count
            )
        }
        let address = try ShadowsocksAddress.encode(destination)
        var bytes = [UInt8]()
        bytes.reserveCapacity(Self.hashHexByteCount + 2 + 1 + address.count + 2)
        bytes.append(contentsOf: passwordHashHex)
        bytes.append(contentsOf: Self.crlf)
        bytes.append(command.rawValue)
        bytes.append(contentsOf: address)
        bytes.append(contentsOf: Self.crlf)
        return bytes
    }

    public func encodedData() throws -> Data {
        Data(try encode())
    }
}
