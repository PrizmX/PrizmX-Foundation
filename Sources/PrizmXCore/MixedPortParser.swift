import Foundation
import PrizmXProtocols

/// Clash mixed-port framing: HTTP CONNECT / absolute-form HTTP, or SOCKS5.
public enum MixedPortParser: Sendable {
    public enum Kind: Sendable, Equatable {
        case socks5
        case http
    }

    public enum HTTPCommand: Sendable, Equatable {
        /// TLS / raw TCP after `HTTP/1.1 200`.
        case connect
        /// Origin-form request already rewritten; send `preface` first.
        case forward
    }

    public struct HTTPRequest: Sendable, Equatable {
        public var host: String
        public var port: UInt16
        public var command: HTTPCommand
        public var preface: Data
    }

    public struct SOCKSRequest: Sendable, Equatable {
        public var host: String
        public var port: UInt16
    }

    public enum ParseError: Error, Equatable {
        case needMore
        case invalid
    }

    public static func kind(firstByte: UInt8) -> Kind {
        firstByte == 0x05 ? .socks5 : .http
    }

    public static let connectEstablished = Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)
    public static let socksNoAuth = Data([0x05, 0x00])
    public static let socksConnectOK = Data([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])

    public static func parseHTTP(_ buffer: Data) throws -> (HTTPRequest, leftover: Data) {
        let separator = Data([0x0D, 0x0A, 0x0D, 0x0A])
        guard let headerEnd = buffer.range(of: separator) else { throw ParseError.needMore }
        let head = buffer.subdata(in: buffer.startIndex..<headerEnd.lowerBound)
        let leftover = buffer.subdata(in: headerEnd.upperBound..<buffer.endIndex)
        guard let text = String(data: head, encoding: .utf8) else { throw ParseError.invalid }
        let lines = text.split(separator: "\r\n", omittingEmptySubsequences: false)
        guard let requestLine = lines.first else { throw ParseError.invalid }
        let parts = requestLine.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count >= 2 else { throw ParseError.invalid }
        let method = parts[0].uppercased()
        let target = String(parts[1])

        if method == "CONNECT" {
            let split = splitHostPort(target, defaultPort: 443)
            return (
                HTTPRequest(host: split.host, port: split.port, command: .connect, preface: Data()),
                leftover
            )
        }

        var hostHeader: String?
        for line in lines.dropFirst() {
            let pair = line.split(separator: ":", maxSplits: 1)
            if pair.count == 2, pair[0].lowercased() == "host" {
                hostHeader = pair[1].trimmingCharacters(in: .whitespaces)
                break
            }
        }

        if target.lowercased().hasPrefix("http://") || target.lowercased().hasPrefix("https://"),
           let url = URL(string: target), let host = url.host {
            let https = target.lowercased().hasPrefix("https://")
            let port = UInt16(url.port ?? (https ? 443 : 80))
            var path = url.path.isEmpty ? "/" : url.path
            if let query = url.query, !query.isEmpty { path += "?\(query)" }
            var rest = Data("\(method) \(path) HTTP/1.1".utf8)
            if head.count > requestLine.utf8.count {
                rest.append(head.dropFirst(requestLine.utf8.count))
            }
            rest.append(separator)
            rest.append(leftover)
            return (
                HTTPRequest(host: host, port: port, command: .forward, preface: rest),
                Data()
            )
        }

        guard let hostHeader, !hostHeader.isEmpty else { throw ParseError.invalid }
        let split = splitHostPort(hostHeader, defaultPort: 80)
        var preface = head
        preface.append(separator)
        preface.append(leftover)
        return (
            HTTPRequest(host: split.host, port: split.port, command: .forward, preface: preface),
            Data()
        )
    }

    /// SOCKS5 greeting: VER, NMETHODS, METHODS. Returns bytes consumed.
    public static func parseSOCKSGreeting(_ buffer: Data) throws -> Int {
        guard buffer.count >= 2 else { throw ParseError.needMore }
        guard buffer[0] == 0x05 else { throw ParseError.invalid }
        let count = Int(buffer[1])
        guard buffer.count >= 2 + count else { throw ParseError.needMore }
        return 2 + count
    }

    public static func parseSOCKSRequest(_ buffer: Data) throws -> (SOCKSRequest, leftover: Data) {
        guard buffer.count >= 7 else { throw ParseError.needMore }
        guard buffer[0] == 0x05, buffer[1] == 0x01 else { throw ParseError.invalid }
        let atyp = buffer[3]
        let host: String
        let portOffset: Int
        switch atyp {
        case 0x01:
            guard buffer.count >= 10 else { throw ParseError.needMore }
            host = "\(buffer[4]).\(buffer[5]).\(buffer[6]).\(buffer[7])"
            portOffset = 8
        case 0x03:
            guard buffer.count >= 5 else { throw ParseError.needMore }
            let length = Int(buffer[4])
            guard buffer.count >= 5 + length + 2 else { throw ParseError.needMore }
            host = String(decoding: buffer[5..<(5 + length)], as: UTF8.self)
            portOffset = 5 + length
        case 0x04:
            guard buffer.count >= 22 else { throw ParseError.needMore }
            var groups: [String] = []
            for index in 0..<8 {
                let value = UInt16(buffer[4 + index * 2]) << 8 | UInt16(buffer[5 + index * 2])
                groups.append(String(value, radix: 16))
            }
            host = groups.joined(separator: ":")
            portOffset = 20
        default:
            throw ParseError.invalid
        }
        let port = UInt16(buffer[portOffset]) << 8 | UInt16(buffer[portOffset + 1])
        let consumed = portOffset + 2
        return (
            SOCKSRequest(host: host, port: port),
            buffer.subdata(in: consumed..<buffer.count)
        )
    }

    public static func endpoint(host: String, port: UInt16) -> Endpoint {
        if let v4 = IPv4Address(parsing: host) {
            return Endpoint(host: .ipv4(v4), port: port)
        }
        if let v6 = IPv6Address(parsing: host) {
            return Endpoint(host: .ipv6(v6), port: port)
        }
        return Endpoint(domain: host, port: port)
    }

    public static func splitHostPort(_ spec: String, defaultPort: UInt16) -> (host: String, port: UInt16) {
        let trimmed = spec.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("["), let close = trimmed.firstIndex(of: "]") {
            let host = String(trimmed[trimmed.index(after: trimmed.startIndex)..<close])
            let rest = trimmed[trimmed.index(after: close)...]
            if rest.hasPrefix(":"), let port = UInt16(rest.dropFirst()) {
                return (host, port)
            }
            return (host, defaultPort)
        }
        if let colon = trimmed.lastIndex(of: ":"),
           trimmed[..<colon].lastIndex(of: ":") == nil,
           let port = UInt16(trimmed[trimmed.index(after: colon)...]) {
            return (String(trimmed[..<colon]), port)
        }
        return (trimmed, defaultPort)
    }
}
