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
        /// `.forward`: the rewritten request head (origin-form, hop-by-hop
        /// proxy headers dropped, `Connection: close`), without the body.
        public var preface: Data
        /// `.forward`: how far the first request's body extends.
        public var body: HTTPBodyFraming = .none
        /// Raw `Proxy-Authorization` value, if any (never forwarded).
        public var proxyAuthorization: String?
    }

    /// Longest request head / SOCKS handshake accepted before giving up.
    public static let maxHeaderBytes = 16 * 1024
    public static let maxSOCKSHandshakeBytes = 1024

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
    public static let socksUserPass = Data([0x05, 0x02])
    public static let socksNoAcceptableMethod = Data([0x05, 0xFF])
    public static let socksAuthOK = Data([0x01, 0x00])
    public static let socksAuthFailed = Data([0x01, 0x01])
    public static let proxyAuthRequired = Data(
        ("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"PrizmX\"\r\n"
            + "Content-Length: 0\r\nConnection: close\r\n\r\n").utf8
    )
    public static let headerTooLarge = Data(
        "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8
    )
    public static let forbidden = Data(
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8
    )
    static let headerSeparator = Data([0x0D, 0x0A, 0x0D, 0x0A])

    /// End of the request head, searching only from `from` (callers pass the
    /// previously scanned length minus 3, so each byte is scanned ~once).
    public static func headerEnd(in buffer: Data, from: Int) -> Range<Data.Index>? {
        let start = buffer.startIndex + max(0, min(from, buffer.count))
        return buffer.range(of: headerSeparator, in: start..<buffer.endIndex)
    }
    public static let socksConnectOK = Data([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])

    public static func parseHTTP(_ buffer: Data) throws -> (HTTPRequest, leftover: Data) {
        guard let headerEnd = buffer.range(of: headerSeparator) else { throw ParseError.needMore }
        let head = buffer.subdata(in: buffer.startIndex..<headerEnd.lowerBound)
        let leftover = buffer.subdata(in: headerEnd.upperBound..<buffer.endIndex)
        guard let text = String(data: head, encoding: .utf8) else { throw ParseError.invalid }
        let lines = text.split(separator: "\r\n", omittingEmptySubsequences: false)
        guard let requestLine = lines.first else { throw ParseError.invalid }
        let parts = requestLine.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count >= 2 else { throw ParseError.invalid }
        let method = parts[0].uppercased()
        let target = String(parts[1])
        let version = parts.count >= 3 ? String(parts[2]) : "HTTP/1.1"

        var hostHeader: String?
        var authorization: String?
        var contentLength: Int?
        var chunked = false
        var upgrade = false
        var connectionLines: [Substring] = []
        var kept: [Substring] = []
        for line in lines.dropFirst() where !line.isEmpty {
            let pair = line.split(separator: ":", maxSplits: 1)
            guard pair.count == 2 else { continue }
            let name = pair[0].trimmingCharacters(in: .whitespaces).lowercased()
            let value = pair[1].trimmingCharacters(in: .whitespaces)
            switch name {
            case "host":
                if hostHeader == nil { hostHeader = value }
            case "proxy-authorization":
                authorization = value
                continue
            case "connection":
                connectionLines.append(line)
                continue
            case "proxy-connection", "keep-alive":
                continue
            case "upgrade":
                upgrade = true
            case "content-length":
                guard let length = Int(value), length >= 0 else { throw ParseError.invalid }
                if let contentLength, contentLength != length { throw ParseError.invalid }
                contentLength = length
            case "transfer-encoding":
                chunked = value.lowercased().split(separator: ",").last?
                    .trimmingCharacters(in: .whitespaces) == "chunked"
            default:
                break
            }
            kept.append(line)
        }

        if method == "CONNECT" {
            let split = splitHostPort(target, defaultPort: 443)
            var request = HTTPRequest(host: split.host, port: split.port, command: .connect, preface: Data())
            request.proxyAuthorization = authorization
            return (request, leftover)
        }

        let host: String
        let port: UInt16
        let path: String
        let lowered = target.lowercased()
        if lowered.hasPrefix("http://") || lowered.hasPrefix("https://") {
            // `percentEncoded*` keep the client's escaping (`URL.path` decodes).
            guard let components = URLComponents(string: target), var parsedHost = components.host,
                  !parsedHost.isEmpty else { throw ParseError.invalid }
            if parsedHost.hasPrefix("["), parsedHost.hasSuffix("]") {
                parsedHost = String(parsedHost.dropFirst().dropLast())
            }
            let https = lowered.hasPrefix("https://")
            guard let resolvedPort = UInt16(exactly: components.port ?? (https ? 443 : 80)) else {
                throw ParseError.invalid
            }
            host = parsedHost
            port = resolvedPort
            var origin = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
            if let query = components.percentEncodedQuery { origin += "?\(query)" }
            path = origin
        } else {
            guard let hostHeader, !hostHeader.isEmpty else { throw ParseError.invalid }
            let split = splitHostPort(hostHeader, defaultPort: 80)
            host = split.host
            port = split.port
            path = target
        }

        var rewritten = "\(method) \(path) \(version)\r\n"
        for line in kept {
            rewritten += line + "\r\n"
        }
        let body: HTTPBodyFraming
        if upgrade {
            // WebSocket-style upgrade: the connection becomes one tunnel to
            // this origin, so keep `Connection: upgrade` and pipe the rest.
            for line in connectionLines { rewritten += line + "\r\n" }
            rewritten += "\r\n"
            body = .passthrough
        } else if chunked {
            body = .chunked
        } else if let contentLength, contentLength > 0 {
            body = .length(contentLength)
        } else {
            body = .none
        }
        if !upgrade {
            // One request per upstream connection: later requests on this
            // client connection may name another origin, so they are never
            // piped here.
            rewritten += "Connection: close\r\n\r\n"
        }
        var request = HTTPRequest(host: host, port: port, command: .forward, preface: Data(rewritten.utf8))
        request.body = body
        request.proxyAuthorization = authorization
        return (request, leftover)
    }

    /// Checks a `Proxy-Authorization: Basic …` value against `user:pass` pairs.
    public static func basicCredentials(_ header: String?) -> String? {
        guard let header else { return nil }
        let parts = header.split(separator: " ", maxSplits: 1)
        guard parts.count == 2, parts[0].lowercased() == "basic",
              let decoded = Data(base64Encoded: String(parts[1]).trimmingCharacters(in: .whitespaces)),
              let text = String(data: decoded, encoding: .utf8)
        else { return nil }
        return text
    }

    /// SOCKS5 username/password sub-negotiation (RFC 1929). Returns
    /// `user:pass` and bytes consumed.
    public static func parseSOCKSUserPass(_ buffer: Data) throws -> (credentials: String, consumed: Int) {
        let bytes = [UInt8](buffer)
        guard bytes.count >= 2 else { throw ParseError.needMore }
        guard bytes[0] == 0x01 else { throw ParseError.invalid }
        let userLength = Int(bytes[1])
        guard bytes.count >= 2 + userLength + 1 else { throw ParseError.needMore }
        let passLength = Int(bytes[2 + userLength])
        let total = 3 + userLength + passLength
        guard bytes.count >= total else { throw ParseError.needMore }
        let user = String(decoding: bytes[2..<(2 + userLength)], as: UTF8.self)
        let pass = String(decoding: bytes[(3 + userLength)..<total], as: UTF8.self)
        return ("\(user):\(pass)", total)
    }

    /// SOCKS5 greeting methods (after VER, NMETHODS).
    public static func socksMethods(_ buffer: Data) -> [UInt8] {
        let bytes = [UInt8](buffer)
        guard bytes.count >= 2 else { return [] }
        return Array(bytes.dropFirst(2).prefix(Int(bytes[1])))
    }

    /// SOCKS5 greeting: VER, NMETHODS, METHODS. Returns bytes consumed.
    public static func parseSOCKSGreeting(_ input: Data) throws -> Int {
        let buffer = Data(input)
        guard buffer.count >= 2 else { throw ParseError.needMore }
        guard buffer[0] == 0x05 else { throw ParseError.invalid }
        let count = Int(buffer[1])
        guard buffer.count >= 2 + count else { throw ParseError.needMore }
        return 2 + count
    }

    public static func parseSOCKSRequest(_ input: Data) throws -> (SOCKSRequest, leftover: Data) {
        let buffer = Data(input)
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

/// Extent of an HTTP/1.1 request body (RFC 9112 §6.3).
public enum HTTPBodyFraming: Sendable, Equatable {
    case none
    case length(Int)
    case chunked
    /// Upgrade request: every later client byte belongs to this origin.
    case passthrough
}

/// Incremental body framer: splits client bytes into "still this request"
/// and "beyond it" without buffering the body.
public struct HTTPBodyFramer: Sendable {
    private enum State: Sendable {
        case length(Int)
        case chunkSize(line: [UInt8])
        case chunkData(Int)
        case chunkDataEnd(Int)
        case trailer(line: Int)
        case passthrough
        case done
    }

    private var state: State

    public init(_ framing: HTTPBodyFraming) {
        switch framing {
        case .none: state = .done
        case .length(let count): state = count > 0 ? .length(count) : .done
        case .chunked: state = .chunkSize(line: [])
        case .passthrough: state = .passthrough
        }
    }

    public var isComplete: Bool {
        if case .done = state { return true }
        return false
    }

    /// Returns how many leading bytes of `data` belong to the body.
    /// Throws on a malformed chunked encoding.
    public mutating func consume(_ data: Data) throws -> Int {
        var index = data.startIndex
        while index < data.endIndex {
            switch state {
            case .done:
                return index - data.startIndex
            case .passthrough:
                return data.count
            case .length(let remaining):
                let take = min(remaining, data.endIndex - index)
                index += take
                state = remaining - take == 0 ? .done : .length(remaining - take)
            case .chunkSize(var line):
                let byte = data[index]
                index += 1
                if byte == 0x0A {
                    if line.last == 0x0D { line.removeLast() }
                    let text = String(decoding: line, as: UTF8.self)
                    let hex = text.split(separator: ";", maxSplits: 1).first.map {
                        $0.trimmingCharacters(in: .whitespaces)
                    } ?? ""
                    guard !hex.isEmpty, hex.count <= 16, let size = Int(hex, radix: 16), size >= 0 else {
                        throw MixedPortParser.ParseError.invalid
                    }
                    state = size == 0 ? .trailer(line: 0) : .chunkData(size)
                } else {
                    guard line.count < 1024 else { throw MixedPortParser.ParseError.invalid }
                    line.append(byte)
                    state = .chunkSize(line: line)
                }
            case .chunkData(let remaining):
                let take = min(remaining, data.endIndex - index)
                index += take
                state = remaining - take == 0 ? .chunkDataEnd(2) : .chunkData(remaining - take)
            case .chunkDataEnd(let remaining):
                index += 1
                state = remaining == 1 ? .chunkSize(line: []) : .chunkDataEnd(remaining - 1)
            case .trailer(let length):
                let byte = data[index]
                index += 1
                if byte == 0x0A {
                    // An empty line (just CRLF) ends the trailer section.
                    state = length == 0 ? .done : .trailer(line: 0)
                } else if byte != 0x0D {
                    guard length < 8 * 1024 else { throw MixedPortParser.ParseError.invalid }
                    state = .trailer(line: length + 1)
                }
            }
        }
        return index - data.startIndex
    }
}
