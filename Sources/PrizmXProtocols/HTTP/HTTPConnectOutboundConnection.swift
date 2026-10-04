import Foundation

/// Tunnels through an upstream HTTP(S) proxy with `CONNECT`.
///
/// `open()` dials (TLS for an `https` proxy), sends
/// `CONNECT host:port HTTP/1.1` with optional Basic auth and extra headers,
/// and requires a 2xx reply. The rest of the connection is the raw tunnel.
public final class HTTPConnectOutboundConnection: OutboundConnection, @unchecked Sendable {
    public let endpoint: Endpoint
    public let server: Endpoint

    public var state: OutboundConnectionState { stream.state }

    private let stream: HandshakeStream

    /// - Parameters:
    ///   - server: Proxy host and port.
    ///   - target: Destination requested with `CONNECT`.
    ///   - credentials: Optional Basic auth (`Proxy-Authorization`).
    ///   - headers: Extra request headers (Clash `headers`).
    ///   - settings: TCP or TLS (`https` proxy) dialing.
    public init(
        server: Endpoint,
        target: Endpoint,
        credentials: ProxyCredentials? = nil,
        headers: [String: String] = [:],
        settings: StreamSettings = StreamSettings()
    ) {
        self.server = server
        self.endpoint = target
        let request = Self.request(target: target, credentials: credentials, headers: headers)
        self.stream = HandshakeStream(
            label: "prizmx.http.outbound",
            server: server,
            target: target,
            settings: settings
        ) { stream in
            try await stream.sendHandshake(request)
            let reply = try await stream.receive(through: Array("\r\n\r\n".utf8), limit: 16 * 1024)
            try Self.checkReply(reply)
        }
    }

    public func open() async throws { try await stream.open() }

    public func write(_ buffer: UnsafeRawBufferPointer) async throws -> Int {
        try await stream.write(buffer)
    }

    public func read(into buffer: UnsafeMutableRawBufferPointer) async throws -> Int {
        try await stream.read(into: buffer)
    }

    public func close() async { await stream.close() }

    public func closeWrite() async { await stream.closeWrite() }

    public var supportsHalfClose: Bool { stream.supportsHalfClose }

    // MARK: Wire

    /// `CONNECT` request head. IPv6 targets are bracketed.
    static func request(
        target: Endpoint,
        credentials: ProxyCredentials?,
        headers: [String: String]
    ) -> [UInt8] {
        let authority = target.description
        var head = "CONNECT \(authority) HTTP/1.1\r\nHost: \(authority)\r\n"
        if let credentials {
            let token = Data("\(credentials.username):\(credentials.password)".utf8).base64EncodedString()
            head += "Proxy-Authorization: Basic \(token)\r\n"
        }
        for (name, value) in headers.sorted(by: { $0.key < $1.key })
        where name.lowercased() != "host" {
            head += "\(name): \(value)\r\n"
        }
        head += "\r\n"
        return Array(head.utf8)
    }

    /// Accepts `HTTP/1.x 2xx …`; anything else fails the open.
    static func checkReply(_ reply: [UInt8]) throws {
        guard let lineEnd = reply.firstIndex(of: 0x0D) else {
            throw ProxyHandshakeError.malformedResponse
        }
        let statusLine = String(decoding: reply[..<lineEnd], as: UTF8.self)
        let parts = statusLine.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2, parts[0].hasPrefix("HTTP/1."), let code = Int(parts[1]) else {
            throw ProxyHandshakeError.malformedResponse
        }
        guard (200..<300).contains(code) else {
            throw ProxyHandshakeError.httpStatus(code)
        }
    }
}
