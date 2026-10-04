import Foundation

/// Username / password for an upstream HTTP or SOCKS5 proxy.
public struct ProxyCredentials: Sendable, Hashable {
    public var username: String
    public var password: String

    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }
}

/// Upstream HTTP / SOCKS5 proxy handshake failures.
@frozen
public enum ProxyHandshakeError: Error, Equatable, Sendable {
    /// HTTP CONNECT answered with a non-2xx status.
    case httpStatus(Int)
    /// The proxy's reply does not parse (or exceeds the size limit).
    case malformedResponse
    /// SOCKS5: the server accepts none of the offered auth methods.
    case socksNoAcceptableMethod
    /// SOCKS5: username / password rejected.
    case socksAuthenticationFailed
    /// SOCKS5: request rejected with this `REP` code.
    case socksRequestFailed(UInt8)
}

extension ProxyHandshakeError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .httpStatus(let code): "HTTP proxy answered \(code)"
        case .malformedResponse: "malformed proxy response"
        case .socksNoAcceptableMethod: "SOCKS5 server accepts no offered auth method"
        case .socksAuthenticationFailed: "SOCKS5 authentication failed"
        case .socksRequestFailed(let code): "SOCKS5 request failed (REP \(code))"
        }
    }
}

/// Shared body for proxies that turn into a raw byte stream after a one-time
/// handshake (HTTP CONNECT, SOCKS5): dial per `StreamSettings`, run
/// `handshake`, then relay bytes untouched. Handshake leftovers stay in the
/// transport inbox and are read first.
final class HandshakeStream: @unchecked Sendable {
    let transport: NWStreamTransport
    let server: Endpoint
    let settings: StreamSettings
    private let handshake: @Sendable (HandshakeStream) async throws -> Void

    init(
        label: String,
        server: Endpoint,
        target: Endpoint,
        settings: StreamSettings,
        handshake: @escaping @Sendable (HandshakeStream) async throws -> Void
    ) {
        self.server = server
        self.settings = settings
        self.handshake = handshake
        self.transport = NWStreamTransport(queueLabel: label, endpoint: target, errorPeer: server)
    }

    var state: OutboundConnectionState { transport.state }

    func open() async throws {
        try await transport.open { try await self.connect() }
    }

    func write(_ buffer: UnsafeRawBufferPointer) async throws -> Int {
        try await transport.write(buffer, connecting: { try await self.connect() }) { buffer in
            let data = Data(buffer)
            try await self.transport.send(data)
            return data.count
        }
    }

    func read(into buffer: UnsafeMutableRawBufferPointer) async throws -> Int {
        if buffer.isEmpty { return 0 }
        try await transport.ensureOpen { try await self.connect() }
        await transport.readMutex.acquire()
        defer { transport.readMutex.release() }
        try transport.ensureReadable()

        let inbox = transport.inbox
        while inbox.readableByteCount == 0 {
            guard let chunk = try await transport.receiveRaw() else { return 0 }
            inbox.append(chunk)
        }
        let take = min(buffer.count, inbox.readableByteCount)
        buffer.copyMemory(from: UnsafeRawBufferPointer(rebasing: inbox.readableBytes.prefix(take)))
        inbox.consume(take)
        return take
    }

    func close() async {
        await transport.close()
    }

    func closeWrite() async {
        await transport.finishWriting()
    }

    var supportsHalfClose: Bool { true }

    private func connect() async throws {
        try await transport.dial(server, settings: settings)
        do {
            try await handshake(self)
        } catch {
            transport.failOpen()
            throw error
        }
        transport.markEstablished()
    }

    // MARK: Handshake I/O (runs inside `open`, before any relay traffic)

    func sendHandshake(_ bytes: [UInt8]) async throws {
        try await transport.send(Data(bytes))
    }

    /// Exactly `count` reply bytes.
    func receive(exactly count: Int) async throws -> [UInt8] {
        let inbox = transport.inbox
        while inbox.readableByteCount < count {
            guard let chunk = try await transport.receiveRaw() else {
                throw ProxyHandshakeError.malformedResponse
            }
            inbox.append(chunk)
        }
        let bytes = Array(inbox.readableBytes.prefix(count))
        inbox.consume(count)
        return bytes
    }

    /// Reply bytes up to and including `delimiter`, at most `limit` bytes.
    func receive(through delimiter: [UInt8], limit: Int) async throws -> [UInt8] {
        let inbox = transport.inbox
        var searched = 0
        while true {
            let readable = inbox.readableBytes
            if readable.count >= delimiter.count {
                let last = readable.count - delimiter.count
                if searched <= last {
                    for start in searched...last
                    where readable[start..<(start + delimiter.count)].elementsEqual(delimiter) {
                        let end = start + delimiter.count
                        let bytes = Array(readable.prefix(end))
                        inbox.consume(end)
                        return bytes
                    }
                    searched = last + 1
                }
            }
            guard readable.count < limit else { throw ProxyHandshakeError.malformedResponse }
            guard let chunk = try await transport.receiveRaw() else {
                throw ProxyHandshakeError.malformedResponse
            }
            inbox.append(chunk)
        }
    }
}
