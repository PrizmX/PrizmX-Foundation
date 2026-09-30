import Foundation
import Network
import os
import PrizmXProtocols

/// Clash mixed-port listener: HTTP CONNECT / HTTP proxy and SOCKS5 on one TCP port.
public final class MixedPortServer: @unchecked Sendable {
    public static let defaultPort: UInt16 = 7890

    public enum Accept: Sendable, Equatable, Hashable {
        case mixed
        case http
        case socks

        var logName: String {
            switch self {
            case .mixed: "mixed-port"
            case .http: "http"
            case .socks: "socks"
            }
        }
    }

    private let engine: Engine
    private let port: UInt16
    private let allowLAN: Bool
    private let accept: Accept
    private let access: MixedPortAccess
    private let listenerBox = OSAllocatedUnfairLock<NWListener?>(initialState: nil)
    /// Whole handshake (greeting, auth, request head) must finish in time.
    static let handshakeTimeout: Duration = .seconds(10)

    /// - Parameters:
    ///   - authentication: Clash `authentication` (`["user:pass", …]`). `nil`
    ///     or empty disables auth.
    ///   - skipAuthPrefixes: Clash `skip-auth-prefixes`; `nil` = loopback.
    ///   - lanAllowedIPs: sources accepted when `allowLAN` is on (mihomo
    ///     `lan-allowed-ips`); `nil` = loopback + private / link-local ranges.
    public init(
        engine: Engine,
        port: UInt16 = defaultPort,
        allowLAN: Bool = false,
        accept: Accept = .mixed,
        authentication: [String]? = nil,
        skipAuthPrefixes: [String]? = nil,
        lanAllowedIPs: [String]? = nil
    ) {
        self.engine = engine
        self.port = port
        self.allowLAN = allowLAN
        self.accept = accept
        self.access = MixedPortAccess(
            authentication: authentication,
            skipAuthPrefixes: skipAuthPrefixes,
            lanAllowedIPs: lanAllowedIPs
        )
    }

    public func start() async throws {
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        parameters.preferNoProxies = true
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw OutboundError.invalidEndpoint(Endpoint(host: .ipv4(.loopback), port: port))
        }
        let listener: NWListener
        if allowLAN {
            listener = try NWListener(using: parameters, on: nwPort)
        } else {
            parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: nwPort)
            listener = try NWListener(using: parameters)
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else {
                connection.cancel()
                return
            }
            let client = Self.clientAddress(of: connection)
            if self.allowLAN, !self.access.acceptsSource(client) {
                TunnelLog.writeOnce("mixed-lan-refused-\(client)", .warn, "\(self.accept.logName) refused LAN client \(client)")
                connection.cancel()
                return
            }
            connection.start(queue: .global(qos: .userInitiated))
            Task { await self.handle(connection, client: client, listenPort: self.port) }
        }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            let settled = OSAllocatedUnfairLock(initialState: false)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    settled.withLock { done in
                        guard !done else { return }
                        done = true
                        cont.resume()
                    }
                case .failed(let error):
                    settled.withLock { done in
                        guard !done else { return }
                        done = true
                        cont.resume(throwing: error)
                    }
                default:
                    break
                }
            }
            listener.start(queue: .global(qos: .utility))
        }
        listenerBox.withLock { $0 = listener }
        let bind = allowLAN ? "0.0.0.0" : "127.0.0.1"
        TunnelLog.write(.info, "\(accept.logName) listen \(bind):\(port)")
    }

    public func stop() {
        let listener = listenerBox.withLock { current -> NWListener? in
            let value = current
            current = nil
            return value
        }
        listener?.cancel()
    }

    static func clientAddress(of connection: NWConnection) -> String {
        if case .hostPort(let host, _) = connection.endpoint {
            return NWInboundStream.hostString(host)
        }
        return ""
    }

    private func handle(_ connection: NWConnection, client: String, listenPort: UInt16) async {
        // Handshake phase is bounded; cancelling the connection fails any
        // pending receive, which unwinds the handshake.
        let timer = Task {
            try await Task.sleep(for: Self.handshakeTimeout)
            connection.cancel()
        }
        let stream: (any InboundStream)?
        do {
            stream = try await handshake(connection, client: client, listenPort: listenPort)
        } catch {
            stream = nil
        }
        timer.cancel()
        guard let stream else {
            connection.cancel()
            return
        }
        await EngineTCPRelay.pipe(stream: stream, engine: engine)
    }

    private func handshake(
        _ connection: NWConnection,
        client: String,
        listenPort: UInt16
    ) async throws -> (any InboundStream)? {
        var buffer = Data()
        while buffer.isEmpty {
            guard let chunk = try await receive(connection) else { return nil }
            buffer.append(chunk)
        }
        switch MixedPortParser.kind(firstByte: buffer[buffer.startIndex]) {
        case .socks5:
            guard accept != .http else { return nil }
            return try await handshakeSOCKS(connection, client: client, listenPort: listenPort, buffer: &buffer)
        case .http:
            guard accept != .socks else { return nil }
            return try await handshakeHTTP(connection, client: client, listenPort: listenPort, buffer: &buffer)
        }
    }

    /// Remote clients may not target this host's loopback services.
    private func refusesTarget(_ host: String, client: String) -> Bool {
        guard !MixedPortAccess.isLoopbackSource(client), MixedPortAccess.isLoopbackTarget(host: host) else {
            return false
        }
        TunnelLog.writeOnce("mixed-loopback-\(client)", .warn, "\(accept.logName) refused \(client) → loopback \(host)")
        return true
    }

    private func handshakeHTTP(
        _ connection: NWConnection,
        client: String,
        listenPort: UInt16,
        buffer: inout Data
    ) async throws -> (any InboundStream)? {
        var scanned = 0
        while true {
            if let end = MixedPortParser.headerEnd(in: buffer, from: scanned - 3) {
                guard end.lowerBound - buffer.startIndex <= MixedPortParser.maxHeaderBytes else {
                    try? await send(connection, MixedPortParser.headerTooLarge)
                    return nil
                }
                break
            }
            guard buffer.count <= MixedPortParser.maxHeaderBytes else {
                try? await send(connection, MixedPortParser.headerTooLarge)
                return nil
            }
            scanned = buffer.count
            guard let chunk = try await receive(connection) else { return nil }
            buffer.append(chunk)
        }
        let (parsed, leftover) = try MixedPortParser.parseHTTP(buffer)
        if access.needsAuthentication(from: client),
           !access.accepts(credentials: MixedPortParser.basicCredentials(parsed.proxyAuthorization)) {
            try? await send(connection, MixedPortParser.proxyAuthRequired)
            return nil
        }
        if refusesTarget(parsed.host, client: client) {
            try? await send(connection, MixedPortParser.forbidden)
            return nil
        }
        let endpoint = MixedPortParser.endpoint(host: parsed.host, port: parsed.port)
        let inner = NWInboundStream(
            endpoint: endpoint,
            connection: connection,
            listenPort: listenPort,
            leftover: leftover
        )
        if parsed.command == .connect {
            try await send(connection, MixedPortParser.connectEstablished)
            return inner
        }
        return HTTPForwardInbound(inner: inner, head: parsed.preface, body: parsed.body)
    }

    private func handshakeSOCKS(
        _ connection: NWConnection,
        client: String,
        listenPort: UInt16,
        buffer: inout Data
    ) async throws -> (any InboundStream)? {
        let consumed = try await receiveUntilParsed(connection, &buffer) {
            try MixedPortParser.parseSOCKSGreeting($0)
        }
        guard let consumed else { return nil }
        let methods = MixedPortParser.socksMethods(buffer)
        buffer = Data(buffer.dropFirst(consumed))
        if access.needsAuthentication(from: client) {
            guard methods.contains(0x02) else {
                try? await send(connection, MixedPortParser.socksNoAcceptableMethod)
                return nil
            }
            try await send(connection, MixedPortParser.socksUserPass)
            let auth = try await receiveUntilParsed(connection, &buffer) {
                try MixedPortParser.parseSOCKSUserPass($0)
            }
            guard let auth else { return nil }
            buffer = Data(buffer.dropFirst(auth.consumed))
            guard access.accepts(credentials: auth.credentials) else {
                try? await send(connection, MixedPortParser.socksAuthFailed)
                return nil
            }
            try await send(connection, MixedPortParser.socksAuthOK)
        } else {
            try await send(connection, MixedPortParser.socksNoAuth)
        }
        let parsed = try await receiveUntilParsed(connection, &buffer) {
            try MixedPortParser.parseSOCKSRequest($0)
        }
        guard let (request, leftover) = parsed else { return nil }
        if refusesTarget(request.host, client: client) {
            // REP 0x02: connection not allowed by ruleset.
            try? await send(connection, Data([0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
            return nil
        }
        try await send(connection, MixedPortParser.socksConnectOK)
        return NWInboundStream(
            endpoint: MixedPortParser.endpoint(host: request.host, port: request.port),
            connection: connection,
            listenPort: listenPort,
            leftover: leftover
        )
    }

    /// Re-parses as bytes arrive (SOCKS messages are tiny); `nil` on EOF or
    /// when the handshake exceeds `maxSOCKSHandshakeBytes`.
    private func receiveUntilParsed<T>(
        _ connection: NWConnection,
        _ buffer: inout Data,
        parse: (Data) throws -> T
    ) async throws -> T? {
        while true {
            do {
                return try parse(buffer)
            } catch MixedPortParser.ParseError.needMore {
                guard buffer.count <= MixedPortParser.maxSOCKSHandshakeBytes,
                      let chunk = try await receive(connection) else { return nil }
                buffer.append(chunk)
            }
        }
    }

    private func receive(_ connection: NWConnection) async throws -> Data? {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let data, !data.isEmpty {
                    continuation.resume(returning: data)
                } else if isComplete {
                    continuation.resume(returning: nil)
                } else {
                    continuation.resume(returning: Data())
                }
            }
        }
    }

    private func send(_ connection: NWConnection, _ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            })
        }
    }
}

final class NWInboundStream: InboundStream, @unchecked Sendable {
    let endpoint: Endpoint
    let clientAddress: String
    let clientPort: UInt16
    let listenPort: UInt16?
    private let connection: NWConnection
    private let leftover = OSAllocatedUnfairLock<Data>(initialState: Data())

    init(endpoint: Endpoint, connection: NWConnection, listenPort: UInt16, leftover seed: Data) {
        self.endpoint = endpoint
        self.connection = connection
        self.listenPort = listenPort
        let remote = connection.currentPath?.remoteEndpoint ?? connection.endpoint
        if case .hostPort(let host, let port) = remote {
            self.clientAddress = Self.hostString(host)
            self.clientPort = port.rawValue
        } else {
            self.clientAddress = ""
            self.clientPort = 0
        }
        leftover.withLock { $0 = seed }
    }

    static func hostString(_ host: NWEndpoint.Host) -> String {
        switch host {
        case .ipv4(let address): return "\(address)"
        case .ipv6(let address): return "\(address)"
        case .name(let name, _): return name
        @unknown default: return "\(host)"
        }
    }

    func read() async throws -> Data? {
        let pending = leftover.withLock { buffer -> Data? in
            guard !buffer.isEmpty else { return nil }
            let data = buffer
            buffer = Data()
            return data
        }
        if let pending { return pending }
        return try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let data, !data.isEmpty {
                    continuation.resume(returning: data)
                } else if isComplete {
                    continuation.resume(returning: nil)
                } else {
                    continuation.resume(returning: Data())
                }
            }
        }
    }

    func write(_ data: Data) async throws {
        guard !data.isEmpty else { return }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            })
        }
    }

    func close() async {
        connection.cancel()
    }

    var supportsHalfClose: Bool { true }

    /// FIN toward the client; receives keep working.
    func closeWrite() async {
        connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in })
    }
}

/// Plain-HTTP proxy request (non-CONNECT): forwards exactly one request —
/// the rewritten head, then its body per `Content-Length` / chunked framing.
/// Later client bytes (a pipelined or keep-alive request, possibly for a
/// different origin) are read and dropped, never sent to this origin; the
/// relay closes the client once the origin finishes (`Connection: close`).
final class HTTPForwardInbound: InboundStream, @unchecked Sendable {
    let endpoint: Endpoint
    var clientAddress: String { inner.clientAddress }
    var clientPort: UInt16 { inner.clientPort }
    var listenPort: UInt16? { inner.listenPort }
    /// Close (not half-close) the client after the origin's EOF.
    var supportsHalfClose: Bool { false }
    private let inner: any InboundStream
    private struct State {
        var head: Data?
        var framer: HTTPBodyFramer
    }
    private let state: OSAllocatedUnfairLock<State>

    init(inner: any InboundStream, head: Data, body: HTTPBodyFraming) {
        self.endpoint = inner.endpoint
        self.inner = inner
        self.state = OSAllocatedUnfairLock(initialState: State(head: head, framer: HTTPBodyFramer(body)))
    }

    func read() async throws -> Data? {
        if let head = state.withLock({ current -> Data? in
            defer { current.head = nil }
            return current.head
        }) {
            return head
        }
        while true {
            if state.withLock({ $0.framer.isComplete }) {
                // Request done: swallow anything else until the client leaves.
                while let extra = try await inner.read() {
                    _ = extra
                }
                return nil
            }
            guard let chunk = try await inner.read() else { return nil }
            if chunk.isEmpty { return chunk }
            let count = try state.withLock { try $0.framer.consume(chunk) }
            if count > 0 { return chunk.prefix(count) }
        }
    }

    func write(_ data: Data) async throws { try await inner.write(data) }
    func close() async { await inner.close() }
}
