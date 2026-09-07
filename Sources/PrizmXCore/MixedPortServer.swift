import Foundation
import Network
import os
import PrizmXProtocols

/// Clash mixed-port listener: HTTP CONNECT / HTTP proxy and SOCKS5 on one TCP port.
public final class MixedPortServer: @unchecked Sendable {
    public static let defaultPort: UInt16 = 7890

    private let engine: Engine
    private let port: UInt16
    private let allowLAN: Bool
    private let listenerBox = OSAllocatedUnfairLock<NWListener?>(initialState: nil)

    public init(engine: Engine, port: UInt16 = defaultPort, allowLAN: Bool = false) {
        self.engine = engine
        self.port = port
        self.allowLAN = allowLAN
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
            connection.start(queue: .global(qos: .userInitiated))
            Task { await self.handle(connection) }
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
        TunnelLog.write(.info, "mixed-port listen \(allowLAN ? "0.0.0.0" : "127.0.0.1"):\(port)")
    }

    public func stop() {
        let listener = listenerBox.withLock { current -> NWListener? in
            let value = current
            current = nil
            return value
        }
        listener?.cancel()
    }

    private func handle(_ connection: NWConnection) async {
        var buffer = Data()
        do {
            while buffer.isEmpty {
                guard let chunk = try await receive(connection) else {
                    connection.cancel()
                    return
                }
                buffer.append(chunk)
            }
            switch MixedPortParser.kind(firstByte: buffer[0]) {
            case .socks5:
                try await handleSOCKS(connection, buffer: &buffer)
            case .http:
                try await handleHTTP(connection, buffer: &buffer)
            }
        } catch {
            connection.cancel()
        }
    }

    private func handleHTTP(_ connection: NWConnection, buffer: inout Data) async throws {
        var parsed: MixedPortParser.HTTPRequest
        var leftover: Data
        while true {
            do {
                (parsed, leftover) = try MixedPortParser.parseHTTP(buffer)
                break
            } catch MixedPortParser.ParseError.needMore {
                guard let chunk = try await receive(connection) else { return }
                buffer.append(chunk)
            }
        }
        if parsed.command == .connect {
            try await send(connection, MixedPortParser.connectEstablished)
        }
        let endpoint = MixedPortParser.endpoint(host: parsed.host, port: parsed.port)
        let stream = NWInboundStream(
            endpoint: endpoint,
            connection: connection,
            leftover: parsed.command == .connect ? leftover : parsed.preface
        )
        await EngineTCPRelay.pipe(stream: stream, engine: engine)
    }

    private func handleSOCKS(_ connection: NWConnection, buffer: inout Data) async throws {
        while true {
            do {
                let consumed = try MixedPortParser.parseSOCKSGreeting(buffer)
                buffer = Data(buffer.dropFirst(consumed))
                break
            } catch MixedPortParser.ParseError.needMore {
                guard let chunk = try await receive(connection) else { return }
                buffer.append(chunk)
            }
        }
        try await send(connection, MixedPortParser.socksNoAuth)
        var request: MixedPortParser.SOCKSRequest
        var leftover: Data
        while true {
            do {
                (request, leftover) = try MixedPortParser.parseSOCKSRequest(buffer)
                break
            } catch MixedPortParser.ParseError.needMore {
                guard let chunk = try await receive(connection) else { return }
                buffer.append(chunk)
            }
        }
        try await send(connection, MixedPortParser.socksConnectOK)
        let stream = NWInboundStream(
            endpoint: MixedPortParser.endpoint(host: request.host, port: request.port),
            connection: connection,
            leftover: leftover
        )
        await EngineTCPRelay.pipe(stream: stream, engine: engine)
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

private final class NWInboundStream: InboundStream, @unchecked Sendable {
    let endpoint: Endpoint
    let clientAddress: String
    let clientPort: UInt16
    private let connection: NWConnection
    private let leftover = OSAllocatedUnfairLock<Data>(initialState: Data())

    init(endpoint: Endpoint, connection: NWConnection, leftover seed: Data) {
        self.endpoint = endpoint
        self.connection = connection
        if case .hostPort(let host, let port) = connection.endpoint {
            self.clientAddress = "\(host)"
            self.clientPort = port.rawValue
        } else {
            self.clientAddress = ""
            self.clientPort = 0
        }
        leftover.withLock { $0 = seed }
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
}
