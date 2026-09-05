import Foundation
import Network
import os
import Security

// MARK: - Factory

/// Dials an AnyTLS server (TLS 1.3 + password SHA-256 auth + session frames).
public struct AnyTLSOutboundFactory: OutboundConnectionFactory, Sendable {
    public let server: Endpoint
    public let password: String
    public let sni: String

    public init(server: Endpoint, password: String, sni: String) {
        self.server = server
        self.password = password
        self.sni = sni
    }

    public func connect(to endpoint: Endpoint) async throws -> any OutboundConnection {
        AnyTLSOutboundConnection(
            server: server,
            password: password,
            target: endpoint,
            sni: sni
        )
    }
}

// MARK: - Outbound connection (stream adapter)

/// One AnyTLS stream, presented as an `OutboundConnection`.
///
/// The TLS session is shared per server identity via `AnyTLSSessionPool`:
/// `open()` acquires/creates the session and opens a stream (SYN + target
/// PSH + SYNACK wait); `close()` FINs only this stream. Session
/// establishment dials with failover across all resolved A records.
public final class AnyTLSOutboundConnection: OutboundConnection, @unchecked Sendable {

    public let endpoint: Endpoint
    public let identity: AnyTLSServerIdentity

    public var server: Endpoint { identity.server }
    public var sni: String { identity.sni }
    public var skipCertVerify: Bool { identity.skipCertVerify }
    public var passwordSHA256: [UInt8] { auth.passwordSHA256 }
    public var tlsMinimumProtocol: tls_protocol_version_t { .TLSv13 }
    public var tlsMaximumProtocol: tls_protocol_version_t { .TLSv13 }

    public var state: OutboundConnectionState {
        lifecycle.withLock { $0.state }
    }

    /// Exposed so tests can inspect the exact `NWParameters.tls` configuration.
    public func makeTLSParameters() -> NWParameters {
        TLSClient.parameters(
            serverName: sni,
            minimum: tlsMinimumProtocol,
            maximum: tlsMaximumProtocol,
            skipVerification: skipCertVerify
        )
    }

    private let auth: AnyTLSAuth
    private let lifecycle = OSAllocatedUnfairLock(initialState: Lifecycle())
    private var stream: AnyTLSSessionStream?
    private var leftover = Data()

    private struct Lifecycle {
        var state: OutboundConnectionState = .idle
        var openTask: Task<Void, Error>?
    }

    /// - Parameters:
    ///   - server: AnyTLS server host and port.
    ///   - password: Shared secret; sent as SHA-256 after TLS.
    ///   - target: SOCKS5 destination carried on the first stream.
    ///   - sni: TLS 1.3 server name (required).
    ///   - skipCertVerify: Clash `skip-cert-verify`; accepts self-signed certs.
    ///   - sessionConfig: Clash `idle-session-*` reuse knobs.
    public init(
        server: Endpoint,
        password: String,
        target: Endpoint,
        sni: String,
        skipCertVerify: Bool = false,
        sessionConfig: AnyTLSSessionConfig = AnyTLSSessionConfig()
    ) {
        self.endpoint = target
        self.identity = AnyTLSServerIdentity(
            server: server,
            password: password,
            sni: sni,
            skipCertVerify: skipCertVerify,
            sessionConfig: sessionConfig
        )
        self.auth = AnyTLSAuth(password: password)
    }

    public convenience init(
        host: String,
        port: UInt16,
        password: String,
        target: Endpoint,
        sni: String
    ) {
        let server = Endpoint(hostname: host, port: port)
            ?? Endpoint(domain: host, port: port)
        self.init(server: server, password: password, target: target, sni: sni)
    }

    // MARK: OutboundConnection

    public func open() async throws {
        let task: Task<Void, Error> = lifecycle.withLock { life in
            switch life.state {
            case .established:
                return Task {}
            case .closed:
                return Task { throw OutboundError.alreadyClosed(self.endpoint) }
            case .connecting:
                return life.openTask!
            case .idle:
                life.state = .connecting
                let task = Task {
                    TunnelLog.write(.debug, "anytls open \(self.identity.server) → \(self.endpoint)")
                    self.stream = try await AnyTLSSessionPool.shared.openStream(
                        identity: self.identity,
                        to: self.endpoint
                    )
                }
                life.openTask = task
                return task
            }
        }
        do {
            try await task.value
            lifecycle.withLock { $0.state = .established }
        } catch {
            lifecycle.withLock { $0.state = .idle }
            throw error
        }
    }

    public func write(_ buffer: UnsafeRawBufferPointer) async throws -> Int {
        if buffer.isEmpty { return 0 }
        try await ensureOpen()
        guard let stream else { throw OutboundError.alreadyClosed(endpoint) }
        try await stream.write(buffer)
        return buffer.count
    }

    public func read(into buffer: UnsafeMutableRawBufferPointer) async throws -> Int {
        if buffer.isEmpty { return 0 }
        try await ensureOpen()
        guard let stream else { throw OutboundError.alreadyClosed(endpoint) }
        if leftover.isEmpty {
            guard let data = try await stream.readData() else { return 0 }
            leftover = data
        }
        let take = min(buffer.count, leftover.count)
        leftover.prefix(take).withUnsafeBytes { raw in
            buffer.copyMemory(from: raw)
        }
        leftover.removeFirst(take)
        return take
    }

    public func close() async {
        let current: AnyTLSSessionStream? = lifecycle.withLock { life in
            if life.state == .closed { return nil }
            life.state = .closed
            return self.stream
        }
        stream = nil
        await current?.close()
    }

    // MARK: Helpers

    private func ensureOpen() async throws {
        switch state {
        case .established: return
        case .closed: throw OutboundError.alreadyClosed(endpoint)
        case .idle, .connecting: try await open()
        }
    }
}
