import Foundation
import Network
import os
import Security

/// Clash `idle-session-*` knobs for AnyTLS session reuse.
public struct AnyTLSSessionConfig: Sendable, Hashable {
    /// Clash `idle-session-check-interval` (seconds).
    public var checkInterval: TimeInterval
    /// Clash `idle-session-timeout` (seconds): close a session this long after
    /// its last stream finishes.
    public var idleTimeout: TimeInterval
    /// Clash `min-idle-session` (0 = never pre-create / keep spare sessions).
    public var minIdleSession: Int

    public init(checkInterval: TimeInterval = 30, idleTimeout: TimeInterval = 30, minIdleSession: Int = 1) {
        self.checkInterval = checkInterval
        self.idleTimeout = idleTimeout
        self.minIdleSession = minIdleSession
    }
}

/// Everything that identifies one AnyTLS server for session pooling.
public struct AnyTLSServerIdentity: Hashable, Sendable {
    public var server: Endpoint
    public var password: String
    public var sni: String
    public var skipCertVerify: Bool
    public var sessionConfig: AnyTLSSessionConfig

    public init(
        server: Endpoint,
        password: String,
        sni: String,
        skipCertVerify: Bool = false,
        sessionConfig: AnyTLSSessionConfig = AnyTLSSessionConfig()
    ) {
        self.server = server
        self.password = password
        self.sni = sni
        self.skipCertVerify = skipCertVerify
        self.sessionConfig = sessionConfig
    }
}

/// What a stream needs from its session (seam for tests).
protocol AnyTLSSessionCore: AnyObject, Sendable {
    func send(_ frame: AnyTLSFrame) async throws
    func closeStream(_ id: UInt32) async
}

/// One stream inside an `AnyTLSSession`. Feeds `OutboundConnection` adapters:
/// `readData` blocks until PSH payload, FIN, or failure.
public final class AnyTLSSessionStream: @unchecked Sendable {
    /// Per-stream receive cap. Past it the session pump stops reading the
    /// shared TLS connection until this stream's consumer drains below it.
    static let receiveBufferLimit = 2 * 1024 * 1024

    public let id: UInt32
    public let target: Endpoint

    private let core: AnyTLSSessionCore
    private let lock = NSLock()
    private var buffer = Data()
    private var waiter: CheckedContinuation<Data?, Error>?
    private var inputFinished = false
    private var failure: Error?
    private var closed = false
    private var ackContinuation: CheckedContinuation<Void, Error>?
    private var acknowledged = false
    private var drainWaiter: CheckedContinuation<Void, Never>?

    init(id: UInt32, target: Endpoint, core: AnyTLSSessionCore) {
        self.id = id
        self.target = target
        self.core = core
    }

    var isAcknowledged: Bool {
        lock.lock()
        defer { lock.unlock() }
        return acknowledged
    }

    // MARK: Session → stream events

    /// Delivers a PSH payload. Returns `true` when the unread backlog is at
    /// or above `receiveBufferLimit` (caller should `waitUntilDrained`).
    @discardableResult
    func ingest(_ payload: Data) -> Bool {
        lock.lock()
        if closed || failure != nil {
            lock.unlock()
            return false
        }
        if let waiter {
            self.waiter = nil
            lock.unlock()
            waiter.resume(returning: payload)
            return false
        }
        buffer.append(payload)
        let full = buffer.count >= Self.receiveBufferLimit
        lock.unlock()
        return full
    }

    /// Suspends until the backlog drops below `receiveBufferLimit`, or the
    /// stream is closed / failed.
    func waitUntilDrained() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            lock.lock()
            if buffer.count < Self.receiveBufferLimit || closed || failure != nil || drainWaiter != nil {
                lock.unlock()
                continuation.resume()
                return
            }
            drainWaiter = continuation
            lock.unlock()
        }
    }

    var bufferedByteCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return buffer.count
    }

    func finishInput() {
        lock.lock()
        inputFinished = true
        let waiter = self.waiter
        self.waiter = nil
        lock.unlock()
        waiter?.resume(returning: nil)
    }

    func fail(_ error: Error) {
        lock.lock()
        failure = error
        inputFinished = true
        let waiter = self.waiter
        self.waiter = nil
        let ack = ackContinuation
        ackContinuation = nil
        let drain = drainWaiter
        drainWaiter = nil
        lock.unlock()
        waiter?.resume(throwing: error)
        ack?.resume(throwing: error)
        drain?.resume()
    }

    /// SYNACK. An error payload fails the stream: a blocked reader wakes
    /// with the error and later writes are refused.
    func acknowledge(errorMessage: String?) {
        if let errorMessage {
            lock.lock()
            acknowledged = true
            let alreadyFailed = failure != nil
            lock.unlock()
            if !alreadyFailed {
                fail(AnyTLSError.streamFailed(errorMessage))
            }
            return
        }
        lock.lock()
        acknowledged = true
        let currentFailure = failure
        let ack = ackContinuation
        ackContinuation = nil
        lock.unlock()
        if let currentFailure {
            ack?.resume(throwing: currentFailure)
        } else {
            ack?.resume()
        }
    }

    /// Waits for `cmdSYNACK` (open acknowledgement) with a hard ceiling.
    func waitAck(timeout: Duration) async throws {
        try preflightAck()
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    self.registerAck(continuation)
                }
            }
            group.addTask {
                try await Task.sleep(for: timeout)
                throw OutboundError.timedOut(self.target)
            }
            do {
                try await group.next()
                group.cancelAll()
            } catch {
                group.cancelAll()
                throw error
            }
        }
    }

    private func preflightAck() throws {
        lock.lock()
        defer { lock.unlock() }
        if let failure { throw failure }
        if acknowledged { return }
    }

    private func registerAck(_ continuation: CheckedContinuation<Void, Error>) {
        lock.lock()
        if let failure {
            lock.unlock()
            continuation.resume(throwing: failure)
            return
        }
        if acknowledged {
            lock.unlock()
            continuation.resume()
            return
        }
        ackContinuation = continuation
        lock.unlock()
    }

    // MARK: Stream I/O

    /// Next inbound chunk; nil at FIN. Throws on session failure.
    func readData() async throws -> Data? {
        try await withCheckedThrowingContinuation { continuation in
            takeForRead(continuation)
        }
    }

    private func takeForRead(_ continuation: CheckedContinuation<Data?, Error>) {
        lock.lock()
        if !buffer.isEmpty {
            let data = buffer
            buffer = Data()
            let drain = drainWaiter
            drainWaiter = nil
            lock.unlock()
            drain?.resume()
            continuation.resume(returning: data)
            return
        }
        if let failure {
            lock.unlock()
            continuation.resume(throwing: failure)
            return
        }
        // After close() nothing ingests or finishes this stream any more, so
        // a read that lost the race with close() must not park.
        if inputFinished || closed {
            lock.unlock()
            continuation.resume(returning: nil)
            return
        }
        waiter = continuation
        lock.unlock()
    }

    /// PSH frames, chunked at the 16-bit frame payload limit.
    func write(_ bytes: UnsafeRawBufferPointer) async throws {
        guard !bytes.isEmpty else { return }
        var offset = 0
        while offset < bytes.count {
            try checkWritable()
            let take = min(bytes.count - offset, 0xFFFF)
            let slice = UnsafeRawBufferPointer(rebasing: bytes[offset..<(offset + take)])
            try await core.send(AnyTLSFrame(command: .psh, streamID: id, payload: Data(slice)))
            offset += take
        }
    }

    private func checkWritable() throws {
        lock.lock()
        defer { lock.unlock() }
        if let failure { throw failure }
        if closed { throw OutboundError.alreadyClosed(target) }
    }

    /// FIN this stream; the session itself stays alive for reuse.
    func close() async {
        let (didClose, pending, drain) = closeOnce()
        guard didClose else { return }
        pending?.resume(returning: nil)
        drain?.resume()
        await core.closeStream(id)
    }

    private func closeOnce() -> (Bool, CheckedContinuation<Data?, Error>?, CheckedContinuation<Void, Never>?) {
        lock.lock()
        defer { lock.unlock() }
        if closed { return (false, nil, nil) }
        closed = true
        let pending = waiter
        waiter = nil
        let drain = drainWaiter
        drainWaiter = nil
        buffer = Data()
        return (true, pending, drain)
    }
}

/// One AnyTLS session: a single TLS connection carrying many streams.
///
/// Establishment: TLS 1.3 dial (failover across all resolved A records) →
/// auth blob → `cmdSettings`. Streams then SYN + PSH(SOCKS5 target) per flow.
public final class AnyTLSSession: AnyTLSSessionCore, @unchecked Sendable {

    enum State: Sendable {
        case established
        case closed
    }

    public let identity: AnyTLSServerIdentity
    /// Pool sequence (newer = larger). anytls-go reuses newest idle first.
    public var seq: UInt64 = 0
    public var idleSince: ContinuousClock.Instant?
    /// Called once when the session dies (pool eviction hook).
    public var onTerminate: (@Sendable (AnyTLSSession) -> Void)?
    /// Called when the last stream FINs and the session is still up (return to idle pool).
    public var onBecameIdle: (@Sendable (AnyTLSSession) -> Void)?
    /// Test seam: replaces the `waste`-frame probe.
    var probeOverrideForTesting: (@Sendable () async -> Bool)?

    private let queue = DispatchQueue(label: "prizmx.anytls.session", qos: .userInitiated)
    private let lock = OSAllocatedUnfairLock(initialState: SessionState())
    private let writeMutex = AsyncMutex()
    private let auth: AnyTLSAuth
    /// Written by attach / terminate, read by the pump and senders.
    private let wire = OSAllocatedUnfairLock(initialState: Wire())
    private let recvWire = DirectBuffer()

    private struct Wire: Sendable {
        var connection: NWConnection?
        var pumpTask: Task<Void, Never>?
    }

    private var connection: NWConnection? {
        wire.withLock { $0.connection }
    }

    private struct SessionState: Sendable {
        var state: State = .established
        var streams: [UInt32: AnyTLSSessionStream] = [:]
        var nextStreamID: UInt32 = 1
    }

    private init(identity: AnyTLSServerIdentity, connection: NWConnection?) {
        self.identity = identity
        self.auth = AnyTLSAuth(password: identity.password)
        self.wire.withLock { $0.connection = connection }
    }

    /// Test seam: a session without a live connection (pool/singleflight tests).
    static func makeForTesting(identity: AnyTLSServerIdentity) -> AnyTLSSession {
        AnyTLSSession(identity: identity, connection: nil)
    }

    public var isUsable: Bool {
        lock.withLock { $0.state == .established }
    }

    /// Write a `waste` frame. Idle reuse calls this so a NAT-dead TLS is
    /// dropped *before* we hand it to the browser / Grok.
    public func probe(timeout: Duration = .seconds(1)) async -> Bool {
        guard isUsable else { return false }
        if let probeOverrideForTesting { return await probeOverrideForTesting() }
        guard connection != nil else { return true }
        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask {
                    try await self.send(AnyTLSFrame(command: .waste))
                }
                group.addTask {
                    try await Task.sleep(for: timeout)
                    throw OutboundError.timedOut(self.identity.server)
                }
                try await group.next()
                group.cancelAll()
            }
            return true
        } catch {
            terminate()
            return false
        }
    }

    // MARK: Establish

    /// Dials with failover over every resolved A record, authenticates, and
    /// sends `cmdSettings`. Shared by all flows to this server identity.
    public static func establish(identity: AnyTLSServerIdentity) async throws -> AnyTLSSession {
        let server = identity.server
        guard server.port > 0, let nwPort = NWEndpoint.Port(rawValue: server.port) else {
            throw OutboundError.invalidEndpoint(server)
        }
        let parameters = TLSClient.parameters(
            serverName: identity.sni,
            minimum: .TLSv13,
            maximum: .TLSv13,
            skipVerification: identity.skipCertVerify
        )

        var candidates: [(host: NWEndpoint.Host, address: IPv4Address?)]
        if case .domain = server.host {
            guard DNSClient.current != nil else { throw DNSError.notConfigured }
            let addresses = try await DNSClient.resolveAll(server.host, role: .proxyServer)
            candidates = addresses.prefix(3).map { (NWEndpoint.Host($0.description), $0) }
        } else {
            candidates = [(NWEndpoint.Host(server.host.description), nil)]
        }

        var lastError: Error = OutboundError.unreachable(server)
        for candidate in candidates {
            let probe = AnyTLSSession(identity: identity, connection: nil)
            let nw = NWConnection(host: candidate.host, port: nwPort, using: parameters)
            do {
                try await probe.waitUntilReady(nw, timeout: .seconds(8))
                TunnelLog.write(.debug, "anytls session \(server) via \(candidate.host)")
                var blob = Data(probe.auth.encode())
                blob.append(AnyTLSFrame(command: .settings, payload: AnyTLSSettings.clientBody()).encode())
                try await probe.send(blob, over: nw)
                if let address = candidate.address,
                   case .domain(let domain) = server.host {
                    DNSClient.current?.markGood(domain: domain, role: .proxyServer, address: address)
                }
                probe.attach(nw)
                return probe
            } catch {
                TunnelLog.write(
                    .error,
                    "anytls session \(server) via \(candidate.host) failed: \(error.localizedDescription)"
                )
                nw.cancel()
                if let address = candidate.address,
                   case .domain(let domain) = server.host {
                    DNSClient.current?.markBad(domain: domain, role: .proxyServer, address: address)
                }
                lastError = error
            }
        }
        throw lastError
    }

    private func attach(_ nw: NWConnection) {
        wire.withLock { $0.connection = nw }
        let task = Task<Void, Never> { [weak self] in
            await self?.pump()
        }
        wire.withLock { $0.pumpTask = task }
    }

    // MARK: Streams

    /// SYN + PSH(target). Clash/anytls-go returns the stream without waiting
    /// for SYNACK — waiting 3s here made every slow handshake a hard failure
    /// and `terminate()` then took down the only TLS path (browser included).
    public func openStream(to target: Endpoint) async throws -> AnyTLSSessionStream {
        guard isUsable else { throw OutboundError.alreadyClosed(identity.server) }
        idleSince = nil

        let streamID = lock.withLock { state -> UInt32 in
            var id = state.nextStreamID
            state.nextStreamID &+= 1
            if state.nextStreamID == 0 { state.nextStreamID = 1 }
            while state.streams[id] != nil {
                id = state.nextStreamID
                state.nextStreamID &+= 1
            }
            return id
        }
        let stream = AnyTLSSessionStream(id: streamID, target: target, core: self)
        lock.withLock { $0.streams[streamID] = stream }

        if connection == nil {
            stream.acknowledge(errorMessage: nil)
            return stream
        }
        var blob = AnyTLSFrame(command: .syn, streamID: streamID).encode()
        let address = try ShadowsocksAddress.encode(target)
        blob.append(AnyTLSFrame(command: .psh, streamID: streamID, payload: Data(address)).encode())
        do {
            try await send(blob)
            return stream
        } catch {
            lock.withLock { $0.streams[streamID] = nil }
            stream.fail(error)
            throw error
        }
    }

    /// Serialized frame write (streams + heartbeat share the connection).
    public func send(_ frame: AnyTLSFrame) async throws {
        try await send(frame.encode())
    }

    private func send(_ data: Data) async throws {
        guard isUsable else { throw OutboundError.alreadyClosed(identity.server) }
        await writeMutex.acquire()
        defer { writeMutex.release() }
        guard let connection else { throw OutboundError.alreadyClosed(identity.server) }
        do {
            try await send(data, over: connection)
        } catch {
            if case OutboundError.timedOut = error {
                TunnelLog.write(.warn, "anytls send timeout \(identity.server)")
            }
            terminate()
            throw error
        }
    }

    private func send(_ data: Data, over connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let once = OnceResume(continuation)
            let timeout = Task {
                try await Task.sleep(for: .seconds(8))
                once.resume(with: .failure(OutboundError.timedOut(self.identity.server)))
            }
            connection.send(content: data, completion: .contentProcessed { error in
                timeout.cancel()
                if let error {
                    once.resume(with: .failure(error))
                } else {
                    once.resume(with: .success(()))
                }
            })
        }
    }

    public func closeStream(_ id: UInt32) async {
        let removed = lock.withLock { $0.streams.removeValue(forKey: id) != nil }
        guard removed else { return }
        if connection != nil {
            try? await send(AnyTLSFrame(command: .fin, streamID: id).encode())
        }
        let idle = lock.withLock { $0.state == .established && $0.streams.isEmpty }
        if idle { onBecameIdle?(self) }
    }

    // MARK: Lifecycle

    /// Fails every stream and drops the connection (pool evicts via hook).
    public func terminate() {
        let shouldTerminate = lock.withLock { state -> Bool in
            if state.state == .closed { return false }
            state.state = .closed
            return true
        }
        guard shouldTerminate else { return }
        let (pump, nw) = wire.withLock { box -> (Task<Void, Never>?, NWConnection?) in
            defer {
                box.pumpTask = nil
                box.connection = nil
            }
            return (box.pumpTask, box.connection)
        }
        pump?.cancel()
        nw?.cancel()
        let streams = lock.withLock { state -> [AnyTLSSessionStream] in
            let all = Array(state.streams.values)
            state.streams.removeAll()
            return all
        }
        for stream in streams {
            stream.fail(OutboundError.alreadyClosed(identity.server))
        }
        onTerminate?(self)
    }

    // MARK: Frame pump

    private func pump() async {
        do {
            while true {
                let chunk = try await receiveOnce()
                if chunk.isEmpty { throw OutboundError.alreadyClosed(identity.server) }
                recvWire.append(chunk)
                while let (frame, consumed) = AnyTLSFrame.consume(recvWire.readableBytes) {
                    recvWire.consume(consumed)
                    if let backlogged = handle(frame) {
                        // Session-level backpressure: stop reading the shared
                        // connection until this stream's consumer catches up.
                        await backlogged.waitUntilDrained()
                    }
                }
            }
        } catch {
            TunnelLog.write(.debug, "anytls session \(identity.server) down: \(error.localizedDescription)")
            terminate()
        }
    }

    /// Returns the stream whose backlog hit the receive cap, if any.
    private func handle(_ frame: AnyTLSFrame) -> AnyTLSSessionStream? {
        switch frame.command {
        case .waste, .settings, .updatePaddingScheme, .serverSettings, .heartResponse, .syn:
            return nil
        case .heartRequest:
            let reply = AnyTLSFrame(command: .heartResponse, streamID: frame.streamID)
            Task { [weak self] in try? await self?.send(reply) }
        case .psh:
            let stream = lock.withLock { $0.streams[frame.streamID] }
            if !frame.payload.isEmpty, let stream, stream.ingest(frame.payload) {
                return stream
            }
        case .fin:
            let stream = lock.withLock { $0.streams[frame.streamID] }
            stream?.finishInput()
        case .synAck:
            let stream = lock.withLock { $0.streams[frame.streamID] }
            if frame.payload.isEmpty {
                stream?.acknowledge(errorMessage: nil)
            } else {
                stream?.acknowledge(errorMessage: String(decoding: frame.payload, as: UTF8.self))
            }
        case .alert:
            let message = String(decoding: frame.payload, as: UTF8.self)
            TunnelLog.write(.warn, "anytls alert \(identity.server): \(message)")
            terminate()
        }
        return nil
    }

    private func receiveOnce() async throws -> Data {
        guard let connection else { throw OutboundError.alreadyClosed(identity.server) }
        return try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                if isComplete && (data == nil || data?.isEmpty == true) {
                    continuation.resume(returning: Data())
                    return
                }
                continuation.resume(returning: data ?? Data())
            }
        }
    }

    private func waitUntilReady(_ nw: NWConnection, timeout: Duration) async throws {
        let peer = identity.server
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    let once = OnceResume(continuation)
                    nw.stateUpdateHandler = { state in
                        switch state {
                        case .ready:
                            once.resume(with: .success(()))
                        case .failed(let error):
                            TunnelLog.write(.debug, "nw failed \(peer): \(error)")
                            once.resume(with: .failure(self.mapTransportError(error)))
                        case .cancelled:
                            once.resume(with: .failure(OutboundError.alreadyClosed(peer)))
                        default:
                            break
                        }
                    }
                    nw.start(queue: self.queue)
                }
            }
            group.addTask {
                try await Task.sleep(for: timeout)
                throw OutboundError.timedOut(peer)
            }
            do {
                try await group.next()
                group.cancelAll()
            } catch {
                nw.cancel()
                group.cancelAll()
                throw error
            }
        }
    }

    private func mapTransportError(_ error: NWError) -> Error {
        switch error {
        case .posix(let code):
            switch code {
            case .ECONNREFUSED: return OutboundError.refused(identity.server)
            case .ETIMEDOUT: return OutboundError.timedOut(identity.server)
            case .EHOSTUNREACH, .ENETUNREACH, .EHOSTDOWN: return OutboundError.unreachable(identity.server)
            default: return error
            }
        case .tls, .dns:
            return OutboundError.unreachable(identity.server)
        default:
            return error
        }
    }
}
