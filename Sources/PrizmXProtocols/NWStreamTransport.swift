import Foundation
import Network
import os

/// Shared `NWConnection` transport skeleton for the proxy outbound
/// connections (Shadowsocks / VLESS / Trojan).
///
/// Owns the parts protocol implementations used to copy-paste: the
/// idempotent `open` lifecycle, ready-wait, raw send/receive, a plaintext
/// staging buffer, and `NWError` → `OutboundError` mapping. Each protocol
/// keeps only its dialing parameters, handshake, and wire transform.
final class NWStreamTransport: @unchecked Sendable {
    /// Logical peer for open/close error labels (the proxied target).
    let endpoint: Endpoint
    /// Server for mapped transport-error labels.
    let errorPeer: Endpoint
    let queue: DispatchQueue

    let writeMutex = AsyncMutex()
    let readMutex = AsyncMutex()
    /// Plaintext staging for simple protocols (Trojan / VLESS response drain).
    let inbox = DirectBuffer()

    private let lifecycle = OSAllocatedUnfairLock(initialState: Lifecycle())
    /// Read (receive task) and written (open / close) from different tasks.
    private let connectionBox = OSAllocatedUnfairLock<NWConnection?>(initialState: nil)
    /// First protocol payload (salt / request header) has been handed to the
    /// wire. Readers check this without taking `writeMutex`, so a stalled
    /// upload never blocks the download direction.
    private let handshakeFlag = OSAllocatedUnfairLock(initialState: false)
    /// Set once the wire returns a clean EOF (read path only).
    private(set) var receiveEOF = false
    /// Framing between the protocol and the socket (WebSocket, gRPC, obfs).
    /// Installed during open, before `markEstablished`.
    private let layerBox = OSAllocatedUnfairLock<(any ByteStream)?>(initialState: nil)

    private struct Lifecycle {
        var state: OutboundConnectionState = .idle
        var openTask: Task<Void, Error>?
        var writeClosed = false
    }

    var connection: NWConnection? {
        connectionBox.withLock { $0 }
    }

    var isHandshakeFlushed: Bool {
        handshakeFlag.withLock { $0 }
    }

    func markHandshakeFlushed() {
        handshakeFlag.withLock { $0 = true }
    }

    init(queueLabel: String, endpoint: Endpoint, errorPeer: Endpoint) {
        self.endpoint = endpoint
        self.errorPeer = errorPeer
        self.queue = DispatchQueue(label: queueLabel, qos: .userInitiated)
    }

    var state: OutboundConnectionState {
        lifecycle.withLock { $0.state }
    }

    /// Idempotent: `body` (dial + handshake) runs at most once; concurrent
    /// callers await the same task.
    func open(running body: @escaping @Sendable () async throws -> Void) async throws {
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
                let task = Task { try await body() }
                life.openTask = task
                return task
            }
        }
        try await task.value
    }

    func ensureOpen(running body: @escaping @Sendable () async throws -> Void) async throws {
        switch state {
        case .established: return
        case .closed:
            // Peer failure keeps the socket for draining reads (see
            // `ensureReadable`); writes still fail in `ensureWritable`.
            if connection != nil { return }
            throw OutboundError.alreadyClosed(endpoint)
        case .idle, .connecting: try await open(running: body)
        }
    }

    func ensureNotClosed() throws {
        if state == .closed || connection == nil {
            throw OutboundError.alreadyClosed(endpoint)
        }
    }

    /// Read-side check: only an explicit `close()` stops reads. After the
    /// peer fails or resets the socket (state `.closed`), reads still drain
    /// what Network.framework has buffered and then surface its error.
    func ensureReadable() throws {
        if connection == nil {
            throw OutboundError.alreadyClosed(endpoint)
        }
    }

    func ensureWritable() throws {
        try ensureNotClosed()
        if isWriteClosed {
            throw OutboundError.alreadyClosed(endpoint)
        }
    }

    /// Connect body: registers the dialing connection before waiting.
    func attach(_ nw: NWConnection) {
        connectionBox.withLock { $0 = nw }
    }

    /// Waits for `.ready`; a later failure / cancel marks the transport closed.
    ///
    /// Hard ceiling on the wait: a silently dropped SYN leaves NWConnection
    /// in `.waiting`/`.preparing` until the kernel TCP timeout (75s+), which
    /// would hang `open()` for the whole flow. On timeout the connection is
    /// cancelled, which also unwinds the suspended ready-wait child task.
    func waitUntilReady(_ nw: NWConnection, timeout: Duration = .seconds(8)) async throws {
        let peer = endpoint
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    let once = OnceResume(continuation)
                    nw.stateUpdateHandler = { [weak self] state in
                        switch state {
                        case .ready:
                            nw.stateUpdateHandler = { [weak self] later in
                                if case .failed = later { self?.markClosed() }
                                if case .cancelled = later { self?.markClosed() }
                            }
                            once.resume(with: .success(()))
                        case .failed(let error):
                            once.resume(with: .failure(self?.mapTransportError(error) ?? error))
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

    /// Connect body failed: close everything so state settles at `.closed`.
    func failOpen(_ nw: NWConnection) {
        lifecycle.withLock { $0.state = .closed }
        nw.cancel()
        connectionBox.withLock { $0 = nil }
    }

    /// `failOpen` for the connection `attach` registered (protocol handshake
    /// failed after `dial`).
    func failOpen() {
        lifecycle.withLock { $0.state = .closed }
        connectionBox.withLock { box -> NWConnection? in
            defer { box = nil }
            return box
        }?.cancel()
    }

    // MARK: Framing layer

    /// The socket itself as a `ByteStream`, for a layer to stack on.
    var socketStream: any ByteStream { SocketStream(transport: self) }

    /// Routes `send` / `receiveRaw` / `finishWriting` through `layer`.
    func install(_ layer: any ByteStream) {
        layerBox.withLock { $0 = layer }
    }

    private var layer: (any ByteStream)? {
        layerBox.withLock { $0 }
    }

    /// The topmost stream so far (installed layer, else the socket), for a
    /// further layer to stack on.
    var currentStream: any ByteStream {
        layer ?? socketStream
    }

    func markEstablished() {
        lifecycle.withLock { $0.state = .established }
    }

    func markClosed() {
        lifecycle.withLock { $0.state = .closed }
    }

    /// Protocol bytes out: through the framing layer when one is installed.
    func send(_ data: Data) async throws {
        if let layer {
            try await layer.send(data)
        } else {
            try await sendSocket(data)
        }
    }

    /// Raw send on the socket with mapped errors.
    fileprivate func sendSocket(_ data: Data) async throws {
        guard let connection else { throw OutboundError.alreadyClosed(endpoint) }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(
                content: data,
                completion: .contentProcessed { error in
                    if let error {
                        continuation.resume(throwing: self.mapTransportError(error))
                    } else {
                        continuation.resume()
                    }
                }
            )
        }
    }

    /// The framing above ended the stream cleanly (TLS `close_notify`) while
    /// the socket may still be open; readers then stop at buffered data.
    func markReceiveEOF() {
        receiveEOF = true
    }

    /// One chunk of protocol bytes (through the framing layer when one is
    /// installed); `nil` at EOF (also flips `receiveEOF`).
    func receiveRaw() async throws -> Data? {
        let chunk = if let layer {
            try await layer.receive()
        } else {
            try await receiveSocket()
        }
        if chunk == nil { receiveEOF = true }
        return chunk
    }

    /// One raw chunk from the socket; `nil` at EOF.
    fileprivate func receiveSocket() async throws -> Data? {
        guard let connection else { throw OutboundError.alreadyClosed(endpoint) }
        let chunk: Data = try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: self.mapTransportError(error))
                    return
                }
                if isComplete && (data == nil || data?.isEmpty == true) {
                    continuation.resume(returning: Data())
                    return
                }
                continuation.resume(returning: data ?? Data())
            }
        }
        return chunk.isEmpty ? nil : chunk
    }

    /// Serialized `write` shell: open check → write mutex → not-closed check,
    /// then hands the caller buffer to the protocol's transform/send and
    /// returns the byte count `send` reports as consumed.
    func write(
        _ buffer: UnsafeRawBufferPointer,
        connecting body: @escaping @Sendable () async throws -> Void,
        send: (UnsafeRawBufferPointer) async throws -> Int
    ) async throws -> Int {
        if buffer.isEmpty { return 0 }
        try await ensureOpen(running: body)
        await writeMutex.acquire()
        defer { writeMutex.release() }
        try ensureWritable()
        return try await send(buffer)
    }

    /// Idempotent. A peer failure already left the state `.closed` but kept
    /// the socket for draining reads (see `ensureReadable`); it is cancelled
    /// here, since a failed `NWConnection` holds its resources until then.
    func close() async {
        lifecycle.withLock { $0.state = .closed }
        let nw = connectionBox.withLock { box -> NWConnection? in
            defer { box = nil }
            return box
        }
        nw?.cancel()
    }

    /// Half-close: sends TCP FIN once the queued bytes are flushed. Reads
    /// keep working. Serialized behind in-flight writes; idempotent.
    ///
    /// Network.framework TLS emits close_notify + FIN for the final message.
    /// A userspace TLS layer seals its own close_notify in `prelude`, which
    /// runs under `writeMutex` after further writes are already refused.
    func finishWriting(prelude: (() async throws -> Void)? = nil) async {
        guard state == .established else { return }
        await writeMutex.acquire()
        defer { writeMutex.release() }
        let proceed: Bool = lifecycle.withLock { life in
            guard life.state == .established, !life.writeClosed else { return false }
            life.writeClosed = true
            return true
        }
        guard proceed else { return }
        if let prelude {
            try? await prelude()
        }
        if let layer {
            await layer.finishWriting()
        } else {
            await finishSocket()
        }
    }

    /// TCP FIN (after TLS close_notify for Network.framework TLS).
    fileprivate func finishSocket() async {
        guard let connection else { return }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            connection.send(
                content: nil,
                contentContext: .finalMessage,
                isComplete: true,
                completion: .contentProcessed { _ in continuation.resume() }
            )
        }
    }

    /// `true` after `finishWriting`; later writes fail fast.
    var isWriteClosed: Bool {
        lifecycle.withLock { $0.writeClosed }
    }

    func mapTransportError(_ error: NWError) -> Error {
        switch error {
        case .posix(let code):
            switch code {
            case .ECONNREFUSED: return OutboundError.refused(errorPeer)
            case .ETIMEDOUT: return OutboundError.timedOut(errorPeer)
            case .EHOSTUNREACH, .ENETUNREACH, .EHOSTDOWN: return OutboundError.unreachable(errorPeer)
            default: return error
            }
        case .tls, .dns:
            return OutboundError.unreachable(errorPeer)
        default:
            return error
        }
    }
}

/// The transport's socket as the bottom `ByteStream` of a framing layer.
///
/// Weak: a layer's background work (gRPC's frame reader, a WebSocket pong)
/// can outlive the connection object; once it is gone the socket reads as
/// closed.
private final class SocketStream: ByteStream, @unchecked Sendable {
    private weak var transport: NWStreamTransport?
    private let endpoint: Endpoint

    init(transport: NWStreamTransport) {
        self.transport = transport
        self.endpoint = transport.endpoint
    }

    func send(_ data: Data) async throws {
        guard let transport else { throw OutboundError.alreadyClosed(endpoint) }
        try await transport.sendSocket(data)
    }

    func receive() async throws -> Data? {
        guard let transport else { return nil }
        return try await transport.receiveSocket()
    }

    func finishWriting() async {
        await transport?.finishSocket()
    }
}
