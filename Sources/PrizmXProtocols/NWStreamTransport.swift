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
    private(set) var connection: NWConnection?
    /// Set once the wire returns a clean EOF.
    private(set) var receiveEOF = false

    private struct Lifecycle {
        var state: OutboundConnectionState = .idle
        var openTask: Task<Void, Error>?
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
        case .closed: throw OutboundError.alreadyClosed(endpoint)
        case .idle, .connecting: try await open(running: body)
        }
    }

    func ensureNotClosed() throws {
        if state == .closed || connection == nil {
            throw OutboundError.alreadyClosed(endpoint)
        }
    }

    /// Connect body: registers the dialing connection before waiting.
    func attach(_ nw: NWConnection) {
        connection = nw
    }

    /// Waits for `.ready`; a later failure / cancel marks the transport closed.
    func waitUntilReady(_ nw: NWConnection) async throws {
        let peer = endpoint
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
            nw.start(queue: queue)
        }
    }

    /// Connect body failed: close everything so state settles at `.closed`.
    func failOpen(_ nw: NWConnection) {
        lifecycle.withLock { $0.state = .closed }
        nw.cancel()
        connection = nil
    }

    func markEstablished() {
        lifecycle.withLock { $0.state = .established }
    }

    func markClosed() {
        lifecycle.withLock { $0.state = .closed }
    }

    /// Raw send on the wire with mapped errors.
    func send(_ data: Data) async throws {
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

    /// One raw chunk from the wire; `nil` at EOF (also flips `receiveEOF`).
    func receiveRaw() async throws -> Data? {
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
        guard !chunk.isEmpty else {
            receiveEOF = true
            return nil
        }
        return chunk
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
        try ensureNotClosed()
        return try await send(buffer)
    }

    func close() async {
        let shouldCancel: Bool = lifecycle.withLock { life in
            if life.state == .closed { return false }
            life.state = .closed
            return true
        }
        guard shouldCancel else { return }
        connection?.cancel()
        connection = nil
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
