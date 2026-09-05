import Foundation
import Network
import os
import PrizmXProtocols

// MARK: - Direct TCP outbound

/// Unproxied TCP connection via `NWConnection`. Used when the router
/// returns `.direct`.
public final class DirectOutboundConnection: OutboundConnection, @unchecked Sendable {

    public let endpoint: Endpoint
    public let role: DNSRole

    public var state: OutboundConnectionState {
        lifecycle.withLock { $0.state }
    }

    public var routingLabel: String { "direct" }

    private let queue: DispatchQueue
    private let lifecycle = OSAllocatedUnfairLock(initialState: Lifecycle())
    private var connection: NWConnection?
    private var leftover = Data()
    private var receiveEOF = false

    private struct Lifecycle {
        var state: OutboundConnectionState = .idle
        var openTask: Task<Void, Error>?
    }

    public init(endpoint: Endpoint, role: DNSRole = .direct) {
        self.endpoint = endpoint
        self.role = role
        self.queue = DispatchQueue(label: "prizmx.direct.outbound", qos: .userInitiated)
    }

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
                let task = Task { try await self.connectTCP() }
                life.openTask = task
                return task
            }
        }
        try await task.value
    }

    public func write(_ buffer: UnsafeRawBufferPointer) async throws -> Int {
        if buffer.isEmpty { return 0 }
        try await ensureOpen()
        guard let connection else { throw OutboundError.alreadyClosed(endpoint) }
        let data = Data(buffer)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(
                content: data,
                completion: .contentProcessed { error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume()
                    }
                }
            )
        }
        return data.count
    }

    public func read(into buffer: UnsafeMutableRawBufferPointer) async throws -> Int {
        if buffer.isEmpty { return 0 }
        try await ensureOpen()
        if leftover.isEmpty {
            leftover = try await receiveOnce()
            if leftover.isEmpty { return 0 }
        }
        let take = min(buffer.count, leftover.count)
        leftover.withUnsafeBytes { raw in
            buffer.copyMemory(from: UnsafeRawBufferPointer(rebasing: raw.prefix(take)))
        }
        leftover.removeFirst(take)
        return take
    }

    public func close() async {
        let shouldCancel: Bool = lifecycle.withLock { life in
            if life.state == .closed { return false }
            life.state = .closed
            return true
        }
        guard shouldCancel else { return }
        connection?.cancel()
        connection = nil
    }

    private func ensureOpen() async throws {
        switch state {
        case .established: return
        case .closed: throw OutboundError.alreadyClosed(endpoint)
        case .idle, .connecting: try await open()
        }
    }

    private func connectTCP() async throws {
        guard endpoint.port > 0, let nwPort = NWEndpoint.Port(rawValue: endpoint.port) else {
            throw OutboundError.invalidEndpoint(endpoint)
        }
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let parameters = NWParameters(tls: nil, tcp: tcp)
        parameters.preferNoProxies = true

        // All A records become dial candidates; a failed attempt poisons that
        // IP and the next candidate is tried immediately.
        var candidates: [(host: NWEndpoint.Host, address: PrizmXProtocols.IPv4Address?)]
        if case .domain = endpoint.host {
            guard DNSClient.current != nil else { throw DNSError.notConfigured }
            let addresses = try await DNSClient.resolveAll(endpoint.host, role: role)
            candidates = addresses.prefix(3).map { (NWEndpoint.Host($0.description), $0) }
        } else {
            candidates = [(NWEndpoint.Host(endpoint.host.description), nil)]
        }

        var lastError: Error = OutboundError.unreachable(endpoint)
        for candidate in candidates {
            let nw = NWConnection(host: candidate.host, port: nwPort, using: parameters)
            do {
                try await waitReady(nw)
                if let address = candidate.address, case .domain(let domain) = endpoint.host {
                    DNSClient.current?.markGood(domain: domain, role: role, address: address)
                }
                self.connection = nw
                lifecycle.withLock { $0.state = .established }
                return
            } catch {
                nw.cancel()
                if let address = candidate.address, case .domain(let domain) = endpoint.host {
                    DNSClient.current?.markBad(domain: domain, role: role, address: address)
                }
                lastError = error
            }
        }
        throw lastError
    }

    private func waitReady(_ nw: NWConnection) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    let once = OSAllocatedUnfairLock<CheckedContinuation<Void, Error>?>(initialState: continuation)
                    nw.stateUpdateHandler = { state in
                        let result: Result<Void, Error>
                        switch state {
                        case .ready:
                            result = .success(())
                        case .failed(let error):
                            result = .failure(error)
                        case .cancelled:
                            result = .failure(OutboundError.alreadyClosed(self.endpoint))
                        default:
                            return
                        }
                        let pending = once.withLock { current -> CheckedContinuation<Void, Error>? in
                            let value = current
                            current = nil
                            return value
                        }
                        pending?.resume(with: result)
                    }
                    nw.start(queue: self.queue)
                }
            }
            group.addTask {
                try await Task.sleep(for: .seconds(5))
                throw OutboundError.timedOut(self.endpoint)
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

    private func receiveOnce() async throws -> Data {
        guard let connection else { throw OutboundError.alreadyClosed(endpoint) }
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
}
