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

    public var chain: [String] { [FlowRoute.direct] }

    private let queue: DispatchQueue
    /// All mutable state lives behind this lock; I/O copies the connection
    /// reference out and never touches the NWConnection while holding it.
    private let lifecycle = OSAllocatedUnfairLock(initialState: Lifecycle())

    private struct Lifecycle {
        var state: OutboundConnectionState = .idle
        var openTask: Task<Void, Error>?
        var connection: NWConnection?
        var leftover = Data()
        var writeClosed = false
    }

    public var supportsHalfClose: Bool { true }

    private var connection: NWConnection? {
        lifecycle.withLock { $0.connection }
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
        var pending = lifecycle.withLock { life -> Data in
            defer { life.leftover = Data() }
            return life.leftover
        }
        if pending.isEmpty {
            pending = try await receiveOnce()
            if pending.isEmpty { return 0 }
        }
        let take = min(buffer.count, pending.count)
        pending.withUnsafeBytes { raw in
            buffer.copyMemory(from: UnsafeRawBufferPointer(rebasing: raw.prefix(take)))
        }
        if take < pending.count {
            let rest = pending.subdata(in: (pending.startIndex + take)..<pending.endIndex)
            lifecycle.withLock { $0.leftover = rest }
        }
        return take
    }

    public func close() async {
        let nw: NWConnection? = lifecycle.withLock { life in
            if life.state == .closed { return nil }
            life.state = .closed
            let current = life.connection
            life.connection = nil
            life.leftover = Data()
            return current
        }
        nw?.cancel()
    }

    /// TCP FIN; the downlink keeps flowing until the peer closes.
    public func closeWrite() async {
        let nw: NWConnection? = lifecycle.withLock { life in
            guard life.state == .established, !life.writeClosed else { return nil }
            life.writeClosed = true
            return life.connection
        }
        nw?.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in })
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
        // IP and the next candidate is tried immediately. A hosts-file hit is
        // dialed as written and does not fall through to upstream DNS.
        var candidates: [(host: NWEndpoint.Host, address: PrizmXProtocols.IPv4Address?)]
        if case .domain(let domain) = endpoint.host, let mapped = SystemHosts.lookup(domain) {
            candidates = mapped.addresses.prefix(8).map { (NWEndpoint.Host($0.description), nil) }
        } else if case .domain = endpoint.host {
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
                // `close()` may have raced the dial: never resurrect a closed flow.
                let adopted = lifecycle.withLock { life -> Bool in
                    guard life.state != .closed else { return false }
                    life.connection = nw
                    life.state = .established
                    return true
                }
                guard adopted else {
                    nw.cancel()
                    throw OutboundError.alreadyClosed(endpoint)
                }
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
