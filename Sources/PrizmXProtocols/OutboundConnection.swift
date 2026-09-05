import Foundation

/// The state of an outbound connection over its lifetime.
@frozen
public enum OutboundConnectionState: Hashable, Sendable {
    /// Created but not yet connected.
    case idle
    /// Connection is being established.
    case connecting
    /// Connection is established and ready for reads/writes.
    case established
    /// Closed (normally or due to an error).
    case closed
}

/// Common reasons an outbound connection fails.
@frozen
public enum OutboundError: Error, Sendable {
    /// The peer refused the connection.
    case refused(Endpoint)
    /// Connection or read/write timed out.
    case timedOut(Endpoint)
    /// Network unreachable / no route to the peer.
    case unreachable(Endpoint)
    /// Invalid endpoint (e.g. reserved port, empty domain).
    case invalidEndpoint(Endpoint)
    /// Read/write attempted on a closed connection.
    case alreadyClosed(Endpoint)
}

extension OutboundError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .refused(let endpoint): "connection refused: \(endpoint)"
        case .timedOut(let endpoint): "timed out: \(endpoint)"
        case .unreachable(let endpoint): "unreachable: \(endpoint)"
        case .invalidEndpoint(let endpoint): "invalid endpoint: \(endpoint)"
        case .alreadyClosed(let endpoint): "already closed: \(endpoint)"
        }
    }
}

/// A unified asynchronous connection abstraction for proxy outbound traffic.
///
/// Design notes:
/// - Reads and writes use raw buffers (`UnsafeRawBufferPointer`) as the core
///   interface; the caller owns the memory and no redundant copies are made on
///   the transfer path. Convenience methods (array versions) copy only once at
///   the boundary.
/// - Implementations **must not** retain the passed-in pointers after
///   `write` / `read` return (pointers are valid only for the duration of the
///   call, including across `await`).
public protocol OutboundConnection: Sendable {

    /// The peer endpoint.
    var endpoint: Endpoint { get }

    /// The current connection state (must be safe to read from any thread).
    var state: OutboundConnectionState { get }

    /// Short routing tag for logs / traffic stats (`direct`, group member, …).
    var routingLabel: String { get }

    /// Establishes the connection. Idempotent: returns immediately if already
    /// established.
    func open() async throws

    /// Best-effort write of `buffer`; returns the number of bytes actually
    /// written (may be less than `buffer.count`).
    ///
    /// - Important: `buffer` is valid only for the duration of this call;
    ///   implementations must not keep it beyond the call.
    func write(_ buffer: UnsafeRawBufferPointer) async throws -> Int

    /// Reads into the caller-provided buffer and returns the number of bytes
    /// actually read. Returns `0` when the peer has gracefully closed with no
    /// remaining data.
    ///
    /// - Important: `buffer` is valid only for the duration of this call;
    ///   implementations must not keep it beyond the call.
    func read(into buffer: UnsafeMutableRawBufferPointer) async throws -> Int

    /// Closes the connection and releases underlying resources. Idempotent.
    func close() async
}

// MARK: - Convenience API (copy once at the boundary; use the raw-buffer
//          versions on hot paths)

extension OutboundConnection {
    public var routingLabel: String { "proxy" }

    /// Writes a byte array and returns the number of bytes written.
    ///
    /// Convenience: the array is copied into a caller-owned scratch buffer
    /// before crossing `await`, so it does not rely on pointer-escape
    /// semantics of array storage. Prefer the raw-buffer version on hot paths.
    public func write(_ bytes: [UInt8]) async throws -> Int {
        guard !bytes.isEmpty else { return 0 }
        let scratch = UnsafeMutableRawBufferPointer.allocate(
            byteCount: bytes.count,
            alignment: MemoryLayout<UInt64>.alignment
        )
        defer { scratch.deallocate() }
        bytes.withUnsafeBytes { raw in scratch.copyMemory(from: raw) }
        return try await write(UnsafeRawBufferPointer(scratch))
    }

    /// Loops until all bytes are written (also through one scratch-buffer copy).
    public func writeAll(_ bytes: [UInt8]) async throws {
        guard !bytes.isEmpty else { return }
        let scratch = UnsafeMutableRawBufferPointer.allocate(
            byteCount: bytes.count,
            alignment: MemoryLayout<UInt64>.alignment
        )
        defer { scratch.deallocate() }
        bytes.withUnsafeBytes { raw in scratch.copyMemory(from: raw) }

        let whole = UnsafeRawBufferPointer(scratch)
        var offset = 0
        while offset < whole.count {
            let chunk = UnsafeRawBufferPointer(rebasing: whole[offset...])
            let written = try await write(chunk)
            guard written > 0 else { throw OutboundError.alreadyClosed(endpoint) }
            offset += written
        }
    }

    /// Loops until all bytes of `data` are written (one scratch copy).
    public func writeAll(_ data: Data) async throws {
        guard !data.isEmpty else { return }
        let scratch = UnsafeMutableRawBufferPointer.allocate(
            byteCount: data.count,
            alignment: MemoryLayout<UInt64>.alignment
        )
        defer { scratch.deallocate() }
        data.withUnsafeBytes { raw in scratch.copyMemory(from: raw) }

        let whole = UnsafeRawBufferPointer(scratch)
        var offset = 0
        while offset < whole.count {
            let chunk = UnsafeRawBufferPointer(rebasing: whole[offset...])
            let written = try await write(chunk)
            guard written > 0 else { throw OutboundError.alreadyClosed(endpoint) }
            offset += written
        }
    }

    /// Reads up to `maximum` bytes into a fresh `Data`. Empty means the peer closed.
    public func readData(upTo maximum: Int) async throws -> Data {
        precondition(maximum > 0, "maximum must be positive")
        let scratch = UnsafeMutableRawBufferPointer.allocate(
            byteCount: maximum,
            alignment: MemoryLayout<UInt64>.alignment
        )
        defer { scratch.deallocate() }
        let count = try await read(into: scratch)
        guard count > 0 else { return Data() }
        return Data(UnsafeRawBufferPointer(rebasing: scratch.prefix(count)))
    }

    /// Reads up to `maximum` bytes and copies them into a fresh array.
    /// An empty array means the peer has closed.
    public func read(upTo maximum: Int) async throws -> [UInt8] {
        precondition(maximum > 0, "maximum must be positive")
        let scratch = UnsafeMutableRawBufferPointer.allocate(
            byteCount: maximum,
            alignment: MemoryLayout<UInt64>.alignment
        )
        defer { scratch.deallocate() }
        let count = try await read(into: scratch)
        guard count > 0 else { return [] }
        let view = UnsafeRawBufferPointer(rebasing: scratch.prefix(count))
        return Array(view.bindMemory(to: UInt8.self))
    }
}

/// The decoupling point between proxy policy and the concrete network stack
/// (direct / remote proxy / pooled connections).
public protocol OutboundConnectionFactory: Sendable {

    /// Returns an unopened outbound connection to `endpoint`.
    /// Call `open()` before the first read or write.
    func connect(to endpoint: Endpoint) async throws -> any OutboundConnection
}
