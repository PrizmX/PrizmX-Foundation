import Foundation
import os

/// Growable byte buffer with a readable slice and a writable tail.
///
/// Storage is a single allocation that is compacted only when the reader
/// index would otherwise force a reallocation. Not thread-safe; callers
/// serialize access per side.
final class DirectBuffer: @unchecked Sendable {
    private var pointer: UnsafeMutableRawPointer
    private var capacity: Int
    private var readerIndex = 0
    private var writerIndex = 0

    var readableByteCount: Int { writerIndex - readerIndex }

    var readableBytes: UnsafeRawBufferPointer {
        UnsafeRawBufferPointer(start: pointer.advanced(by: readerIndex), count: readableByteCount)
    }

    init(initialCapacity: Int = 16 * 1024) {
        let capacity = max(initialCapacity, 64)
        self.pointer = UnsafeMutableRawPointer.allocate(
            byteCount: capacity,
            alignment: MemoryLayout<UInt64>.alignment
        )
        self.capacity = capacity
    }

    deinit {
        pointer.deallocate()
    }

    func clear() {
        readerIndex = 0
        writerIndex = 0
    }

    func consume(_ count: Int) {
        precondition(count >= 0 && count <= readableByteCount)
        readerIndex += count
        if readerIndex == writerIndex {
            readerIndex = 0
            writerIndex = 0
        }
    }

    func append(_ bytes: UnsafeRawBufferPointer) {
        guard !bytes.isEmpty else { return }
        let writable = prepareWritable(minimumCapacity: bytes.count)
        writable.copyMemory(from: bytes)
        commitWritten(bytes.count)
    }

    func append(_ data: Data) {
        guard !data.isEmpty else { return }
        data.withUnsafeBytes { append($0) }
    }

    func append(_ bytes: [UInt8]) {
        bytes.withUnsafeBytes { append($0) }
    }

    func prepareWritable(minimumCapacity: Int) -> UnsafeMutableRawBufferPointer {
        let writable = capacity - writerIndex
        if writable < minimumCapacity {
            let readable = readableByteCount
            let needed = readable + minimumCapacity
            if readerIndex > 0 && needed <= capacity {
                compact()
            } else {
                grow(to: max(capacity * 2, needed))
            }
        }
        return UnsafeMutableRawBufferPointer(
            start: pointer.advanced(by: writerIndex),
            count: capacity - writerIndex
        )
    }

    func commitWritten(_ count: Int) {
        precondition(count >= 0 && writerIndex + count <= capacity)
        writerIndex += count
    }

    private func compact() {
        let readable = readableByteCount
        if readable > 0 && readerIndex > 0 {
            pointer.copyMemory(from: pointer.advanced(by: readerIndex), byteCount: readable)
        }
        readerIndex = 0
        writerIndex = readable
    }

    private func grow(to newCapacity: Int) {
        let readable = readableByteCount
        let newPointer = UnsafeMutableRawPointer.allocate(
            byteCount: newCapacity,
            alignment: MemoryLayout<UInt64>.alignment
        )
        if readable > 0 {
            newPointer.copyMemory(from: pointer.advanced(by: readerIndex), byteCount: readable)
        }
        pointer.deallocate()
        pointer = newPointer
        capacity = newCapacity
        readerIndex = 0
        writerIndex = readable
    }
}

/// FIFO async mutex. Acquire/release must be paired; not reentrant.
final class AsyncMutex: @unchecked Sendable {
    private struct State {
        var waiters: [CheckedContinuation<Void, Never>] = []
        var isLocked = false
    }

    private let state = OSAllocatedUnfairLock(initialState: State())

    func acquire() async {
        let acquired = state.withLock { current -> Bool in
            if !current.isLocked {
                current.isLocked = true
                return true
            }
            return false
        }
        if acquired { return }

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let stolen = state.withLock { current -> Bool in
                if !current.isLocked {
                    current.isLocked = true
                    return true
                }
                current.waiters.append(continuation)
                return false
            }
            if stolen {
                continuation.resume()
            }
        }
    }

    func release() {
        let next = state.withLock { current -> CheckedContinuation<Void, Never>? in
            if current.waiters.isEmpty {
                current.isLocked = false
                return nil
            }
            return current.waiters.removeFirst()
        }
        next?.resume()
    }
}

final class OnceResume: @unchecked Sendable {
    private let lock = OSAllocatedUnfairLock<CheckedContinuation<Void, Error>?>(initialState: nil)

    init(_ continuation: CheckedContinuation<Void, Error>) {
        lock.withLock { $0 = continuation }
    }

    func resume(with result: Result<Void, Error>) {
        let pending = lock.withLock { current -> CheckedContinuation<Void, Error>? in
            let value = current
            current = nil
            return value
        }
        pending?.resume(with: result)
    }
}

/// Big-endian UInt64 load from a raw buffer at `offset`.
@inline(__always)
func loadUInt64BE(_ buffer: UnsafeRawBufferPointer, offset: Int) -> UInt64 {
    var value: UInt64 = 0
    for index in 0..<8 {
        value = (value << 8) | UInt64(buffer[offset + index])
    }
    return value
}
