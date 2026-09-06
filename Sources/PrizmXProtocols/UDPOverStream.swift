import Foundation
import Network

extension NWConnection {
    /// One datagram (or chunk) from a started UDP connection.
    ///
    /// Returns `nil` on completion or error so pump loops can `guard let`.
    /// Used by the TUN UDP relay.
    public func receiveDatagram(maximumLength: Int = 64 * 1024) async -> Data? {
        await withCheckedContinuation { continuation in
            receive(minimumIncompleteLength: 1, maximumLength: maximumLength) { data, _, isComplete, _ in
                if isComplete && (data == nil || data?.isEmpty == true) {
                    continuation.resume(returning: nil)
                } else {
                    continuation.resume(returning: data ?? Data())
                }
            }
        }
    }
}

/// Length-prefixed framing for UDP-over-TCP relay (VLESS `udp` command):
/// each datagram is `[uint16 length][payload]` on the wire.
public enum UDPOverStreamFrame {
    /// Frames one datagram for the wire.
    public static func encode(_ payload: Data) -> Data {
        var frame = Data(count: 2 + payload.count)
        frame[0] = UInt8(truncatingIfNeeded: payload.count >> 8)
        frame[1] = UInt8(truncatingIfNeeded: payload.count)
        if !payload.isEmpty {
            frame.replaceSubrange(2..<frame.count, with: payload)
        }
        return frame
    }

    /// Incremental decoder: feed stream bytes, drain complete datagrams.
    public struct Decoder {
        private var leftover = Data()

        public init() {}

        /// Appends `chunk` and returns every datagram now complete.
        public mutating func feed(_ chunk: Data) -> [Data] {
            leftover.append(chunk)
            var datagrams: [Data] = []
            while leftover.count >= 2 {
                let length = Int(leftover[0]) << 8 | Int(leftover[1])
                guard leftover.count >= 2 + length else { break }
                datagrams.append(leftover.subdata(in: 2..<(2 + length)))
                leftover.removeSubrange(0..<(2 + length))
            }
            return datagrams
        }
    }
}
