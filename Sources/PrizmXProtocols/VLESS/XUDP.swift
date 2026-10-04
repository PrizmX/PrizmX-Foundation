import Foundation

/// XUDP: UDP for VLESS users with a flow (Vision), as one mux.cool session
/// carried by a VLESS `mux` request (Xray `common/xudp`).
///
/// Frames are `[meta length][meta][data length][data]`, meta
/// `[session 0x0000][status][option]…`:
/// - first datagram: status `New`, network UDP, the destination and an
///   8-byte global id (lets the server keep the UDP session, full cone);
/// - later datagrams: status `Keep` with their destination;
/// - downlink: `Keep` frames (address optional), `KeepAlive` is skipped,
///   anything else ends the session.
///
/// sing-box rejects plain VLESS UDP for Vision users; Xray accepts both.
public struct XUDPFraming: DatagramStreamFraming {
    private enum Status: UInt8 {
        case new = 0x01
        case keep = 0x02
        case end = 0x03
        case keepAlive = 0x04
    }

    private static let optionData: UInt8 = 0x01
    private static let networkUDP: UInt8 = 0x02

    private let globalID: [UInt8]
    private var opened = false
    private var leftover = Data()

    /// - Parameter globalID: 8 bytes identifying the client flow; random
    ///   per relay by default.
    public init(globalID: [UInt8] = (0..<8).map { _ in UInt8.random(in: 0...255) }) {
        precondition(globalID.count == 8, "XUDP global id is 8 bytes")
        self.globalID = globalID
    }

    public mutating func encode(_ payload: Data, to destination: Endpoint) throws -> Data {
        guard payload.count <= 0xFFFF else {
            throw VLESSError.truncated(expected: 0xFFFF, actual: payload.count)
        }
        let address: [UInt8]
        do {
            address = try VMessRequestHeader.address(destination)
        } catch {
            throw VLESSError.invalidAddress(destination)
        }
        var meta: [UInt8] = [0x00, 0x00]
        if opened {
            meta += [Status.keep.rawValue, Self.optionData, Self.networkUDP] + address
        } else {
            opened = true
            meta += [Status.new.rawValue, Self.optionData, Self.networkUDP] + address + globalID
        }
        var frame = Data(capacity: 4 + meta.count + payload.count)
        frame.append(contentsOf: [UInt8(meta.count >> 8), UInt8(meta.count & 0xFF)])
        frame.append(contentsOf: meta)
        frame.append(contentsOf: [UInt8(payload.count >> 8), UInt8(payload.count & 0xFF)])
        frame.append(payload)
        return frame
    }

    public mutating func decode(_ chunk: Data) throws -> [Data] {
        leftover.append(chunk)
        var datagrams: [Data] = []
        while true {
            let bytes = [UInt8](leftover.prefix(4))
            guard bytes.count >= 2 else { break }
            let metaLength = Int(bytes[0]) << 8 | Int(bytes[1])
            guard metaLength >= 4 else { throw XUDPError.sessionEnded }
            guard leftover.count >= 2 + metaLength else { break }
            let metaStart = leftover.startIndex + 2
            let status = leftover[metaStart + 2]
            let option = leftover[metaStart + 3]
            var frameEnd = 2 + metaLength
            var payload: Data?
            if option & Self.optionData != 0 {
                guard leftover.count >= frameEnd + 2 else { break }
                let lengthAt = leftover.startIndex + frameEnd
                let length = Int(leftover[lengthAt]) << 8 | Int(leftover[lengthAt + 1])
                guard leftover.count >= frameEnd + 2 + length else { break }
                payload = leftover.subdata(in: (lengthAt + 2)..<(lengthAt + 2 + length))
                frameEnd += 2 + length
            }
            leftover.removeFirst(frameEnd)
            switch Status(rawValue: status) {
            case .keep:
                if let payload, !payload.isEmpty { datagrams.append(payload) }
            case .keepAlive:
                continue
            case .new, .end, nil:
                // Xray ends the session on anything but Keep / KeepAlive.
                if datagrams.isEmpty { throw XUDPError.sessionEnded }
                return datagrams
            }
        }
        return datagrams
    }
}

@frozen
public enum XUDPError: Error, Equatable, Sendable {
    /// The server ended (or broke) the mux session.
    case sessionEnded
}
