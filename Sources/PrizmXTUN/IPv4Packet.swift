import PrizmXProtocols

/// IP layer protocol numbers (only the ones commonly used by proxy / TUN
/// scenarios).
@frozen
public enum IPProtocolNumber: UInt8, Sendable, CaseIterable {
    case icmp = 1
    case tcp = 6
    case udp = 17
    case icmpv6 = 58
}

/// Raw IP packet parsing errors.
@frozen
public enum TUNPacketError: Error, Equatable, Sendable {
    /// The buffer is shorter than the header declares (or the minimum header).
    case truncated(expected: Int, actual: Int)
    /// Unsupported IP version (currently only 4 is supported; IPv6 is a
    /// future stub).
    case unsupportedIPVersion(UInt8)
    /// Invalid IHL field (legal range is 20...60 bytes).
    case invalidHeaderLength(Int)
    /// totalLength is smaller than the header length.
    case invalidTotalLength(UInt16)
}
