import Foundation

/// Transport used for process attribution (TCP / UDP only).
public enum FlowTransport: UInt8, Sendable, Hashable, Codable, Equatable {
    case tcp = 6
    case udp = 17
}

/// Process that owns a local socket. `accountingKey` is the stable
/// ranking identity (bundle ID when the owner is a GUI app).
public struct FlowAttribution: Sendable, Hashable, Codable, Equatable {
    public var pid: Int32
    public var processName: String
    public var bundleID: String?
    public var executablePath: String?

    public init(
        pid: Int32,
        processName: String,
        bundleID: String? = nil,
        executablePath: String? = nil
    ) {
        self.pid = pid
        self.processName = processName
        self.bundleID = bundleID
        self.executablePath = executablePath
    }

    /// Ledger / ranking key. Prefer bundle ID so Safari helper processes
    /// can still collapse under the app when we later join by identifier.
    public var accountingKey: String {
        if let bundleID, !bundleID.isEmpty { return bundleID }
        return processName
    }
}

/// Looks up which process owns a 5-tuple. Implementations are platform-
/// specific; iOS / tvOS pass `nil` and attribution stays empty.
///
/// TCP: call `attribute` on SYN and `forget` on FIN/RST/timeout.
/// UDP: `attribute` is cache-first and populates on miss.
public protocol FlowAttributing: Sendable {
    func attribute(
        transport: FlowTransport,
        localAddress: String,
        localPort: UInt16,
        remoteAddress: String,
        remotePort: UInt16
    ) -> FlowAttribution?

    func forget(
        transport: FlowTransport,
        localPort: UInt16,
        remoteAddress: String,
        remotePort: UInt16
    )
}

extension FlowAttributing {
    public func forget(
        transport: FlowTransport,
        localPort: UInt16,
        remoteAddress: String,
        remotePort: UInt16
    ) {}
}
