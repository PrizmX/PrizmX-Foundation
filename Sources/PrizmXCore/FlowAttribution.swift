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

/// Looks up which process owns a socket, at flow open. Implementations are
/// platform-specific; iOS / tvOS pass `nil` and attribution stays empty.
///
/// `remoteAddress` / `remotePort` are the destination as the client's socket
/// sees it (TUN: the wire IP, FakeIP included; mixed-port: its listener, with
/// an empty address meaning "any").
public protocol FlowAttributing: Sendable {
    func attribute(
        transport: FlowTransport,
        localAddress: String,
        localPort: UInt16,
        remoteAddress: String,
        remotePort: UInt16
    ) -> FlowAttribution?

    /// Second chance for a mixed-port flow `attribute` could not place,
    /// answered from another process's view of the socket table (the root
    /// tunnel extension, for the sandboxed app). `since` is when the first
    /// lookup ran; only a view taken after it surely holds the socket.
    func attributeLate(
        transport: FlowTransport,
        localPort: UInt16,
        remotePort: UInt16,
        since: Date
    ) async -> FlowAttribution?
}

/// A local client socket of a mixed-port listener (`listenPort`), as the
/// root tunnel extension sees it. The sandboxed app cannot read the sockets
/// of root / system-account processes, so it looks them up here.
public struct LoopbackClient: Sendable, Hashable, Codable, Equatable {
    public var clientPort: UInt16
    public var listenPort: UInt16
    public var attribution: FlowAttribution

    public init(clientPort: UInt16, listenPort: UInt16, attribution: FlowAttribution) {
        self.clientPort = clientPort
        self.listenPort = listenPort
        self.attribution = attribution
    }
}

extension FlowAttributing {
    public func attributeLate(
        transport: FlowTransport,
        localPort: UInt16,
        remotePort: UInt16,
        since: Date
    ) async -> FlowAttribution? {
        nil
    }

    /// Flow-open lookup; the same as `attribute`.
    public func attributeFresh(
        transport: FlowTransport,
        localAddress: String,
        localPort: UInt16,
        remoteAddress: String,
        remotePort: UInt16
    ) -> FlowAttribution? {
        attribute(
            transport: transport,
            localAddress: localAddress,
            localPort: localPort,
            remoteAddress: remoteAddress,
            remotePort: remotePort
        )
    }
}
