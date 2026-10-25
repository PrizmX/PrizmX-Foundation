import Foundation
import PrizmXProtocols

#if os(macOS)
/// XPC between the app (client) and the Packet Tunnel system extension
/// (listener). The extension publishes `machServiceName` through
/// `NEMachServiceName` in its Info.plist; the app connects with `.privileged`
/// because the extension lives in the system domain. Only a system extension
/// can publish it (an app extension cannot), so the Mac App Store build keeps
/// `sendProviderMessage`.
///
/// The extension keeps running without the app, which simply has no client to
/// serve; the app finds the service only while the tunnel is up.
@objc public protocol TunnelXPCService {
    /// JSON `TrafficSnapshot` of the last second, or nil until the engine is up.
    func fetchMetrics(reply: @escaping (Data?) -> Void)

    /// JSON `[LoopbackClient]`: the local clients of the app's mixed-port
    /// listeners, read from the socket table when asked. Root sees the
    /// sockets of every process; the app does not. nil until the tunnel
    /// is up.
    func fetchProxyClients(reply: @escaping (Data?) -> Void)
}

public enum TunnelXPC: Sendable {
    /// A child of the app group, as XPC from a sandboxed client requires;
    /// repeated as `NEMachServiceName` in `PacketTunnel/Info.plist`.
    public static let machServiceName = "\(PrizmXAppGroup.identifier).xpc"

    private static let teamID = "N49M3Z72D3"

    /// What the extension requires of the app that connects.
    public static let appRequirement = requirement(identifier: "app.prizmx.macos")

    /// What the app requires of the service it connected to.
    public static let tunnelRequirement = requirement(identifier: "app.prizmx.macos.packet-tunnel")

    private static func requirement(identifier: String) -> String {
        "anchor apple generic and identifier \"\(identifier)\" "
            + "and certificate leaf[subject.OU] = \"\(teamID)\""
    }
}
#endif
