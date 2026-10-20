import Darwin
import Foundation
import Network
import os

/// Keeps PrizmX's own connections out of its own tunnel.
///
/// When the tunnel carries the default route ("route all traffic"), a socket
/// the engine opens would be routed back into the tunnel, accepted by the
/// TUN stack and dialed again, without end. Every outbound `NWConnection`
/// passes its parameters through `prepare(_:)`, which prohibits the tunnel
/// interface so the system picks the best other one (Wi-Fi, Ethernet, or a
/// more specific route of another VPN). In the extension, `admits(_:peer:)`
/// checks the result on `.ready` and `noteLoop(_:)` counts any connection
/// that still came back. The app is a client of the tunnel: its dials that
/// still go through it are only routed twice, never a loop.
///
/// Inactive by default, which leaves every dial exactly as before.
public enum TunnelEgress {
    /// The tunnel's own IPv4 address. The app finds PrizmX's utun by it.
    public static let tunnelAddress = IPv4Address(198, 18, 0, 1)

    /// A dial that `admits(_:peer:)` refused.
    public struct LoopError: LocalizedError, Sendable {
        public init() {}
        public var errorDescription: String? { "connection was routed back into the PrizmX tunnel" }
    }

    private struct State {
        /// The tunnel interface to keep off (`utun5`); nil when inactive.
        var name: String?
        /// That interface, once known. Until then every VPN-type interface
        /// is avoided rather than risk a loop.
        var interface: NWInterface?
        /// Finds `interface` by `name` for callers that only know the name.
        var monitor: NWPathMonitor?
        /// The app, a client of the tunnel: its dials to the tunnel's FakeIP
        /// range belong in the tunnel, and one that goes through the tunnel
        /// is routed twice, not looped. The extension is the tunnel.
        var isClient = false
        /// Interfaces ready connections used, for one log line each.
        var seen: Set<String> = []
        var loops = 0
        /// Dials `admits` refused, by local port and peer, so the tunnel can
        /// still recognize their flow after the socket is gone.
        var refused: [String: ContinuousClock.Instant] = [:]
    }

    /// How long a refused dial stays recognizable.
    private static let refusedTTL: Duration = .seconds(30)

    private static let state = OSAllocatedUnfairLock(uncheckedState: State())

    /// True while a tunnel interface is avoided.
    public static var isActive: Bool {
        state.withLockUnchecked { $0.name != nil }
    }

    /// Connections that came back through the avoided interface since it was
    /// set. Read twice to see whether loops are still happening.
    public static var loopCount: Int {
        state.withLockUnchecked { $0.loops }
    }

    /// Avoids `interface` (the extension's `virtualInterface`); nil stops.
    public static func avoid(_ interface: NWInterface?) {
        update(name: interface?.name, interface: interface, isClient: false)
    }

    /// Avoids the interface called `name`; nil stops. For the app, which
    /// knows only the name (`interfaceName(holding:)`) and still reaches
    /// FakeIP addresses through the tunnel.
    public static func avoid(interfaceNamed name: String?) {
        update(name: name, interface: nil, isClient: true)
    }

    /// Applies the avoidance to the parameters of an outbound connection.
    /// `destination`, when the dial targets a client-given address: in the
    /// app, a FakeIP one (a SOCKS client that resolved through FakeDNS) is
    /// left to reach the tunnel.
    public static func prepare(_ parameters: NWParameters, to destination: Endpoint.Host? = nil) {
        let (name, interface, isClient) = state.withLockUnchecked {
            ($0.name, $0.interface, $0.isClient)
        }
        guard name != nil else { return }
        if isClient, let destination, isTunnelRange(destination) { return }
        if let interface {
            parameters.prohibitedInterfaces = [interface]
        } else {
            parameters.prohibitedInterfaceTypes = [.other]
        }
    }

    /// Checked when a connection is ready: false when, in the extension, it
    /// still runs through the avoided interface. The caller then fails the
    /// dial, so the flow it would open in the tunnel never starts another
    /// round.
    public static func admits(_ path: NWPath?, peer: @autoclosure () -> String) -> Bool {
        guard let path, let used = path.availableInterfaces.first?.name else { return true }
        let key = refusedKey(path)
        let (looped, firstUse) = state.withLockUnchecked { state -> (Bool, Bool) in
            guard let name = state.name else { return (false, false) }
            if used == name {
                // The app's dial was prepared before the tunnel took the
                // default route, or targets FakeIP: routed twice, not looped.
                if state.isClient { return (false, false) }
                if let key {
                    let now = ContinuousClock.now
                    state.refused = state.refused.filter { now - $0.value < refusedTTL }
                    state.refused[key] = now
                }
                return (true, false)
            }
            return (false, state.seen.insert(used).inserted)
        }
        if firstUse {
            TunnelLog.write(.info, "egress: PrizmX connections leave via \(used)")
        }
        guard looped else { return true }
        noteLoop("\(peer()) went out through \(used)")
        return false
    }

    /// True for a tunnel flow whose dial `admits` refused (its socket may
    /// already be closed, so a socket-table lookup no longer finds it).
    public static func wasRefused(localPort: UInt16, remoteAddress: String, remotePort: UInt16) -> Bool {
        let key = refusedKey(localPort: localPort, remoteAddress: remoteAddress, remotePort: remotePort)
        return state.withLockUnchecked { state in
            state.refused[key].map { ContinuousClock.now - $0 < refusedTTL } ?? false
        }
    }

    private static func refusedKey(_ path: NWPath) -> String? {
        guard case .hostPort(_, let localPort)? = path.localEndpoint,
              case .hostPort(let remoteHost, let remotePort)? = path.remoteEndpoint
        else { return nil }
        return refusedKey(
            localPort: localPort.rawValue,
            remoteAddress: "\(remoteHost)",
            remotePort: remotePort.rawValue
        )
    }

    private static func refusedKey(localPort: UInt16, remoteAddress: String, remotePort: UInt16) -> String {
        // NW and the TUN stack spell addresses differently (brackets, scope).
        var address = remoteAddress.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if let scope = address.firstIndex(of: "%") { address = String(address[..<scope]) }
        if let v4 = IPv4Address(parsing: address) {
            address = v4.description
        } else if let v6 = IPv6Address(parsing: address) {
            address = v6.description
        }
        return "\(localPort)|\(address)|\(remotePort)"
    }

    /// A PrizmX connection that came back through the tunnel, seen either on
    /// the dialing side or as a flow arriving in the TUN stack.
    public static func noteLoop(_ description: @autoclosure () -> String) {
        let count = state.withLockUnchecked { state -> Int in
            state.loops += 1
            return state.loops
        }
        if count <= 10 || count.isMultiple(of: 100) {
            TunnelLog.write(.error, "egress loop #\(count): \(description())")
        }
    }

    /// Name of the interface holding `address`, e.g. the utun that has
    /// `tunnelAddress`.
    public static func interfaceName(holding address: IPv4Address) -> String? {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return nil }
        defer { freeifaddrs(list) }
        for entry in sequence(first: first, next: { $0.pointee.ifa_next }) {
            guard let socketAddress = entry.pointee.ifa_addr,
                  socketAddress.pointee.sa_family == sa_family_t(AF_INET)
            else { continue }
            let value = socketAddress.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                UInt32(bigEndian: $0.pointee.sin_addr.s_addr)
            }
            if value == address.rawValue {
                return String(cString: entry.pointee.ifa_name)
            }
        }
        return nil
    }

    /// The FakeIP ranges the tunnel answers for (`FakeIPAllocator`).
    static func isTunnelRange(_ host: Endpoint.Host) -> Bool {
        switch host {
        case .ipv4(let address):
            address.rawValue & 0xFFFF_0000 == tunnelAddress.rawValue & 0xFFFF_0000
        case .ipv6(let address):
            address.high == 0xfd11_4514_1919_6472
        case .domain:
            false
        }
    }

    private static func update(name: String?, interface: NWInterface?, isClient: Bool) {
        let (previousMonitor, changed) = state.withLockUnchecked { state -> (NWPathMonitor?, Bool) in
            guard state.name != name || (interface != nil && state.interface != interface) else {
                return (nil, false)
            }
            let previous = state.monitor
            state = State(name: name, interface: interface, isClient: isClient)
            return (previous, true)
        }
        previousMonitor?.cancel()
        guard changed else { return }
        guard let name else {
            TunnelLog.write(.info, "egress: no longer avoiding a tunnel interface")
            return
        }
        TunnelLog.write(.info, "egress: keeping PrizmX connections off \(name)")
        guard interface == nil else { return }
        // A path monitor lists the utun once it carries routes.
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { path in
            guard let match = path.availableInterfaces.first(where: { $0.name == name }) else { return }
            let resolved = state.withLockUnchecked { state -> NWPathMonitor? in
                guard state.name == name, state.interface == nil else { return nil }
                state.interface = match
                defer { state.monitor = nil }
                return state.monitor
            }
            guard let resolved else { return }
            resolved.cancel()
            TunnelLog.write(.info, "egress: found \(name); only it is avoided now")
        }
        let installed = state.withLockUnchecked { state -> Bool in
            guard state.name == name, state.interface == nil, state.monitor == nil else { return false }
            state.monitor = monitor
            return true
        }
        if installed {
            monitor.start(queue: .global(qos: .utility))
        }
    }
}
