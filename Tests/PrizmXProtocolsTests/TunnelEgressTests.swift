import Foundation
import Network
import os
import Testing
@testable import PrizmXProtocols

/// `TunnelEgress` is process-wide: each test leaves it inactive again.
@Suite(.serialized)
struct TunnelEgressTests {
    @Test func inactiveLeavesParametersAlone() {
        TunnelEgress.avoid(nil)
        let parameters = NWParameters.tcp
        TunnelEgress.prepare(parameters)
        #expect(!TunnelEgress.isActive)
        #expect(parameters.prohibitedInterfaceTypes?.isEmpty ?? true)
        #expect(parameters.prohibitedInterfaces?.isEmpty ?? true)
    }

    /// Until the named interface is found, every VPN-type interface is
    /// avoided rather than risk the tunnel.
    @Test func unresolvedTunnelAvoidsEveryVPNInterface() {
        TunnelEgress.avoid(interfaceNamed: "utun-missing")
        defer { TunnelEgress.avoid(nil) }
        #expect(TunnelEgress.isActive)
        let parameters = NWParameters.udp
        TunnelEgress.prepare(parameters)
        #expect(parameters.prohibitedInterfaceTypes == [.other])
    }

    /// The app still reaches FakeIP addresses through the tunnel.
    @Test func appDialsToFakeIPStayInTheTunnel() {
        TunnelEgress.avoid(interfaceNamed: "utun-missing")
        defer { TunnelEgress.avoid(nil) }
        let fake = NWParameters.tcp
        TunnelEgress.prepare(fake, to: .ipv4(IPv4Address(198, 18, 3, 4)))
        #expect(fake.prohibitedInterfaceTypes?.isEmpty ?? true)
        let real = NWParameters.tcp
        TunnelEgress.prepare(real, to: .ipv4(IPv4Address(203, 0, 113, 1)))
        #expect(real.prohibitedInterfaceTypes == [.other])
    }

    @Test func findsTheInterfaceHoldingAnAddress() {
        #expect(TunnelEgress.interfaceName(holding: IPv4Address(127, 0, 0, 1)) == "lo0")
        #expect(TunnelEgress.interfaceName(holding: IPv4Address(192, 0, 2, 77)) == nil)
    }

    /// The guarantee the tunnel relies on: with an interface avoided, no dial
    /// comes back usable over it. Loopback stands in for the utun: the dial
    /// is either kept off it, or refused once ready (and counted as a loop).
    @Test func aDialOverTheAvoidedInterfaceIsNeverUsable() async throws {
        TunnelEgress.avoid(nil)
        let listener = try NWListener(using: .tcp)
        listener.newConnectionHandler = { $0.start(queue: .global()) }
        let port = try await Self.start(listener)
        defer { listener.cancel() }

        let open = try #require(await Self.readyPath(port: port))
        let loopback = try #require(open.availableInterfaces.first)
        #expect(loopback.type == .loopback)
        #expect(TunnelEgress.admits(open, peer: "test"))

        TunnelEgress.avoid(loopback)
        defer { TunnelEgress.avoid(nil) }
        // The extension is the tunnel: even a FakeIP dial must stay off it.
        let fake = NWParameters.tcp
        TunnelEgress.prepare(fake, to: .ipv4(IPv4Address(198, 18, 3, 4)))
        #expect(fake.prohibitedInterfaces == [loopback])
        let loopsBefore = TunnelEgress.loopCount
        if let avoided = await Self.readyPath(port: port) {
            #expect(!TunnelEgress.admits(avoided, peer: "test"))
            #expect(TunnelEgress.loopCount == loopsBefore + 1)
        }
    }

    /// Loopback stands in for the utun. In the extension a refused dial
    /// stays recognizable after its socket closes, for the tunnel-side
    /// check; in the app (a client of the tunnel) nothing is refused.
    @Test func extensionRemembersRefusedDialsAndTheAppRefusesNone() async throws {
        TunnelEgress.avoid(nil)
        let listener = try NWListener(using: .tcp)
        listener.newConnectionHandler = { $0.start(queue: .global()) }
        let port = try await Self.start(listener)
        defer { listener.cancel() }
        let path = try #require(await Self.readyPath(port: port))
        let loopback = try #require(path.availableInterfaces.first)
        defer { TunnelEgress.avoid(nil) }

        TunnelEgress.avoid(interfaceNamed: loopback.name)
        let loopsBefore = TunnelEgress.loopCount
        #expect(TunnelEgress.admits(path, peer: "app"))
        #expect(TunnelEgress.loopCount == loopsBefore)

        TunnelEgress.avoid(loopback)
        #expect(!TunnelEgress.admits(path, peer: "extension"))
        guard case .hostPort(_, let local)? = path.localEndpoint else {
            Issue.record("no local endpoint")
            return
        }
        #expect(TunnelEgress.wasRefused(localPort: local.rawValue, remoteAddress: "127.0.0.1", remotePort: port.rawValue))
        #expect(!TunnelEgress.wasRefused(localPort: local.rawValue, remoteAddress: "127.0.0.2", remotePort: port.rawValue))
    }

    @Test func loopsAreCounted() {
        TunnelEgress.avoid(interfaceNamed: "utun-missing")
        defer { TunnelEgress.avoid(nil) }
        let before = TunnelEgress.loopCount
        TunnelEgress.noteLoop("test")
        #expect(TunnelEgress.loopCount == before + 1)
    }

    private static func start(_ listener: NWListener) async throws -> NWEndpoint.Port {
        try await withCheckedThrowingContinuation { continuation in
            let once = OSAllocatedUnfairLock<CheckedContinuation<NWEndpoint.Port, Error>?>(initialState: continuation)
            let finish: @Sendable (Result<NWEndpoint.Port, Error>) -> Void = { result in
                once.withLock { current in
                    defer { current = nil }
                    return current
                }?.resume(with: result)
            }
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(.success(listener.port ?? 0))
                case .failed(let error): finish(.failure(error))
                default: break
                }
            }
            listener.start(queue: .global())
        }
    }

    /// The path of a prepared dial to 127.0.0.1:`port` once ready; nil when
    /// it never gets there.
    private static func readyPath(port: NWEndpoint.Port) async -> NWPath? {
        let parameters = NWParameters.tcp
        TunnelEgress.prepare(parameters)
        let connection = NWConnection(host: "127.0.0.1", port: port, using: parameters)
        defer { connection.cancel() }
        let ready = await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
            let once = OSAllocatedUnfairLock<CheckedContinuation<Bool, Never>?>(initialState: continuation)
            let finish: @Sendable (Bool) -> Void = { value in
                once.withLock { current in
                    defer { current = nil }
                    return current
                }?.resume(returning: value)
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(true)
                case .failed, .cancelled, .waiting: finish(false)
                default: break
                }
            }
            connection.start(queue: .global())
            Task {
                try? await Task.sleep(for: .seconds(2))
                finish(false)
            }
        }
        return ready ? connection.currentPath : nil
    }
}
