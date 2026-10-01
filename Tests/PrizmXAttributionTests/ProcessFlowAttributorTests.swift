import Darwin
import Foundation
import Testing
@testable import PrizmXAttribution
import PrizmXAttributionC
import PrizmXCore

private func v4(_ text: String) -> SocketAddress? { SocketAddress(text) }

private func owner(
    pid: Int32,
    _ transport: FlowTransport,
    lport: UInt16,
    remote: String = "",
    rport: UInt16
) -> SocketOwner {
    SocketOwner(
        pid: pid,
        transport: transport,
        localPort: lport,
        remotePort: rport,
        localAddress: v4("198.18.0.1"),
        remoteAddress: SocketAddress(remote)
    )
}

private final class TestClock: @unchecked Sendable {
    var now = ContinuousClock.now
}

/// Serialized: several tests read this process's live socket table, and one
/// spawns a child, which briefly holds copies of our descriptors.
@Suite(.serialized)
struct ProcessFlowAttributorTests {
    @Test func tcpMatchesTheExactRemoteNeverJustThePort() {
        let me = getpid()
        let table = FakeSocketTable(owners: [
            owner(pid: me, .tcp, lport: 52_000, remote: "198.18.0.3", rport: 443),
            owner(pid: 1, .tcp, lport: 52_000, remote: "198.18.0.9", rport: 443),
        ])
        let attributor = ProcessFlowAttributor(table: table, ownPID: 2, now: { ContinuousClock.now })
        let hit = attributor.attribute(
            transport: .tcp, localAddress: "198.18.0.1", localPort: 52_000,
            remoteAddress: "198.18.0.3", remotePort: 443
        )
        #expect(hit?.pid == me)
        #expect(hit?.processName.isEmpty == false)
        // Same local port, different peer: no "first socket on the port" guess.
        #expect(attributor.attribute(
            transport: .tcp, localAddress: "198.18.0.1", localPort: 52_000,
            remoteAddress: "198.18.0.4", remotePort: 443
        ) == nil)
    }

    @Test func mixedPortMatchesOnTheListenPortWithoutAnAddress() {
        let me = getpid()
        let table = FakeSocketTable(owners: [
            owner(pid: me, .tcp, lport: 52_100, remote: "127.0.0.1", rport: 7_890),
        ])
        let attributor = ProcessFlowAttributor(table: table, ownPID: 2, now: { ContinuousClock.now })
        #expect(attributor.attribute(
            transport: .tcp, localAddress: "127.0.0.1", localPort: 52_100,
            remoteAddress: "", remotePort: 7_890
        )?.pid == me)
        #expect(attributor.attribute(
            transport: .tcp, localAddress: "127.0.0.1", localPort: 52_100,
            remoteAddress: "", remotePort: 7_891
        ) == nil)
    }

    @Test func udpPrefersConnectedThenUnambiguousUnconnected() {
        let me = getpid()
        let table = FakeSocketTable(owners: [
            owner(pid: me, .udp, lport: 53_000, remote: "8.8.8.8", rport: 53),
            owner(pid: me, .udp, lport: 53_100, rport: 0),
            owner(pid: me, .udp, lport: 53_200, rport: 0),
            owner(pid: 1, .udp, lport: 53_200, rport: 0),
        ])
        let attributor = ProcessFlowAttributor(table: table, ownPID: 2, now: { ContinuousClock.now })
        func lookup(_ port: UInt16, _ remote: String, _ rport: UInt16) -> Int32? {
            attributor.attribute(
                transport: .udp, localAddress: "", localPort: port,
                remoteAddress: remote, remotePort: rport
            )?.pid
        }
        #expect(lookup(53_000, "8.8.8.8", 53) == me)
        // Connected socket to another peer: not this flow.
        #expect(lookup(53_000, "1.1.1.1", 53) == nil)
        // Unconnected socket (sendto): one owner on the port.
        #expect(lookup(53_100, "1.1.1.1", 443) == me)
        // Two processes share the port unconnected: ambiguous.
        #expect(lookup(53_200, "1.1.1.1", 443) == nil)
    }

    @Test func rereadsWhenTheSnapshotPredatesTheRequest() {
        let me = getpid()
        let clock = TestClock()
        let table = CountingSocketTable(owners: [])
        let attributor = ProcessFlowAttributor(table: table, ownPID: 2, now: { clock.now })
        func lookup(_ port: UInt16) -> Int32? {
            attributor.attribute(
                transport: .tcp, localAddress: "", localPort: port,
                remoteAddress: "198.18.0.3", remotePort: 443
            )?.pid
        }
        #expect(lookup(52_010) == nil)
        #expect(table.snapshots == 1)
        // The client opens a socket after that read; its lookup comes later.
        table.owners = [owner(pid: me, .tcp, lport: 52_010, remote: "198.18.0.3", rport: 443)]
        clock.now += .milliseconds(5)
        #expect(lookup(52_010) == me)
        #expect(table.snapshots == 2)
    }

    @Test func aBurstOfLookupsSharesOneRead() {
        let me = getpid()
        let clock = TestClock()
        let table = CountingSocketTable(owners: (0..<20).map {
            owner(pid: me, .tcp, lport: 52_200 + UInt16($0), remote: "198.18.0.3", rport: 443)
        })
        let attributor = ProcessFlowAttributor(table: table, ownPID: 2, now: { clock.now })
        for index in 0..<20 {
            clock.now += .milliseconds(1)
            #expect(attributor.attribute(
                transport: .tcp, localAddress: "", localPort: 52_200 + UInt16(index),
                remoteAddress: "198.18.0.3", remotePort: 443
            )?.pid == me)
        }
        // Exact hits within the reuse window never re-read the table.
        #expect(table.snapshots == 1)
        // A miss re-reads once (the socket may be newer than the snapshot)…
        #expect(attributor.attribute(
            transport: .tcp, localAddress: "", localPort: 60_000,
            remoteAddress: "198.18.0.3", remotePort: 443
        ) == nil)
        #expect(table.snapshots == 2)
        // …and a snapshot older than the reuse window is not trusted.
        clock.now += .seconds(2)
        _ = attributor.attribute(
            transport: .tcp, localAddress: "", localPort: 52_200,
            remoteAddress: "198.18.0.3", remotePort: 443
        )
        #expect(table.snapshots == 3)
    }

    @Test func skipsOwnPID() {
        let pid = getpid()
        let table = FakeSocketTable(owners: [owner(pid: pid, .tcp, lport: 52_001, remote: "1.1.1.1", rport: 443)])
        let attributor = ProcessFlowAttributor(table: table, ownPID: pid, now: { ContinuousClock.now })
        #expect(attributor.attribute(
            transport: .tcp, localAddress: "", localPort: 52_001,
            remoteAddress: "1.1.1.1", remotePort: 443
        ) == nil)
    }

    @Test func socketAddressNormalizesTextForms() {
        #expect(SocketAddress("1.2.3.4") == .v4(0x0102_0304))
        #expect(SocketAddress("::ffff:1.2.3.4") == .v4(0x0102_0304))
        #expect(SocketAddress("fe80::1%en0") == .v6(0xFE80_0000_0000_0000, 1))
        #expect(SocketAddress("") == nil)
        #expect(SocketAddress("0.0.0.0") == nil)
        #expect(SocketAddress("::") == nil)
        #expect(SocketAddress("example.com") == nil)
    }

    @Test func accountingKeyPrefersBundleID() {
        let withBundle = FlowAttribution(
            pid: 1,
            processName: "Safari",
            bundleID: "com.apple.Safari"
        )
        #expect(withBundle.accountingKey == "com.apple.Safari")
        let daemon = FlowAttribution(pid: 2, processName: "mDNSResponder")
        #expect(daemon.accountingKey == "mDNSResponder")
    }

    // MARK: - Real kernel socket table

    /// Connects a loopback TCP pair and returns (client local port, server port).
    private func loopbackPair(ipv6: Bool) throws -> (client: Int32, listener: Int32, accepted: Int32, lport: UInt16, rport: UInt16) {
        let family = ipv6 ? AF_INET6 : AF_INET
        let listener = socket(family, SOCK_STREAM, 0)
        let client = socket(family, SOCK_STREAM, 0)
        try #require(listener >= 0 && client >= 0)
        var storage = sockaddr_storage()
        var length: socklen_t
        if ipv6 {
            var addr = sockaddr_in6()
            addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_addr = in6addr_loopback
            length = socklen_t(MemoryLayout<sockaddr_in6>.size)
            withUnsafeBytes(of: addr) { raw in
                withUnsafeMutableBytes(of: &storage) { $0.copyMemory(from: raw) }
            }
        } else {
            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
            length = socklen_t(MemoryLayout<sockaddr_in>.size)
            withUnsafeBytes(of: addr) { raw in
                withUnsafeMutableBytes(of: &storage) { $0.copyMemory(from: raw) }
            }
        }
        try withUnsafeMutablePointer(to: &storage) { pointer in
            try pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                try #require(bind(listener, sa, length) == 0)
                try #require(listen(listener, 1) == 0)
                var bound = length
                getsockname(listener, sa, &bound)
                try #require(connect(client, sa, length) == 0)
            }
        }
        let accepted = accept(listener, nil, nil)
        try #require(accepted >= 0)
        var local = sockaddr_storage()
        var localLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
        var server = sockaddr_storage()
        var serverLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
        withUnsafeMutablePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(client, $0, &localLength) }
        }
        withUnsafeMutablePointer(to: &server) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(listener, $0, &serverLength) }
        }
        func port(_ storage: sockaddr_storage) -> UInt16 {
            withUnsafeBytes(of: storage) { UInt16($0[2]) << 8 | UInt16($0[3]) }
        }
        return (client, listener, accepted, port(local), port(server))
    }

    @Test(arguments: [false, true])
    func socketTableDecodesLoopbackAddresses(ipv6: Bool) throws {
        let pair = try loopbackPair(ipv6: ipv6)
        defer {
            close(pair.accepted)
            close(pair.client)
            close(pair.listener)
        }
        let owners = LibprocSocketTable().snapshot(skipPID: 0)
        let row = owners.first {
            $0.transport == .tcp && $0.localPort == pair.lport && $0.remotePort == pair.rport
        }
        let found = try #require(row, "client socket missing from the table")
        let loopback: SocketAddress = ipv6 ? .v6(0, 1) : .v4(0x7F00_0001)
        #expect(found.pid == getpid())
        #expect(found.remoteAddress == loopback)
        #expect(found.localAddress == loopback)

        // The table above may come from the libproc fallback (a non-root
        // caller only sees its own sockets in pcblist_n). The unfiltered
        // parse still lists our own socket, so check the xinpcb_n decoder
        // (the path the root extension uses) on it directly.
        var rows = [prizmx_socket_row](repeating: prizmx_socket_row(), count: 8_192)
        let count = rows.withUnsafeMutableBufferPointer {
            Int(prizmx_list_pcblist_n_raw($0.baseAddress, Int32($0.count), 0))
        }
        let pcb = try #require(rows.prefix(max(0, count)).first {
            $0.transport == 6 && $0.local_port == pair.lport && $0.remote_port == pair.rport
        }, "pcblist_n did not list our own socket")
        #expect(pcb.pid == getpid())
        #expect((pcb.is_ipv6 != 0) == ipv6)
        #expect(withUnsafeBytes(of: pcb.remote_addr) { SocketAddress(bytes: $0, isIPv6: ipv6) } == loopback)
        #expect(withUnsafeBytes(of: pcb.local_addr) { SocketAddress(bytes: $0, isIPv6: ipv6) } == loopback)

        // End to end through the attributor with the real table.
        let exact = ProcessFlowAttributor(table: LibprocSocketTable(), ownPID: 0, now: { ContinuousClock.now })
        #expect(exact.attribute(
            transport: .tcp, localAddress: "", localPort: pair.lport,
            remoteAddress: ipv6 ? "::1" : "127.0.0.1", remotePort: pair.rport
        )?.pid == getpid())
    }

    @Test func ownProcessSocketsCountOnlyWhenIncluded() {
        let me = getpid()
        let table = FakeSocketTable(owners: [
            owner(pid: me, .tcp, lport: 52_200, remote: "127.0.0.1", rport: 7_890),
        ])
        func lookup(_ attributor: ProcessFlowAttributor) -> Int32? {
            attributor.attribute(
                transport: .tcp, localAddress: "127.0.0.1", localPort: 52_200,
                remoteAddress: "", remotePort: 7_890
            )?.pid
        }
        // The tunnel never attributes a flow to itself.
        #expect(lookup(ProcessFlowAttributor(table: table, ownPID: me, now: { ContinuousClock.now })) == nil)
        // The in-app listener counts the app's own requests.
        #expect(lookup(ProcessFlowAttributor(
            table: table, ownPID: me, includesOwnProcess: true, now: { ContinuousClock.now }
        )) == me)
    }

    @Test func loopbackClientsListOnlyTheListenersPeers() {
        let me = getpid()
        func client(_ lport: UInt16, remote: String, rport: UInt16) -> SocketOwner {
            SocketOwner(
                pid: me, transport: .tcp, localPort: lport, remotePort: rport,
                localAddress: SocketAddress(remote), remoteAddress: SocketAddress(remote)
            )
        }
        let table = FakeSocketTable(owners: [
            client(52_300, remote: "127.0.0.1", rport: 7_890),
            client(52_301, remote: "::1", rport: 7_891),
            client(52_302, remote: "192.168.1.5", rport: 7_890),
            client(52_303, remote: "127.0.0.1", rport: 8_080),
        ])
        let attributor = ProcessFlowAttributor(table: table, ownPID: 2, now: { ContinuousClock.now })
        let clients = attributor.loopbackClients(listenPorts: [7_890, 7_891])
        #expect(clients.map(\.clientPort).sorted() == [52_300, 52_301])
        #expect(clients.allSatisfy { $0.attribution.pid == me })
        #expect(attributor.loopbackClients(listenPorts: []).isEmpty)
    }

    @Test func socketTableListsOneProcess() throws {
        let pair = try loopbackPair(ipv6: false)
        defer {
            close(pair.accepted)
            close(pair.client)
            close(pair.listener)
        }
        let owners = LibprocSocketTable().sockets(ofPID: getpid())
        #expect(owners.contains {
            $0.transport == .tcp && $0.localPort == pair.lport && $0.remotePort == pair.rport
        })
        #expect(owners.allSatisfy { $0.pid == getpid() })
    }

    @Test func versionNamedExecutablesUseTheirLaunchName() {
        #expect(ProcessIdentityResolver.readableName("2.1.286", launchName: "claude") == "claude")
        #expect(ProcessIdentityResolver.readableName("2.1.286", launchName: nil) == "2.1.286")
        #expect(ProcessIdentityResolver.readableName("2.1.286", launchName: "2.1.286") == "2.1.286")
        #expect(ProcessIdentityResolver.readableName("node", launchName: "claude") == "node")
    }

    @Test func resolveNamesAVersionedBinaryByItsLink() throws {
        // Like Claude Code: `claude` links to `…/versions/2.1.286`.
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let binary = dir.appendingPathComponent("9.9.9")
        try FileManager.default.copyItem(atPath: "/bin/sleep", toPath: binary.path)
        let link = dir.appendingPathComponent("sleeper")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: binary)
        let process = Process()
        process.executableURL = link
        process.arguments = ["30"]
        try process.run()
        defer {
            process.terminate()
            process.waitUntilExit()
        }
        let identity = try #require(ProcessIdentityResolver().resolve(pid: process.processIdentifier))
        #expect(identity.processName == "sleeper")
    }

    @Test func pcblistNFindsSelfPID() throws {
        let pair = try loopbackPair(ipv6: false)
        defer {
            close(pair.accepted)
            close(pair.client)
            close(pair.listener)
        }
        let found = PCBListLookup.findPID(forLocalPort: pair.lport, isTCP: true)
        // A filtered pcblist_n (only the caller's sockets) trips the
        // claimed/actual guard and reports nothing; otherwise it finds us.
        var rows = [prizmx_socket_row](repeating: prizmx_socket_row(), count: 4096)
        let rowCount = rows.withUnsafeMutableBufferPointer { buffer in
            prizmx_list_pcblist_n(buffer.baseAddress, Int32(buffer.count), 0)
        }
        if rowCount > 0 {
            #expect(found == getpid())
        }
    }
}

private struct FakeSocketTable: SocketTableReading {
    var owners: [SocketOwner]

    func snapshot(skipPID: Int32) -> [SocketOwner] {
        owners.filter { $0.pid != skipPID }
    }

    func sockets(ofPID pid: Int32) -> [SocketOwner] {
        owners.filter { $0.pid == pid }
    }
}

private final class CountingSocketTable: SocketTableReading, @unchecked Sendable {
    var owners: [SocketOwner]
    var snapshots = 0

    init(owners: [SocketOwner]) {
        self.owners = owners
    }

    func snapshot(skipPID: Int32) -> [SocketOwner] {
        snapshots += 1
        return owners.filter { $0.pid != skipPID }
    }
}
