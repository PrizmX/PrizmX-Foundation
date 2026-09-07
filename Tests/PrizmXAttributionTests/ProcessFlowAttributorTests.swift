import Darwin
import Testing
@testable import PrizmXAttribution
import PrizmXCore

struct ProcessFlowAttributorTests {
    @Test func tcpMatchesLocalPort() {
        let pid = getpid()
        let table = FakeSocketTable(owners: [
            SocketOwner(
                pid: pid,
                transport: .tcp,
                localPort: 52_000,
                remotePort: 443,
                localAddress: "10.0.0.2",
                remoteAddress: "1.1.1.1"
            )
        ])
        let attributor = ProcessFlowAttributor(table: table, ownPID: 1, now: { ContinuousClock.now })
        let hit = attributor.attribute(
            transport: .tcp,
            localAddress: "10.0.0.2",
            localPort: 52_000,
            remoteAddress: "1.1.1.1",
            remotePort: 443
        )
        #expect(hit?.pid == pid)
        #expect(hit?.processName.isEmpty == false)
    }

    @Test func udpRequiresRemoteTriple() {
        let pid = getpid()
        let table = FakeSocketTable(owners: [
            SocketOwner(
                pid: pid,
                transport: .udp,
                localPort: 53_000,
                remotePort: 53,
                localAddress: "10.0.0.2",
                remoteAddress: "8.8.8.8"
            )
        ])
        let attributor = ProcessFlowAttributor(table: table, ownPID: 1, now: { ContinuousClock.now })
        let miss = attributor.attribute(
            transport: .udp,
            localAddress: "10.0.0.2",
            localPort: 53_000,
            remoteAddress: "1.1.1.1",
            remotePort: 9_999
        )
        #expect(miss == nil)
        let hit = attributor.attribute(
            transport: .udp,
            localAddress: "10.0.0.2",
            localPort: 53_000,
            remoteAddress: "8.8.8.8",
            remotePort: 53
        )
        #expect(hit?.pid == pid)
    }

    @Test func skipsOwnPID() {
        let pid = getpid()
        let table = FakeSocketTable(owners: [
            SocketOwner(
                pid: pid,
                transport: .tcp,
                localPort: 52_001,
                remotePort: 443,
                localAddress: "10.0.0.2",
                remoteAddress: "1.1.1.1"
            )
        ])
        let attributor = ProcessFlowAttributor(table: table, ownPID: pid, now: { ContinuousClock.now })
        let hit = attributor.attribute(
            transport: .tcp,
            localAddress: "10.0.0.2",
            localPort: 52_001,
            remoteAddress: "1.1.1.1",
            remotePort: 443
        )
        #expect(hit == nil)
    }

    @Test func tcpCacheSurvivesUntilForget() {
        let pid = getpid()
        let table = CountingSocketTable(owners: [
            SocketOwner(
                pid: pid,
                transport: .tcp,
                localPort: 52_010,
                remotePort: 443,
                localAddress: "10.0.0.2",
                remoteAddress: "1.1.1.1"
            )
        ])
        let attributor = ProcessFlowAttributor(table: table, ownPID: 1, now: { ContinuousClock.now })
        #expect(attributor.attribute(
            transport: .tcp,
            localAddress: "10.0.0.2",
            localPort: 52_010,
            remoteAddress: "1.1.1.1",
            remotePort: 443
        )?.pid == pid)
        table.owners = []
        #expect(attributor.attribute(
            transport: .tcp,
            localAddress: "10.0.0.2",
            localPort: 52_010,
            remoteAddress: "1.1.1.1",
            remotePort: 443
        )?.pid == pid)
        #expect(table.snapshots == 1)
        attributor.forget(
            transport: .tcp,
            localPort: 52_010,
            remoteAddress: "1.1.1.1",
            remotePort: 443
        )
        #expect(attributor.attribute(
            transport: .tcp,
            localAddress: "10.0.0.2",
            localPort: 52_010,
            remoteAddress: "1.1.1.1",
            remotePort: 443
        ) == nil)
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

    @Test func pcblistNFindsSelfPID() throws {
        let listener = socket(AF_INET, SOCK_STREAM, 0)
        let client = socket(AF_INET, SOCK_STREAM, 0)
        #expect(listener >= 0 && client >= 0)
        var yes: Int32 = 1
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        addr.sin_port = 0
        let bindOK = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        #expect(bindOK == 0)
        #expect(listen(listener, 1) == 0)
        var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        getsockname(listener, UnsafeMutableRawPointer(&addr).assumingMemoryBound(to: sockaddr.self), &addrLen)
        let connectOK = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(client, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        #expect(connectOK == 0)
        let accepted = accept(listener, nil, nil)
        #expect(accepted >= 0)
        var local = sockaddr_in()
        var localLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        getsockname(client, UnsafeMutableRawPointer(&local).assumingMemoryBound(to: sockaddr.self), &localLen)
        let port = UInt16(bigEndian: local.sin_port)
        let found = PCBListLookup.findPID(forLocalPort: port, isTCP: true)
        #expect(found == getpid())
        close(accepted)
        close(client)
        close(listener)
    }
}

private struct FakeSocketTable: SocketTableReading {
    var owners: [SocketOwner]

    func snapshot(skipPID: Int32) -> [SocketOwner] {
        owners.filter { $0.pid != skipPID }
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
