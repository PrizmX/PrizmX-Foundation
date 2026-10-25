import Foundation
import Network
import os
import Testing
import PrizmXCore
import PrizmXNodes
@testable import PrizmXProtocols
@testable import PrizmXTUN
import PrizmXRules

private typealias IPv6Address = PrizmXProtocols.IPv6Address

/// The app side of the tunnel and a public server it talks to.
private let client6 = FakeIPAllocator.gateway6
private let server6 = IPv6Address(high: 0x2606_4700_4700_0000, low: 0x1111)

/// IPv6 the tunnel carries is relayed like IPv4; with Clash `ipv6: false`
/// it is refused.
@Suite(.serialized)
struct TUNIPv6Tests {
    @Test func carriedIPv6UDPReachesTheRelay() async throws {
        let stack = TUNStack(fakeIP: nil, carriesIPv6: true) { _ in }
        await stack.start()
        let stream = await stack.udpDatagrams()
        let payload = Data([0x01, 0x02, 0x03, 0x04])
        await stack.input(packets: [
            UDPDatagram(sourcePort: 50_000, destinationPort: 443, payload: payload)
                .encode(source: client6, destination: server6),
        ])
        let received = try #require(await firstDatagram(stream))
        #expect(received.source == Endpoint(host: .ipv6(client6), port: 50_000))
        #expect(received.destination == Endpoint(host: .ipv6(server6), port: 443))
        #expect(received.payload == payload)
        await stack.stop()
    }

    @Test func refusedIPv6TCPIsReset() async throws {
        let output = Output()
        let stack = TUNStack(fakeIP: nil, carriesIPv6: false) { output.append($0) }
        await stack.start()
        await stack.input(packets: [ipv6SYN(from: client6, to: server6, port: 443)])
        let reply = try #require(await output.first { $0.first.map { $0 >> 4 } == 6 })
        #expect(reply[6] == 6)
        #expect(reply[53] & 0x04 != 0)
        await stack.stop()
    }

    /// Like IPv4, DNS an app sends to any server is answered by FakeDNS,
    /// from that server's address.
    @Test func dnsToAnyIPv6ServerIsAnswered() async throws {
        let output = Output()
        let pool = FakeIPAllocator()
        let stack = TUNStack(fakeIP: pool, carriesIPv6: true) { output.append($0) }
        await stack.start()
        let resolver = IPv6Address(high: 0x2001_4860_4860_0000, low: 0x8888)
        await stack.input(packets: [
            UDPDatagram(sourcePort: 53_001, destinationPort: 53, payload: dnsQuery(name: "www.example.com", type: 1))
                .encode(source: client6, destination: resolver),
            UDPDatagram(sourcePort: 53_002, destinationPort: 53, payload: dnsQuery(name: "www.example.com", type: 28))
                .encode(source: client6, destination: resolver),
        ])
        let isDNSReply: (Data, UInt16) -> Bool = { packet, port in
            packet.count > 48 && packet[0] >> 4 == 6 && packet[6] == 17
                && UInt16(packet[42]) << 8 | UInt16(packet[43]) == port
        }
        let a = try #require(await output.first { isDNSReply($0, 53_001) })
        #expect(a.subdata(in: 8..<24) == bytes(resolver))
        #expect(a.subdata(in: 24..<40) == bytes(client6))
        #expect(pool.count == 1)
        #expect(a[48 + 7] == 1) // ANCOUNT: the FakeIP
        // No AAAA answer without `dns.ipv6`.
        let aaaa = try #require(await output.first { isDNSReply($0, 53_002) })
        #expect(aaaa[48 + 7] == 0)
        await stack.stop()
    }

    /// IPv6 UDP goes out DIRECT and the answer returns on the app's flow.
    /// An echo server on ::1 stands in for the destination.
    @Test func relayCarriesIPv6UDPBothWays() async throws {
        let echo = try await EchoServer.start()
        defer { echo.stop() }
        let output = Output()
        let stack = TUNStack(fakeIP: nil, carriesIPv6: true) { output.append($0) }
        await stack.start()
        let engine = Engine(
            router: Router(rules: [], default: .direct),
            nodeManager: NodeManager(nodes: [], groups: [])
        )
        let relay = Task { await TUNUDPRelay.run(stack: stack, engine: engine) }
        let payload = Data("ping over IPv6".utf8)
        let datagram = UDPDatagram(sourcePort: 50_001, destinationPort: echo.port, payload: payload)
            .encode(source: client6, destination: IPv6Address.loopback)
        let isEcho: (Data) -> Bool = { packet in
            packet.count > 48 && packet[0] >> 4 == 6 && packet[6] == 17 && packet.suffix(payload.count) == payload
        }
        // The relay subscribes to the stack's datagrams on its own task; one
        // sent before that is dropped, as UDP may be. Send until one returns.
        var echoed: Data?
        for _ in 0..<15 where echoed == nil {
            await stack.input(packets: [datagram])
            echoed = await output.first(within: .milliseconds(200), where: isEcho)
        }
        let reply = try #require(echoed)
        #expect(reply.subdata(in: 8..<24) == bytes(IPv6Address.loopback))
        #expect(reply.subdata(in: 24..<40) == bytes(client6))
        relay.cancel()
        await stack.stop()
    }
}

/// Packets the stack wrote, in order. Written from the stack's tasks.
private final class Output: @unchecked Sendable {
    private let lock = NSLock()
    private var packets: [Data] = []

    func append(_ batch: [Data]) {
        lock.withLock { packets += batch }
    }

    func first(within timeout: Duration = .seconds(3), where matches: (Data) -> Bool) async -> Data? {
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline {
            if let hit = lock.withLock({ packets.first(where: matches) }) { return hit }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return nil
    }
}

private func firstDatagram(
    _ stream: AsyncStream<TUNUDPDatagram>,
    within timeout: Duration = .seconds(3)
) async -> TUNUDPDatagram? {
    await withTaskGroup(of: TUNUDPDatagram?.self) { group in
        group.addTask {
            var iterator = stream.makeAsyncIterator()
            return await iterator.next()
        }
        group.addTask {
            try? await Task.sleep(for: timeout)
            return nil
        }
        let first = await group.next() ?? nil
        group.cancelAll()
        return first
    }
}

private func bytes(_ address: IPv6Address) -> Data {
    var data = Data(count: 16)
    for index in 0..<8 {
        data[index] = UInt8(truncatingIfNeeded: address.high >> (56 - 8 * index))
        data[8 + index] = UInt8(truncatingIfNeeded: address.low >> (56 - 8 * index))
    }
    return data
}

private func ipv6SYN(from source: IPv6Address, to destination: IPv6Address, port: UInt16) -> Data {
    var packet = Data(count: 60)
    packet[0] = 0x60
    packet[5] = 20
    packet[6] = 6
    packet[7] = 64
    packet.replaceSubrange(8..<24, with: bytes(source))
    packet.replaceSubrange(24..<40, with: bytes(destination))
    packet[40] = 0xC3
    packet[41] = 0x50
    packet[42] = UInt8(port >> 8)
    packet[43] = UInt8(port & 0xFF)
    packet[47] = 1
    packet[52] = 5 << 4
    packet[53] = 0x02
    return packet
}

private func dnsQuery(name: String, type: UInt8) -> Data {
    var query = Data([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    for label in name.split(separator: ".") {
        query.append(UInt8(label.count))
        query.append(contentsOf: Array(label.utf8))
    }
    query.append(contentsOf: [0x00, 0x00, type, 0x00, 0x01])
    return query
}

/// UDP echo on the loopback addresses.
private final class EchoServer: @unchecked Sendable {
    let port: UInt16
    private let listener: NWListener

    private init(listener: NWListener, port: UInt16) {
        self.listener = listener
        self.port = port
    }

    static func start() async throws -> EchoServer {
        let listener = try NWListener(using: .udp)
        listener.newConnectionHandler = { connection in
            connection.start(queue: .global())
            echo(connection)
        }
        let port: UInt16 = try await withCheckedThrowingContinuation { continuation in
            let once = OSAllocatedUnfairLock<CheckedContinuation<UInt16, Error>?>(initialState: continuation)
            let finish: @Sendable (Result<UInt16, Error>) -> Void = { result in
                once.withLock { current in
                    defer { current = nil }
                    return current
                }?.resume(with: result)
            }
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(.success(listener.port?.rawValue ?? 0))
                case .failed(let error): finish(.failure(error))
                default: break
                }
            }
            listener.start(queue: .global())
        }
        return EchoServer(listener: listener, port: port)
    }

    func stop() {
        listener.cancel()
    }

    private static func echo(_ connection: NWConnection) {
        connection.receiveMessage { data, _, _, error in
            guard let data, error == nil else { return }
            connection.send(content: data, completion: .contentProcessed { _ in })
            echo(connection)
        }
    }
}
