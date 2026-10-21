import Foundation
import Network
import os
import Testing
import PrizmXNodes
@testable import PrizmXProtocols

/// DIRECT dials an IPv6 literal (what the tunnel relays once it carries
/// IPv6). A TCP echo server on ::1 stands in for the destination.
@Test func directDialsAnIPv6Literal() async throws {
    let (listener, port) = try await startEchoListener()
    defer { listener.cancel() }

    let connection = DirectOutboundConnection(endpoint: Endpoint(host: .ipv6(.loopback), port: port))
    try await connection.open()
    #expect(try await roundTrip(connection) == Data("hello over IPv6".utf8))
    await connection.close()
}

/// A name without an A record is dialed at its AAAA address.
@Test func directDialsANameWithoutIPv4OverIPv6() async throws {
    let (listener, port) = try await startEchoListener()
    defer { listener.cancel() }
    let dns = DNSClient(settings: DNSSettings(defaultNameservers: [.udp(address: "10.0.0.1", port: 53)]))
    dns.transportFactory = { _ in LoopbackAAAA() }

    let connection = DirectOutboundConnection(endpoint: Endpoint(domain: "v6only.example", port: port))
    try await DNSClient.$current.withValue(dns) { try await connection.open() }
    #expect(try await roundTrip(connection) == Data("hello over IPv6".utf8))
    await connection.close()
}

/// No A record; `::1` as the AAAA record.
private struct LoopbackAAAA: NameserverTransport {
    func query(_ domain: String) async throws -> [DNSWire.Record] { [] }

    func queryAAAA(_ domain: String) async throws -> [DNSWire.AAAARecord] {
        [DNSWire.AAAARecord(address: .loopback, ttl: 60)]
    }
}

private func startEchoListener() async throws -> (NWListener, UInt16) {
    let listener = try NWListener(using: .tcp)
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
    return (listener, port)
}

private func roundTrip(_ connection: DirectOutboundConnection) async throws -> Data {
    try await connection.writeAll(Data("hello over IPv6".utf8))
    var received = Data()
    while received.count < 15 {
        let chunk = try await connection.readData(upTo: 64)
        guard !chunk.isEmpty else { break }
        received += chunk
    }
    return received
}

private func echo(_ connection: NWConnection) {
    connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, done, error in
        guard let data, error == nil else { return }
        connection.send(content: data, completion: .contentProcessed { _ in })
        if !done { echo(connection) }
    }
}
