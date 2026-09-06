import Foundation
import Network
import os

/// Wire transport for one nameserver endpoint.
public protocol NameserverTransport: Sendable {
    func query(_ domain: String) async throws -> [DNSWire.Record]
    func queryAAAA(_ domain: String) async throws -> [DNSWire.AAAARecord]
}

public enum NameserverFactory: Sendable {
    public static func make(_ endpoint: NameserverEndpoint) throws -> any NameserverTransport {
        switch endpoint {
        case .udp(let address, let port):
            guard NameserverAddress.isUsableIPv4(address) else {
                throw DNSError.nameserverMustBeIP(address)
            }
            return UDPNameserver(address: address, port: port)
        case .doh:
            throw DNSError.transportNotImplemented(.doh)
        }
    }
}

/// Shared NWConnection readiness wait with a hard ceiling (handles `.cancelled`,
/// which otherwise leaks the continuation forever).
enum NWReady {
    static func wait(_ connection: NWConnection, timeout: Duration) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    let once = OSAllocatedUnfairLock<CheckedContinuation<Void, Error>?>(initialState: continuation)
                    connection.stateUpdateHandler = { state in
                        let result: Result<Void, Error>
                        switch state {
                        case .ready: result = .success(())
                        case .failed(let error): result = .failure(error)
                        case .cancelled: result = .failure(DNSError.timeout)
                        default: return
                        }
                        let pending = once.withLock { current -> CheckedContinuation<Void, Error>? in
                            let value = current
                            current = nil
                            return value
                        }
                        pending?.resume(with: result)
                    }
                    connection.start(queue: .global(qos: .userInitiated))
                }
            }
            group.addTask {
                try await Task.sleep(for: timeout)
                throw DNSError.timeout
            }
            do {
                try await group.next()
                group.cancelAll()
            } catch {
                connection.cancel()
                group.cancelAll()
                throw error
            }
        }
    }
}

/// DNS over UDP to an IP literal. `preferNoProxies` keeps the query off any
/// system proxy; it never touches the system resolver (FakeDNS).
struct UDPNameserver: NameserverTransport {
    var address: String
    var port: UInt16

    func query(_ domain: String) async throws -> [DNSWire.Record] {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return [] }
        let parameters = NWParameters.udp
        parameters.preferNoProxies = true
        let connection = NWConnection(host: NWEndpoint.Host(address), port: nwPort, using: parameters)
        defer { connection.cancel() }
        try await NWReady.wait(connection, timeout: .seconds(2))
        let queryID = UInt16.random(in: .min ... .max)
        try await send(connection, DNSWire.makeQuery(id: queryID, domain: domain))
        let answer = try await receiveMessage(connection, timeout: .seconds(3))
        return DNSWire.aRecords(in: answer, expectedID: queryID)
    }

    func queryAAAA(_ domain: String) async throws -> [DNSWire.AAAARecord] {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return [] }
        let parameters = NWParameters.udp
        parameters.preferNoProxies = true
        let connection = NWConnection(host: NWEndpoint.Host(address), port: nwPort, using: parameters)
        defer { connection.cancel() }
        try await NWReady.wait(connection, timeout: .seconds(2))
        let queryID = UInt16.random(in: .min ... .max)
        try await send(
            connection,
            DNSWire.makeQuery(id: queryID, domain: domain, type: DNSWire.typeAAAA)
        )
        let answer = try await receiveMessage(connection, timeout: .seconds(3))
        return DNSWire.aaaaRecords(in: answer, expectedID: queryID)
    }

    private func send(_ connection: NWConnection, _ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            })
        }
    }

    private func receiveMessage(_ connection: NWConnection, timeout: Duration) async throws -> Data {
        try await withThrowingTaskGroup(of: Data.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { continuation in
                    let once = OSAllocatedUnfairLock<CheckedContinuation<Data, Error>?>(initialState: continuation)
                    connection.receiveMessage { data, _, _, error in
                        let pending = once.withLock { current -> CheckedContinuation<Data, Error>? in
                            let value = current
                            current = nil
                            return value
                        }
                        if let error {
                            pending?.resume(throwing: error)
                        } else {
                            pending?.resume(returning: data ?? Data())
                        }
                    }
                }
            }
            group.addTask {
                try await Task.sleep(for: timeout)
                throw DNSError.timeout
            }
            do {
                let data = try await group.next() ?? Data()
                group.cancelAll()
                return data
            } catch {
                connection.cancel()
                group.cancelAll()
                throw error
            }
        }
    }
}
