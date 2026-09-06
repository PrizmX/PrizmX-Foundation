import Foundation
import Network
import os

/// RFC 8484 DNS-over-HTTPS over a raw `NWConnection` (HTTP/1.1 GET).
///
/// `URLSession` is deliberately not used: it resolves the DoH hostname through
/// the system resolver, which is FakeDNS while the tunnel is up. The host is
/// resolved through the bootstrap nameservers instead, and the TLS server name
/// stays the DoH hostname.
struct DoHNameserver: NameserverTransport {
    var url: URL
    /// Resolves the DoH server hostname via bootstrap UDP resolvers.
    var resolveHost: @Sendable (String) async throws -> [IPv4Address]

    func query(_ domain: String) async throws -> [DNSWire.Record] {
        let (body, queryID) = try await queryWire(domain: domain, type: DNSWire.typeA)
        return DNSWire.aRecords(in: body, expectedID: queryID)
    }

    func queryAAAA(_ domain: String) async throws -> [DNSWire.AAAARecord] {
        let (body, queryID) = try await queryWire(domain: domain, type: DNSWire.typeAAAA)
        return DNSWire.aaaaRecords(in: body, expectedID: queryID)
    }

    private func queryWire(domain: String, type: UInt16) async throws -> (Data, UInt16) {
        guard let host = url.host else { throw DNSError.noRecord(url.absoluteString) }
        let port = UInt16(url.port ?? 443)
        let addresses = try await resolveHost(host)
        guard let address = addresses.first else { throw DNSError.noRecord(host) }

        let queryID = UInt16.random(in: .min ... .max)
        let wireQuery = DNSWire.makeQuery(id: queryID, domain: domain, type: type)
        var target = url.path.isEmpty ? "/" : url.path
        target += url.query.map { _ in "&dns=" } ?? "?dns="
        target += DNSWire.base64url(wireQuery)

        let request = "GET \(target) HTTP/1.1\r\n"
            + "Host: \(host)\(url.port.map { ":\($0)" } ?? "")\r\n"
            + "Accept: application/dns-message\r\n"
            + "Connection: close\r\n\r\n"

        let parameters = TLSClient.parameters(serverName: host)
        parameters.preferNoProxies = true
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw DNSError.noRecord(host)
        }
        let connection = NWConnection(
            host: NWEndpoint.Host(address.description),
            port: nwPort,
            using: parameters
        )
        defer { connection.cancel() }
        try await NWReady.wait(connection, timeout: .seconds(4))
        try await send(connection, Data(request.utf8))
        let response = try await receiveAll(connection, timeout: .seconds(5))
        return (try Self.dnsMessage(from: response), queryID)
    }

    static func parse(response: Data, expectedID: UInt16) throws -> [DNSWire.Record] {
        DNSWire.aRecords(in: try dnsMessage(from: response), expectedID: expectedID)
    }

    static func dnsMessage(from response: Data) throws -> Data {
        guard let headerEnd = response.range(of: Data([0x0D, 0x0A, 0x0D, 0x0A])) else {
            throw DNSError.noRecord("malformed DoH response")
        }
        guard let head = String(bytes: response[..<headerEnd.lowerBound], encoding: .utf8),
              head.contains(" 200") else {
            throw DNSError.noRecord("DoH non-200")
        }
        // NB: `response.suffix(from:)` shares storage and keeps the original
        // (non-zero) indices — `Data` is its own SubSequence. Record parsers
        // index from 0, so a fresh, rebased copy is mandatory here.
        return response.subdata(in: headerEnd.upperBound..<response.count)
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

    /// Reads until the peer closes (`Connection: close`).
    private func receiveAll(_ connection: NWConnection, timeout: Duration) async throws -> Data {
        try await withThrowingTaskGroup(of: Data.self) { group in
            group.addTask {
                var collected = Data()
                while true {
                    let chunk: Data? = try await withCheckedThrowingContinuation { continuation in
                        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, isComplete, error in
                            if let error {
                                continuation.resume(throwing: error)
                            } else if let data, !data.isEmpty {
                                continuation.resume(returning: data)
                            } else if isComplete {
                                continuation.resume(returning: nil)
                            } else {
                                continuation.resume(returning: Data())
                            }
                        }
                    }
                    guard let chunk else { return collected }
                    collected.append(chunk)
                    if collected.count > 256 * 1024 { return collected }
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
