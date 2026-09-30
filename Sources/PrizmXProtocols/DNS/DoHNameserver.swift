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
        let target = Self.requestTarget(for: url, dnsParameter: DNSWire.base64url(wireQuery))

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

    /// Path plus the template's existing query (e.g. `?ct=…`), then `dns=`.
    static func requestTarget(for url: URL, dnsParameter: String) -> String {
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let path = components?.percentEncodedPath ?? url.path
        var target = path.isEmpty ? "/" : path
        if let query = components?.percentEncodedQuery, !query.isEmpty {
            target += "?" + query + "&dns="
        } else {
            target += "?dns="
        }
        return target + dnsParameter
    }

    static func dnsMessage(from response: Data) throws -> Data {
        guard let body = try httpBody(in: response, atEOF: true) else {
            throw DNSError.noRecord("truncated DoH response")
        }
        return body
    }

    /// HTTP/1.1 response body: honors `Content-Length` and chunked
    /// transfer-encoding; otherwise the body runs to EOF. Returns `nil` while
    /// more bytes are needed (`atEOF == false`). The result is a fresh,
    /// zero-based `Data` (record parsers index from 0).
    static func httpBody(in response: Data, atEOF: Bool) throws -> Data? {
        let bytes = [UInt8](response)
        guard let headerEnd = find(crlfcrlf, in: bytes, from: 0) else {
            if atEOF { throw DNSError.noRecord("malformed DoH response") }
            return nil
        }
        guard let head = String(bytes: bytes[..<headerEnd], encoding: .utf8) else {
            throw DNSError.noRecord("malformed DoH response")
        }
        let lines = head.components(separatedBy: "\r\n")
        let status = lines.first?.split(separator: " ", maxSplits: 2) ?? []
        guard status.count >= 2, status[0].hasPrefix("HTTP/"), status[1] == "200" else {
            throw DNSError.noRecord("DoH non-200")
        }
        var contentLength: Int?
        var chunked = false
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            if name == "content-length" {
                guard let length = Int(value), length >= 0 else {
                    throw DNSError.noRecord("DoH bad Content-Length")
                }
                contentLength = length
            } else if name == "transfer-encoding" {
                chunked = value.lowercased().split(separator: ",").contains {
                    $0.trimmingCharacters(in: .whitespaces) == "chunked"
                }
            }
        }
        let bodyStart = headerEnd + 4
        if chunked {
            return try dechunk(bytes, from: bodyStart, atEOF: atEOF)
        }
        if let contentLength {
            guard bytes.count - bodyStart >= contentLength else {
                if atEOF { throw DNSError.noRecord("truncated DoH response") }
                return nil
            }
            return Data(bytes[bodyStart..<(bodyStart + contentLength)])
        }
        return atEOF ? Data(bytes[bodyStart...]) : nil
    }

    private static let crlf: [UInt8] = [0x0D, 0x0A]
    private static let crlfcrlf: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]

    private static func dechunk(_ bytes: [UInt8], from start: Int, atEOF: Bool) throws -> Data? {
        var body = Data()
        var offset = start
        while true {
            guard let lineEnd = find(crlf, in: bytes, from: offset) else { break }
            let sizeField = String(decoding: bytes[offset..<lineEnd], as: UTF8.self)
                .split(separator: ";", maxSplits: 1).first
                .map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
            guard let size = Int(sizeField, radix: 16), size >= 0 else {
                throw DNSError.noRecord("DoH bad chunk size")
            }
            if size == 0 { return body }
            let dataStart = lineEnd + 2
            guard size <= bytes.count - dataStart - 2 else { break }
            body.append(contentsOf: bytes[dataStart..<(dataStart + size)])
            guard bytes[dataStart + size] == 0x0D, bytes[dataStart + size + 1] == 0x0A else {
                throw DNSError.noRecord("DoH bad chunk framing")
            }
            offset = dataStart + size + 2
        }
        if atEOF { throw DNSError.noRecord("truncated DoH chunked response") }
        return nil
    }

    private static func find(_ needle: [UInt8], in bytes: [UInt8], from start: Int) -> Int? {
        guard bytes.count >= needle.count, start <= bytes.count - needle.count else { return nil }
        var index = start
        while index <= bytes.count - needle.count {
            if bytes[index..<(index + needle.count)].elementsEqual(needle) {
                return index
            }
            index += 1
        }
        return nil
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

    /// Reads until the body is complete (Content-Length / chunked) or the
    /// peer closes (`Connection: close`).
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
                    if try Self.httpBody(in: collected, atEOF: false) != nil { return collected }
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
