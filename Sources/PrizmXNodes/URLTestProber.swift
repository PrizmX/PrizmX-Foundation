import Foundation
import PrizmXProtocols

/// Clash/Surge url-test: time a request to `url` through the node.
///
/// `http://` sends a real GET. `https://` completes a TLS ClientHello with SNI
/// and waits for a ServerHello (full inner HTTP-over-TLS is not required to
/// prove the node can reach the probe host).
enum URLTestProber: Sendable {
    static func probe(
        node: OutboundNode,
        url: URL,
        timeout: Duration = .seconds(5)
    ) async -> Duration? {
        await withTaskGroup(of: Duration?.self) { group in
            group.addTask {
                await run(node: node, url: url)
            }
            group.addTask {
                try? await Task.sleep(for: timeout)
                return nil
            }
            let first = await group.next() ?? nil
            group.cancelAll()
            return first ?? nil
        }
    }

    static func request(for url: URL) -> (endpoint: Endpoint, payload: Data?, https: Bool)? {
        guard let host = url.host, !host.isEmpty else { return nil }
        let https = url.scheme?.lowercased() == "https"
        let port = UInt16(url.port ?? (https ? 443 : 80))
        let endpoint: Endpoint
        if let address = IPv4Address(parsing: host) {
            endpoint = Endpoint(host: .ipv4(address), port: port)
        } else {
            endpoint = Endpoint(domain: host, port: port)
        }
        if https {
            return (endpoint, nil, true)
        }
        var path = url.path.isEmpty ? "/" : url.path
        if let query = url.query, !query.isEmpty {
            path += "?\(query)"
        }
        let header = "GET \(path) HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\nUser-Agent: PrizmX/url-test\r\n\r\n"
        return (endpoint, Data(header.utf8), false)
    }

    private static func run(node: OutboundNode, url: URL) async -> Duration? {
        guard let request = request(for: url) else { return nil }
        let start = ContinuousClock.now
        do {
            let connection = try NodeFactory.makeConnection(from: node, to: request.endpoint)
            try await connection.open()
            if request.https {
                guard let host = url.host else { return nil }
                try await connection.writeAll(tlsClientHello(sni: host))
                let record = try await connection.readData(upTo: 5)
                // 0x16 handshake (ServerHello) proves the path; 0x15 alert
                // still means a TLS endpoint answered through the node.
                guard let type = record.first, type == 0x16 || type == 0x15 else {
                    await connection.close()
                    return nil
                }
            } else if let payload = request.payload {
                try await connection.writeAll(payload)
                _ = try await connection.readData(upTo: 256)
            }
            await connection.close()
            return ContinuousClock.now - start
        } catch {
            return nil
        }
    }

    static func tlsClientHello(sni: String) -> Data {
        let hostname = Array(sni.utf8.prefix(253))
        var serverName = Data([0x00])
        serverName.append(UInt8(hostname.count >> 8))
        serverName.append(UInt8(hostname.count & 0xFF))
        serverName.append(contentsOf: hostname)
        var sniList = Data()
        sniList.append(UInt8(serverName.count >> 8))
        sniList.append(UInt8(serverName.count & 0xFF))
        sniList.append(serverName)
        var extensionBody = Data([0x00, 0x00])
        extensionBody.append(UInt8(sniList.count >> 8))
        extensionBody.append(UInt8(sniList.count & 0xFF))
        extensionBody.append(sniList)

        var hello = Data([0x03, 0x03])
        hello.append(Data(repeating: 0x11, count: 32))
        hello.append(0x00)
        hello.append(contentsOf: [0x00, 0x02, 0x00, 0x2F])
        hello.append(contentsOf: [0x01, 0x00])
        hello.append(UInt8(extensionBody.count >> 8))
        hello.append(UInt8(extensionBody.count & 0xFF))
        hello.append(extensionBody)

        var handshake = Data([0x01])
        let helloLen = hello.count
        handshake.append(UInt8((helloLen >> 16) & 0xFF))
        handshake.append(UInt8((helloLen >> 8) & 0xFF))
        handshake.append(UInt8(helloLen & 0xFF))
        handshake.append(hello)

        var record = Data([0x16, 0x03, 0x01])
        record.append(UInt8(handshake.count >> 8))
        record.append(UInt8(handshake.count & 0xFF))
        record.append(handshake)
        return record
    }
}
