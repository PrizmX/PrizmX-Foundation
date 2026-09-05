import Foundation
import Testing
@testable import PrizmXConfig
import Network
import PrizmXProtocols

@Test func nodeHostnamesExtractedFromClashYAML() {
    let yaml = """
    proxies:
      - {name: HK01, type: anytls, server: node.example.sbs, port: 5868, password: x, sni: a.com}
      - {name: info, type: anytls, server: node.example.sbs, port: 5868, password: x, sni: a.com}
      - {name: US, type: anytls, server: other.example.sbs, port: 443, password: x, sni: a.com}
    proxy-groups:
      - {name: Proxies, type: select, proxies: [HK01, US]}
    rules:
      - MATCH,Proxies
    """
    let hosts = NodeAddressStore.nodeHostnames(in: yaml)
    #expect(hosts == ["node.example.sbs", "other.example.sbs"])
}

@Test func nodeEndpointsCollectPortsPerHost() {
    let yaml = """
    proxies:
      - {name: HK01, type: anytls, server: node.example.sbs, port: 5868, password: x, sni: a.com}
      - {name: HK02, type: anytls, server: node.example.sbs, port: 5869, password: x, sni: a.com}
      - {name: US, type: anytls, server: other.example.sbs, port: 443, password: x, sni: a.com}
    proxy-groups:
      - {name: Proxies, type: select, proxies: [HK01, US]}
    rules:
      - MATCH,Proxies
    """
    let endpoints = NodeAddressStore.nodeEndpoints(in: yaml)
    #expect(endpoints["node.example.sbs"] == [5868, 5869])
    #expect(endpoints["other.example.sbs"] == [443])
    #expect(NodeAddressStore.nodeHostnames(in: yaml) == ["node.example.sbs", "other.example.sbs"])
}

@Test func probeAliveKeepsOnlyAnsweringAddresses() async throws {
    let listener = try NWListener(using: .tcp, on: .any)
    listener.newConnectionHandler = { connection in
        connection.start(queue: .global())
    }
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready: continuation.resume()
            case .failed(let error): continuation.resume(throwing: error)
            default: break
            }
        }
        listener.start(queue: .global())
    }
    defer { listener.cancel() }
    let port = try #require(listener.port?.rawValue)

    let loopback = PrizmXProtocols.IPv4Address(127, 0, 0, 1)
    let alive = await NodeAddressStore.probeAlive(
        addresses: [loopback],
        ports: [port],
        timeout: .milliseconds(800)
    )
    #expect(alive == [loopback])

    // Port 9 (discard) is closed: refused immediately → dropped.
    let dead = await NodeAddressStore.probeAlive(
        addresses: [loopback],
        ports: [9],
        timeout: .milliseconds(800)
    )
    #expect(dead.isEmpty)
}
