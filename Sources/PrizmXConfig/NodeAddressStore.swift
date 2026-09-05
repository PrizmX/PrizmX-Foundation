import Foundation
import Network
import os
import PrizmXNodes
import PrizmXProtocols

/// App-process node hostname → IPv4 map, stored in the App Group.
///
/// The Packet Tunnel cannot use the system resolver (FakeDNS owns it).
/// The main app resolves node servers **before** the tunnel starts and the
/// extension treats this map as the first candidate list.
public enum NodeAddressStore: Sendable {
    public static let relativePath = "tunnel/node-addrs.json"

    public static func load(
        appGroupIdentifier: String = TunnelConfigStorage.defaultAppGroupIdentifier,
        directoryName: String = TunnelConfigStorage.defaultDirectoryName
    ) -> [String: [PrizmXProtocols.IPv4Address]] {
        guard let root = TunnelConfigStorage.containerURL(
            appGroupIdentifier: appGroupIdentifier,
            directoryName: directoryName
        ) else { return [:] }
        let url = root.appendingPathComponent(relativePath)
        guard let data = try? Data(contentsOf: url),
              let dict = try? JSONDecoder().decode([String: [String]].self, from: data) else {
            return [:]
        }
        var result: [String: [PrizmXProtocols.IPv4Address]] = [:]
        for (host, raw) in dict {
            let addresses = raw.compactMap { PrizmXProtocols.IPv4Address(parsing: $0) }
            if !addresses.isEmpty {
                result[host.lowercased()] = addresses
            }
        }
        return result
    }

    public static func save(
        _ map: [String: [PrizmXProtocols.IPv4Address]],
        appGroupIdentifier: String = TunnelConfigStorage.defaultAppGroupIdentifier,
        directoryName: String = TunnelConfigStorage.defaultDirectoryName
    ) throws {
        guard let root = TunnelConfigStorage.containerURL(
            appGroupIdentifier: appGroupIdentifier,
            directoryName: directoryName
        ) else {
            throw TunnelConfigStorageError.appGroupUnavailable
        }
        let url = root.appendingPathComponent(relativePath)
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let encoded = Dictionary(uniqueKeysWithValues: map.map { key, value in
            (key.lowercased(), value.map(\.description))
        })
        let data = try JSONEncoder().encode(encoded)
        try data.write(to: url, options: .atomic)
    }

    /// Public resolvers queried alongside the system resolver — the Clash
    /// `proxy-server-nameserver` idea: node hostnames never trust a single
    /// (possibly GeoDNS-split / poisoned) channel.
    public static let fallbackResolverIPs = ["223.5.5.5", "119.29.29.29"]

    /// Resolves every node hostname in `configText` from the **app** process.
    ///
    /// Candidates are the union of three channels — process resolver,
    /// captured system DNS over UDP, and public resolvers — then **TCP-probed
    /// against the node's ports**: only answers that accept a connection are
    /// pinned, so a split / poisoned answer can never brick a node.
    public static func refresh(
        configText: String,
        nameservers: [String],
        probeTimeout: Duration = .seconds(1)
    ) async -> [String: [PrizmXProtocols.IPv4Address]] {
        let endpoints = nodeEndpoints(in: configText)
        guard !endpoints.isEmpty else { return [:] }
        let publicDNS = DNSClient(settings: .bootstrap(physicalIPs: [], fallbackIPs: fallbackResolverIPs))
        let capturedDNS = DNSClient(settings: .bootstrap(physicalIPs: nameservers, fallbackIPs: []))
        var map: [String: [PrizmXProtocols.IPv4Address]] = [:]
        await withTaskGroup(of: (String, [PrizmXProtocols.IPv4Address]).self) { group in
            for (host, ports) in endpoints {
                group.addTask {
                    async let systemAnswers = HostResolver.ipv4(host)
                    async let capturedAnswers = (try? await capturedDNS.resolveAll(host, role: .proxyServer)) ?? []
                    async let publicAnswers = (try? await publicDNS.resolveAll(host, role: .proxyServer)) ?? []
                    var candidates: [PrizmXProtocols.IPv4Address] = []
                    for list in [await systemAnswers, await capturedAnswers, await publicAnswers] {
                        for address in list where !candidates.contains(address) {
                            candidates.append(address)
                        }
                    }
                    guard !candidates.isEmpty else { return (host, []) }
                    let alive = await probeAlive(
                        addresses: candidates,
                        ports: ports,
                        timeout: probeTimeout
                    )
                    if alive.isEmpty {
                        TunnelLog.write(.warn, "app resolved \(host): all \(candidates.count) candidates unreachable")
                    } else if alive.count < candidates.count {
                        let dead = candidates.filter { !alive.contains($0) }
                        TunnelLog.write(.info, "app resolved \(host): dropped unreachable \(dead.map(\.description))")
                    }
                    return (host, alive)
                }
            }
            for await (host, addresses) in group where !addresses.isEmpty {
                map[host] = addresses
            }
        }
        try? save(map)
        let preview = map.map { "\($0.key)→\($0.value.map(\.description))" }.sorted().joined(separator: ",")
        TunnelLog.write(.info, "app resolved \(map.count) node hosts \(preview)")
        return map
    }

    public static func nodeHostnames(in configText: String) -> [String] {
        nodeEndpoints(in: configText).keys.sorted()
    }

    /// Node hostname → the ports its nodes dial (sorted, capped at 4 per host).
    public static func nodeEndpoints(in configText: String) -> [String: [UInt16]] {
        guard let parsed = try? ConfigAdapter.parse(rawString: configText) else { return [:] }
        var portsByHost: [String: Set<UInt16>] = [:]
        for node in parsed.1.nodesByID.values {
            guard let probe = node.probeEndpoint, case .domain(let domain) = probe.host else {
                continue
            }
            portsByHost[domain.lowercased(), default: []].insert(probe.port)
        }
        return portsByHost.mapValues { Array($0.sorted().prefix(4)) }
    }

    /// TCP-connects every (address, port) pair concurrently; an address is
    /// alive when any of its ports accepts. Order follows `addresses`.
    /// Test seam: localhost ports.
    static func probeAlive(
        addresses: [PrizmXProtocols.IPv4Address],
        ports: [UInt16],
        timeout: Duration
    ) async -> [PrizmXProtocols.IPv4Address] {
        await withTaskGroup(of: (PrizmXProtocols.IPv4Address, Bool).self) { group in
            for address in addresses {
                for port in ports {
                    group.addTask {
                        (address, await tcpProbe(address, port: port, timeout: timeout))
                    }
                }
            }
            var aliveSet = Set<PrizmXProtocols.IPv4Address>()
            for await (address, ok) in group where ok {
                aliveSet.insert(address)
            }
            return addresses.filter { aliveSet.contains($0) }
        }
    }

    private static func tcpProbe(
        _ address: PrizmXProtocols.IPv4Address,
        port: UInt16,
        timeout: Duration
    ) async -> Bool {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return false }
        let parameters = NWParameters.tcp
        parameters.preferNoProxies = true
        let connection = NWConnection(
            host: NWEndpoint.Host(address.description),
            port: nwPort,
            using: parameters
        )
        defer { connection.cancel() }
        return await withCheckedContinuation { continuation in
            let gate = OSAllocatedUnfairLock(initialState: false)
            @Sendable func finish(_ value: Bool) {
                let first = gate.withLock { done -> Bool in
                    if done { return false }
                    done = true
                    return true
                }
                if first { continuation.resume(returning: value) }
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    finish(true)
                case .failed, .cancelled:
                    finish(false)
                default:
                    break
                }
            }
            connection.start(queue: .global(qos: .userInitiated))
            Task {
                try? await Task.sleep(for: timeout)
                finish(false)
            }
        }
    }
}
