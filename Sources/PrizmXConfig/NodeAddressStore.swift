import Foundation
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
    /// (possibly GeoDNS-split / poisoned) channel. Their answers are pinned
    /// FIRST so a poisoned system answer is never dialed first.
    public static let fallbackResolverIPs = ["223.5.5.5", "119.29.29.29"]

    /// Resolves every node hostname in `configText` from the **app** process.
    ///
    /// Candidates are the union of three channels — public resolvers,
    /// captured system DNS over UDP, and the process resolver — public
    /// answers first. Like Clash/Surge, startup never probes: liveness is
    /// established by url-test probing after the tunnel is up, and a stale
    /// pin is healed by the extension's last-resort re-resolution.
    public static func refresh(
        configText: String,
        nameservers: [String]
    ) async -> [String: [PrizmXProtocols.IPv4Address]] {
        let hosts = nodeHostnames(in: configText)
        guard !hosts.isEmpty else { return [:] }
        let publicDNS = DNSClient(settings: .bootstrap(physicalIPs: [], fallbackIPs: fallbackResolverIPs))
        let capturedDNS = DNSClient(settings: .bootstrap(physicalIPs: nameservers, fallbackIPs: []))
        var map: [String: [PrizmXProtocols.IPv4Address]] = [:]
        await withTaskGroup(of: (String, [PrizmXProtocols.IPv4Address]).self) { group in
            for host in hosts {
                group.addTask {
                    async let publicAnswers = (try? await publicDNS.resolveAll(host, role: .proxyServer)) ?? []
                    async let capturedAnswers = (try? await capturedDNS.resolveAll(host, role: .proxyServer)) ?? []
                    async let systemAnswers = HostResolver.ipv4(host)
                    var candidates: [PrizmXProtocols.IPv4Address] = []
                    for list in [await publicAnswers, await capturedAnswers, await systemAnswers] {
                        for address in list where !candidates.contains(address) {
                            candidates.append(address)
                        }
                    }
                    return (host, candidates)
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
}
