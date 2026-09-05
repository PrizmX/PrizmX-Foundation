import Foundation
import PrizmXNodes
import PrizmXProtocols

/// App-process node hostname → IPv4 map, stored in the App Group.
///
/// The Packet Tunnel cannot use the system resolver (FakeDNS owns it).
/// The main app can, so it resolves node servers **before** the tunnel
/// starts and the extension treats this map as the first candidate list.
public enum NodeAddressStore: Sendable {
    public static let relativePath = "tunnel/node-addrs.json"

    public static func load(
        appGroupIdentifier: String = TunnelConfigStorage.defaultAppGroupIdentifier,
        directoryName: String = TunnelConfigStorage.defaultDirectoryName
    ) -> [String: [IPv4Address]] {
        guard let root = TunnelConfigStorage.containerURL(
            appGroupIdentifier: appGroupIdentifier,
            directoryName: directoryName
        ) else { return [:] }
        let url = root.appendingPathComponent(relativePath)
        guard let data = try? Data(contentsOf: url),
              let dict = try? JSONDecoder().decode([String: [String]].self, from: data) else {
            return [:]
        }
        var result: [String: [IPv4Address]] = [:]
        for (host, raw) in dict {
            let addresses = raw.compactMap { IPv4Address(parsing: $0) }
            if !addresses.isEmpty {
                result[host.lowercased()] = addresses
            }
        }
        return result
    }

    public static func save(
        _ map: [String: [IPv4Address]],
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

    /// Resolves every node hostname in `configText` from the **app** process
    /// (system resolver first, then UDP to `nameservers`).
    public static func refresh(
        configText: String,
        nameservers: [String]
    ) async -> [String: [IPv4Address]] {
        let hosts = nodeHostnames(in: configText)
        guard !hosts.isEmpty else { return [:] }
        let client = DNSClient(settings: .bootstrap(physicalIPs: nameservers))
        var map: [String: [IPv4Address]] = [:]
        await withTaskGroup(of: (String, [IPv4Address]).self) { group in
            for host in hosts {
                group.addTask {
                    var addresses = await HostResolver.ipv4(host)
                    if addresses.isEmpty {
                        addresses = (try? await client.resolveAll(host, role: .direct)) ?? []
                    }
                    return (host, addresses)
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
        guard let parsed = try? ConfigAdapter.parse(rawString: configText) else { return [] }
        var hosts: Set<String> = []
        for node in parsed.1.nodesByID.values {
            if case .domain(let domain) = node.probeEndpoint?.host {
                hosts.insert(domain.lowercased())
            }
        }
        return Array(hosts).sorted()
    }
}
