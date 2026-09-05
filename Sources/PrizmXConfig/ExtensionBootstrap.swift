import Foundation
import PrizmXCore
import PrizmXProtocols

/// Shared bootstrap for the tunnel extensions (Packet Tunnel / App Proxy):
/// merges `startTunnel`/`startProxy` options over `providerConfiguration`,
/// resolves the persisted inputs (config file, GeoIP, pinned node addresses,
/// app-captured DNS), and builds the `Engine`.
///
/// Keeping this in one place guarantees both extensions read the same keys.
public struct ExtensionBootstrap: Sendable {
    public var configText: String?
    public var geoIPURL: URL?
    public var geositeJSON: String?
    public var useFakeIP: Bool
    /// Resolver IPs captured in the **app** — never snapshot DNS inside an
    /// extension (FakeDNS / DHCP state there is not the user's resolver).
    public var systemDNS: [String]
    /// Node hostnames already resolved in the app.
    public var pinnedNodeAddresses: [String: [IPv4Address]]

    public init(providerConfiguration: [String: Any]?, options: [String: Any]?) {
        var provider = providerConfiguration ?? [:]
        if let options {
            for (key, value) in options { provider[key] = value }
        }
        configText = TunnelConfigStorage.configText(from: provider)
        geoIPURL = (provider[TunnelProviderKeys.geoIPPath] as? String)
            .map { URL(fileURLWithPath: $0) }
        geositeJSON = provider[TunnelProviderKeys.geositeJSON] as? String
        useFakeIP = (provider[TunnelProviderKeys.fakeIP] as? Bool) ?? true
        let dnsFromApp = (provider[TunnelProviderKeys.dnsServers] as? [String]) ?? []
        systemDNS = dnsFromApp.filter { NameserverAddress.isUsableIPv4($0) }
        pinnedNodeAddresses = NodeAddressStore.load()
    }

    public func makeEngine() throws -> Engine {
        try EngineFactory.make(
            configText: configText,
            geoIPURL: geoIPURL,
            geositeJSON: geositeJSON,
            systemDNS: systemDNS,
            pinnedNodeAddresses: pinnedNodeAddresses
        )
    }
}
