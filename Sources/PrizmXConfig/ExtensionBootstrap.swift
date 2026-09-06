import Foundation
import PrizmXCore
import PrizmXProtocols

/// Shared bootstrap for the Packet Tunnel extension:
/// merges `startTunnel`/`startProxy` options over `providerConfiguration`,
/// resolves the persisted inputs (config file, GeoIP, pinned node addresses,
/// app-captured DNS), and builds the `Engine`.
///
/// Keeping this in one place guarantees both extensions read the same keys.
public struct ExtensionBootstrap: Sendable {
    public var configText: String?
    public var geoIPURL: URL?
    public var geositeURL: URL?
    public var geositeJSON: String?
    public var useFakeIP: Bool
    public var systemProxy: Bool
    public var allowLAN: Bool
    public var mixedPort: UInt16
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
        geoIPURL = GeoAssetStore.resolve(provider[TunnelProviderKeys.geoIPPath] as? String)
        geositeURL = GeoAssetStore.resolve(provider[TunnelProviderKeys.geositePath] as? String)
        geositeJSON = provider[TunnelProviderKeys.geositeJSON] as? String
        useFakeIP = (provider[TunnelProviderKeys.fakeIP] as? Bool) ?? true
        systemProxy = (provider[TunnelProviderKeys.systemProxy] as? Bool) ?? false
        allowLAN = (provider[TunnelProviderKeys.allowLAN] as? Bool) ?? false
        let port = provider[TunnelProviderKeys.mixedPort] as? Int ?? TunnelProviderKeys.defaultMixedPort
        mixedPort = UInt16(clamping: port)
        let dnsFromApp = (provider[TunnelProviderKeys.dnsServers] as? [String]) ?? []
        systemDNS = dnsFromApp.filter { NameserverAddress.isUsableIPv4($0) }
        pinnedNodeAddresses = NodeAddressStore.load()
    }

    public func makeEngine() throws -> Engine {
        try EngineFactory.make(
            configText: configText,
            geoIPURL: geoIPURL,
            geositeURL: geositeURL,
            geositeJSON: geositeJSON,
            systemDNS: systemDNS,
            pinnedNodeAddresses: pinnedNodeAddresses
        )
    }
}
