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
    public var asnURL: URL?
    public var geositeJSON: String?
    public var useFakeIP: Bool
    /// "Route All Traffic": TUN takes the default route (`CapturePreferenceStore`).
    public var captureAllTraffic: Bool
    public var systemProxy: Bool
    public var allowLAN: Bool
    public var mixedPort: UInt16
    /// Resolver IPs captured in the **app** — never snapshot DNS inside an
    /// extension (FakeDNS / DHCP state there is not the user's resolver).
    public var systemDNS: [String]
    /// Node hostnames already resolved in the app.
    public var pinnedNodeAddresses: [String: [IPv4Address]]
    public var overlay: ProfileOverlay

    public init(providerConfiguration: [String: Any]?, options: [String: Any]?) {
        var provider = providerConfiguration ?? [:]
        if let options {
            for (key, value) in options { provider[key] = value }
        }
        configText = TunnelConfigStorage.configText(from: provider)
        geoIPURL = GeoAssetStore.resolve(provider[TunnelProviderKeys.geoIPPath] as? String)
        geositeURL = GeoAssetStore.resolve(provider[TunnelProviderKeys.geositePath] as? String)
        asnURL = GeoAssetStore.resolve(provider[TunnelProviderKeys.asnPath] as? String)
        geositeJSON = provider[TunnelProviderKeys.geositeJSON] as? String
        useFakeIP = (provider[TunnelProviderKeys.fakeIP] as? Bool) ?? true
        captureAllTraffic = useFakeIP && CapturePreferenceStore.load().allTraffic
        systemProxy = (provider[TunnelProviderKeys.systemProxy] as? Bool) ?? false
        allowLAN = (provider[TunnelProviderKeys.allowLAN] as? Bool) ?? false
        let port = provider[TunnelProviderKeys.mixedPort] as? Int ?? TunnelProviderKeys.defaultMixedPort
        mixedPort = UInt16(clamping: port)
        let dnsFromApp = (provider[TunnelProviderKeys.dnsServers] as? [String]) ?? []
        systemDNS = dnsFromApp.filter { NameserverAddress.isUsableIPv4($0) }
        pinnedNodeAddresses = NodeAddressStore.load()
        overlay = ProfileOverlayStore.load(from: provider)
    }

    /// `traffic`: the running engine's counter on a reload, so totals and
    /// open flows carry over.
    public func makeEngine(
        flowAttributor: (any FlowAttributing)? = nil,
        traffic: TrafficCounter? = nil
    ) throws -> Engine {
        try EngineFactory.make(
            configText: configText,
            geoIPURL: geoIPURL,
            geositeURL: geositeURL,
            asnURL: asnURL,
            geositeJSON: geositeJSON,
            systemDNS: systemDNS,
            pinnedNodeAddresses: pinnedNodeAddresses,
            overlay: overlay,
            flowAttributor: flowAttributor,
            traffic: traffic
        )
    }
}
