/// Keys stored in `NETunnelProviderProtocol.providerConfiguration`.
/// Shared by Packet Tunnel, App Proxy, and the main app.
public enum TunnelProviderKeys: Sendable {
    /// Relative path (inside the App Group container) of the config file.
    /// The config text itself is never stored in the profile:
    /// NetworkExtension profiles cap at 512 KB.
    public static let configPath = "configPath"
    /// Absolute path to a GeoIP `.mmdb` (App Group container).
    public static let geoIPPath = "geoIPPath"
    /// JSON object: `{ "cn": { "exact": [], "suffixes": [], "keywords": [] } }`.
    public static let geositeJSON = "geositeJSON"
    /// `Bool`. When true (default), Packet Tunnel hijacks DNS to FakeIP `198.18.0.2`.
    /// Ignored by the macOS Transparent Proxy path.
    public static let fakeIP = "fakeIP"
    /// Optional `[String]` of DNS IPs used when FakeIP is disabled (Packet Tunnel).
    public static let dnsServers = "dnsServers"
}
