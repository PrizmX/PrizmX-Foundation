/// Keys stored in `NETunnelProviderProtocol.providerConfiguration`.
/// Shared by Packet Tunnel and the main app.
public enum TunnelProviderKeys: Sendable {
    /// Relative path (inside the App Group container) of the config file.
    /// The config text itself is never stored in the profile:
    /// NetworkExtension profiles cap at 512 KB.
    public static let configPath = "configPath"
    /// Relative path of the active `ProfileOverlay` JSON (App Group).
    public static let overlayPath = "overlayPath"
    /// GeoIP `.mmdb` / `.metadb` path: App Group-relative, or absolute.
    public static let geoIPPath = "geoIPPath"
    /// `geosite.dat` (or a small JSON fixture) path: App Group-relative, or absolute.
    public static let geositePath = "geositePath"
    /// Tiny JSON fixture for tests. Production uses `geositePath` — a full
    /// geosite dump exceeds the Network Extension profile size cap.
    public static let geositeJSON = "geositeJSON"
    /// `Bool`. When true (default), Packet Tunnel hijacks DNS to FakeIP `198.18.0.2`.
    public static let fakeIP = "fakeIP"
    /// Optional `[String]` of DNS IPs used when FakeIP is disabled (Packet Tunnel).
    public static let dnsServers = "dnsServers"
    /// `Bool`. Clash/Surge System Proxy: mixed-port on 127.0.0.1 plus NE HTTP proxy.
    public static let systemProxy = "systemProxy"
    /// Mixed-port TCP port (default 7890).
    public static let mixedPort = "mixedPort"
    public static let defaultMixedPort = 7890
    /// `Bool`. Bind mixed-port on all interfaces (Surge Allow LAN).
    public static let allowLAN = "allowLAN"
}
