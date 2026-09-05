import Foundation
import PrizmXCore
import PrizmXNodes
import PrizmXProtocols
import PrizmXRules

/// Builds an `Engine` from Packet Tunnel `providerConfiguration` values.
public enum EngineFactory: Sendable {
    /// `systemDNS`: resolver IPs captured in the **app** (not the extension).
    /// `pinnedNodeAddresses`: node hostnames already resolved in the app.
    public static func make(
        configText: String?,
        geoIPURL: URL? = nil,
        geositeJSON: String? = nil,
        systemDNS: [String] = [],
        pinnedNodeAddresses: [String: [IPv4Address]] = [:]
    ) throws -> Engine {
        let parsed: (Router, NodeManager)
        if let configText {
            let trimmed = configText.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                parsed = Self.directOnly()
            } else {
                parsed = try ConfigAdapter.parse(rawString: trimmed)
            }
        } else {
            parsed = Self.directOnly()
        }

        let dnsSection = configText.flatMap { ClashDNSSection.parse(from: $0) }
        var dnsSettings = DNSSettings.fromClash(section: dnsSection, systemDNS: systemDNS)
        // Node server domains never receive fake IPs: an app-side lookup
        // (node ping, subscription refresh) must not loop into the tunnel.
        let nodeHosts = parsed.1.nodesByID.values.compactMap { node -> String? in
            guard case .domain(let domain) = node.probeEndpoint?.host else { return nil }
            return domain.lowercased()
        }
        var seenFilters = Set(dnsSettings.fakeIPFilter)
        dnsSettings.fakeIPFilter.append(
            contentsOf: nodeHosts.filter { seenFilters.insert($0).inserted }
        )
        let dns = DNSClient(
            settings: dnsSettings,
            persistenceURL: DNSClient.defaultPersistenceURL,
            pinnedNodeAddresses: pinnedNodeAddresses
        )

        let geoIP = try geoIPURL.map { try GeoIPMatcher(contentsOf: $0) }
        let geosite = try geositeJSON.map(Self.parseGeosite)
        let router = Router(
            rules: parsed.0.rules,
            default: parsed.0.defaultPolicy,
            geoIP: geoIP,
            geosite: geosite
        )
        let nodeManager = parsed.1
        let selections = PolicySelectionStore.load()
        nodeManager.applySelections(selections)
        if !selections.isEmpty {
            TunnelLog.write(.info, "policy selections \(selections)")
        }
        return Engine(router: router, nodeManager: nodeManager, dns: dns)
    }

    private static func directOnly() -> (Router, NodeManager) {
        (
            Router(
                rules: [RouteRule(type: .matchAll, policy: .direct)],
                default: .direct
            ),
            NodeManager(nodes: [], groups: [])
        )
    }

    private static func parseGeosite(_ json: String) throws -> GeositeMatcher {
        struct File: Decodable {
            var exact: [String]?
            var suffixes: [String]?
            var keywords: [String]?
        }
        let decoded = try JSONDecoder().decode([String: File].self, from: Data(json.utf8))
        var groups: [String: GeositeGroup] = [:]
        for (tag, file) in decoded {
            groups[tag] = GeositeGroup(
                exact: file.exact ?? [],
                suffixes: file.suffixes ?? [],
                keywords: file.keywords ?? []
            )
        }
        return GeositeMatcher(groups: groups)
    }
}
