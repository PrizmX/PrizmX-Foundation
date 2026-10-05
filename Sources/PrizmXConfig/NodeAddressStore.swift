import Foundation
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
                .filter { NameserverAddress.isUsableIPv4($0.description) }
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

    /// Forgets node hostname pins and proven addresses (`dns-good.json`) in
    /// the App Group and in the staged runtime kit — staging skips missing
    /// sources, so a stale runtime copy would otherwise survive. Run while
    /// the tunnel is down: a live extension re-persists what it holds.
    public static func clearCache(
        kitRoots: [URL] = [TunnelConfigStorage.containerURL(), TunnelRuntimeStore.runtimeKitRoot()]
            .compactMap { $0 }
    ) {
        for root in kitRoots {
            for name in [relativePath, "dns-good.json"] {
                try? FileManager.default.removeItem(at: root.appendingPathComponent(name))
            }
        }
        TunnelLog.write(.info, "node DNS cache cleared")
    }

    /// Public resolvers queried alongside the system resolver — the Clash
    /// `proxy-server-nameserver` idea: node hostnames never trust a single
    /// (possibly GeoDNS-split / poisoned) channel. Their answers are pinned
    /// FIRST so a poisoned system answer is never dialed first.
    public static let fallbackResolverIPs = ["223.5.5.5", "119.29.29.29"]

    /// Resolves every node hostname in `configText` from the **app** process.
    ///
    /// When the profile's DNS resolves node hostnames (`followsProfileDNS`),
    /// its answer is the whole pin. Otherwise, or when the profile's
    /// resolvers return nothing within `profileDNSDeadline`, the candidate order
    /// per host is: proven-good dials (persisted by the extension) → the
    /// previous pin file → public resolvers → captured system DNS → process
    /// resolver. DNS answers are just candidates — a proven address survives
    /// rotation / poisoning, and a fresh-but-dead generation never displaces
    /// it. Like Clash/Surge, startup never probes: liveness comes from
    /// url-test probing after the tunnel is up.
    ///
    /// `overrideDNS`: nil reads the stored "Override DNS" switch.
    public static func refresh(
        configText: String,
        nameservers: [String],
        overrideDNS: Bool? = nil
    ) async -> [String: [PrizmXProtocols.IPv4Address]] {
        let hosts = nodeHostnames(in: configText)
        guard !hosts.isEmpty else { return [:] }
        let profileSettings = nodeDNSSettings(
            configText: configText,
            systemDNS: nameservers,
            overrideDNS: overrideDNS
        )
        // No last resort here: a failed profile lookup falls through to the
        // full candidate chain below.
        let profileDNS = profileSettings.resolvesNodesViaProfile
            ? DNSClient(settings: profileSettings, lastResortNameservers: [])
            : nil
        let publicDNS = DNSClient(settings: .bootstrap(physicalIPs: [], fallbackIPs: fallbackResolverIPs))
        let capturedDNS = DNSClient(settings: .bootstrap(physicalIPs: nameservers, fallbackIPs: []))
        let good = DNSClient.persistedGoodNodeAddresses()
        let previous = load()
        var map: [String: [PrizmXProtocols.IPv4Address]] = [:]
        var unanswered: [String] = []
        await withTaskGroup(of: (String, [PrizmXProtocols.IPv4Address], Bool).self) { group in
            for host in hosts {
                group.addTask {
                    var profileMissed = false
                    if let profileDNS {
                        let answers = await profileAnswers(profileDNS, host: host)
                        if !answers.isEmpty { return (host, answers, false) }
                        profileMissed = true
                    }
                    async let publicAnswers = (try? await publicDNS.resolveAll(host, role: .proxyServer)) ?? []
                    async let capturedAnswers = (try? await capturedDNS.resolveAll(host, role: .proxyServer)) ?? []
                    async let systemAnswers = HostResolver.ipv4(host)
                    let ordered = orderedCandidates(
                        good: good[host] ?? [],
                        previous: previous[host] ?? [],
                        publicAnswers: await publicAnswers,
                        captured: await capturedAnswers,
                        system: await systemAnswers
                    )
                    return (host, ordered, profileMissed)
                }
            }
            for await (host, addresses, profileMissed) in group {
                if profileMissed { unanswered.append(host) }
                if !addresses.isEmpty { map[host] = addresses }
            }
        }
        if !unanswered.isEmpty {
            TunnelLog.write(
                .warn,
                "app profile DNS answered none of \(unanswered.sorted()) in time, using fallback resolvers"
            )
        }
        try? save(map)
        let preview = map.map { "\($0.key)→\($0.value.map(\.description))" }.sorted().joined(separator: ",")
        TunnelLog.write(.info, "app resolved \(map.count) node hosts \(preview)")
        return map
    }

    /// Bound on one host's profile lookup in the app. Endpoints are queried
    /// one after another (a dead DoH costs up to ~9 s), and every tunnel
    /// start waits for the pins.
    static let profileDNSDeadline: Duration = .seconds(3)

    /// The profile's answer for `host`, or empty once the deadline passes.
    /// The lookup itself is left to finish (or time out) on its own.
    private static func profileAnswers(
        _ client: DNSClient,
        host: String
    ) async -> [PrizmXProtocols.IPv4Address] {
        await withCheckedContinuation { continuation in
            let resumed = OSAllocatedUnfairLock(initialState: false)
            let finish: @Sendable ([PrizmXProtocols.IPv4Address]) -> Void = { answers in
                let first = resumed.withLock { done in
                    defer { done = true }
                    return !done
                }
                if first { continuation.resume(returning: answers) }
            }
            Task {
                let answers = (try? await client.resolveAll(host, role: .proxyServer)) ?? []
                finish(answers.filter { NameserverAddress.isUsableIPv4($0.description) })
            }
            Task {
                try? await Task.sleep(for: Self.profileDNSDeadline)
                finish([])
            }
        }
    }

    /// True when node hostnames in `configText` resolve through the
    /// profile's own DNS: `dns.enable` with a usable nameserver and the
    /// "Override DNS" switch off (nil reads the stored switch).
    public static func followsProfileDNS(configText: String, overrideDNS: Bool? = nil) -> Bool {
        nodeDNSSettings(configText: configText, systemDNS: [], overrideDNS: overrideDNS)
            .resolvesNodesViaProfile
    }

    private static func nodeDNSSettings(
        configText: String,
        systemDNS: [String],
        overrideDNS: Bool?
    ) -> DNSSettings {
        DNSSettings.fromClash(
            section: ClashDNSSection.parse(from: configText),
            systemDNS: systemDNS,
            overrideDNS: overrideDNS ?? DNSPreferenceStore.load().overrideDNS
        )
    }

    /// Candidate ordering for one node host: proven-good → previous pins →
    /// public → captured → system, deduplicated, order preserved.
    public static func orderedCandidates(
        good: [PrizmXProtocols.IPv4Address],
        previous: [PrizmXProtocols.IPv4Address],
        publicAnswers: [PrizmXProtocols.IPv4Address],
        captured: [PrizmXProtocols.IPv4Address],
        system: [PrizmXProtocols.IPv4Address]
    ) -> [PrizmXProtocols.IPv4Address] {
        var merged: [PrizmXProtocols.IPv4Address] = []
        for list in [good, previous, publicAnswers, captured, system] {
            for address in list where !merged.contains(address) {
                guard NameserverAddress.isUsableIPv4(address.description) else {
                    continue
                }
                merged.append(address)
            }
        }
        return merged
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
