import Foundation
import Testing
import PrizmXConfig
import PrizmXCore
import PrizmXNodes

@Suite struct LiveReloadIPCTests {
    @Test func reloadRequestCarriesTheProviderPayload() throws {
        let payload: [String: Any] = ["configPath": "tunnel/active.conf", "fakeIP": true, "dnsServers": ["1.1.1.1"]]
        let plist = try PropertyListSerialization.data(fromPropertyList: payload, format: .binary, options: 0)
        let data = try TunnelIPC.encode(.init(method: .reloadConfig, providerConfiguration: plist))
        let decoded = try TunnelIPC.decodeRequest(from: data)
        #expect(decoded.method == .reloadConfig)
        let back = try #require(decoded.providerConfiguration)
        let dict = try #require(try PropertyListSerialization.propertyList(from: back, format: nil) as? [String: Any])
        #expect(dict["configPath"] as? String == "tunnel/active.conf")
        #expect(dict["fakeIP"] as? Bool == true)
    }

    @Test func groupSelectionsSurviveTheMetricsFileAndPreferTheTunnel() throws {
        var tunnel = TrafficSnapshot()
        tunnel.groupSelections = ["Auto": "HK 01"]
        var local = TrafficSnapshot()
        local.groupSelections = ["Auto": "JP 01", "Backup": "SG"]
        let merged = tunnel.merging(local)
        #expect(merged.groupSelections == ["Auto": "HK 01", "Backup": "SG"])

        let data = try JSONEncoder().encode(tunnel)
        let decoded = try JSONDecoder().decode(TrafficSnapshot.self, from: data)
        #expect(decoded.groupSelections == ["Auto": "HK 01"])
    }

    @Test func autoSelectionsNameTheLiveURLTestPick() {
        let nodes = [
            OutboundNode(id: "a", name: "A", protocolConfig: .direct),
            OutboundNode(id: "b", name: "B", protocolConfig: .direct),
        ]
        let groups = [
            PolicyGroup(name: "Auto", mode: .urlTest, nodeIDs: ["a", "b"]),
            PolicyGroup(name: "Pick", mode: .select, nodeIDs: ["a", "b"]),
        ]
        let manager = NodeManager(nodes: nodes, groups: groups)
        manager.recordLatency(.milliseconds(90), nodeID: "a", inGroup: "Auto")
        manager.recordLatency(.milliseconds(20), nodeID: "b", inGroup: "Auto")
        #expect(manager.autoSelections() == ["Auto": "b"])
    }
}
