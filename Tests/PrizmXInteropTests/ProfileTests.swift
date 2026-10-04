import Foundation
import Testing
@testable import PrizmXConfig
import PrizmXNodes
import PrizmXProtocols

/// The interop profiles themselves. No servers needed: these run in every
/// `swift test`, so a broken or drifting profile fails before Docker does.
@Suite("Interop profile")
struct ProfileTests {

    @Test func everyDeclaredNodeImportsWithoutWarnings() throws {
        let result = try InteropProfile.imported()
        #expect(result.warnings.isEmpty, "\(result.warnings)")
        #expect(!InteropProfile.declaredNames.isEmpty)
        #expect(InteropProfile.nodes.map(\.name) == InteropProfile.declaredNames)
        #expect(Set(InteropProfile.declaredNames).count == InteropProfile.declaredNames.count, "duplicate node names")
    }

    @Test func groupOffersEveryNode() throws {
        let manager = try InteropProfile.imported().nodeManager
        let group = try #require(manager.group(named: InteropEnvironment.group))
        #expect(group.nodeIDs == InteropProfile.declaredNames)
    }

    /// `udp:` must match what the node can do, so a wrong annotation does
    /// not silently skip (or fail) the UDP scenarios.
    @Test(arguments: InteropProfile.nodes)
    func udpExpectationMatchesCapability(node: InteropNode) throws {
        let outbound = try NodeFactory.makeDatagramOutbound(from: node.node, to: InteropEnvironment.dnsTarget)
        #expect((outbound != nil) == node.expectsUDP)
    }

    /// The sing-box twin imports to the same nodes (importer parity).
    @Test func singboxTwinMatchesProfile() throws {
        let text = try String(contentsOf: InteropProfile.singboxURL, encoding: .utf8)
        let result = try SingboxConfigParser().parseWithWarnings(rawString: text)
        #expect(result.warnings.isEmpty, "\(result.warnings)")
        let twins = result.nodeManager.nodesByID
        let expected = InteropProfile.nodes.filter(\.hasSingboxTwin)
        for node in expected {
            let twin = try #require(twins[node.name], "\(node.name) missing from profile.singbox.json")
            #expect(twin.protocolConfig == node.node.protocolConfig, "\(node.name)")
        }
        #expect(Set(twins.keys) == Set(expected.map(\.name)))
    }

    /// `known-issue:` keys must name scenario families, or the issue would
    /// never match a scenario and the failure would surface as a plain one.
    @Test func knownIssuesNameScenarioFamilies() {
        let families = Set(NodeTests.scenarios.map(\.family))
        for node in InteropProfile.nodes {
            for family in node.knownIssues.keys {
                #expect(families.contains(family), "\(node.name): unknown family \(family)")
            }
        }
    }
}
