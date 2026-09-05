import Foundation
import Testing
import PrizmXConfig
import PrizmXProtocols

@Test func nodeHostnamesExtractedFromClashYAML() {
    let yaml = """
    proxies:
      - {name: HK01, type: anytls, server: node.example.sbs, port: 5868, password: x, sni: a.com}
      - {name: info, type: anytls, server: node.example.sbs, port: 5868, password: x, sni: a.com}
      - {name: US, type: anytls, server: other.example.sbs, port: 443, password: x, sni: a.com}
    proxy-groups:
      - {name: Proxies, type: select, proxies: [HK01, US]}
    rules:
      - MATCH,Proxies
    """
    let hosts = NodeAddressStore.nodeHostnames(in: yaml)
    #expect(hosts == ["node.example.sbs", "other.example.sbs"])
}

@Test func nodeEndpointsCollectPortsPerHost() {
    let yaml = """
    proxies:
      - {name: HK01, type: anytls, server: node.example.sbs, port: 5868, password: x, sni: a.com}
      - {name: HK02, type: anytls, server: node.example.sbs, port: 5869, password: x, sni: a.com}
      - {name: US, type: anytls, server: other.example.sbs, port: 443, password: x, sni: a.com}
    proxy-groups:
      - {name: Proxies, type: select, proxies: [HK01, US]}
    rules:
      - MATCH,Proxies
    """
    let endpoints = NodeAddressStore.nodeEndpoints(in: yaml)
    #expect(endpoints["node.example.sbs"] == [5868, 5869])
    #expect(endpoints["other.example.sbs"] == [443])
    #expect(NodeAddressStore.nodeHostnames(in: yaml) == ["node.example.sbs", "other.example.sbs"])
}
