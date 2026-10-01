import Foundation
import Testing
import PrizmXConfig
import PrizmXCore

@Test func proxyClientStoreRoundTripsAndExpires() {
    let kit = FileManager.default.temporaryDirectory
        .appendingPathComponent("proxy-clients-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: kit) }

    let apsd = LoopbackClient(
        clientPort: 52_400,
        listenPort: 7_891,
        attribution: FlowAttribution(pid: 617, processName: "apsd")
    )
    #expect(ProxyClientStore.save([apsd], kitRoot: kit, writtenAt: 100))
    let loaded = ProxyClientStore.load(maxAge: 3, kitRoot: kit, now: 101)
    #expect(loaded?.client(port: 52_400, listenPort: 7_891) == apsd)
    #expect(loaded?.client(port: 52_400, listenPort: 7_890) == nil)
    // Not refreshed: the tunnel stopped publishing.
    #expect(ProxyClientStore.load(maxAge: 3, kitRoot: kit, now: 104) == nil)

    ProxyClientStore.clear(kitRoot: kit)
    #expect(ProxyClientStore.load(maxAge: 3, kitRoot: kit, now: 101) == nil)
}
