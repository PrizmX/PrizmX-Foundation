import Testing
import PrizmXConfig
import PrizmXCore

@Test func inboundListenUsesAppDefaultsWhenMissing() {
    let listen = InboundListenConfig.parse(from: nil)
    #expect(listen == .appDefault)
    #expect(listen.sockets.map(\.port) == [7890, 7891])
    #expect(listen.sockets.map(\.accept) == [.http, .socks])
}

@Test func inboundListenParsesClashPorts() {
    let listen = InboundListenConfig.parse(
        from: """
        port: 7890
        socks-port: 7891
        proxies: []
        """
    )
    #expect(listen.httpPort == 7890)
    #expect(listen.socksPort == 7891)
    #expect(listen.mixedPort == nil)
    #expect(listen.systemProxyHTTPPort == 7890)
    #expect(listen.systemProxySOCKSPort == 7891)
}

@Test func inboundListenParsesMixedPortOnly() {
    let listen = InboundListenConfig.parse(from: "mixed-port: 7890\nproxies: []\n")
    #expect(listen.mixedPort == 7890)
    #expect(listen.httpPort == nil)
    #expect(listen.socksPort == nil)
    #expect(listen.sockets == [InboundListenConfig.Socket(port: 7890, accept: .mixed)])
    #expect(listen.systemProxyHTTPPort == 7890)
    #expect(listen.systemProxySOCKSPort == 7890)
}

@Test func inboundListenSkipsDuplicateMixedAndHTTP() {
    let listen = InboundListenConfig.parse(
        from: """
        mixed-port: 7890
        port: 7890
        socks-port: 7891
        """
    )
    #expect(listen.sockets.map(\.port) == [7890, 7891])
    #expect(listen.sockets.map(\.accept) == [.mixed, .socks])
}
