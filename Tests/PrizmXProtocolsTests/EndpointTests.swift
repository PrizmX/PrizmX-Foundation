import Testing
@testable import PrizmXProtocols

// MARK: - IPv4Address

@Test func ipv4ParsesDottedQuad() {
    let address = IPv4Address(parsing: "192.168.1.100")
    #expect(address == IPv4Address(192, 168, 1, 100))
    #expect(address?.description == "192.168.1.100")
}

@Test func ipv4RejectsInvalidLiterals() {
    #expect(IPv4Address(parsing: "256.1.1.1") == nil)
    #expect(IPv4Address(parsing: "1.2.3") == nil)
    #expect(IPv4Address(parsing: "1.2.3.4.5") == nil)
    #expect(IPv4Address(parsing: "a.b.c.d") == nil)
    #expect(IPv4Address(parsing: "") == nil)
}

@Test func ipv4NetworkOrderRoundTrip() {
    // Simulate natively loading 10.0.0.1 from an IP header byte stream.
    let headerBytes: [UInt8] = [10, 0, 0, 1]
    let loaded = headerBytes.withUnsafeBytes { $0.load(as: UInt32.self) }
    let address = IPv4Address(networkOrder: loaded)
    #expect(address == IPv4Address(10, 0, 0, 1))

    // Writing back as a byte stream must reproduce the same sequence.
    var output = [UInt8](repeating: 0, count: 4)
    output.withUnsafeMutableBytes { $0.storeBytes(of: address.networkOrder, as: UInt32.self) }
    #expect(output == headerBytes)
}

// MARK: - IPv6Address

@Test func ipv6ParsesCompressedForm() {
    #expect(IPv6Address(parsing: "::1") == .loopback)
    #expect(IPv6Address(parsing: "::") == .any)

    let address = IPv6Address(parsing: "2001:db8::1")
    let expected = IPv6Address.Segments(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1)
    #expect(address?.segments == expected)
}

@Test func ipv6ParsesEmbeddedIPv4() {
    let mapped = IPv6Address(parsing: "::ffff:192.168.0.1")
    let expected = IPv6Address.Segments(0, 0, 0, 0, 0, 0xFFFF, 0xC0A8, 0x0001)
    #expect(mapped?.segments == expected)
}

@Test func ipv6ParsesFullForm() {
    let address = IPv6Address(parsing: "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    let expected = IPv6Address.Segments(
        0x2001, 0x0DB8, 0x85A3, 0, 0, 0x8A2E, 0x0370, 0x7334
    )
    #expect(address?.segments == expected)
}

@Test func ipv6RejectsInvalidLiterals() {
    #expect(IPv6Address(parsing: ":1") == nil)
    #expect(IPv6Address(parsing: "1:") == nil)
    #expect(IPv6Address(parsing: "1:::2") == nil)
    #expect(IPv6Address(parsing: "1::2::3") == nil)
    #expect(IPv6Address(parsing: "1:2:3:4:5:6:7:8:9") == nil)
    #expect(IPv6Address(parsing: "12345::") == nil)
    #expect(IPv6Address(parsing: "") == nil)
}

@Test func ipv6DescriptionCompressesZeroRun() {
    #expect(IPv6Address.loopback.description == "::1")
    #expect(IPv6Address.any.description == "::")
    let address = IPv6Address(
        segments: IPv6Address.Segments(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1)
    )
    #expect(address.description == "2001:db8::1")
}

// MARK: - Endpoint

@Test func endpointNormalizesDomainCase() {
    let endpoint = Endpoint(domain: "Example.COM", port: 443)
    #expect(endpoint.host == .domain("example.com"))
    #expect(endpoint.port == 443)
}

@Test func endpointDescriptionUsesIPv6Brackets() {
    let endpoint = Endpoint(host: .ipv6(.loopback), port: 8080)
    #expect(endpoint.description == "[::1]:8080")

    let v4 = Endpoint(host: .ipv4(IPv4Address(10, 1, 2, 3)), port: 53)
    #expect(v4.description == "10.1.2.3:53")
}

@Test func endpointParsesHostnameAndPort() {
    let domain = Endpoint(hostname: "API.Example.COM", port: 443)
    #expect(domain?.host == .domain("api.example.com"))
    #expect(domain?.port == 443)

    let v4 = Endpoint(hostname: "10.1.2.3", port: 53)
    #expect(v4?.host == .ipv4(IPv4Address(10, 1, 2, 3)))

    let v6 = Endpoint(hostname: "2001:db8::1", port: 8080)
    #expect(v6?.host == .ipv6(IPv6Address(parsing: "2001:db8::1")!))

    let bracketed = Endpoint(hostname: "[::1]", port: 443)
    #expect(bracketed?.host == .ipv6(.loopback))

    #expect(Endpoint(hostname: "example.com", port: 0) == nil)
    #expect(Endpoint(hostname: "", port: 443) == nil)
}

@Test func endpointParsesHostPortText() {
    let domain = Endpoint(parsing: "api.example.com:443")
    #expect(domain?.host == .domain("api.example.com"))
    #expect(domain?.port == 443)

    let v6 = Endpoint(parsing: "[2001:db8::1]:8080")
    #expect(v6?.host == .ipv6(IPv6Address(parsing: "2001:db8::1")!))
    #expect(v6?.port == 8080)

    #expect(Endpoint(parsing: "example.com:0") == nil)
    #expect(Endpoint(parsing: "example.com:70000") == nil)
    #expect(Endpoint(parsing: "example.com") == nil)
}
