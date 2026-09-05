import Foundation
import Testing
import PrizmXProtocols
@testable import PrizmXTUN

@Test func ipv4PortUnreachableLooksLikeICMP() {
    let packet = ICMPReply.portUnreachable(
        client: IPv4Address(198, 18, 0, 10),
        destination: IPv4Address(198, 18, 0, 20),
        sourcePort: 443,
        destinationPort: 443
    )
    #expect(packet.count == 56)
    #expect(packet[0] >> 4 == 4)
    #expect(packet[9] == 1)
    #expect(packet[20] == 3)
    #expect(packet[21] == 3)
    #expect(ICMPReply.internetChecksum(packet.prefix(20)) == 0)
}

@Test func ipv6UnreachableLooksLikeICMPv6() throws {
    var original = Data(count: 40)
    original[0] = 0x60
    original[7] = 64
    original[6] = 17
    let reply = try #require(ICMPReply.ipv6Unreachable(original: original))
    #expect(reply[0] >> 4 == 6)
    #expect(reply[6] == 58)
    #expect(reply[40] == 1)
    #expect(reply[41] == 3)
}
