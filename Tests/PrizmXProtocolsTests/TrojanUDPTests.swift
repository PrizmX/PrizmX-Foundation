import Foundation
import Testing
@testable import PrizmXProtocols

@Suite("Trojan UDP framing")
struct TrojanUDPTests {

    @Test func encodesAddressLengthCRLFPayload() throws {
        let framing = TrojanUDPFraming()
        let destination = Endpoint(host: .ipv4(IPv4Address(8, 8, 8, 8)), port: 53)
        let packet = try framing.encode(Data([0xAA, 0xBB, 0xCC]), to: destination)
        #expect(Array(packet) == [
            0x01, 8, 8, 8, 8, 0x00, 0x35,
            0x00, 0x03,
            0x0D, 0x0A,
            0xAA, 0xBB, 0xCC,
        ])
    }

    @Test func decodesPacketsSplitAcrossChunks() throws {
        var framing = TrojanUDPFraming()
        let first = try framing.encode(Data("hello".utf8), to: Endpoint(domain: "example.com", port: 443))
        let second = try framing.encode(Data(), to: Endpoint(host: .ipv4(IPv4Address(1, 1, 1, 1)), port: 53))
        let wire = first + second

        var datagrams: [Data] = []
        datagrams += try framing.decode(wire.prefix(3))
        #expect(datagrams.isEmpty)
        datagrams += try framing.decode(wire.dropFirst(3).prefix(first.count))
        #expect(datagrams == [Data("hello".utf8)])
        datagrams += try framing.decode(wire.dropFirst(3 + first.count))
        #expect(datagrams == [Data("hello".utf8), Data()])
    }

    @Test func rejectsMissingCRLF() throws {
        var framing = TrojanUDPFraming()
        let bad = Data([0x01, 1, 2, 3, 4, 0x00, 0x35, 0x00, 0x01, 0x00, 0x00, 0xFF])
        #expect(throws: TrojanError.malformedUDPPacket) {
            try framing.decode(bad)
        }
    }

    @Test func lengthPrefixedFramingRoundTrip() throws {
        var framing = LengthPrefixedDatagramFraming()
        let target = Endpoint(domain: "example.com", port: 443)
        let wire = try framing.encode(Data([1, 2, 3]), to: target) + framing.encode(Data([4]), to: target)
        #expect(try framing.decode(wire) == [Data([1, 2, 3]), Data([4])])
    }
}
