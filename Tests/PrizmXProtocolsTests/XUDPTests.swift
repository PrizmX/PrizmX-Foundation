import Foundation
import Testing
@testable import PrizmXProtocols

@Suite("VLESS XUDP")
struct XUDPTests {
    private let id = "b831381d-6324-4d53-ad4f-8cda48b30811"

    @Test func muxHeaderCarriesNoAddress() throws {
        let header = try VLESSHeader(uuid: id, destination: VLESSHeader.muxDestination, command: .mux)
        let encoded = try header.encode()
        // version + uuid + addon length + command, nothing after.
        #expect(encoded.count == 1 + 16 + 1 + 1)
        #expect(encoded.last == 0x03)
        #expect(try VLESSHeader.decode(encoded).destination == VLESSHeader.muxDestination)
    }

    @Test func visionPadsMuxSessionsButNotPlainUDP() throws {
        let server = Endpoint(host: .ipv4(IPv4Address(127, 0, 0, 1)), port: 443)
        let mux = try VLESSOutboundConnection(server: server, uuid: id, target: VLESSHeader.muxDestination, flow: "xtls-rprx-vision", command: .mux)
        let udp = try VLESSOutboundConnection(server: server, uuid: id, target: server, flow: "xtls-rprx-vision", command: .udp)
        #expect(mux.usesUserspaceTLS)
        #expect(!udp.usesUserspaceTLS)
    }

    @Test func firstFrameIsNewWithGlobalIDThenKeep() throws {
        var framing = XUDPFraming(globalID: [1, 2, 3, 4, 5, 6, 7, 8])
        let target = Endpoint(host: .ipv4(IPv4Address(8, 8, 8, 8)), port: 53)
        let first = [UInt8](try framing.encode(Data([0xAA]), to: target))
        #expect(first == [
            0x00, 0x14,                         // meta length 20
            0x00, 0x00, 0x01, 0x01, 0x02,       // session 0, New, data, UDP
            0x00, 0x35, 0x01, 8, 8, 8, 8,       // port 53, IPv4
            1, 2, 3, 4, 5, 6, 7, 8,             // global id
            0x00, 0x01, 0xAA,
        ])
        let second = [UInt8](try framing.encode(Data([0xBB, 0xCC]), to: target))
        #expect(second == [
            0x00, 0x0C, 0x00, 0x00, 0x02, 0x01, 0x02, 0x00, 0x35, 0x01, 8, 8, 8, 8,
            0x00, 0x02, 0xBB, 0xCC,
        ])
    }

    @Test func decodesKeepFramesSkipsKeepAliveAndEndsOnEnd() throws {
        var framing = XUDPFraming()
        let withAddress: [UInt8] = [0x00, 0x0C, 0x00, 0x00, 0x02, 0x01, 0x02, 0x00, 0x35, 0x01, 1, 1, 1, 1, 0x00, 0x02, 0x68, 0x69]
        let keepAlive: [UInt8] = [0x00, 0x04, 0x00, 0x00, 0x04, 0x00]
        let bare: [UInt8] = [0x00, 0x04, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x21]
        let wire = Data(withAddress + keepAlive + bare)
        #expect(try framing.decode(wire.prefix(7)) == [])
        #expect(try framing.decode(wire.dropFirst(7)) == [Data("hi".utf8), Data("!".utf8)])
        #expect(throws: XUDPError.sessionEnded) {
            try framing.decode(Data([0x00, 0x04, 0x00, 0x00, 0x03, 0x00]))
        }
    }
}
