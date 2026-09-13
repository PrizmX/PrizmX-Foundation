import CryptoKit
import Foundation
import Testing
@testable import PrizmXProtocols

private let testUUIDString = "b831381d-6324-4d53-ad4f-8cda3b4b0c7f"
private let testUUID = UUID(uuidString: testUUIDString)!
private let testUUIDBytes: [UInt8] = [
    0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53,
    0xad, 0x4f, 0x8c, 0xda, 0x3b, 0x4b, 0x0c, 0x7f,
]

@Suite("VLESS Vision addons")
struct VLESSVisionAddonTests {
    @Test func protobufFlowFieldIsLengthPrefixedString() {
        let addons = VLESSVision.addons(flow: "xtls-rprx-vision")
        #expect(Array(addons) == [0x0A, 0x10] + Array("xtls-rprx-vision".utf8))
    }

    @Test func udp443SuffixIsTruncatedToVisionName() {
        let addons = VLESSVision.addons(flow: "xtls-rprx-vision-udp443")
        #expect(addons == VLESSVision.addons(flow: VLESSVision.flowName))
    }

    @Test func isEnabledAcceptsVisionNames() {
        #expect(VLESSVision.isEnabled("xtls-rprx-vision"))
        #expect(VLESSVision.isEnabled("xtls-rprx-vision-udp443"))
        #expect(!VLESSVision.isEnabled(nil))
        #expect(!VLESSVision.isEnabled(""))
        #expect(!VLESSVision.isEnabled("none"))
    }

    @Test func requestHeaderCarriesVisionAddons() throws {
        let addons = VLESSVision.addons(flow: VLESSVision.flowName)
        let header = try VLESSHeader(
            uuid: testUUIDString,
            destination: Endpoint(host: .ipv4(IPv4Address(1, 2, 3, 4)), port: 443),
            addons: addons
        )
        let encoded = try header.encode()
        #expect(encoded[17] == UInt8(addons.count))
        #expect(encoded.subdata(in: 18..<(18 + addons.count)) == addons)
        #expect(try VLESSHeader.decode(encoded).addons == addons)
    }
}

@Suite("VLESS Vision padding")
struct VLESSVisionPaddingTests {
    @Test func firstFrameLayoutIsUUIDCommandAndBigEndianLengths() {
        let content = Data("hi".utf8)
        let padding = Data(repeating: 0xAB, count: 4)
        let frame = VLESSVision.frame(
            command: VLESSVision.commandEnd,
            content: content,
            padding: padding,
            uuid: testUUIDBytes
        )
        #expect(Array(frame.prefix(16)) == testUUIDBytes)
        #expect(frame[16] == VLESSVision.commandEnd)
        #expect(frame[17] == 0)
        #expect(frame[18] == 2)
        #expect(frame[19] == 0)
        #expect(frame[20] == 4)
        #expect(frame.subdata(in: 21..<23) == content)
        #expect(frame.subdata(in: 23..<27) == padding)
    }

    @Test func readerRoundTripWithUUIDAndEnd() {
        let content = Data("HTTP/1.1 204 No Content\r\n\r\n".utf8)
        let frame = VLESSVision.frame(
            command: VLESSVision.commandEnd,
            content: content,
            padding: Data(repeating: 0x11, count: 32),
            uuid: testUUIDBytes
        )
        let reader = VLESSVisionReader(userID: testUUID)
        #expect(reader.feed(frame) == content)
    }

    @Test func readerAcceptsSplitFeeds() {
        let content = Data([0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00])
        let frame = VLESSVision.frame(
            command: VLESSVision.commandContinue,
            content: content,
            padding: Data(repeating: 0x22, count: 8),
            uuid: testUUIDBytes
        )
        let reader = VLESSVisionReader(userID: testUUID)
        var output = Data()
        for byte in frame {
            output.append(reader.feed(Data([byte])))
        }
        #expect(output == content)
    }

    @Test func continueThenEndThenRaw() {
        let hello = Data("hello".utf8)
        let world = Data("world".utf8)
        let raw = Data("RAW".utf8)
        var wire = VLESSVision.frame(
            command: VLESSVision.commandContinue,
            content: hello,
            padding: Data(repeating: 0x01, count: 3),
            uuid: testUUIDBytes
        )
        wire.append(
            VLESSVision.frame(
                command: VLESSVision.commandEnd,
                content: world,
                padding: Data(repeating: 0x02, count: 3)
            )
        )
        wire.append(raw)
        let reader = VLESSVisionReader(userID: testUUID)
        #expect(reader.feed(wire) == hello + world + raw)
        #expect(reader.feed(Data("more".utf8)) == Data("more".utf8))
    }

    @Test func writerCamouflageStartsWithUUIDAndUnpadsToEmpty() {
        let writer = VLESSVisionWriter(userID: testUUID)
        let reader = VLESSVisionReader(userID: testUUID)
        let camouflage = writer.camouflage()
        #expect(Array(camouflage.prefix(16)) == testUUIDBytes)
        #expect(
            camouflage[16] == VLESSVision.commandContinue
                || camouflage[16] == VLESSVision.commandEnd
        )
        #expect(reader.feed(camouflage).isEmpty)
    }

    @Test func writerThenReaderRoundTripHTTP() {
        let writer = VLESSVisionWriter(userID: testUUID)
        let reader = VLESSVisionReader(userID: testUUID)
        #expect(reader.feed(writer.camouflage()).isEmpty)
        let get = Data("GET / HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        #expect(reader.feed(writer.encode(get)) == get)
    }

    @Test func outboundStoresVisionFlow() throws {
        let connection = try VLESSOutboundConnection(
            server: Endpoint(domain: "vless.example", port: 443),
            uuid: testUUIDString,
            target: Endpoint(host: .ipv4(IPv4Address(1, 2, 3, 4)), port: 80),
            flow: "xtls-rprx-vision"
        )
        #expect(connection.flow == VLESSVision.flowName)
    }

    @Test func recordLayerDirectCopyTransition() throws {
        // Simulate the server: two sealed Vision frames (continue, direct),
        // then raw inner-TLS bytes. After the direct frame the record layer
        // must stop decrypting and hand buffered bytes over untouched.
        func trafficKeys() -> TLS13TrafficKeys {
            TLS13TrafficKeys(
                key: SymmetricKey(size: .bits256),
                iv: TLS13Random.bytes(12),
                sequence: 0,
                aead: .aesGCM
            )
        }
        let pair = TLS13TrafficPair(client: trafficKeys(), server: trafficKeys())
        let layer = TLS13RecordLayer(application: pair)

        let uuid = testUUIDBytes
        let continueFrame = VLESSVision.frame(
            command: VLESSVision.commandContinue,
            content: Data("SERVERHELLO".utf8),
            padding: Data(repeating: 0x01, count: 8),
            uuid: uuid
        )
        let directFrame = VLESSVision.frame(
            command: VLESSVision.commandDirect,
            content: Data("TICKET".utf8),
            padding: Data(repeating: 0x02, count: 4)
        )
        let rawBytes = Data([0x17, 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC])

        var sealingServer = pair.server
        var wire = try TLS13AEAD.seal(
            plaintext: continueFrame,
            keys: &sealingServer,
            contentType: TLS13.contentApplicationData
        )
        wire.append(try TLS13AEAD.seal(
            plaintext: directFrame,
            keys: &sealingServer,
            contentType: TLS13.contentApplicationData
        ))
        wire.append(rawBytes)

        layer.appendWire(wire)
        let reader = VLESSVisionReader(userID: testUUID)

        let first = try #require(try layer.decryptNextRecord())
        #expect(reader.feed(first) == Data("SERVERHELLO".utf8))
        #expect(!reader.sawDirectCommand)

        let second = try #require(try layer.decryptNextRecord())
        #expect(reader.feed(second) == Data("TICKET".utf8))
        #expect(reader.sawDirectCommand)

        layer.enableRawMode()
        #expect(layer.isRawMode)
        #expect(layer.drainRawIncoming() == rawBytes)
    }
}
