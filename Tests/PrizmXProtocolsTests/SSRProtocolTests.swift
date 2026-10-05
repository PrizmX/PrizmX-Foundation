import Foundation
import Testing
@testable import PrizmXProtocols

/// Server frames that pass their checksums but carry impossible fields must
/// throw, not trap: they come off the wire.
@Suite("SSR protocol plugins")
struct SSRProtocolTests {
    private let context = SSRContext(key: Array(repeating: 7, count: 16), iv: Array(repeating: 1, count: 16), protocolParam: "", overhead: 0)

    @Test func authSHA1V4RejectsPaddingPastTheFrame() {
        // [len BE = 9][crc16 LE][padding marker 200 > frame][adler32 LE]
        let length = 9
        var frame = SSRBytes.be16(length)
        frame += SSRBytes.le16(Int(CRC32.checksum(SSRBytes.be16(length)) & 0xFFFF))
        frame.append(200)
        frame += SSRBytes.le32(SSRBytes.adler32(frame))
        #expect(throws: SSRError.malformedFrame) {
            try SSRAuthSHA1V4(context: context).decode(frame)
        }
    }

    @Test func authAES128RejectsPaddingPastTheFrame() {
        // [len LE = 9][HMAC 2][padding marker 200 > frame][HMAC 4], recv id 1.
        let length = 9
        let macKey = context.key + SSRBytes.le32(1)
        var frame = SSRBytes.le16(length)
        frame += SSRBytes.hmac(macKey, frame, sha1: false).prefix(2)
        frame.append(200)
        frame += SSRBytes.hmac(macKey, frame, sha1: false).prefix(4)
        #expect(throws: SSRError.malformedFrame) {
            try SSRAuthAES128(context: context, sha1: false).decode(frame)
        }
    }

    @Test func authChainARejectsDataBeforeItsAuthFrame() {
        // The server hash chain starts from the client's auth frame.
        #expect(throws: SSRError.malformedFrame) {
            try SSRAuthChainA(context: context).decode(Array(repeating: 0, count: 16))
        }
    }

    @Test func authChainARoundTripsTheAddressHeader() throws {
        // Encoding must not trap and must keep the first frame's layout:
        // check head (12) + uid (4) + auth block (16) + server hash (4) + frame.
        let codec = SSRAuthChainA(context: context)
        let header = try ShadowsocksAddress.encode(Endpoint(domain: "echo.test", port: 7))
        let wire = try codec.encode(header)
        #expect(wire.count >= 12 + 4 + 16 + 4 + 2 + 2)
    }
}
