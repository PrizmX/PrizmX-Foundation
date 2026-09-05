import Foundation
import Testing
@testable import PrizmXProtocols

// MARK: - Helpers

private func bytes(hex: String) -> [UInt8] {
    let hex = hex.filter { !$0.isWhitespace }
    precondition(hex.count.isMultiple(of: 2), "hex string must have even length")
    var result: [UInt8] = []
    result.reserveCapacity(hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        result.append(UInt8(hex[index..<next], radix: 16)!)
        index = next
    }
    return result
}

private let testUUIDString = "b831381d-6324-4d53-ad4f-8cda3b4b0c7f"
private let testUUIDBytes = bytes(hex: "b831381d63244d53ad4f8cda3b4b0c7f")

// MARK: - UUID

@Suite("VLESS UUID")
struct VLESSUserIDTests {

    @Test func hyphenatedStringToRaw16Bytes() throws {
        let uuid = try VLESSUserID.parse(testUUIDString)
        #expect(VLESSUserID.rawBytes(uuid) == testUUIDBytes)
        #expect(uuid == UUID(uuidString: testUUIDString))
    }

    @Test func hexStringWithoutHyphens() throws {
        let uuid = try VLESSUserID.parse("b831381d63244d53ad4f8cda3b4b0c7f")
        #expect(VLESSUserID.rawBytes(uuid) == testUUIDBytes)
    }

    @Test func bracedAndUppercase() throws {
        let uuid = try VLESSUserID.parse("{B831381D-6324-4D53-AD4F-8CDA3B4B0C7F}")
        #expect(VLESSUserID.rawBytes(uuid) == testUUIDBytes)
    }

    @Test func rejectsMalformed() {
        do {
            _ = try VLESSUserID.parse("not-a-uuid")
            Issue.record("expected invalidUserID")
        } catch let error as VLESSError {
            #expect(error == .invalidUserID("not-a-uuid"))
        } catch {
            Issue.record("unexpected \(error)")
        }
    }
}

// MARK: - Request header wire format

@Suite("VLESS request header")
struct VLESSHeaderTests {

    @Test func encodesIPv4TCPExactly() throws {
        let header = try VLESSHeader(
            uuid: testUUIDString,
            destination: Endpoint(host: .ipv4(IPv4Address(1, 2, 3, 4)), port: 443)
        )
        let encoded = try header.encode()
        #expect(
            Array(encoded) == bytes(
                hex: """
                00
                b831381d63244d53ad4f8cda3b4b0c7f
                00
                01
                01bb
                01
                01020304
                """
            )
        )
        #expect(try VLESSHeader.decode(encoded) == header)
    }

    @Test func encodesIPv6TCPExactly() throws {
        let header = try VLESSHeader(
            uuid: testUUIDString,
            destination: Endpoint(host: .ipv6(.loopback), port: 443)
        )
        let encoded = try header.encode()
        #expect(
            Array(encoded) == bytes(
                hex: """
                00
                b831381d63244d53ad4f8cda3b4b0c7f
                00
                01
                01bb
                03
                00000000000000000000000000000001
                """
            )
        )
        #expect(try VLESSHeader.decode(encoded) == header)
    }

    @Test func encodesDomainTCPExactly() throws {
        let header = try VLESSHeader(
            uuid: testUUIDString,
            destination: Endpoint(domain: "example.com", port: 443)
        )
        let encoded = try header.encode()
        var expected = bytes(
            hex: """
            00
            b831381d63244d53ad4f8cda3b4b0c7f
            00
            01
            01bb
            02
            0b
            """
        )
        expected += Array("example.com".utf8)
        #expect(Array(encoded) == expected)
        #expect(try VLESSHeader.decode(encoded) == header)
    }

    @Test func encodesUDPCommand() throws {
        let header = try VLESSHeader(
            uuid: testUUIDString,
            destination: Endpoint(host: .ipv4(IPv4Address(8, 8, 8, 8)), port: 53),
            command: .udp
        )
        let encoded = try header.encode()
        #expect(encoded[1 + 16 + 1] == VLESSCommand.udp.rawValue)
        #expect(try VLESSHeader.decode(encoded).command == .udp)
    }

    @Test func emptyAddonsAreASingleZeroByte() throws {
        let header = try VLESSHeader(
            uuid: testUUIDString,
            destination: Endpoint(host: .ipv4(IPv4Address(127, 0, 0, 1)), port: 80)
        )
        let encoded = try header.encode()
        #expect(encoded[17] == 0x00)
        #expect(encoded.count == header.encodedByteCount)
    }

    @Test func rejectsEmptyDomain() {
        let endpoint = Endpoint(domain: "", port: 1)
        let header = VLESSHeader(
            userID: UUID(uuidString: testUUIDString)!,
            destination: endpoint
        )
        do {
            _ = try header.encode()
            Issue.record("expected invalidAddress")
        } catch let error as VLESSError {
            #expect(error == .invalidAddress(endpoint))
        } catch {
            Issue.record("unexpected \(error)")
        }
    }
}

// MARK: - Response header

@Suite("VLESS response header")
struct VLESSResponseHeaderTests {

    @Test func emptyAddonsIsTwoZeroBytes() throws {
        let header = VLESSResponseHeader()
        #expect(Array(try header.encode()) == [0x00, 0x00])
    }

    @Test func consumeStripsHeaderAndLeavesPayload() throws {
        var wire = Data([0x00, 0x00])
        wire.append(contentsOf: [0x48, 0x49]) // "HI"
        let parsed = try wire.withUnsafeBytes { try VLESSResponseHeader.consume($0) }
        #expect(parsed?.0.version == 0)
        #expect(parsed?.0.addons.isEmpty == true)
        #expect(parsed?.1 == 2)
        #expect(Array(wire[parsed!.1...]) == [0x48, 0x49])
    }

    @Test func consumeRejectsUnknownVersion() {
        let wire = Data([0x01, 0x00])
        do {
            _ = try wire.withUnsafeBytes { try VLESSResponseHeader.consume($0) }
            Issue.record("expected unsupportedVersion")
        } catch let error as VLESSError {
            #expect(error == .unsupportedVersion(1))
        } catch {
            Issue.record("unexpected \(error)")
        }
    }

    @Test func consumeReturnsNilWhenTruncated() throws {
        let wire = Data([0x00, 0x03, 0x01])
        let parsed = try wire.withUnsafeBytes { try VLESSResponseHeader.consume($0) }
        #expect(parsed == nil)
    }
}
