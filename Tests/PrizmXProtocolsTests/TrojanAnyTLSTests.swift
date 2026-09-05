import Foundation
import Network
import Security
import Testing
@testable import PrizmXProtocols

private func bytes(hex: String) -> [UInt8] {
    let hex = hex.filter { !$0.isWhitespace }
    precondition(hex.count.isMultiple(of: 2))
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

// MARK: - SHA-224 / Trojan header

@Suite("Trojan SHA-224 header")
struct TrojanHeaderTests {

    @Test func sha224MatchesFIPSVectorABC() {
        // FIPS 180-4 SHA-224("abc")
        #expect(
            SHA224.hexString(Array("abc".utf8))
                == "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        )
    }

    @Test func sha224PasswordHexIs56LowercaseBytes() {
        let hex = SHA224.hexDigest(Array("password".utf8))
        #expect(hex.count == 56)
        #expect(
            String(decoding: hex, as: UTF8.self)
                == "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        )
        #expect(hex.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) })
    }

    @Test func headerConcatenatesHashCRLFCommandSOCKS5CRLF() throws {
        let destination = Endpoint(host: .ipv4(IPv4Address(1, 2, 3, 4)), port: 443)
        let header = TrojanHeader(password: "password", destination: destination)
        let encoded = try header.encode()

        let hash = SHA224.hexDigest(Array("password".utf8))
        var expected = hash
        expected.append(contentsOf: [0x0D, 0x0A])
        expected.append(TrojanCommand.connect.rawValue)
        expected.append(contentsOf: [0x01, 1, 2, 3, 4, 0x01, 0xBB])
        expected.append(contentsOf: [0x0D, 0x0A])
        #expect(encoded == expected)
        #expect(encoded.count == 56 + 2 + 1 + 7 + 2)
    }

    @Test func headerEncodesDomainAndUDPCommand() throws {
        let destination = Endpoint(domain: "example.com", port: 80)
        let header = TrojanHeader(
            password: "password",
            destination: destination,
            command: .udpAssociate
        )
        let encoded = try header.encode()
        #expect(encoded[56] == 0x0D && encoded[57] == 0x0A)
        #expect(encoded[58] == 0x03)
        #expect(encoded[59] == 0x03)
        #expect(encoded[60] == UInt8("example.com".utf8.count))
        #expect(encoded.suffix(2) == [0x0D, 0x0A])
    }

    @Test func convenienceInitStoresServerPortAndHash() {
        let target = Endpoint(host: .ipv4(IPv4Address(8, 8, 8, 8)), port: 53)
        let connection = TrojanOutboundConnection(
            host: "trojan.example.com",
            port: 443,
            password: "password",
            target: target,
            sni: "trojan.example.com"
        )
        #expect(connection.server.port == 443)
        #expect(connection.sni == "trojan.example.com")
        #expect(connection.passwordHashHex.count == 56)
        #expect(connection.state == .idle)
    }
}

// MARK: - AnyTLS

@Suite("AnyTLS TLS 1.3 + framing")
struct AnyTLSTests {

    @Test func authBlobIsSHA256PlusPaddingLength() {
        let auth = AnyTLSAuth(password: "password", paddingByteCount: 30)
        let encoded = auth.encode()
        let sha256 = bytes(
            hex: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        )
        #expect(Array(encoded.prefix(32)) == sha256)
        #expect(encoded[32] == 0 && encoded[33] == 30)
        #expect(encoded.count == 32 + 2 + 30)
        #expect(encoded.suffix(30).allSatisfy { $0 == 0 })
    }

    @Test func frameRoundTripPSH() {
        let payload = Data([0x01, 0x02, 0x03])
        let frame = AnyTLSFrame(command: .psh, streamID: 1, payload: payload)
        let encoded = frame.encode()
        #expect(encoded.count == 7 + 3)
        #expect(encoded[0] == AnyTLSCommand.psh.rawValue)
        let parsed = encoded.withUnsafeBytes { AnyTLSFrame.consume($0) }
        let (decoded, consumed) = try! #require(parsed)
        #expect(consumed == encoded.count)
        #expect(decoded.command == .psh)
        #expect(decoded.streamID == 1)
        #expect(decoded.payload == payload)
    }

    @Test func settingsBodyContainsVersionAndClient() {
        let body = AnyTLSSettings.clientBody(paddingMD5Hex: "deadbeef")
        let text = String(decoding: body, as: UTF8.self)
        #expect(text.contains("v=2"))
        #expect(text.contains("client=prizmx/1.0"))
        #expect(text.contains("padding-md5=deadbeef"))
    }

    @Test func connectionPinsTLS13AndSNI() {
        let target = Endpoint(host: .ipv4(IPv4Address(1, 1, 1, 1)), port: 443)
        let connection = AnyTLSOutboundConnection(
            host: "anytls.example.com",
            port: 443,
            password: "secret",
            target: target,
            sni: "cdn.example.com"
        )
        #expect(connection.sni == "cdn.example.com")
        #expect(connection.tlsMinimumProtocol == .TLSv13)
        #expect(connection.tlsMaximumProtocol == .TLSv13)
        #expect(connection.passwordSHA256.count == 32)
        #expect(connection.state == .idle)

        let parameters = connection.makeTLSParameters()
        #expect(parameters.preferNoProxies == true)
        #expect(parameters.defaultProtocolStack.internetProtocol != nil)
    }
}
