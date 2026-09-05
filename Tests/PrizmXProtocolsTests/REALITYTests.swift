import CryptoKit
import Foundation
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

private func keyBytes(_ key: SymmetricKey) -> [UInt8] {
    key.withUnsafeBytes { Array($0) }
}

private func hexKey(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

// MARK: - Public key / Short ID encoding

@Suite("REALITY key encoding")
struct REALITYKeyEncodingTests {

    @Test func hexBase64Base64URLAndBase45AllDecodeTo32Bytes() throws {
        let raw = bytes(hex: "8515e4d1f8d6c86c7d0c0e6e1e4c7a9b0c1d2e3f405162738495a6b7c8d9e0f1")
        let hex = hexKey(raw)
        let std = Data(raw).base64EncodedString()
        let url = std.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let b45 = REALITYKeyEncoding.encodeBase45(raw)

        #expect(try REALITYKeyEncoding.decode32(hex) == raw)
        #expect(try REALITYKeyEncoding.decode32(std) == raw)
        #expect(try REALITYKeyEncoding.decode32(url) == raw)
        #expect(try REALITYKeyEncoding.decode32(b45) == raw)
    }

    @Test func shortIDAcceptsEmptyAndEvenHexUpTo8Bytes() throws {
        #expect(try REALITYKeyEncoding.decodeShortID("") == [])
        #expect(try REALITYKeyEncoding.decodeShortID("ab") == [0xAB])
        #expect(try REALITYKeyEncoding.decodeShortID("0123456789abcdef") == bytes(hex: "0123456789abcdef"))
        do {
            _ = try REALITYKeyEncoding.decodeShortID("abc")
            Issue.record("odd hex should fail")
        } catch let error as REALITYError {
            #expect(error == .invalidShortID("abc"))
        }
        do {
            _ = try REALITYKeyEncoding.decodeShortID("001122334455667788")
            Issue.record("9-byte short id should fail")
        } catch is REALITYError {
            // expected
        }
    }

    @Test func configRejectsEmptySNIAndBadPublicKey() {
        do {
            _ = try REALITYConfig(publicKey: "not-a-key", serverName: "www.apple.com")
            Issue.record("expected invalidPublicKey")
        } catch let error as REALITYError {
            guard case .invalidPublicKey = error else {
                Issue.record("unexpected \(error)")
                return
            }
        } catch {
            Issue.record("unexpected \(error)")
        }
        do {
            let hex = hexKey([UInt8](repeating: 1, count: 32))
            _ = try REALITYConfig(publicKey: hex, serverName: "  ")
            Issue.record("expected invalidServerName")
        } catch let error as REALITYError {
            #expect(error == .invalidServerName)
        } catch {
            Issue.record("unexpected \(error)")
        }
    }
}

// MARK: - ECDH + HKDF

@Suite("REALITY ECDH and HKDF")
struct REALITYCryptoTests {

    @Test func x25519RFC7748KeysAgreeInBothDirections() throws {
        // RFC 7748 §6.1 scalars, loaded through CryptoKit. Apple clamps the
        // scalar on use so the shared secret may differ from the RFC hex
        // vector; both directions must still match.
        let alice = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data(bytes(hex:
                "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
            ))
        )
        let bob = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data(bytes(hex:
                "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
            ))
        )
        let ab = try REALITYHandshaker.sharedSecret(
            ephemeral: alice,
            serverPublicKey: bob.publicKey
        )
        let ba = try REALITYHandshaker.sharedSecret(
            ephemeral: bob,
            serverPublicKey: alice.publicKey
        )
        #expect(ab == ba)
        #expect(ab.count == 32)
        #expect(!ab.allSatisfy { $0 == 0 })
    }

    @Test func bothPartiesDeriveTheSameSharedSecret() throws {
        let client = Curve25519.KeyAgreement.PrivateKey()
        let server = Curve25519.KeyAgreement.PrivateKey()
        let ab = try REALITYHandshaker.sharedSecret(
            ephemeral: client,
            serverPublicKey: server.publicKey
        )
        let ba = try REALITYHandshaker.sharedSecret(
            ephemeral: server,
            serverPublicKey: client.publicKey
        )
        #expect(ab == ba)
        #expect(ab.count == 32)
    }

    @Test func hkdfSHA256MatchesRFC5869Case1() {
        // RFC 5869 A.1 — SHA-256, L=42
        let ikm = Data(bytes(hex: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))
        let salt = Data(bytes(hex: "000102030405060708090a0b0c"))
        let info = Data(bytes(hex: "f0f1f2f3f4f5f6f7f8f9"))
        let prk = TLS13HashKind.sha256.extract(salt: salt, ikm: ikm)
        #expect(Array(prk) == bytes(hex:
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        ))
        let okm = TLS13HashKind.sha256.expand(prk: prk, info: info, length: 42)
        #expect(Array(okm) == bytes(hex:
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        ))
    }

    @Test func authKeyIsHKDFSHA256WithSaltRandomPrefix20AndInfoREALITY() throws {
        let shared = Data(bytes(hex:
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        ))
        var random = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 { random[i] = UInt8(i & 0xFF) }

        let key = REALITYHandshaker.deriveAuthKey(sharedSecret: shared, clientRandom: random)
        let expected = TLS13HashKind.sha256.expand(
            prk: TLS13HashKind.sha256.extract(
                salt: Data(random.prefix(20)),
                ikm: shared
            ),
            info: Data(REALITY.hkdfInfo.utf8),
            length: 32
        )
        #expect(keyBytes(key) == Array(expected))
        #expect(keyBytes(key).count == 32)
        #expect(REALITY.hkdfInfo == "REALITY")
    }
}

// MARK: - Session ID layout / ClientHello overlay

@Suite("REALITY Session ID")
struct REALITYSessionIDTests {

    @Test func plaintextLayoutIsVersionTimestampAndPaddedShortID() {
        let shortID = bytes(hex: "aabbccdd")
        let sid = REALITYHandshaker.sessionIDPlaintext(
            version: (25, 8, 3),
            unixTime: 0x0102_0304,
            shortID: shortID
        )
        #expect(sid.count == 32)
        #expect(sid[0] == 25)
        #expect(sid[1] == 8)
        #expect(sid[2] == 3)
        #expect(sid[3] == 0)
        #expect(sid[4..<8] == [0x01, 0x02, 0x03, 0x04])
        #expect(Array(sid[8..<12]) == shortID)
        #expect(sid[12..<32].allSatisfy { $0 == 0 })
    }

    @Test func paddedShortIDFillsEightBytes() throws {
        let hex = hexKey([UInt8](repeating: 7, count: 32))
        let config = try REALITYConfig(
            publicKey: hex,
            shortId: "abcd",
            serverName: "www.apple.com"
        )
        #expect(config.paddedShortID == [0xAB, 0xCD, 0, 0, 0, 0, 0, 0])
    }

    @Test func clientHelloPlacesSealedSessionIDAtHandshakeOffset39() throws {
        let server = Curve25519.KeyAgreement.PrivateKey()
        let publicHex = hexKey(Array(server.publicKey.rawRepresentation))
        let config = try REALITYConfig(
            publicKey: publicHex,
            shortId: "0123456789abcdef",
            serverName: "www.apple.com",
            spiderX: "/"
        )
        let unix: UInt32 = 1_700_000_000
        var random = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 { random[i] = UInt8(0xA0 &+ UInt8(i)) }

        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let prepared = try REALITYHandshaker(config: config).makeClientHello(
            ephemeral: ephemeral,
            unixTime: unix,
            random: random
        )

        let handshake = prepared.handshake
        #expect(handshake[0] == 0x01) // client_hello
        #expect(handshake[38] == 32)
        #expect(handshake.count > REALITY.handshakeSessionIDOffset + 32)
        #expect(prepared.wireSessionID == prepared.sealedSessionID)
        #expect(prepared.wireSessionID.count == 32)
        #expect(prepared.wireSessionID != prepared.plaintextSessionID)

        let plaintext = REALITYHandshaker.sessionIDPlaintext(
            version: REALITY.clientVersion,
            unixTime: unix,
            shortID: config.paddedShortID
        )
        #expect(prepared.plaintextSessionID == plaintext)
        #expect(plaintext[0..<3] == [
            REALITY.clientVersion.0,
            REALITY.clientVersion.1,
            REALITY.clientVersion.2,
        ])
        #expect(Array(plaintext[8..<16]) == config.paddedShortID)

        // AAD is the handshake with zeros in the Session ID (Xray copies zeros
        // into Raw[39:] before Seal). Opening with that AAD recovers SID[:16].
        let opened = try REALITYHandshaker.openSessionID(
            sealedSID: prepared.sealedSessionID,
            clientRandom: prepared.random,
            handshakeAAD: prepared.handshakeAAD,
            authKey: prepared.authKey
        )
        #expect(opened == Array(plaintext.prefix(16)))

        // Opening with the overlaid (ciphertext) handshake as AAD must fail.
        do {
            _ = try REALITYHandshaker.openSessionID(
                sealedSID: prepared.sealedSessionID,
                clientRandom: prepared.random,
                handshakeAAD: handshake,
                authKey: prepared.authKey
            )
            Issue.record("AAD with ciphertext SID should not authenticate")
        } catch is REALITYError {
            // expected
        }

        // AuthKey must equal ECDH(ephemeral, server) then HKDF.
        let shared = try REALITYHandshaker.sharedSecret(
            ephemeral: ephemeral,
            serverPublicKey: server.publicKey
        )
        let expectedKey = REALITYHandshaker.deriveAuthKey(
            sharedSecret: shared,
            clientRandom: random
        )
        #expect(keyBytes(prepared.authKey) == keyBytes(expectedKey))
    }

    @Test func hmacSHA512MatchesAuthKeyAndRejectsTampering() throws {
        let authKey = SymmetricKey(data: Data((0..<32).map { UInt8($0) }))
        let publicKey = [UInt8](repeating: 0x42, count: 32)
        let mac = HMAC<SHA512>.authenticationCode(for: Data(publicKey), using: authKey)
        try REALITYHandshaker.verifyCertificateHMAC(
            authKey: authKey,
            publicKey: publicKey,
            signature: Array(mac)
        )
        do {
            var bad = Array(mac)
            bad[0] ^= 0x01
            try REALITYHandshaker.verifyCertificateHMAC(
                authKey: authKey,
                publicKey: publicKey,
                signature: bad
            )
            Issue.record("tampered HMAC should fail")
        } catch let error as REALITYError {
            #expect(error == .unverifiedCertificate)
        }
    }
}

@Suite("VLESS REALITY wiring")
struct VLESSREALITYWiringTests {

    @Test func outboundStoresREALITYConfigAndSkipsNetworkTLS() throws {
        let hex = hexKey([UInt8](repeating: 9, count: 32))
        let reality = try REALITYConfig(
            publicKey: hex,
            shortId: "aa",
            serverName: "www.apple.com"
        )
        let connection = try VLESSOutboundConnection(
            server: Endpoint(domain: "vless.example", port: 443),
            uuid: "b831381d-6324-4d53-ad4f-8cda3b4b0c7f",
            target: Endpoint(host: .ipv4(IPv4Address(1, 2, 3, 4)), port: 443),
            sni: "www.apple.com",
            tls: true,
            reality: reality
        )
        #expect(connection.reality?.serverName == "www.apple.com")
        #expect(connection.tlsEnabled)
        #expect(connection.reality?.shortId == "aa")
    }
}
