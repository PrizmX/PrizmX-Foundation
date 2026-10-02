import CryptoKit
import Foundation
import Security
import Testing
@testable import PrizmXProtocols

// MARK: - Minimal DER / X.509 builder (test certificates)

private func derLength(_ count: Int) -> [UInt8] {
    if count < 0x80 { return [UInt8(count)] }
    if count < 0x100 { return [0x81, UInt8(count)] }
    return [0x82, UInt8(count >> 8), UInt8(count & 0xFF)]
}

private func der(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
    [tag] + derLength(content.count) + content
}

private func sequence(_ parts: [UInt8]...) -> [UInt8] {
    der(0x30, parts.flatMap { $0 })
}

private let ecdsaWithSHA256: [UInt8] = sequence(der(0x06, [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]))

/// X.509 v3 cert carrying `spki`, signed by a throwaway P-256 issuer key.
private func makeCertificate(spki: [UInt8], commonName: String = "prizmx.test") throws -> [UInt8] {
    let name = sequence(der(0x31, sequence(der(0x06, [0x55, 0x04, 0x03]), der(0x0C, Array(commonName.utf8)))))
    let validity = sequence(der(0x17, Array("250101000000Z".utf8)), der(0x17, Array("350101000000Z".utf8)))
    let tbs = sequence(
        der(0xA0, der(0x02, [0x02])),
        der(0x02, [0x01]),
        ecdsaWithSHA256,
        name,
        validity,
        name,
        spki
    )
    let issuer = P256.Signing.PrivateKey()
    let signature = try issuer.signature(for: Data(tbs)).derRepresentation
    return sequence(tbs, ecdsaWithSHA256, der(0x03, [0x00] + Array(signature)))
}

private func leaf(_ der: [UInt8]) throws -> TLS13Certificate {
    try TLS13X509.parse(der)
}

private let transcriptHash = Data(SHA256.hash(data: Data("transcript".utf8)))
private let signedContent = TLS13PeerVerifier.certificateVerifyContent(transcriptHash: transcriptHash)

@Suite("TLS 1.3 server authentication")
struct TLS13VerificationTests {

    @Test func ecdsaP256CertificateVerify() throws {
        let key = P256.Signing.PrivateKey()
        let cert = try leaf(makeCertificate(spki: Array(key.publicKey.derRepresentation)))
        let signature = Array(try key.signature(for: signedContent).derRepresentation)

        try TLS13PeerVerifier.verifyCertificateVerify(
            scheme: 0x0403, signature: signature, transcriptHash: transcriptHash, leaf: cert
        )
        var tampered = signature
        tampered[tampered.count - 1] ^= 0x01
        #expect(throws: TLS13PeerVerificationError.badCertificateVerify) {
            try TLS13PeerVerifier.verifyCertificateVerify(
                scheme: 0x0403, signature: tampered, transcriptHash: transcriptHash, leaf: cert
            )
        }
        // Signature over another transcript must not verify.
        #expect(throws: TLS13PeerVerificationError.badCertificateVerify) {
            try TLS13PeerVerifier.verifyCertificateVerify(
                scheme: 0x0403, signature: signature, transcriptHash: Data(count: 32), leaf: cert
            )
        }
        // Scheme pins the curve / key type.
        #expect(throws: TLS13PeerVerificationError.keyMismatch(0x0503)) {
            try TLS13PeerVerifier.verifyCertificateVerify(
                scheme: 0x0503, signature: signature, transcriptHash: transcriptHash, leaf: cert
            )
        }
        #expect(throws: TLS13PeerVerificationError.keyMismatch(0x0804)) {
            try TLS13PeerVerifier.verifyCertificateVerify(
                scheme: 0x0804, signature: signature, transcriptHash: transcriptHash, leaf: cert
            )
        }
        // PKCS#1 v1.5 is not a TLS 1.3 CertificateVerify scheme.
        #expect(throws: TLS13PeerVerificationError.unsupportedSignatureScheme(0x0401)) {
            try TLS13PeerVerifier.verifyCertificateVerify(
                scheme: 0x0401, signature: signature, transcriptHash: transcriptHash, leaf: cert
            )
        }
    }

    @Test func ecdsaP384CertificateVerify() throws {
        let key = P384.Signing.PrivateKey()
        let cert = try leaf(makeCertificate(spki: Array(key.publicKey.derRepresentation)))
        let signature = Array(try key.signature(for: signedContent).derRepresentation)
        try TLS13PeerVerifier.verifyCertificateVerify(
            scheme: 0x0503, signature: signature, transcriptHash: transcriptHash, leaf: cert
        )
        #expect(throws: TLS13PeerVerificationError.keyMismatch(0x0403)) {
            try TLS13PeerVerifier.verifyCertificateVerify(
                scheme: 0x0403, signature: signature, transcriptHash: transcriptHash, leaf: cert
            )
        }
    }

    @Test func rsaPSSCertificateVerify() throws {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048,
        ]
        var error: Unmanaged<CFError>?
        let privateKey = try #require(SecKeyCreateRandomKey(attributes as CFDictionary, &error))
        let publicKey = try #require(SecKeyCopyPublicKey(privateKey))
        let pkcs1 = try #require(SecKeyCopyExternalRepresentation(publicKey, &error) as Data?)
        let rsaEncryption = sequence(
            der(0x06, [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]),
            [0x05, 0x00]
        )
        let spki = sequence(rsaEncryption, der(0x03, [0x00] + Array(pkcs1)))
        let cert = try leaf(makeCertificate(spki: spki))

        for (scheme, algorithm) in [
            (UInt16(0x0804), SecKeyAlgorithm.rsaSignatureMessagePSSSHA256),
            (UInt16(0x0805), SecKeyAlgorithm.rsaSignatureMessagePSSSHA384),
            (UInt16(0x0806), SecKeyAlgorithm.rsaSignatureMessagePSSSHA512),
        ] {
            let signature = try #require(
                SecKeyCreateSignature(privateKey, algorithm, signedContent as CFData, &error) as Data?
            )
            try TLS13PeerVerifier.verifyCertificateVerify(
                scheme: scheme, signature: Array(signature), transcriptHash: transcriptHash, leaf: cert
            )
            #expect(throws: TLS13PeerVerificationError.badCertificateVerify) {
                try TLS13PeerVerifier.verifyCertificateVerify(
                    scheme: scheme, signature: Array(signature), transcriptHash: Data(count: 32), leaf: cert
                )
            }
        }
    }

    @Test func ed25519CertificateVerify() throws {
        let key = Curve25519.Signing.PrivateKey()
        let spki = sequence(
            sequence(der(0x06, [0x2B, 0x65, 0x70])),
            der(0x03, [0x00] + Array(key.publicKey.rawRepresentation))
        )
        let cert = try leaf(makeCertificate(spki: spki))
        let signature = Array(try key.signature(for: signedContent))
        try TLS13PeerVerifier.verifyCertificateVerify(
            scheme: TLS13.signatureEd25519, signature: signature, transcriptHash: transcriptHash, leaf: cert
        )
        #expect(throws: TLS13PeerVerificationError.keyMismatch(0x0403)) {
            try TLS13PeerVerifier.verifyCertificateVerify(
                scheme: 0x0403, signature: signature, transcriptHash: transcriptHash, leaf: cert
            )
        }
    }

    @Test func untrustedChainIsRejected() throws {
        let key = P256.Signing.PrivateKey()
        let der = try makeCertificate(spki: Array(key.publicKey.derRepresentation), commonName: "example.com")
        #expect(throws: TLS13PeerVerificationError.self) {
            try TLS13PeerVerifier.verifyChain([der], serverName: "example.com")
        }
        #expect(throws: TLS13PeerVerificationError.emptyCertificateChain) {
            try TLS13PeerVerifier.verifyChain([], serverName: "example.com")
        }
    }

    @Test func clientHelloOmitsSNIForIPAndCarriesConfiguredALPN() throws {
        let hello = TLS13ClientHelloBuilder.build(
            serverName: nil,
            ephemeral: Curve25519.KeyAgreement.PrivateKey(),
            alpn: ["http/1.1"]
        )
        let bytes = hello.handshake
        let h2 = Array("h2".utf8)
        let http11 = Array("http/1.1".utf8)
        func contains(_ needle: [UInt8]) -> Bool {
            guard bytes.count >= needle.count else { return false }
            return (0...(bytes.count - needle.count)).contains { Array(bytes[$0..<($0 + needle.count)]) == needle }
        }
        #expect(contains(http11))
        #expect(!contains([0x02] + h2))
        // No server_name extension (type 0x0000 followed by a host_name list).
        let named = TLS13ClientHelloBuilder.build(
            serverName: "vless.example",
            ephemeral: Curve25519.KeyAgreement.PrivateKey()
        )
        #expect(named.handshake.count > bytes.count)
    }
}

// MARK: - Record layer: KeyUpdate + close_notify

@Suite("TLS 1.3 record layer")
struct TLS13RecordLayerTests {

    private func makePair() throws -> (TLS13TrafficPair, TLS13CipherSuite) {
        let suite = try TLS13CipherSuite.parse(TLS13.aes128GCMSha256)
        let master = Data((0..<32).map { UInt8($0) })
        let pair = TLS13KeySchedule.applicationSecrets(suite: suite, master: master, transcript: Data("t".utf8))
        return (pair, suite)
    }

    /// Splits sealed records and opens them with `keys`, rotating on KeyUpdate.
    private func openAll(
        _ wire: Data,
        keys: inout TLS13TrafficKeys,
        suite: TLS13CipherSuite
    ) throws -> [(UInt8, Data)] {
        var bytes = [UInt8](wire)
        var out: [(UInt8, Data)] = []
        while bytes.count >= 5 {
            let length = (Int(bytes[3]) << 8) | Int(bytes[4])
            let header = Array(bytes[0..<5])
            let fragment = Array(bytes[5..<(5 + length)])
            bytes.removeFirst(5 + length)
            let opened = try TLS13AEAD.open(recordHeader: header, fragment: fragment, keys: &keys)
            out.append((opened.contentType, opened.plaintext))
            if opened.contentType == TLS13.contentHandshake, opened.plaintext.first == TLS13.handshakeKeyUpdate {
                keys = TLS13KeySchedule.nextTrafficKeys(keys, suite: suite)
            }
        }
        return out
    }

    @Test func serverKeyUpdateRotatesReadKeysAndAnswersRequest() throws {
        let (pair, suite) = try makePair()
        let layer = TLS13RecordLayer(application: pair, suite: suite)

        var server = pair.server
        var wire = try TLS13AEAD.seal(
            plaintext: Data([TLS13.handshakeKeyUpdate, 0, 0, 1, 1]), // update_requested
            keys: &server,
            contentType: TLS13.contentHandshake
        )
        server = TLS13KeySchedule.nextTrafficKeys(server, suite: suite)
        wire.append(try TLS13AEAD.seal(
            plaintext: Data("after".utf8),
            keys: &server,
            contentType: TLS13.contentApplicationData
        ))

        try layer.feedWire(wire)
        #expect(layer.drainPlaintext() == Data("after".utf8))
        #expect(layer.hasPendingKeyUpdate)

        // Our KeyUpdate (not requested) goes first under the old keys, then
        // application data under the new ones.
        let sealed = try layer.sealApplication(Data("up".utf8))
        #expect(!layer.hasPendingKeyUpdate)
        var client = pair.client
        let records = try openAll(sealed, keys: &client, suite: suite)
        #expect(records.count == 2)
        #expect(records[0].0 == TLS13.contentHandshake)
        #expect(records[0].1 == Data([TLS13.handshakeKeyUpdate, 0, 0, 1, 0]))
        #expect(records[1].0 == TLS13.contentApplicationData)
        #expect(records[1].1 == Data("up".utf8))

        // Later records keep using the rotated keys.
        let more = try openAll(try layer.sealApplication(Data("again".utf8)), keys: &client, suite: suite)
        #expect(more.map(\.1) == [Data("again".utf8)])
    }

    @Test func newSessionTicketIsIgnored() throws {
        let (pair, suite) = try makePair()
        let layer = TLS13RecordLayer(application: pair, suite: suite)
        var server = pair.server
        var wire = try TLS13AEAD.seal(
            plaintext: Data([TLS13.handshakeNewSessionTicket, 0, 0, 2, 0xAA, 0xBB]),
            keys: &server,
            contentType: TLS13.contentHandshake
        )
        wire.append(try TLS13AEAD.seal(plaintext: Data("x".utf8), keys: &server, contentType: TLS13.contentApplicationData))
        try layer.feedWire(wire)
        #expect(layer.drainPlaintext() == Data("x".utf8))
        #expect(!layer.hasPendingKeyUpdate)
    }

    @Test func closeNotifyIsASealedWarningAlert() throws {
        let (pair, suite) = try makePair()
        let layer = TLS13RecordLayer(application: pair, suite: suite)
        var client = pair.client
        let records = try openAll(try layer.sealCloseNotify(), keys: &client, suite: suite)
        #expect(records.count == 1)
        #expect(records[0].0 == TLS13.contentAlert)
        #expect(records[0].1 == Data([1, 0]))
    }

    @Test func peerCloseNotifyEndsCleanlyAfterBufferedData() throws {
        let (pair, suite) = try makePair()
        let layer = TLS13RecordLayer(application: pair, suite: suite)
        var server = pair.server
        // Last data record and close_notify in one TCP chunk, then stray bytes.
        var wire = try TLS13AEAD.seal(plaintext: Data("tail".utf8), keys: &server, contentType: TLS13.contentApplicationData)
        wire.append(try TLS13AEAD.seal(plaintext: Data([1, 0]), keys: &server, contentType: TLS13.contentAlert))
        wire.append(try TLS13AEAD.seal(plaintext: Data("late".utf8), keys: &server, contentType: TLS13.contentApplicationData))

        try layer.feedWire(wire)
        #expect(layer.receivedCloseNotify)
        #expect(layer.drainPlaintext() == Data("tail".utf8))
        try layer.feedWire(Data([0x17, 0x03, 0x03, 0x00, 0x01, 0x00]))
        #expect(layer.drainPlaintext().isEmpty)
    }

    @Test func fatalAlertStillFails() throws {
        let (pair, suite) = try makePair()
        let layer = TLS13RecordLayer(application: pair, suite: suite)
        var server = pair.server
        let wire = try TLS13AEAD.seal(plaintext: Data([2, 40]), keys: &server, contentType: TLS13.contentAlert)
        #expect(throws: REALITYError.self) { try layer.feedWire(wire) }
        #expect(!layer.receivedCloseNotify)
    }
}
