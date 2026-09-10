import CryptoKit
import Foundation
import Network

// MARK: - AuthKey / Session ID (Xray UClient)

/// REALITY Session ID construction, ECDH / HKDF AuthKey derivation, AES-256-GCM
/// overlay, and post-handshake HMAC-SHA512 certificate check.
///
/// Matches Xray-core `transport/internet/reality.UClient`:
/// 1. Build a TLS 1.3 ClientHello whose Session ID is 32 zero bytes (offset 39).
/// 2. ECDH(client ephemeral key_share, server `publicKey`) → 32-byte shared secret.
/// 3. `AuthKey = HKDF-SHA256(ikm=shared, salt=Random[:20], info="REALITY")` (32 bytes).
/// 4. `AES-256-GCM.Seal(SID[:16], nonce=Random[20:32], aad=hello.Raw)` → 16 ct + 16 tag.
/// 5. Copy the 32-byte blob back to `hello.Raw[39:]`.
/// 6. After TLS 1.3 Certificate: `HMAC-SHA512(AuthKey, Ed25519 pubkey) == cert.Signature`.
public struct REALITYHandshaker: Sendable {
    public let config: REALITYConfig

    public init(config: REALITYConfig) {
        self.config = config
    }

    // MARK: Session ID plaintext

    /// Builds the 32-byte plaintext Session ID (Xray `hello.SessionId` before Seal).
    ///
    /// Layout: `[ver_x][ver_y][ver_z][0][unix_be_u32][short_id 8 bytes padded]`.
    /// Only `[0..<16]` is GCM plaintext; `[16..<32]` is zero and is overwritten by the tag.
    public static func sessionIDPlaintext(
        version: (UInt8, UInt8, UInt8) = REALITY.clientVersion,
        unixTime: UInt32,
        shortID: [UInt8]
    ) -> [UInt8] {
        var sid = [UInt8](repeating: 0, count: REALITY.sessionIDByteCount)
        sid[0] = version.0
        sid[1] = version.1
        sid[2] = version.2
        sid[3] = 0
        sid[4] = UInt8((unixTime >> 24) & 0xFF)
        sid[5] = UInt8((unixTime >> 16) & 0xFF)
        sid[6] = UInt8((unixTime >> 8) & 0xFF)
        sid[7] = UInt8(unixTime & 0xFF)
        let copied = min(shortID.count, REALITY.sessionIDByteCount - 8)
        if copied > 0 {
            sid.replaceSubrange(8..<(8 + copied), with: shortID.prefix(copied))
        }
        return sid
    }

    // MARK: ECDH + HKDF

    /// X25519 ECDH shared secret (32 bytes) between the ClientHello key_share
    /// ephemeral and the REALITY server public key.
    public static func sharedSecret(
        ephemeral: Curve25519.KeyAgreement.PrivateKey,
        serverPublicKey: Curve25519.KeyAgreement.PublicKey
    ) throws -> Data {
        let secret = try ephemeral.sharedSecretFromKeyAgreement(with: serverPublicKey)
        return secret.withUnsafeBytes { Data($0) }
    }

    /// `AuthKey = HKDF-SHA256(Extract+Expand)` with salt `Random[:20]` and info `"REALITY"`.
    /// Output is 32 bytes (AES-256-GCM key), matching `golang.org/x/crypto/hkdf.New`.
    public static func deriveAuthKey(sharedSecret: Data, clientRandom: [UInt8]) -> SymmetricKey {
        precondition(clientRandom.count == 32, "ClientHello.Random must be 32 bytes")
        let salt = Data(clientRandom.prefix(20))
        let info = Data(REALITY.hkdfInfo.utf8)
        let prk = TLS13HashKind.sha256.extract(salt: salt, ikm: sharedSecret)
        let okm = TLS13HashKind.sha256.expand(prk: prk, info: info, length: 32)
        return SymmetricKey(data: okm)
    }

    // MARK: AES-256-GCM Session ID

    /// Seals `plaintextSID[:16]` with `aad = handshake` (zeros still in the SID slot).
    /// Returns the 32-byte ciphertext‖tag that occupies the Session ID field.
    public static func sealSessionID(
        plaintextSID: [UInt8],
        clientRandom: [UInt8],
        handshakeAAD: [UInt8],
        authKey: SymmetricKey
    ) throws -> [UInt8] {
        precondition(plaintextSID.count == REALITY.sessionIDByteCount)
        precondition(clientRandom.count == 32)
        let nonce = try AES.GCM.Nonce(data: Data(clientRandom[20..<32]))
        let plaintext = Data(plaintextSID.prefix(16))
        let box = try AES.GCM.seal(
            plaintext,
            using: authKey,
            nonce: nonce,
            authenticating: Data(handshakeAAD)
        )
        var sealed = [UInt8](repeating: 0, count: REALITY.sessionIDByteCount)
        let ciphertext = Array(box.ciphertext)
        let tag = Array(box.tag)
        precondition(ciphertext.count == 16 && tag.count == 16)
        sealed.replaceSubrange(0..<16, with: ciphertext)
        sealed.replaceSubrange(16..<32, with: tag)
        return sealed
    }

    /// Inverse of `sealSessionID`. AAD must be the handshake with a **zeroed** SID.
    public static func openSessionID(
        sealedSID: [UInt8],
        clientRandom: [UInt8],
        handshakeAAD: [UInt8],
        authKey: SymmetricKey
    ) throws -> [UInt8] {
        precondition(sealedSID.count == REALITY.sessionIDByteCount)
        let nonce = try AES.GCM.Nonce(data: Data(clientRandom[20..<32]))
        let box = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: Data(sealedSID[0..<16]),
            tag: Data(sealedSID[16..<32])
        )
        do {
            let plain = try AES.GCM.open(box, using: authKey, authenticating: Data(handshakeAAD))
            return Array(plain)
        } catch {
            throw REALITYError.handshakeFailed("Session ID GCM open failed")
        }
    }

    /// HMAC-SHA512(AuthKey, Ed25519 pubkey) compared to `signature` (X.509 BIT STRING).
    public static func verifyCertificateHMAC(
        authKey: SymmetricKey,
        publicKey: [UInt8],
        signature: [UInt8]
    ) throws {
        guard publicKey.count == 32 else {
            throw REALITYError.unverifiedCertificate
        }
        let mac = HMAC<SHA512>.authenticationCode(for: Data(publicKey), using: authKey)
        let macBytes = mac.withUnsafeBytes { Data($0) }
        guard macBytes.count == signature.count else {
            throw REALITYError.unverifiedCertificate
        }
        var diff: UInt8 = 0
        for (a, b) in zip(macBytes, signature) { diff |= a ^ b }
        guard diff == 0 else {
            throw REALITYError.unverifiedCertificate
        }
    }

    /// HMAC-SHA512(AuthKey, leaf Ed25519 public key) must equal `cert.Signature`.
    static func verifyPeerCertificate(
        authKey: SymmetricKey,
        certificate: TLS13Certificate
    ) throws {
        guard certificate.isEd25519 else {
            throw REALITYError.unverifiedCertificate
        }
        try verifyCertificateHMAC(
            authKey: authKey,
            publicKey: certificate.publicKey,
            signature: certificate.signature
        )
    }

    // MARK: ClientHello overlay

    /// Builds a TLS 1.3 ClientHello and overlays the encrypted REALITY Session ID.
    ///
    /// The same ephemeral X25519 key is placed in `key_share` (TLS 1.3 ECDHE)
    /// and used for AuthKey ECDH with `config.publicKey`.
    public func makeClientHello(
        ephemeral: Curve25519.KeyAgreement.PrivateKey = Curve25519.KeyAgreement.PrivateKey(),
        unixTime: UInt32 = UInt32(Date().timeIntervalSince1970),
        random: [UInt8]? = nil
    ) throws -> REALITYClientHello {
        var hello = TLS13ClientHelloBuilder.build(
            serverName: config.serverName,
            ephemeral: ephemeral,
            sessionID: [UInt8](repeating: 0, count: REALITY.sessionIDByteCount),
            random: random
        )
        precondition(hello.handshake.count > REALITY.handshakeSessionIDOffset + REALITY.sessionIDByteCount)
        precondition(hello.handshake[38] == UInt8(REALITY.sessionIDByteCount))

        let plaintextSID = Self.sessionIDPlaintext(
            version: REALITY.clientVersion,
            unixTime: unixTime,
            shortID: config.paddedShortID
        )
        let aad = hello.handshake
        let shared = try Self.sharedSecret(
            ephemeral: hello.ephemeral,
            serverPublicKey: config.serverPublicKey
        )
        let authKey = Self.deriveAuthKey(sharedSecret: shared, clientRandom: hello.random)
        let sealed = try Self.sealSessionID(
            plaintextSID: plaintextSID,
            clientRandom: hello.random,
            handshakeAAD: aad,
            authKey: authKey
        )
        hello.handshake.replaceSubrange(
            REALITY.handshakeSessionIDOffset..<(REALITY.handshakeSessionIDOffset + REALITY.sessionIDByteCount),
            with: sealed
        )
        return REALITYClientHello(
            hello: hello,
            handshakeAAD: aad,
            plaintextSessionID: plaintextSID,
            sealedSessionID: sealed,
            authKey: authKey
        )
    }

    /// Raw TCP handshake: custom ClientHello, then TLS 1.3, then HMAC cert check.
    /// Application data afterwards is TLS 1.3 records via the returned session.
    ///
    /// The whole exchange runs under a hard ceiling: `waitUntilReady` only
    /// covers TCP setup, and a peer (or middlebox) that accepts the socket
    /// but then goes silent would otherwise suspend `open()` forever. On
    /// timeout the connection is cancelled, which also unwinds the receive
    /// continuation suspended inside the handshake child task.
    public func handshake(
        on connection: NWConnection,
        queue: DispatchQueue,
        timeout: Duration = .seconds(10)
    ) async throws -> REALITYSession {
        let prepared = try makeClientHello()
        let layer = try await withThrowingTaskGroup(of: TLS13RecordLayer.self) { group in
            group.addTask {
                try await TLS13Handshake.run(
                    connection: connection,
                    queue: queue,
                    clientHello: prepared.hello
                ) { certificate in
                    try Self.verifyPeerCertificate(authKey: prepared.authKey, certificate: certificate)
                }
            }
            group.addTask {
                try await Task.sleep(for: timeout)
                throw REALITYError.handshakeFailed("TLS handshake timed out")
            }
            do {
                let layer = try await group.next()!
                group.cancelAll()
                return layer
            } catch {
                connection.cancel()
                group.cancelAll()
                throw error
            }
        }
        return REALITYSession(layer: layer, authKey: prepared.authKey)
    }
}

// MARK: - Prepared ClientHello (tests + handshake)

/// ClientHello after REALITY Session ID overlay, plus the AuthKey used to seal it.
public struct REALITYClientHello: Sendable {
    var hello: TLS13ClientHelloBuilt
    /// Handshake bytes used as GCM AAD (Session ID still zeros).
    public let handshakeAAD: [UInt8]
    /// 32-byte plaintext SID (only first 16 bytes are GCM plaintext).
    public let plaintextSessionID: [UInt8]
    /// 32-byte ciphertext‖tag written at handshake offset 39.
    public let sealedSessionID: [UInt8]
    public let authKey: SymmetricKey

    /// Handshake message after overlay (utls `hello.Raw`).
    public var handshake: [UInt8] { hello.handshake }
    /// 32-byte ClientHello.Random.
    public var random: [UInt8] { hello.random }
    public var ephemeral: Curve25519.KeyAgreement.PrivateKey { hello.ephemeral }

    /// Session ID field as it appears on the wire (`handshake[39..<71]`).
    public var wireSessionID: [UInt8] {
        let start = REALITY.handshakeSessionIDOffset
        let end = start + REALITY.sessionIDByteCount
        return Array(hello.handshake[start..<end])
    }
}

// MARK: - Post-handshake TLS session

/// TLS 1.3 application-data wrapper after a successful REALITY handshake.
public final class REALITYSession: @unchecked Sendable {
    private let layer: TLS13RecordLayer
    public let authKey: SymmetricKey

    init(layer: TLS13RecordLayer, authKey: SymmetricKey) {
        self.layer = layer
        self.authKey = authKey
    }

    func sealApplication(_ plaintext: Data) throws -> Data {
        try layer.sealApplication(plaintext)
    }

    func feedWire(_ chunk: Data) throws {
        try layer.feedWire(chunk)
    }

    func drainPlaintext() -> Data {
        layer.drainPlaintext()
    }
}

// MARK: - Crypto helpers (tests + call sites)

/// Session ID / AuthKey helpers used by unit tests. Delegates to `REALITYHandshaker`.
public enum REALITYCrypto {
    public static func sessionIDPlaintext(
        shortID: [UInt8],
        unixTime: UInt32,
        version: (UInt8, UInt8, UInt8) = REALITY.clientVersion
    ) -> [UInt8] {
        REALITYHandshaker.sessionIDPlaintext(version: version, unixTime: unixTime, shortID: shortID)
    }

    public static func deriveAuthKey(sharedSecret: SharedSecret, clientRandom: [UInt8]) -> SymmetricKey {
        let bytes = sharedSecret.withUnsafeBytes { Data($0) }
        return REALITYHandshaker.deriveAuthKey(sharedSecret: bytes, clientRandom: clientRandom)
    }

    public static func deriveAuthKey(sharedSecretBytes: [UInt8], clientRandom: [UInt8]) -> [UInt8] {
        let key = REALITYHandshaker.deriveAuthKey(
            sharedSecret: Data(sharedSecretBytes),
            clientRandom: clientRandom
        )
        return key.withUnsafeBytes { Array($0) }
    }

    public static func hkdfSHA256(ikm: Data, salt: Data, info: Data, outputByteCount: Int) -> [UInt8] {
        let prk = TLS13HashKind.sha256.extract(salt: salt, ikm: ikm)
        return Array(TLS13HashKind.sha256.expand(prk: prk, info: info, length: outputByteCount))
    }

    public static func sealSessionID(
        plaintext16: [UInt8],
        random: [UInt8],
        handshakeAAD: [UInt8],
        authKey: SymmetricKey
    ) throws -> [UInt8] {
        var sid = plaintext16
        if sid.count < REALITY.sessionIDByteCount {
            sid.append(contentsOf: [UInt8](repeating: 0, count: REALITY.sessionIDByteCount - sid.count))
        }
        return try REALITYHandshaker.sealSessionID(
            plaintextSID: Array(sid.prefix(REALITY.sessionIDByteCount)),
            clientRandom: random,
            handshakeAAD: handshakeAAD,
            authKey: authKey
        )
    }

    public static func openSessionID(
        sealed32: [UInt8],
        random: [UInt8],
        handshakeAAD: [UInt8],
        authKey: SymmetricKey
    ) throws -> [UInt8] {
        try REALITYHandshaker.openSessionID(
            sealedSID: sealed32,
            clientRandom: random,
            handshakeAAD: handshakeAAD,
            authKey: authKey
        )
    }

    public static func verifyPeerCertificate(
        authKey: SymmetricKey,
        publicKey: [UInt8],
        signature: [UInt8]
    ) -> Bool {
        do {
            try REALITYHandshaker.verifyCertificateHMAC(
                authKey: authKey,
                publicKey: publicKey,
                signature: signature
            )
            return true
        } catch {
            return false
        }
    }
}
