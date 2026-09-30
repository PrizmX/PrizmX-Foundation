import CryptoKit
import Foundation
import Network
import Security

/// Failures of standard (non-REALITY) TLS 1.3 server authentication.
public enum TLS13PeerVerificationError: Error, Equatable, Sendable {
    case emptyCertificateChain
    case invalidCertificate
    /// `SecTrustEvaluateWithError` rejected the chain (reason text).
    case untrustedCertificate(String)
    /// CertificateVerify used a scheme this client did not offer / support.
    case unsupportedSignatureScheme(UInt16)
    /// Scheme does not match the leaf key type / curve.
    case keyMismatch(UInt16)
    case badCertificateVerify
    /// Server selected an ALPN protocol that was not offered.
    case alpnMismatch(String)
    case handshakeTimedOut
}

extension TLS13PeerVerificationError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .emptyCertificateChain: "TLS: server sent no certificate"
        case .invalidCertificate: "TLS: malformed server certificate"
        case .untrustedCertificate(let reason): "TLS: untrusted server certificate (\(reason))"
        case .unsupportedSignatureScheme(let scheme):
            "TLS: unsupported CertificateVerify scheme 0x\(String(scheme, radix: 16))"
        case .keyMismatch(let scheme):
            "TLS: CertificateVerify scheme 0x\(String(scheme, radix: 16)) does not match the certificate key"
        case .badCertificateVerify: "TLS: CertificateVerify signature is invalid"
        case .alpnMismatch(let name): "TLS: server selected unexpected ALPN \"\(name)\""
        case .handshakeTimedOut: "TLS: handshake timed out"
        }
    }
}

/// Web-PKI server authentication for the userspace TLS 1.3 client
/// (`xtls-rprx-vision` over plain TLS, where Network.framework TLS cannot
/// hand the raw socket over after Vision's `direct` switch).
enum TLS13PeerVerifier {

    /// Chain (leaf first) against the system trust store with hostname check.
    /// `serverName` nil skips the name check only when the server is an IP
    /// literal with no SNI (callers pass the IP string when they have it).
    static func verifyChain(_ chain: [[UInt8]], serverName: String?) throws {
        guard !chain.isEmpty else { throw TLS13PeerVerificationError.emptyCertificateChain }
        var certificates: [SecCertificate] = []
        for der in chain {
            guard let certificate = SecCertificateCreateWithData(nil, Data(der) as CFData) else {
                throw TLS13PeerVerificationError.invalidCertificate
            }
            certificates.append(certificate)
        }
        let policy = SecPolicyCreateSSL(true, serverName.map { $0 as CFString })
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certificates as CFArray, policy, &trust) == errSecSuccess,
              let trust else {
            throw TLS13PeerVerificationError.invalidCertificate
        }
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            let reason = error.map { CFErrorCopyDescription($0) as String } ?? "evaluation failed"
            throw TLS13PeerVerificationError.untrustedCertificate(reason)
        }
    }

    /// RFC 8446 §4.4.3: 64 spaces ‖ context string ‖ 0x00 ‖ Transcript-Hash.
    static func certificateVerifyContent(transcriptHash: Data) -> Data {
        var signed = Data(repeating: 0x20, count: 64)
        signed.append(contentsOf: Array("TLS 1.3, server CertificateVerify".utf8))
        signed.append(0)
        signed.append(transcriptHash)
        return signed
    }

    /// Checks the server's CertificateVerify against the leaf public key.
    /// Supported: ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384,
    /// rsa_pss_rsae_sha256/384/512, ed25519.
    static func verifyCertificateVerify(
        scheme: UInt16,
        signature: [UInt8],
        transcriptHash: Data,
        leaf: TLS13Certificate
    ) throws {
        let content = certificateVerifyContent(transcriptHash: transcriptHash)

        if scheme == TLS13.signatureEd25519 {
            guard leaf.isEd25519, leaf.publicKey.count == 32 else {
                throw TLS13PeerVerificationError.keyMismatch(scheme)
            }
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: Data(leaf.publicKey))
            guard key.isValidSignature(Data(signature), for: content) else {
                throw TLS13PeerVerificationError.badCertificateVerify
            }
            return
        }

        let algorithm: SecKeyAlgorithm
        let keyType: CFString
        let keyBits: Int?
        switch scheme {
        case 0x0403:
            (algorithm, keyType, keyBits) = (.ecdsaSignatureMessageX962SHA256, kSecAttrKeyTypeECSECPrimeRandom, 256)
        case 0x0503:
            (algorithm, keyType, keyBits) = (.ecdsaSignatureMessageX962SHA384, kSecAttrKeyTypeECSECPrimeRandom, 384)
        case 0x0804:
            (algorithm, keyType, keyBits) = (.rsaSignatureMessagePSSSHA256, kSecAttrKeyTypeRSA, nil)
        case 0x0805:
            (algorithm, keyType, keyBits) = (.rsaSignatureMessagePSSSHA384, kSecAttrKeyTypeRSA, nil)
        case 0x0806:
            (algorithm, keyType, keyBits) = (.rsaSignatureMessagePSSSHA512, kSecAttrKeyTypeRSA, nil)
        default:
            throw TLS13PeerVerificationError.unsupportedSignatureScheme(scheme)
        }

        guard let certificate = SecCertificateCreateWithData(nil, Data(leaf.der) as CFData),
              let key = SecCertificateCopyKey(certificate) else {
            throw TLS13PeerVerificationError.invalidCertificate
        }
        let attributes = SecKeyCopyAttributes(key) as? [CFString: Any] ?? [:]
        guard let type = attributes[kSecAttrKeyType] as? String, type == keyType as String else {
            throw TLS13PeerVerificationError.keyMismatch(scheme)
        }
        if let keyBits {
            // ECDSA schemes pin the curve (RFC 8446 §4.2.3).
            let bits = (attributes[kSecAttrKeySizeInBits] as? NSNumber)?.intValue
            guard bits == keyBits else { throw TLS13PeerVerificationError.keyMismatch(scheme) }
        }
        guard SecKeyIsAlgorithmSupported(key, .verify, algorithm) else {
            throw TLS13PeerVerificationError.keyMismatch(scheme)
        }
        var error: Unmanaged<CFError>?
        guard SecKeyVerifySignature(key, algorithm, content as CFData, Data(signature) as CFData, &error) else {
            _ = error?.takeRetainedValue()
            throw TLS13PeerVerificationError.badCertificateVerify
        }
    }
}

// MARK: - Standard TLS 1.3 client handshake

/// Userspace TLS 1.3 client with Web-PKI authentication over a raw TCP
/// `NWConnection` (already `.ready`). Used where the caller needs the raw
/// socket after TLS (Vision `direct` splicing).
enum TLS13ClientHandshake {
    /// - Parameters:
    ///   - serverName: SNI + hostname for the trust check (nil / IP: no SNI).
    ///   - verifyName: name checked against the certificate; defaults to
    ///     `serverName`.
    ///   - alpn: offered protocols (`[]` omits ALPN).
    ///   - skipCertificateVerification: skip chain trust only (explicit
    ///     `skip-cert-verify`). CertificateVerify is still checked against
    ///     the presented leaf, and Finished still authenticates the handshake.
    static func run(
        on connection: NWConnection,
        queue: DispatchQueue,
        serverName: String?,
        verifyName: String? = nil,
        alpn: [String] = TLS13.defaultALPN,
        skipCertificateVerification: Bool = false,
        timeout: Duration = .seconds(10)
    ) async throws -> TLS13RecordLayer {
        let hello = TLS13ClientHelloBuilder.build(
            serverName: isIPLiteral(serverName) ? nil : serverName,
            ephemeral: Curve25519.KeyAgreement.PrivateKey(),
            sessionID: TLS13Random.bytes(REALITY.sessionIDByteCount),
            alpn: alpn
        )
        let checkName = verifyName ?? serverName
        return try await withThrowingTaskGroup(of: TLS13RecordLayer.self) { group in
            group.addTask {
                try await TLS13Handshake.run(
                    connection: connection,
                    queue: queue,
                    clientHello: hello,
                    offeredALPN: alpn
                ) { chain, _ in
                    guard !skipCertificateVerification else { return }
                    try TLS13PeerVerifier.verifyChain(chain, serverName: checkName)
                }
            }
            group.addTask {
                try await Task.sleep(for: timeout)
                throw TLS13PeerVerificationError.handshakeTimedOut
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
    }

    private static func isIPLiteral(_ name: String?) -> Bool {
        guard let name else { return false }
        return IPv4Address(parsing: name) != nil || name.contains(":")
    }
}
