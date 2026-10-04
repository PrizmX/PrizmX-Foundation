import Foundation
import Testing
@testable import PrizmXProtocols

private func hex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

@Suite("Crypto primitives")
struct CryptoPrimitiveTests {

    @Test func shake128EmptyInput() {
        var shake = SHAKE128(absorbing: [UInt8]())
        #expect(hex(shake.squeeze(32)) == "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
    }

    @Test func shake128StreamsAcrossCalls() {
        var whole = SHAKE128(absorbing: Array("abc".utf8))
        var pieces = SHAKE128(absorbing: Array("abc".utf8))
        let expected = whole.squeeze(400)
        var joined: [UInt8] = []
        for size in [1, 2, 165, 7, 225] {
            joined += pieces.squeeze(size)
        }
        #expect(joined == expected)
    }

    @Test func checksums() {
        #expect(CRC32.checksum(Array("123456789".utf8)) == 0xCBF4_3926)
        #expect(FNV1a32.hash([UInt8]()) == 0x811C_9DC5)
        #expect(FNV1a32.hash(Array("a".utf8)) == 0xE40C_292C)
    }

    @Test func aesBlockRoundTrip() {
        // FIPS-197 C.1 (AES-128).
        let key = (0..<16).map { UInt8($0) }
        let plain: [UInt8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        let cipher = AESBlock.encrypt(block: plain, key: key)
        #expect(hex(cipher) == "69c4e0d86a7b0430d8cdb78070b4c55a")
        #expect(AESBlock.decrypt(block: cipher, key: key) == plain)
    }
}

/// Reference values computed with xray-core v1.260327.0.
@Suite("VMess")
struct VMessTests {
    let key = Array("0123456789abcdef".utf8)

    @Test func kdfMatchesXray() {
        #expect(hex(VMessKDF.derive(key, [])) == "76dfb9fefccab1e16280787cb1ec533ff64c4919d01a3602e0e7b58c6d1edc21")
        #expect(hex(VMessKDF.derive(key, "AES Auth ID Encryption")) == "ebde3a0b17bf94c86fa140917ec6a0c9773a777693a18a40bb09b38fb9b0b816")
        #expect(
            hex(VMessKDF.derive(key, "VMess Header AEAD Key", "authid0123456789", "nonce678"))
                == "237e4fbda3805e91df37c73a08ace55b8094d597f9aca02ec0f743bfba57c486"
        )
    }

    @Test func commandAndChaChaKeysMatchXray() throws {
        let id = try #require(UUID(uuidString: "b831381d-6324-4d53-ad4f-8cda48b30811"))
        #expect(hex(VMessKDF.commandKey(userID: id)) == "b50d916ac0cec067981af8e5f38a758f")
        #expect(hex(VMessKDF.chachaKey(key)) == "4032af8d61035123906e58e067140cc567304ba676a616064c4340059e1b6370")
    }

    @Test func lengthMaskConsumesPaddingBeforeMask() {
        // Xray: NextPaddingLen() → 8, 6; then Encode(1234) → da57.
        var shake = SHAKE128(absorbing: (0..<16).map { UInt8($0) })
        #expect(shake.nextUInt16() % 64 == 8)
        #expect(shake.nextUInt16() % 64 == 6)
        #expect(shake.nextUInt16() ^ 1234 == 0xDA57)
    }

    @Test func requestHeaderLayout() throws {
        let session = VMessSession(
            requestKey: [UInt8](repeating: 0xAA, count: 16),
            requestIV: [UInt8](repeating: 0xBB, count: 16),
            responseAuth: 0x5A
        )
        let header = VMessRequestHeader(
            session: session,
            options: VMessRequestHeader.options(for: .aes128GCM),
            security: .aes128GCM,
            command: .tcp,
            target: Endpoint(domain: "a.io", port: 443),
            padding: [1, 2]
        )
        let bytes = try header.encode()
        #expect(bytes[0] == 1)
        #expect(Array(bytes[1..<17]) == session.requestIV)
        #expect(Array(bytes[17..<33]) == session.requestKey)
        #expect(Array(bytes[33..<38]) == [0x5A, 0x0D, 0x23, 0x00, 0x01])
        #expect(Array(bytes[38..<48]) == [0x01, 0xBB, 0x02, 4, 0x61, 0x2E, 0x69, 0x6F, 1, 2])
        let checksum = FNV1a32.hash(bytes.prefix(48))
        #expect(Array(bytes.suffix(4)) == withUnsafeBytes(of: checksum.bigEndian) { Array($0) })
    }

    /// Opens a sealed header the way an Xray server does.
    @Test func sealedHeaderOpensServerSide() throws {
        let commandKey = Array("cmdkey0123456789".utf8)
        let plaintext = Array("header-plaintext".utf8)
        let nonce: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        let sealed = try VMessRequestHeader.seal(
            plaintext,
            commandKey: commandKey,
            timestamp: 1_700_000_000,
            connectionNonce: nonce,
            authRandom: [9, 9, 9, 9]
        )
        let authID = Array(sealed[0..<16])
        let decoded = AESBlock.decrypt(
            block: authID,
            key: VMessKDF.derive16(commandKey, [Array("AES Auth ID Encryption".utf8)])
        )
        #expect(Array(decoded[0..<8]) == withUnsafeBytes(of: Int64(1_700_000_000).bigEndian) { Array($0) })
        #expect(Array(decoded[12..<16]) == withUnsafeBytes(of: CRC32.checksum(decoded[0..<12]).bigEndian) { Array($0) })
        #expect(Array(sealed[34..<42]) == nonce)

        let lengthKey = VMessKDF.derive16(commandKey, [Array("VMess Header AEAD Key_Length".utf8), authID, nonce])
        let lengthNonce = Array(VMessKDF.derive(commandKey, [Array("VMess Header AEAD Nonce_Length".utf8), authID, nonce]).prefix(12))
        let length = try VMessAEAD.open(Array(sealed[16..<34]), key: lengthKey, nonce: lengthNonce, aad: authID)
        #expect(length == [0, UInt8(plaintext.count)])

        let headerKey = VMessKDF.derive16(commandKey, [Array("VMess Header AEAD Key".utf8), authID, nonce])
        let headerNonce = Array(VMessKDF.derive(commandKey, [Array("VMess Header AEAD Nonce".utf8), authID, nonce]).prefix(12))
        #expect(try VMessAEAD.open(Array(sealed[42...]), key: headerKey, nonce: headerNonce, aad: authID) == plaintext)
    }

    @Test(arguments: [VMessSecurity.aes128GCM, .chacha20Poly1305, .none])
    func chunksRoundTripWithEndOfStream(security: VMessSecurity) throws {
        let key = [UInt8](repeating: 7, count: 16)
        let iv = (0..<16).map { UInt8($0) }
        let options = VMessRequestHeader.options(for: security)
        var sealer = VMessChunkCipher(security: security, key: key, iv: iv, options: options)
        var opener = VMessChunkCipher(security: security, key: key, iv: iv, options: options)

        for payload in [Array("first".utf8), [UInt8](repeating: 0xEE, count: VMessChunkCipher.maxPayload), []] {
            let chunk = try sealer.seal(payload)
            let (size, padding) = opener.openLength(Array(chunk.prefix(2)))
            #expect(size == chunk.count - 2)
            if payload.isEmpty {
                #expect(opener.isEndOfStream(size: size, padding: padding))
            } else {
                #expect(!opener.isEndOfStream(size: size, padding: padding))
                #expect(try opener.open(Array(chunk.dropFirst(2)), padding: padding) == payload)
            }
        }
    }
}
