import Foundation
import Testing
@testable import PrizmXProtocols

// MARK: - Helpers

private func bytes(hex: String) -> [UInt8] {
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

private func utf8(_ string: String) -> [UInt8] { Array(string.utf8) }

// MARK: - HKDF-SHA1

@Suite("Shadowsocks HKDF-SHA1")
struct ShadowsocksHKDFTests {

    @Test func rfc5869TestCase4() {
        // RFC 5869 Appendix A.4 — SHA-1, L = 42.
        let ikm = bytes(hex: "0b0b0b0b0b0b0b0b0b0b0b")
        let salt = bytes(hex: "000102030405060708090a0b0c")
        let info = bytes(hex: "f0f1f2f3f4f5f6f7f8f9")

        let prk = ShadowsocksKeyDerivation.extract(salt: salt, inputKeyMaterial: ikm)
        #expect(prk == bytes(hex: "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243"))

        let okm = ShadowsocksKeyDerivation.expand(prk: prk, info: info, outputByteCount: 42)
        #expect(
            okm == bytes(
                hex: "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"
            )
        )
    }

    @Test func derivesSSSubkeyAES256() {
        let psk = bytes(hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let salt = [UInt8](repeating: 0xFF, count: 32)
        let subkey = ShadowsocksKeyDerivation.deriveSubkey(
            preSharedKey: psk,
            salt: salt,
            byteCount: 32
        )
        #expect(subkey == bytes(hex: "5c40c132e3370ed6d010959df27717a30168670c42de6255aa0781532232a0a5"))
    }

    @Test func derivesSSSubkeyAES128() {
        let psk = bytes(hex: "000102030405060708090a0b0c0d0e0f")
        let salt = [UInt8](repeating: 0xFF, count: 16)
        let subkey = ShadowsocksKeyDerivation.deriveSubkey(
            preSharedKey: psk,
            salt: salt,
            byteCount: 16
        )
        #expect(subkey == bytes(hex: "01a420b1778eab0fa81ac383c64b916a"))
    }

    @Test func evpBytesToKeyMatchesMD5Chain() {
        #expect(
            ShadowsocksCipher.aes128GCM.masterKey(fromPassword: "test")
                == bytes(hex: "098f6bcd4621d373cade4e832627b4f6")
        )
        #expect(
            ShadowsocksCipher.aes256GCM.masterKey(fromPassword: "test")
                == bytes(hex: "098f6bcd4621d373cade4e832627b4f60a9172716ae6428409885b8b829ccb05")
        )
        #expect(
            ShadowsocksCipher.aes256GCM.masterKey(fromPassword: "password")
                == bytes(hex: "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08")
        )
    }
}

// MARK: - Nonce

@Suite("Shadowsocks AEAD nonce")
struct ShadowsocksNonceTests {

    @Test func startsAtZeroAndHasNoPadding() {
        #expect(MemoryLayout<ShadowsocksNonce>.size == 12)
        #expect(ShadowsocksNonce().bytes == [UInt8](repeating: 0, count: 12))
    }

    @Test func incrementsLittleEndian() {
        var nonce = ShadowsocksNonce()
        nonce.increment()
        #expect(nonce.bytes == [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

        for _ in 0..<254 { nonce.increment() }
        #expect(nonce.bytes[0] == 255)
        #expect(nonce.bytes[1] == 0)

        nonce.increment()
        #expect(nonce.bytes[0] == 0)
        #expect(nonce.bytes[1] == 1)
        #expect(nonce.bytes.dropFirst(2).allSatisfy { $0 == 0 })
    }

    @Test func eachChunkAdvancesNonceTwice() throws {
        let psk = ShadowsocksCipher.aes256GCM.masterKey(fromPassword: "test")
        let salt = [UInt8](repeating: 0x11, count: 32)
        var context = try ShadowsocksAEADContext(
            cipher: .aes256GCM,
            preSharedKey: psk,
            salt: salt
        )
        #expect(context.nonce.bytes.allSatisfy { $0 == 0 })

        _ = try context.sealChunk(utf8("one"))
        #expect(context.nonce.bytes[0] == 2)

        _ = try context.sealChunk(utf8("two"))
        #expect(context.nonce.bytes[0] == 4)
        #expect(context.nonce.bytes.dropFirst().allSatisfy { $0 == 0 })
    }
}

// MARK: - Chunk pack / unpack

@Suite("Shadowsocks AEAD chunks")
struct ShadowsocksChunkTests {

    @Test(arguments: [ShadowsocksCipher.aes128GCM, .aes256GCM])
    func roundTripSingleChunk(cipher: ShadowsocksCipher) throws {
        let psk = cipher.masterKey(fromPassword: "correct horse")
        let salt = [UInt8](repeating: 0xAB, count: cipher.saltByteCount)
        var encoder = try ShadowsocksAEADContext(cipher: cipher, preSharedKey: psk, salt: salt)
        var decoder = try ShadowsocksAEADContext(cipher: cipher, preSharedKey: psk, salt: salt)

        let plaintext = utf8("hello shadowsocks aead")
        let sealed = try encoder.sealChunk(plaintext)
        #expect(sealed.count == ShadowsocksAEAD.sealedChunkByteCount(plaintextCount: plaintext.count))
        #expect(try decoder.openChunk(sealed) == plaintext)
        #expect(encoder.nonce.bytes == decoder.nonce.bytes)
    }

    @Test func roundTripMultipleChunksPreservesOrder() throws {
        let cipher = ShadowsocksCipher.aes256GCM
        let psk = cipher.masterKey(fromPassword: "test")
        let salt = [UInt8](repeating: 0x5A, count: cipher.saltByteCount)
        var encoder = try ShadowsocksAEADContext(cipher: cipher, preSharedKey: psk, salt: salt)
        var decoder = try ShadowsocksAEADContext(cipher: cipher, preSharedKey: psk, salt: salt)

        let frames = [utf8("alpha"), utf8("bravo"), utf8(""), utf8("charlie")]
        for frame in frames {
            let sealed = try encoder.sealChunk(frame)
            #expect(try decoder.openChunk(sealed) == frame)
        }
        #expect(encoder.nonce.bytes[0] == UInt8(frames.count * 2))
    }

    @Test func firstPacketIsSaltPlusEncryptedAddressAndData() throws {
        let cipher = ShadowsocksCipher.aes256GCM
        let psk = cipher.masterKey(fromPassword: "test")
        let salt = [UInt8](repeating: 0x42, count: cipher.saltByteCount)
        let target = Endpoint(host: .ipv4(IPv4Address(1, 2, 3, 4)), port: 443)
        let header = try ShadowsocksAddress.encode(target)
        let initial = utf8("GET / HTTP/1.1\r\n\r\n")
        let firstPayload = header + initial

        var encoder = try ShadowsocksAEADContext(cipher: cipher, preSharedKey: psk, salt: salt)
        let sealed = try encoder.sealChunk(firstPayload)
        let packet = salt + sealed

        #expect(Array(packet.prefix(salt.count)) == salt)

        var decoder = try ShadowsocksAEADContext(cipher: cipher, preSharedKey: psk, salt: salt)
        let opened = try decoder.openChunk(Array(packet[salt.count...]))
        #expect(opened == firstPayload)
        #expect(Array(opened.prefix(header.count)) == header)
        #expect(Array(opened[header.count...]) == initial)
    }

    @Test func tamperedTagFailsAuthentication() throws {
        let cipher = ShadowsocksCipher.aes128GCM
        let psk = cipher.masterKey(fromPassword: "test")
        let salt = [UInt8](repeating: 0x09, count: cipher.saltByteCount)
        var encoder = try ShadowsocksAEADContext(cipher: cipher, preSharedKey: psk, salt: salt)
        var decoder = try ShadowsocksAEADContext(cipher: cipher, preSharedKey: psk, salt: salt)

        var sealed = try encoder.sealChunk(utf8("payload"))
        sealed[sealed.count - 1] ^= 0xFF

        do {
            _ = try decoder.openChunk(sealed)
            Issue.record("expected authenticationFailed")
        } catch let error as ShadowsocksError {
            #expect(error == .authenticationFailed)
        }
    }

    @Test func identicalInputsProduceIdenticalCiphertext() throws {
        let psk = ShadowsocksCipher.aes256GCM.masterKey(fromPassword: "k")
        let salt = [UInt8](repeating: 0x01, count: 32)
        var a = try ShadowsocksAEADContext(cipher: .aes256GCM, preSharedKey: psk, salt: salt)
        var b = try ShadowsocksAEADContext(cipher: .aes256GCM, preSharedKey: psk, salt: salt)
        let payload = utf8("deterministic")
        let left = try a.sealChunk(payload)
        let right = try b.sealChunk(payload)
        #expect(left == right)
    }

    @Test func rejectsOversizedPayload() throws {
        let psk = ShadowsocksCipher.aes256GCM.masterKey(fromPassword: "test")
        let salt = [UInt8](repeating: 0x00, count: 32)
        var encoder = try ShadowsocksAEADContext(cipher: .aes256GCM, preSharedKey: psk, salt: salt)
        let tooLarge = [UInt8](repeating: 0x61, count: ShadowsocksAEAD.maxPayloadLength + 1)
        do {
            _ = try encoder.sealChunk(tooLarge)
            Issue.record("expected payloadTooLarge")
        } catch let error as ShadowsocksError {
            #expect(error == .payloadTooLarge(tooLarge.count))
        }
        #expect(encoder.nonce.bytes.allSatisfy { $0 == 0 })
    }

    @Test func maxLegalPayloadRoundTrip() throws {
        let psk = ShadowsocksCipher.aes128GCM.masterKey(fromPassword: "test")
        let salt = [UInt8](repeating: 0xCD, count: 16)
        var encoder = try ShadowsocksAEADContext(cipher: .aes128GCM, preSharedKey: psk, salt: salt)
        var decoder = try ShadowsocksAEADContext(cipher: .aes128GCM, preSharedKey: psk, salt: salt)
        let payload = [UInt8](repeating: 0x5E, count: ShadowsocksAEAD.maxPayloadLength)
        let sealed = try encoder.sealChunk(payload)
        #expect(try decoder.openChunk(sealed) == payload)
    }
}

// MARK: - Address header

@Suite("Shadowsocks address header")
struct ShadowsocksAddressTests {

    @Test func encodesIPv4() throws {
        let endpoint = Endpoint(host: .ipv4(IPv4Address(192, 168, 1, 1)), port: 80)
        #expect(try ShadowsocksAddress.encode(endpoint) == [0x01, 192, 168, 1, 1, 0x00, 0x50])
    }

    @Test func encodesDomain() throws {
        let endpoint = Endpoint(domain: "example.com", port: 443)
        var expected: [UInt8] = [0x03, 11]
        expected += utf8("example.com")
        expected += [0x01, 0xBB]
        #expect(try ShadowsocksAddress.encode(endpoint) == expected)
    }

    @Test func encodesIPv6() throws {
        let endpoint = Endpoint(host: .ipv6(.loopback), port: 443)
        let encoded = try ShadowsocksAddress.encode(endpoint)
        #expect(encoded.count == 19)
        #expect(encoded[0] == 0x04)
        #expect(Array(encoded[1..<17]) == [UInt8](repeating: 0, count: 15) + [1])
        #expect(Array(encoded[17...]) == [0x01, 0xBB])
    }

    @Test func rejectsEmptyDomain() {
        let endpoint = Endpoint(domain: "", port: 1)
        do {
            _ = try ShadowsocksAddress.encode(endpoint)
            Issue.record("expected invalidAddress")
        } catch let error as ShadowsocksError {
            #expect(error == .invalidAddress(endpoint))
        } catch {
            Issue.record("unexpected \(error)")
        }
    }

    @Test func decodeRoundTripDomain() throws {
        let endpoint = Endpoint(domain: "example.com", port: 443)
        let encoded = try ShadowsocksAddress.encode(endpoint)
        let (decoded, count) = try encoded.withUnsafeBytes { try ShadowsocksAddress.decode($0) }
        #expect(decoded == endpoint)
        #expect(count == encoded.count)
    }
}

@Suite("Shadowsocks UDP AEAD")
struct ShadowsocksUDPTests {

    @Test func datagramRoundTrip() throws {
        let cipher = ShadowsocksCipher.aes128GCM
        let key = cipher.masterKey(fromPassword: "udp-secret")
        let destination = Endpoint(domain: "example.com", port: 443)
        let payload = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let packet = try ShadowsocksUDP.encode(
            cipher: cipher,
            preSharedKey: key,
            destination: destination,
            payload: payload
        )
        let decoded = try ShadowsocksUDP.decode(
            cipher: cipher,
            preSharedKey: key,
            packet: packet
        )
        #expect(decoded.destination == destination)
        #expect(decoded.payload == payload)
    }
}
