import CryptoKit
import Foundation
import Testing
@testable import PrizmXProtocols

private func hex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

@Suite("Shadowsocks 2022")
struct Shadowsocks2022Tests {
    private let key16 = Data((0..<16).map { UInt8($0) }).base64EncodedString()
    private let key32 = Data((0..<32).map { UInt8($0) }).base64EncodedString()

    @Test func parsesKeysAndRejectsBadOnes() throws {
        let single = try Shadowsocks2022Keys(cipher: .blake3AES128GCM, password: key16)
        #expect(single.pskList == [(0..<16).map { UInt8($0) }])
        let chain = try Shadowsocks2022Keys(cipher: .blake3AES256GCM, password: "\(key32):\(key32)")
        #expect(chain.pskList.count == 2)
        // Wrong length, not base64, and multi-user ChaCha20 are refused.
        #expect(throws: ShadowsocksError.self) { try Shadowsocks2022Keys(cipher: .blake3AES256GCM, password: key16) }
        #expect(throws: ShadowsocksError.self) { try Shadowsocks2022Keys(cipher: .blake3AES128GCM, password: "not base64!") }
        #expect(throws: ShadowsocksError.self) {
            try Shadowsocks2022Keys(cipher: .blake3ChaCha20Poly1305, password: "\(key32):\(key32)")
        }
    }

    /// draft-irtf-cfrg-xchacha-03 §2.2.1.
    @Test func timestampCheckDoesNotTrap() {
        #expect(Shadowsocks2022.isFresh(Shadowsocks2022.now + 10))
        #expect(!Shadowsocks2022.isFresh(Shadowsocks2022.now - 31))
        #expect(!Shadowsocks2022.isFresh(.min))
        #expect(!Shadowsocks2022.isFresh(.max))
    }

    @Test func hchacha20MatchesDraftVector() {
        let key = (0..<32).map { UInt8($0) }
        let nonce: [UInt8] = [0, 0, 0, 0x09, 0, 0, 0, 0x4A, 0, 0, 0, 0, 0x31, 0x41, 0x59, 0x27]
        #expect(hex(ChaCha20.hchacha20(key: key, nonce: nonce)) == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
    }

    @Test func xchachaRoundTripsAndRejectsTampering() throws {
        let key = [UInt8](repeating: 3, count: 32)
        let nonce = (0..<24).map { UInt8($0) }
        var sealed = try XChaCha20Poly1305.seal(Array("datagram".utf8), key: key, nonce: nonce)
        #expect(try XChaCha20Poly1305.open(sealed, key: key, nonce: nonce) == Array("datagram".utf8))
        sealed[0] ^= 1
        #expect(throws: ShadowsocksError.authenticationFailed) { try XChaCha20Poly1305.open(sealed, key: key, nonce: nonce) }
    }

    /// The identity header decrypts (as a server does) to BLAKE3 of the next key.
    @Test func identityHeaderProvesTheUserKey() throws {
        let identity = Data([UInt8](repeating: 0xA1, count: 32)).base64EncodedString()
        let keys = try Shadowsocks2022Keys(cipher: .blake3AES256GCM, password: "\(identity):\(key32)")
        let salt = [UInt8](repeating: 0x5A, count: 32)
        let header = keys.identityHeaders(salt: salt)
        #expect(header.count == 16)
        let subkey = BLAKE3.deriveKey(context: "shadowsocks 2022 identity subkey", material: keys.pskList[0] + salt)
        #expect(AESBlock.decrypt(block: header, key: subkey) == Array(BLAKE3.hash(keys.pskList[1]).prefix(16)))
    }

    /// With identity keys, the request header uses the first key and the
    /// reply header the user's key.
    @Test func identityRelayUsesUserKeyForReplies() throws {
        let identity = Data([UInt8](repeating: 0xA1, count: 32)).base64EncodedString()
        let keys = try Shadowsocks2022Keys(cipher: .blake3AES256GCM, password: "\(identity):\(key32)")
        let outbound = Shadowsocks2022DatagramOutbound(server: Endpoint(domain: "s.example", port: 1), keys: keys)
        let request = try outbound.encode(Data([1]), to: Endpoint(host: .ipv4(IPv4Address(1, 1, 1, 1)), port: 7), packetID: 1)
        let session = Array(AESBlock.decrypt(block: Array(request.prefix(16)), key: keys.pskList[0]).prefix(8))
        // 16-byte header, then one identity header, then the body.
        let identityHeader = Array(request[16..<32])
        let plainHeader = AESBlock.decrypt(block: Array(request.prefix(16)), key: keys.pskList[0])
        let expected = zip(keys.identityHash(0), plainHeader).map { $0 ^ $1 }
        #expect(AESBlock.decrypt(block: identityHeader, key: keys.pskList[0]) == expected)

        let serverSession: [UInt8] = [4, 4, 4, 4, 4, 4, 4, 4]
        let header = serverSession + [0, 0, 0, 0, 0, 0, 0, 1]
        let body: [UInt8] = [1] + Shadowsocks2022.be64(UInt64(Shadowsocks2022.now)) + session + [0, 0]
            + [0x01, 1, 1, 1, 1, 0, 7] + Array("ok".utf8)
        let box = try AES.GCM.seal(body, using: SymmetricKey(data: keys.sessionKey(salt: serverSession)), nonce: AES.GCM.Nonce(data: header[4..<16]))
        let reply = Data(AESBlock.encrypt(block: header, key: keys.userPSK)) + box.ciphertext + box.tag
        #expect(try outbound.decode(reply) == Data("ok".utf8))
    }

    /// A server reply built by hand decodes; a foreign client session does not.
    @Test(arguments: [ShadowsocksCipher.blake3AES128GCM, .blake3ChaCha20Poly1305])
    func decodesServerUDPReply(cipher: ShadowsocksCipher) throws {
        let password = cipher.keyByteCount == 16 ? key16 : key32
        let keys = try Shadowsocks2022Keys(cipher: cipher, password: password)
        let outbound = Shadowsocks2022DatagramOutbound(server: Endpoint(domain: "s.example", port: 1), keys: keys)
        // Learn our session id from an encoded request.
        let request = try outbound.encode(Data([1]), to: Endpoint(host: .ipv4(IPv4Address(1, 1, 1, 1)), port: 53), packetID: 1)
        let session: [UInt8]
        if cipher.usesAES {
            session = Array(AESBlock.decrypt(block: Array(request.prefix(16)), key: keys.pskList[0]).prefix(8))
        } else {
            let plain = try XChaCha20Poly1305.open(Array(request.dropFirst(24)), key: keys.userPSK, nonce: Array(request.prefix(24)))
            session = Array(plain.prefix(8))
        }

        func reply(clientSession: [UInt8]) throws -> Data {
            let serverSession: [UInt8] = [9, 9, 9, 9, 9, 9, 9, 9]
            let header = serverSession + [0, 0, 0, 0, 0, 0, 0, 1]
            var body: [UInt8] = [1] + Shadowsocks2022.be64(UInt64(Shadowsocks2022.now)) + clientSession + [0, 2, 0, 0]
            body += [0x01, 1, 1, 1, 1, 0, 53] + Array("pong".utf8)
            if cipher.usesAES {
                let key = keys.sessionKey(salt: serverSession)
                let box = try AES.GCM.seal(body, using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: header[4..<16]))
                return Data(AESBlock.encrypt(block: header, key: keys.pskList[0])) + box.ciphertext + box.tag
            }
            let nonce = [UInt8](repeating: 7, count: 24)
            return Data(nonce) + (try XChaCha20Poly1305.seal(header + body, key: keys.userPSK, nonce: nonce))
        }

        #expect(try outbound.decode(reply(clientSession: session)) == Data("pong".utf8))
        if cipher.usesAES {
            // Replies seal the header with the user's key (here equal to the
            // only key; see the identity-header test below).
            #expect(keys.userPSK == keys.pskList[0])
        }
        #expect(throws: Shadowsocks2022Error.badClientSession) {
            try outbound.decode(reply(clientSession: [0, 0, 0, 0, 0, 0, 0, 0]))
        }
    }
}
