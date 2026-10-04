import CommonCrypto
import Foundation

/// Raw AES operations CryptoKit does not expose: single-block ECB (VMess
/// auth ID, Shadowsocks 2022 UDP header) and the legacy stream / block modes
/// ShadowsocksR still uses.
enum AESBlock {
    /// Encrypts exactly one 16-byte block with `key` (16 / 24 / 32 bytes).
    static func encrypt(block: [UInt8], key: [UInt8]) -> [UInt8] {
        crypt(CCOperation(kCCEncrypt), block: block, key: key)
    }

    /// Decrypts exactly one 16-byte block.
    static func decrypt(block: [UInt8], key: [UInt8]) -> [UInt8] {
        crypt(CCOperation(kCCDecrypt), block: block, key: key)
    }

    private static func crypt(_ operation: CCOperation, block: [UInt8], key: [UInt8]) -> [UInt8] {
        precondition(block.count == kCCBlockSizeAES128, "AES block must be 16 bytes")
        precondition([16, 24, 32].contains(key.count), "AES key must be 16, 24 or 32 bytes")
        var output = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
        var moved = 0
        let status = CCCrypt(
            operation,
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionECBMode),
            key, key.count,
            nil,
            block, block.count,
            &output, output.count,
            &moved
        )
        precondition(status == kCCSuccess && moved == kCCBlockSizeAES128, "AES-ECB failed (\(status))")
        return output
    }
}
