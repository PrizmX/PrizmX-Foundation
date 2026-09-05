/// RFC 1071 Internet checksum (one's complement).
enum InternetChecksum {
    static func sum(_ bytes: UnsafeRawBufferPointer, initial: UInt32 = 0) -> UInt32 {
        var total = initial
        var offset = 0
        while offset + 1 < bytes.count {
            total += UInt32(bytes[offset]) << 8 | UInt32(bytes[offset + 1])
            offset += 2
        }
        if offset < bytes.count {
            total += UInt32(bytes[offset]) << 8
        }
        return total
    }

    static func fold(_ total: UInt32) -> UInt16 {
        var value = total
        while value >> 16 != 0 {
            value = (value & 0xFFFF) + (value >> 16)
        }
        return ~UInt16(truncatingIfNeeded: value)
    }

    static func compute(_ bytes: UnsafeRawBufferPointer) -> UInt16 {
        fold(sum(bytes))
    }
}
