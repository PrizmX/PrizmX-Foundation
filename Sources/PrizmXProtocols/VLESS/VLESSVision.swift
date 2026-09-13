import Foundation

// MARK: - xtls-rprx-vision

/// Xray Vision (`xtls-rprx-vision`) padding used after the VLESS header.
///
/// Wire frame (Xray `XtlsPadding` / `XtlsUnpadding`):
///
/// ```
/// [uuid 16, first frame only][command 1][contentLen 2 BE][paddingLen 2 BE]
/// [content][padding]
/// ```
///
/// Commands: `0x00` continue, `0x01` end, `0x02` direct. After end/direct the
/// rest of the stream is raw. The protobuf `Addons.Flow` field is a separate
/// prefix on the VLESS request header, not part of these frames.
public enum VLESSVision {
    /// Clash / Xray flow name written into the VLESS protobuf addon.
    public static let flowName = "xtls-rprx-vision"

    public static let commandContinue: UInt8 = 0x00
    public static let commandEnd: UInt8 = 0x01
    public static let commandDirect: UInt8 = 0x02

    /// Xray `buf.Size` cap used when computing padding.
    public static let maxBuffer = 8192
    /// First-frame UUID + 5-byte command header.
    public static let maxHeader = 21
    /// Xray default `testseed`: long padding when content is shorter than this.
    public static let longPaddingThreshold = 900

    /// True when `flow` is Vision (including the `-udp443` suffix form).
    public static func isEnabled(_ flow: String?) -> Bool {
        guard let flow else { return false }
        let trimmed = flow.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed == flowName || trimmed.hasPrefix(flowName)
    }

    /// Empty / whitespace `flow` becomes `nil`.
    public static func normalized(_ flow: String?) -> String? {
        guard let flow else { return nil }
        let trimmed = flow.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Protobuf `Addons { string Flow = 1 }` without the 1-byte VLESS length prefix.
    public static func addons(flow: String) -> Data {
        let trimmed = flow.trimmingCharacters(in: .whitespacesAndNewlines)
        let wire = isEnabled(trimmed) ? flowName : trimmed
        let utf8 = Array(wire.utf8)
        precondition(utf8.count <= 253, "VLESS addon flow exceeds 253 bytes")
        var data = Data([0x0A, UInt8(utf8.count)])
        data.append(contentsOf: utf8)
        return data
    }

    /// Builds one Vision frame. `uuid` is the 16-byte user id on the first frame.
    public static func frame(
        command: UInt8,
        content: Data,
        padding: Data,
        uuid: [UInt8]? = nil
    ) -> Data {
        var data = Data()
        data.reserveCapacity((uuid?.count ?? 0) + 5 + content.count + padding.count)
        if let uuid {
            data.append(contentsOf: uuid)
        }
        let contentLen = UInt16(clamping: content.count)
        let padLen = UInt16(clamping: padding.count)
        data.append(command)
        data.append(UInt8(contentLen >> 8))
        data.append(UInt8(contentLen & 0xFF))
        data.append(UInt8(padLen >> 8))
        data.append(UInt8(padLen & 0xFF))
        data.append(content.prefix(Int(contentLen)))
        data.append(padding.prefix(Int(padLen)))
        return data
    }

    static func paddingLength(contentLength: Int, longPadding: Bool) -> Int {
        let contentLength = max(0, contentLength)
        var padding: Int
        if longPadding && contentLength < longPaddingThreshold {
            padding = Int.random(in: 0..<500) + longPaddingThreshold - contentLength
        } else {
            padding = Int.random(in: 0..<256)
        }
        let cap = maxBuffer - maxHeader - contentLength
        if padding > cap { padding = max(0, cap) }
        return padding
    }

    static func randomBytes(_ count: Int) -> Data {
        guard count > 0 else { return Data() }
        var bytes = [UInt8](repeating: 0, count: count)
        for index in bytes.indices {
            bytes[index] = UInt8.random(in: 0...255)
        }
        return Data(bytes)
    }
}

// MARK: - Writer

/// Pads uplink application bytes until Vision end/direct.
public final class VLESSVisionWriter: @unchecked Sendable {
    private let userID: [UInt8]
    private var includeUUID = true
    private var padding = true
    private var packetsToFilter = 8
    private var isTLS = false

    public init(userID: UUID) {
        self.userID = VLESSUserID.rawBytes(userID)
    }

    /// Long empty Continue frame (Xray: hide the VLESS header).
    public func camouflage() -> Data {
        encode(Data(), longPadding: true)
    }

    /// Pads `plaintext` when still in the padding phase; otherwise returns it as-is.
    public func encode(_ plaintext: Data, longPadding: Bool = false) -> Data {
        guard padding else { return plaintext }
        if plaintext.count <= Self.chunkSize {
            return encodeChunk(plaintext, longPadding: longPadding, isLast: true)
        }
        var output = Data()
        var offset = 0
        while offset < plaintext.count {
            let end = min(offset + Self.chunkSize, plaintext.count)
            let chunk = plaintext.subdata(in: offset..<end)
            output.append(
                encodeChunk(chunk, longPadding: longPadding, isLast: end == plaintext.count)
            )
            offset = end
        }
        return output
    }

    private static let chunkSize = 8000

    private func encodeChunk(_ content: Data, longPadding: Bool, isLast: Bool) -> Data {
        guard padding else { return content }
        // Xray does not filter the empty camouflage frame.
        if !content.isEmpty { filterTLS(content) }
        var command = VLESSVision.commandContinue
        if content.starts(with: Self.tlsApplicationData) {
            // End (not Direct): keep uplink REALITY-sealed so the server keeps
            // decrypting it. Downlink direct copy is handled by the reader.
            command = VLESSVision.commandEnd
            padding = false
        } else if !isTLS {
            // HTTP and other non-TLS: one padded frame, then raw.
            command = VLESSVision.commandEnd
            padding = false
        } else if isLast && packetsToFilter <= 1 {
            command = VLESSVision.commandEnd
            padding = false
        }
        let pad = VLESSVision.randomBytes(
            VLESSVision.paddingLength(contentLength: content.count, longPadding: longPadding)
        )
        let uuid = includeUUID ? userID : nil
        includeUUID = false
        return VLESSVision.frame(command: command, content: content, padding: pad, uuid: uuid)
    }

    private static let tlsApplicationData: [UInt8] = [0x17, 0x03, 0x03]

    private func filterTLS(_ content: Data) {
        guard packetsToFilter > 0 else { return }
        packetsToFilter -= 1
        guard content.count >= 6 else { return }
        if content[0] == 0x16 && content[1] == 0x03 && content[5] == 0x01 {
            isTLS = true
        }
    }
}

// MARK: - Reader

/// Strips Vision padding from downlink bytes until end/direct, then passthrough.
public final class VLESSVisionReader: @unchecked Sendable {
    private let userID: [UInt8]
    private var pending = Data()
    private var remainingCommand = -1
    private var remainingContent = -1
    private var remainingPadding = -1
    private var currentCommand: UInt8 = 0
    private var passthrough = false
    /// Set when a `command=direct` frame completed: peer now splices raw.
    public private(set) var sawDirectCommand = false

    public init(userID: UUID) {
        self.userID = VLESSUserID.rawBytes(userID)
    }

    public func feed(_ data: Data) -> Data {
        if data.isEmpty { return Data() }
        if passthrough { return data }
        pending.append(data)
        var output = Data()
        while step(&output) {}
        return output
    }

    private func step(_ output: inout Data) -> Bool {
        if passthrough {
            flushPending(into: &output)
            return false
        }
        if remainingCommand == -1 && remainingContent == -1 && remainingPadding == -1 {
            return startBlock(into: &output)
        }
        if remainingCommand > 0 {
            return readHeaderByte()
        }
        if remainingContent > 0 {
            return copyContent(into: &output)
        }
        if remainingPadding > 0 {
            return skipPadding()
        }
        return finishBlock(into: &output)
    }

    private func startBlock(into output: inout Data) -> Bool {
        if pending.count < 16 { return false }
        if pending.starts(with: userID) {
            if pending.count < 21 { return false }
            pending.removeFirst(16)
            remainingCommand = 5
            remainingContent = 0
            remainingPadding = 0
            return true
        }
        passthrough = true
        flushPending(into: &output)
        return false
    }

    private func readHeaderByte() -> Bool {
        guard !pending.isEmpty else { return false }
        let byte = pending.removeFirst()
        switch remainingCommand {
        case 5: currentCommand = byte
        case 4: remainingContent = Int(byte) << 8
        case 3: remainingContent |= Int(byte)
        case 2: remainingPadding = Int(byte) << 8
        case 1: remainingPadding |= Int(byte)
        default: break
        }
        remainingCommand -= 1
        return true
    }

    private func copyContent(into output: inout Data) -> Bool {
        let take = min(remainingContent, pending.count)
        guard take > 0 else { return false }
        output.append(pending.prefix(take))
        pending.removeFirst(take)
        remainingContent -= take
        return true
    }

    private func skipPadding() -> Bool {
        let take = min(remainingPadding, pending.count)
        guard take > 0 else { return false }
        pending.removeFirst(take)
        remainingPadding -= take
        return true
    }

    private func finishBlock(into output: inout Data) -> Bool {
        if currentCommand == VLESSVision.commandContinue {
            remainingCommand = 5
            remainingContent = 0
            remainingPadding = 0
            return !pending.isEmpty
        }
        if currentCommand == VLESSVision.commandDirect {
            sawDirectCommand = true
        }
        passthrough = true
        remainingCommand = -1
        remainingContent = -1
        remainingPadding = -1
        flushPending(into: &output)
        return false
    }

    private func flushPending(into output: inout Data) {
        guard !pending.isEmpty else { return }
        output.append(pending)
        pending.removeAll(keepingCapacity: true)
    }
}
