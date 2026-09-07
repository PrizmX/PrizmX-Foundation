import Darwin
import Foundation
import PrizmXCore

/// Resolves pid → executable path / process name / bundle ID.
/// Bundle ID is read from the enclosing `.app` via Foundation (no AppKit).
struct ProcessIdentityResolver: Sendable {
    func resolve(pid: Int32) -> FlowAttribution? {
        guard pid > 0 else { return nil }
        let path = Self.pidPath(pid)
        let app = path.flatMap(Self.enclosingApp)
        let bundle = app.flatMap { Bundle(url: $0) }
        let name = bundle.flatMap(Self.displayName)
            ?? Self.pidName(pid)
            ?? path.flatMap { URL(fileURLWithPath: $0).lastPathComponent }
            ?? "pid-\(pid)"
        return FlowAttribution(
            pid: pid,
            processName: name,
            bundleID: bundle?.bundleIdentifier,
            executablePath: app?.path ?? path
        )
    }

    /// Outermost `.app` so Chrome Helper traffic ranks under Chrome.
    static func enclosingApp(forExecutable path: String) -> URL? {
        var url = URL(fileURLWithPath: path)
        var found: URL?
        while url.pathComponents.count > 1 {
            if url.pathExtension == "app" {
                found = url
            }
            url.deleteLastPathComponent()
        }
        return found
    }

    static func bundleID(forExecutable path: String) -> String? {
        enclosingApp(forExecutable: path).flatMap { Bundle(url: $0)?.bundleIdentifier }
    }

    private static func displayName(for bundle: Bundle) -> String? {
        let keys = ["CFBundleDisplayName", "CFBundleName"]
        for key in keys {
            if let name = bundle.object(forInfoDictionaryKey: key) as? String, !name.isEmpty {
                return name
            }
        }
        return bundle.bundleURL.deletingPathExtension().lastPathComponent
    }

    private static func pidPath(_ pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: 4 * 1024)
        let written = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard written > 0 else { return nil }
        return cString(buffer)
    }

    private static func pidName(_ pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: 256)
        let written = proc_name(pid, &buffer, UInt32(buffer.count))
        guard written > 0 else { return nil }
        return cString(buffer)
    }

    private static func cString(_ buffer: [CChar]) -> String {
        let end = buffer.firstIndex(of: 0) ?? buffer.endIndex
        return String(decoding: buffer[..<end].map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
