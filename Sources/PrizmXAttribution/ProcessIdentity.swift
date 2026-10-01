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
        let executableName = Self.pidName(pid)
            ?? path.flatMap { URL(fileURLWithPath: $0).lastPathComponent }
        let name = bundle.flatMap(Self.displayName)
            ?? executableName.map { Self.readableName($0, launchName: Self.launchName(pid)) }
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

    /// A versioned executable (`~/.local/share/claude/versions/2.1.286`) is
    /// started through a named link; show that name (`claude`) instead.
    /// `launchName` is only read when the executable name has no letters.
    static func readableName(_ executableName: String, launchName: @autoclosure () -> String?) -> String {
        guard !executableName.contains(where: \.isLetter),
              let launched = launchName(),
              launched.contains(where: \.isLetter)
        else { return executableName }
        return launched
    }

    /// Last path component of argv[0] (`KERN_PROCARGS2`).
    static func launchName(_ pid: Int32) -> String? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else {
            return nil
        }
        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0 else { return nil }
        // argc, then the exec path, NUL padding, then argv[0].
        var index = MemoryLayout<Int32>.size
        while index < size, buffer[index] != 0 { index += 1 }
        while index < size, buffer[index] == 0 { index += 1 }
        let start = index
        while index < size, buffer[index] != 0 { index += 1 }
        guard index > start else { return nil }
        let argv0 = String(decoding: buffer[start..<index], as: UTF8.self)
        let name = URL(fileURLWithPath: argv0).lastPathComponent
        return name.isEmpty ? nil : name
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
