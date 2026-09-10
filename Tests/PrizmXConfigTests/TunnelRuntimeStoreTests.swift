import Foundation
import Testing
import PrizmXConfig

@Test func stageCopiesPresentFilesAndSkipsMissing() throws {
    let fileManager = FileManager.default
    let root = fileManager.temporaryDirectory.appendingPathComponent("runtime-stage-\(UUID().uuidString)")
    let source = root.appendingPathComponent("source", isDirectory: true)
    let dest = root.appendingPathComponent("dest", isDirectory: true)
    defer { try? fileManager.removeItem(at: root) }

    try fileManager.createDirectory(
        at: source.appendingPathComponent("tunnel", isDirectory: true),
        withIntermediateDirectories: true
    )
    try "proxies: []\n".write(
        to: source.appendingPathComponent("tunnel/active.conf"),
        atomically: true,
        encoding: .utf8
    )
    try #"{"a.example":["1.2.3.4"]}"#.write(
        to: source.appendingPathComponent("tunnel/node-addrs.json"),
        atomically: true,
        encoding: .utf8
    )

    let staged = try TunnelRuntimeStore.stage(from: source, to: dest, fileManager: fileManager)
    #expect(staged == dest)
    #expect(
        try String(contentsOf: dest.appendingPathComponent("tunnel/active.conf"), encoding: .utf8)
            == "proxies: []\n"
    )
    #expect(fileManager.fileExists(atPath: dest.appendingPathComponent("tunnel/node-addrs.json").path))
    #expect(!fileManager.fileExists(atPath: dest.appendingPathComponent("dns-good.json").path))
    #expect(fileManager.fileExists(atPath: dest.appendingPathComponent("logs", isDirectory: true).path))
}

@Test func stageReplacesPreviousCopy() throws {
    let fileManager = FileManager.default
    let root = fileManager.temporaryDirectory.appendingPathComponent("runtime-replace-\(UUID().uuidString)")
    let source = root.appendingPathComponent("source", isDirectory: true)
    let dest = root.appendingPathComponent("dest", isDirectory: true)
    defer { try? fileManager.removeItem(at: root) }

    try fileManager.createDirectory(
        at: source.appendingPathComponent("tunnel", isDirectory: true),
        withIntermediateDirectories: true
    )
    try "v1".write(to: source.appendingPathComponent("tunnel/active.conf"), atomically: true, encoding: .utf8)
    _ = try TunnelRuntimeStore.stage(from: source, to: dest, fileManager: fileManager)
    try "v2".write(to: source.appendingPathComponent("tunnel/active.conf"), atomically: true, encoding: .utf8)
    _ = try TunnelRuntimeStore.stage(from: source, to: dest, fileManager: fileManager)
    #expect(
        try String(contentsOf: dest.appendingPathComponent("tunnel/active.conf"), encoding: .utf8) == "v2"
    )
}
