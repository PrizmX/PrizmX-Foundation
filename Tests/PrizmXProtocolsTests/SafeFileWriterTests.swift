import Foundation
import Testing
@testable import PrizmXProtocols

@Suite("SafeFileWriter")
struct SafeFileWriterTests {
    private func makeDirectory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("safe-writer-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    @Test func replaceCreatesMissingDirectoriesAndSetsMode() throws {
        let root = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("a/b/file.json")

        try SafeFileWriter.replace(Data("one".utf8), at: url)
        try SafeFileWriter.replace(Data("two".utf8), at: url)

        #expect(try Data(contentsOf: url) == Data("two".utf8))
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        #expect((attrs[.posixPermissions] as? NSNumber)?.intValue == 0o644)
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: url.deletingLastPathComponent().path)
        #expect(leftovers == ["file.json"])
    }

    @Test func replaceDoesNotFollowSymlinkAtTarget() throws {
        let root = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let victim = root.appendingPathComponent("victim.txt")
        try Data("secret".utf8).write(to: victim)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: victim.path)
        let target = root.appendingPathComponent("kit/metrics.json")
        try FileManager.default.createDirectory(
            at: target.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try FileManager.default.createSymbolicLink(at: target, withDestinationURL: victim)

        try SafeFileWriter.replace(Data("fresh".utf8), at: target)

        #expect(try Data(contentsOf: victim) == Data("secret".utf8))
        let victimAttrs = try FileManager.default.attributesOfItem(atPath: victim.path)
        #expect((victimAttrs[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        let targetAttrs = try FileManager.default.attributesOfItem(atPath: target.path)
        #expect(targetAttrs[.type] as? FileAttributeType == .typeRegular)
        #expect(try Data(contentsOf: target) == Data("fresh".utf8))
    }

    @Test func appendDoesNotFollowSymlinkOrHardLink() throws {
        let root = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let victim = root.appendingPathComponent("victim.txt")
        try Data("secret".utf8).write(to: victim)
        let logs = root.appendingPathComponent("logs", isDirectory: true)
        try FileManager.default.createDirectory(at: logs, withIntermediateDirectories: true)
        let log = logs.appendingPathComponent("tunnel.log")

        try FileManager.default.createSymbolicLink(at: log, withDestinationURL: victim)
        try SafeFileWriter.append(Data("line1\n".utf8), to: log)
        #expect(try Data(contentsOf: victim) == Data("secret".utf8))
        #expect(try Data(contentsOf: log) == Data("line1\n".utf8))

        try FileManager.default.removeItem(at: log)
        try FileManager.default.linkItem(at: victim, to: log)
        try SafeFileWriter.append(Data("line2\n".utf8), to: log)
        #expect(try Data(contentsOf: victim) == Data("secret".utf8))
        #expect(try Data(contentsOf: log) == Data("line2\n".utf8))
    }

    @Test func appendRotatesToTail() throws {
        let root = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let log = root.appendingPathComponent("tunnel.log")
        try SafeFileWriter.append(Data("0123456789".utf8), to: log)
        try SafeFileWriter.append(Data("AB".utf8), to: log, rotateAbove: 8, keepBytes: 4)
        #expect(try Data(contentsOf: log) == Data("6789AB".utf8))
    }

    @Test func rejectsSymlinkedDirectoryAndRootOwnedDirectory() throws {
        let root = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let real = root.appendingPathComponent("real", isDirectory: true)
        try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
        let link = root.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)

        #expect(throws: SafeFileWriter.Failure.self) {
            try SafeFileWriter.replace(Data("x".utf8), at: link.appendingPathComponent("f"))
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: real.path).isEmpty)

        // `/private/tmp` is root-owned: refused before anything is created.
        let name = "prizmx-safe-writer-\(UUID().uuidString)"
        #expect(throws: SafeFileWriter.Failure.rootOwnedDirectory("/private/tmp")) {
            try SafeFileWriter.replace(Data("x".utf8), at: URL(fileURLWithPath: "/private/tmp/\(name)"))
        }
        #expect(!FileManager.default.fileExists(atPath: "/private/tmp/\(name)"))
    }

    @Test func logLinesEscapeControlCharacters() {
        #expect(TunnelLog.escapedLine("sni=a.com") == "sni=a.com")
        #expect(TunnelLog.escapedLine("host=evil\r\n12-01 [error] forged") == "host=evil\\r\\n12-01 [error] forged")
        #expect(TunnelLog.escapedLine("x\u{0}y") == "x\\u{0}y")
    }

    @Test(.timeLimit(.minutes(1))) func appendAndRotateDoNotBlockOnPlantedFIFO() throws {
        let root = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let log = root.appendingPathComponent("tunnel.log")
        #expect(mkfifo(log.path, 0o644) == 0)

        // Rotation opens for reading and append for writing: neither may hang.
        try SafeFileWriter.append(Data("line\n".utf8), to: log, rotateAbove: 1, keepBytes: 1)

        let attrs = try FileManager.default.attributesOfItem(atPath: log.path)
        #expect(attrs[.type] as? FileAttributeType == .typeRegular)
        #expect(try Data(contentsOf: log) == Data("line\n".utf8))
    }

    @Test func rootOwnedDirectoryMigrationDecision() {
        // Running as root, root-owned kit subdir under a user-owned parent: adopt.
        let adopted = SafeFileWriter.migratedOwner(directoryUID: 0, parentUID: 501, parentGID: 20, effectiveUID: 0)
        #expect(adopted?.uid == 501)
        #expect(adopted?.gid == 20)
        // Root-owned parent: the path points into the system — refuse.
        #expect(SafeFileWriter.migratedOwner(directoryUID: 0, parentUID: 0, parentGID: 0, effectiveUID: 0) == nil)
        // Not root: cannot chown anyway — refuse.
        #expect(SafeFileWriter.migratedOwner(directoryUID: 0, parentUID: 501, parentGID: 20, effectiveUID: 501) == nil)
        // Directory already user-owned: nothing to migrate.
        #expect(SafeFileWriter.migratedOwner(directoryUID: 501, parentUID: 501, parentGID: 20, effectiveUID: 0) == nil)
    }
}
