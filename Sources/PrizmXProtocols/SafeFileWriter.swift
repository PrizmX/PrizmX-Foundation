import Darwin
import Foundation

/// Symlink-safe file writes into a user-owned directory.
///
/// The macOS Packet Tunnel system extension runs as root but writes into the
/// user's kit (`~/Library/Application Support/PrizmX/kit`). Path-based APIs
/// (`FileHandle(forWritingTo:)`, `setAttributes`, `Data.write`) follow
/// symlinks, so a same-user process could redirect a root write or chown
/// onto a system file. Every operation here is anchored on a directory fd:
///
/// - the target directory is opened with `O_DIRECTORY | O_NOFOLLOW` and
///   refused when it and its parent are owned by root (the directory, or an
///   ancestor, was redirected into a system location);
/// - files are created with `O_CREAT | O_EXCL | O_NOFOLLOW` relative to that
///   fd, `fchown` / `fchmod`ed to the directory owner, and `renameat`ed into
///   place, so an existing symlink or hard link at the target is replaced,
///   never written through;
/// - existing files open with `O_NOFOLLOW | O_NONBLOCK` (a planted FIFO
///   cannot block) and anything that is not a single-link regular file owned
///   by the directory owner is replaced, never written through;
/// - a root-owned target directory whose parent belongs to a regular user
///   (left by an older root extension) is `fchown`ed back to that user.
public enum SafeFileWriter: Sendable {

    public enum Failure: Error, Equatable, Sendable {
        /// A POSIX call failed (`operation`, `errno`).
        case posix(String, Int32)
        /// The target directory is owned by root.
        case rootOwnedDirectory(String)
        /// The target exists but is not a plain, single-link file owned by
        /// the directory owner (e.g. a planted hard link).
        case unsafeTarget(String)
        case invalidPath(String)
    }

    /// Atomically replaces `url` with `data` (temp file + `renameat`).
    /// Missing parent directories are created, owned by their parent's owner.
    public static func replace(_ data: Data, at url: URL, mode: mode_t = 0o644) throws {
        let (directory, name) = try split(url)
        let dir = try OpenDirectory(url: directory, create: true)
        defer { dir.close() }
        try dir.replace(name: name, with: data, mode: mode)
    }

    /// Appends `data` to `url`, creating it when missing. When the file is
    /// already larger than `rotateAbove`, it is first atomically replaced by
    /// its last `keepBytes` bytes.
    public static func append(
        _ data: Data,
        to url: URL,
        rotateAbove: Int? = nil,
        keepBytes: Int = 0,
        mode: mode_t = 0o644
    ) throws {
        let (directory, name) = try split(url)
        let dir = try OpenDirectory(url: directory, create: true)
        defer { dir.close() }

        if let rotateAbove {
            try dir.rotate(name: name, above: rotateAbove, keepBytes: keepBytes, mode: mode)
        }
        let fd = try dir.openForAppend(name: name, mode: mode)
        defer { Darwin.close(fd) }
        try writeAll(fd, data)
    }

    // MARK: - Internals

    private static func split(_ url: URL) throws -> (URL, String) {
        let name = url.lastPathComponent
        guard url.isFileURL, !name.isEmpty, name != "/", name != ".", name != ".." else {
            throw Failure.invalidPath(url.path)
        }
        return (url.deletingLastPathComponent(), name)
    }

    /// Ownership a root-owned target directory is migrated to, or nil to
    /// refuse: only when we run as root and the parent belongs to a regular
    /// user (a root-owned parent means the path points into the system).
    static func migratedOwner(
        directoryUID: uid_t,
        parentUID: uid_t,
        parentGID: gid_t,
        effectiveUID: uid_t
    ) -> (uid: uid_t, gid: gid_t)? {
        guard directoryUID == 0, effectiveUID == 0, parentUID != 0 else { return nil }
        return (parentUID, parentGID)
    }

    /// Opens an existing entry without blocking (a FIFO planted at the target
    /// would otherwise hang `open`), then restores blocking I/O. The caller
    /// still validates the file type.
    fileprivate static func openExisting(_ dirFD: Int32, _ name: String, _ flags: Int32) -> Int32 {
        let fd = openat(dirFD, name, flags | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return fd }
        let current = fcntl(fd, F_GETFL)
        if current >= 0 { _ = fcntl(fd, F_SETFL, current & ~O_NONBLOCK) }
        return fd
    }

    fileprivate static func posixError(_ operation: String) -> Failure {
        .posix(operation, errno)
    }

    fileprivate static func writeAll(_ fd: Int32, _ data: Data) throws {
        try data.withUnsafeBytes { raw in
            guard var base = raw.baseAddress else { return }
            var remaining = raw.count
            while remaining > 0 {
                let written = Darwin.write(fd, base, remaining)
                if written < 0 {
                    if errno == EINTR { continue }
                    throw posixError("write")
                }
                remaining -= written
                base = base.advanced(by: written)
            }
        }
    }

    /// A directory opened without following its last component.
    fileprivate struct OpenDirectory {
        let fd: Int32
        let owner: uid_t
        let group: gid_t

        init(url: URL, create: Bool) throws {
            let fd = try Self.open(path: url.path, create: create)
            var info = stat()
            guard fstat(fd, &info) == 0 else {
                let error = SafeFileWriter.posixError("fstat")
                Darwin.close(fd)
                throw error
            }
            var owner = info.st_uid
            var group = info.st_gid
            if owner == 0 {
                // Earlier versions (root extension) left root-owned kit
                // subdirectories behind. Hand such a directory back to its
                // parent's non-root owner instead of silently refusing.
                var parent = stat()
                let parentFD = openat(fd, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
                let parentOK = parentFD >= 0 && fstat(parentFD, &parent) == 0
                if parentFD >= 0 { Darwin.close(parentFD) }
                guard parentOK,
                      let adopted = SafeFileWriter.migratedOwner(
                          directoryUID: info.st_uid,
                          parentUID: parent.st_uid,
                          parentGID: parent.st_gid,
                          effectiveUID: geteuid()
                      ),
                      fchown(fd, adopted.uid, adopted.gid) == 0
                else {
                    Darwin.close(fd)
                    throw Failure.rootOwnedDirectory(url.path)
                }
                owner = adopted.uid
                group = adopted.gid
            }
            self.fd = fd
            self.owner = owner
            self.group = group
        }

        func close() {
            Darwin.close(fd)
        }

        /// Opens `path` as a directory (no symlink at the last component),
        /// creating missing components when `create` is set. New directories
        /// inherit their parent's owner so a root writer never leaves
        /// root-owned directories inside the user kit, and are never created
        /// inside a root-owned parent while running as root.
        private static func open(path: String, create: Bool) throws -> Int32 {
            let flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
            let fd = Darwin.open(path, flags)
            if fd >= 0 { return fd }
            guard create, errno == ENOENT, path != "/" else {
                throw SafeFileWriter.posixError("open(\(path))")
            }
            let url = URL(fileURLWithPath: path)
            let name = url.lastPathComponent
            let parentFD = try open(path: url.deletingLastPathComponent().path, create: true)
            defer { Darwin.close(parentFD) }
            var parent = stat()
            guard fstat(parentFD, &parent) == 0 else { throw SafeFileWriter.posixError("fstat") }
            if geteuid() == 0, parent.st_uid == 0 {
                throw Failure.rootOwnedDirectory(url.deletingLastPathComponent().path)
            }
            if mkdirat(parentFD, name, 0o755) != 0, errno != EEXIST {
                throw SafeFileWriter.posixError("mkdirat(\(name))")
            }
            let child = openat(parentFD, name, flags)
            guard child >= 0 else { throw SafeFileWriter.posixError("openat(\(name))") }
            if geteuid() == 0 {
                var info = stat()
                if fstat(child, &info) == 0, info.st_uid != parent.st_uid || info.st_gid != parent.st_gid {
                    _ = fchown(child, parent.st_uid, parent.st_gid)
                }
            }
            return child
        }

        /// Creates a fresh temp file, writes `data`, and renames it over `name`.
        func replace(name: String, with data: Data, mode: mode_t) throws {
            let temp = ".\(name).\(UUID().uuidString).tmp"
            let tfd = openat(fd, temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
            guard tfd >= 0 else { throw SafeFileWriter.posixError("openat(\(temp))") }
            var renamed = false
            defer {
                Darwin.close(tfd)
                if !renamed { unlinkat(fd, temp, 0) }
            }
            try adopt(tfd, mode: mode)
            try SafeFileWriter.writeAll(tfd, data)
            guard renameat(fd, temp, fd, name) == 0 else {
                throw SafeFileWriter.posixError("renameat(\(name))")
            }
            renamed = true
        }

        /// `O_APPEND` fd for `name`; creates it (owned by the directory owner)
        /// when missing and validates it when it already exists.
        func openForAppend(name: String, mode: mode_t, retried: Bool = false) throws -> Int32 {
            let created = openat(fd, name, O_WRONLY | O_APPEND | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
            if created >= 0 {
                do {
                    try adopt(created, mode: mode)
                } catch {
                    Darwin.close(created)
                    throw error
                }
                return created
            }
            guard errno == EEXIST else { throw SafeFileWriter.posixError("openat(\(name))") }
            let existing = SafeFileWriter.openExisting(fd, name, O_WRONLY | O_APPEND)
            guard existing >= 0 else {
                // ELOOP: a symlink sits at `name`; ENXIO: a FIFO without a
                // reader. Swap it for a fresh file (the rename replaces the
                // entry itself, never its target).
                guard errno == ELOOP || errno == ENXIO, !retried else {
                    throw SafeFileWriter.posixError("openat(\(name))")
                }
                try replace(name: name, with: Data(), mode: mode)
                return try openForAppend(name: name, mode: mode, retried: true)
            }
            do {
                try validate(existing, name: name)
            } catch {
                Darwin.close(existing)
                guard !retried else { throw error }
                // Planted hard link or a stale root-owned file: detach it
                // from `name` without touching the other inode's contents.
                try replace(name: name, with: Data(), mode: mode)
                return try openForAppend(name: name, mode: mode, retried: true)
            }
            return existing
        }

        /// Replaces `name` with its tail when it grew past `above` bytes.
        func rotate(name: String, above: Int, keepBytes: Int, mode: mode_t) throws {
            let rfd = SafeFileWriter.openExisting(fd, name, O_RDONLY)
            guard rfd >= 0 else {
                if errno == ENOENT || errno == ELOOP { return }
                throw SafeFileWriter.posixError("openat(\(name))")
            }
            defer { Darwin.close(rfd) }
            // Unsafe targets are never read (that would copy another file's
            // contents); `openForAppend` detaches them instead.
            guard (try? validate(rfd, name: name)) != nil else { return }
            var info = stat()
            guard fstat(rfd, &info) == 0 else { throw SafeFileWriter.posixError("fstat") }
            let size = Int(info.st_size)
            guard size > above else { return }
            let keep = max(0, min(keepBytes, size))
            var tail = Data(count: keep)
            let read = tail.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return 0 }
                return pread(rfd, base, keep, off_t(size - keep))
            }
            guard read >= 0 else { throw SafeFileWriter.posixError("pread") }
            try replace(name: name, with: tail.prefix(read), mode: mode)
        }

        /// New files: hand them to the directory owner with `mode`.
        private func adopt(_ file: Int32, mode: mode_t) throws {
            if geteuid() == 0, fchown(file, owner, group) != 0 {
                throw SafeFileWriter.posixError("fchown")
            }
            if fchmod(file, mode) != 0 {
                throw SafeFileWriter.posixError("fchmod")
            }
        }

        /// Existing files must be a plain single-link file of the directory
        /// owner; a planted hard link to a system file fails here.
        private func validate(_ file: Int32, name: String) throws {
            var info = stat()
            guard fstat(file, &info) == 0 else { throw SafeFileWriter.posixError("fstat") }
            guard (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1, info.st_uid == owner else {
                throw Failure.unsafeTarget(name)
            }
        }
    }
}
