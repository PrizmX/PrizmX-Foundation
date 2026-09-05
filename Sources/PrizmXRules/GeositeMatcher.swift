import Foundation

/// One geosite category (`cn`, `google`, …).
public struct GeositeGroup: Sendable, Hashable {
    public var exact: [String]
    public var suffixes: [String]
    public var keywords: [String]

    public init(exact: [String] = [], suffixes: [String] = [], keywords: [String] = []) {
        self.exact = exact
        self.suffixes = suffixes
        self.keywords = keywords
    }
}

/// Kind of a single geosite domain entry (v2ray `Domain.Type` mapping).
@frozen
public enum GeositeEntryKind: Sendable, Hashable {
    /// Full hostname (`www.baidu.com`).
    case exact
    /// Suffix (`baidu.com` matches itself and `*.baidu.com`).
    case suffix
    /// Substring / keyword (`baidu` matches `www.baidu.com`).
    case keyword
}

/// Memory-optimized geosite matcher.
///
/// Each tag owns:
/// - a hash set of exact hostnames (O(1))
/// - a reversed-label suffix trie (O(label count), independent of rule count)
/// - a small keyword list (linear, typically tiny)
public final class GeositeMatcher: Sendable {
    private struct CompiledGroup: Sendable {
        var exact: Set<String>
        var suffixes: SuffixTrie
        var keywords: [String]
    }

    private let groups: [String: CompiledGroup]

    public init(groups: [String: GeositeGroup] = [:]) {
        var compiled: [String: CompiledGroup] = [:]
        compiled.reserveCapacity(groups.count)
        for (tag, group) in groups {
            let key = tag.lowercased()
            compiled[key] = CompiledGroup(
                exact: Set(group.exact.map { $0.lowercased() }),
                suffixes: SuffixTrie(suffixes: group.suffixes.map { $0.lowercased() }),
                keywords: group.keywords.map { $0.lowercased() }.filter { !$0.isEmpty }
            )
        }
        self.groups = compiled
    }

    /// Convenience builder used by tests and config loaders.
    public convenience init(entries: [(tag: String, value: String, kind: GeositeEntryKind)]) {
        var raw: [String: GeositeGroup] = [:]
        for entry in entries {
            let tag = entry.tag.lowercased()
            var group = raw[tag] ?? GeositeGroup()
            switch entry.kind {
            case .exact: group.exact.append(entry.value)
            case .suffix: group.suffixes.append(entry.value)
            case .keyword: group.keywords.append(entry.value)
            }
            raw[tag] = group
        }
        self.init(groups: raw)
    }

    /// Returns whether `domain` belongs to geosite `group` (e.g. `"cn"`).
    public func match(domain: String, group: String) -> Bool {
        let host = domain.lowercased()
        guard let compiled = groups[group.lowercased()] else { return false }
        if compiled.exact.contains(host) { return true }
        if compiled.suffixes.contains(host) { return true }
        for keyword in compiled.keywords where host.contains(keyword) {
            return true
        }
        return false
    }
}

// MARK: - Reversed-label suffix trie

/// `example.com` is stored as `com -> example`. A walk from the TLD inward
/// reports a hit as soon as a terminal node is reached, so `a.b.example.com`
/// matches the `example.com` suffix in one pass.
struct SuffixTrie: Sendable {
    private struct Node: Sendable {
        var children: [String: Int] = [:]
        var terminal = false
    }

    private var nodes: [Node]

    init(suffixes: [String]) {
        var nodes = [Node()]
        for raw in suffixes {
            var suffix = raw.lowercased()
            if suffix.hasPrefix("*.") { suffix.removeFirst(2) }
            while suffix.hasPrefix(".") { suffix.removeFirst() }
            while suffix.hasSuffix(".") { suffix.removeLast() }
            guard !suffix.isEmpty else { continue }
            var index = 0
            for label in suffix.split(separator: ".").reversed() {
                let key = String(label)
                if let next = nodes[index].children[key] {
                    index = next
                } else {
                    nodes.append(Node())
                    nodes[index].children[key] = nodes.count - 1
                    index = nodes.count - 1
                }
            }
            nodes[index].terminal = true
        }
        self.nodes = nodes
    }

    func contains(_ domain: String) -> Bool {
        var index = 0
        var hit = nodes[0].terminal
        for label in domain.split(separator: ".").reversed() {
            guard let next = nodes[index].children[String(label)] else { break }
            index = next
            if nodes[index].terminal { hit = true }
        }
        return hit
    }
}
