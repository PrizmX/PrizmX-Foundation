import Foundation
import PrizmXProtocols

/// Allocates addresses from `198.18.0.0/16` (skipping the gateway and FakeDNS
/// hosts) so geosite matching can recover the original domain from TUN IPs.
///
/// Mappings are LRU: a DNS answer and a flow lookup both refresh an entry, and
/// when the pool is full the least recently used mapping is recycled. Entries
/// pinned by live TCP flows (`retain` / `release`) are skipped when possible,
/// so a long-lived connection never has its address handed to another name.
public final class FakeIPAllocator: @unchecked Sendable {
    public static let network = IPv4Address(198, 18, 0, 0)
    public static let gateway = IPv4Address(198, 18, 0, 1)
    public static let dns = IPv4Address(198, 18, 0, 2)
    /// Clash Meta default `fake-ip-range6`.
    public static let network6 = IPv6Address(high: 0xfd11_4514_1919_6472, low: 0)
    public static let gateway6 = IPv6Address(high: 0xfd11_4514_1919_6472, low: 1)
    public static let dns6 = IPv6Address(high: 0xfd11_4514_1919_6472, low: 2)

    private static let first = IPv4Address(198, 18, 0, 3).rawValue
    private static let last = IPv4Address(198, 18, 255, 254).rawValue
    /// Every usable address in 198.18.0.0/16.
    public static let poolSize = Int(last - first + 1)

    private let lock = NSLock()
    private var table4: LRUTable<UInt32>
    private var next: UInt32 = FakeIPAllocator.first
    private var table6: LRUTable<UInt64>
    private var next6: UInt64 = 3

    /// `capacity` bounds live mappings per family; it defaults to (and is
    /// clamped to) the whole IPv4 pool.
    public init(capacity: Int = FakeIPAllocator.poolSize) {
        let bounded = min(max(16, capacity), Self.poolSize)
        table4 = LRUTable(capacity: bounded)
        table6 = LRUTable(capacity: bounded)
    }

    public func contains(_ address: IPv4Address) -> Bool {
        address.rawValue >= Self.network.rawValue && address.rawValue <= Self.last
    }

    public func allocate(domain: String) -> IPv4Address {
        let key = domain.lowercased()
        lock.lock()
        defer { lock.unlock() }
        if let existing = table4.address(for: key) {
            table4.touch(existing)
            return IPv4Address(rawValue: existing)
        }
        let raw: UInt32
        if table4.count < table4.capacity, table4.domain(for: next) == nil {
            raw = next
            next = next == Self.last ? Self.first : next &+ 1
        } else if let recycled = table4.evict() {
            raw = recycled
        } else {
            raw = next
            next = next == Self.last ? Self.first : next &+ 1
        }
        table4.insert(raw, domain: key)
        return IPv4Address(rawValue: raw)
    }

    /// Domain for a FakeIP; a hit refreshes the mapping.
    public func domain(for address: IPv4Address) -> String? {
        lock.lock()
        defer { lock.unlock() }
        guard let domain = table4.domain(for: address.rawValue) else { return nil }
        table4.touch(address.rawValue)
        return domain
    }

    public func contains(_ address: IPv6Address) -> Bool {
        address.high == Self.network6.high && address.low >= 1
    }

    public func allocateIPv6(domain: String) -> IPv6Address {
        let key = domain.lowercased()
        lock.lock()
        defer { lock.unlock() }
        if let existing = table6.address(for: key) {
            table6.touch(existing)
            return IPv6Address(high: Self.network6.high, low: existing)
        }
        if table6.count >= table6.capacity {
            _ = table6.evict()
        }
        // The /64 is effectively inexhaustible: never reuse a recycled suffix.
        if next6 < 3 || next6 == UInt64.max { next6 = 3 }
        let low = next6
        next6 &+= 1
        table6.insert(low, domain: key)
        return IPv6Address(high: Self.network6.high, low: low)
    }

    public func domain(for address: IPv6Address) -> String? {
        guard contains(address) else { return nil }
        lock.lock()
        defer { lock.unlock() }
        guard let domain = table6.domain(for: address.low) else { return nil }
        table6.touch(address.low)
        return domain
    }

    /// Pins a mapping while a flow uses it (no-op for non-FakeIP addresses).
    public func retain(_ address: IPv4Address) {
        lock.lock(); table4.pin(address.rawValue, by: 1); lock.unlock()
    }

    public func release(_ address: IPv4Address) {
        lock.lock(); table4.pin(address.rawValue, by: -1); lock.unlock()
    }

    public func retain(_ address: IPv6Address) {
        guard contains(address) else { return }
        lock.lock(); table6.pin(address.low, by: 1); lock.unlock()
    }

    public func release(_ address: IPv6Address) {
        guard contains(address) else { return }
        lock.lock(); table6.pin(address.low, by: -1); lock.unlock()
    }

    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return table4.count
    }
}

/// Address ↔ domain map with an intrusive doubly linked LRU list (O(1)
/// touch / insert / evict). Not thread-safe; the allocator locks around it.
struct LRUTable<Address: Hashable & Sendable>: Sendable {
    private struct Entry: Sendable {
        var domain: String
        var pins: Int
        var older: Address?
        var newer: Address?
    }

    let capacity: Int
    private var entries: [Address: Entry] = [:]
    private var byDomain: [String: Address] = [:]
    /// Least recently used end.
    private var oldest: Address?
    /// Most recently used end.
    private var newest: Address?

    init(capacity: Int) {
        self.capacity = capacity
    }

    var count: Int { entries.count }

    func address(for domain: String) -> Address? { byDomain[domain] }

    func domain(for address: Address) -> String? { entries[address]?.domain }

    mutating func insert(_ address: Address, domain: String) {
        if entries[address] != nil { remove(address) }
        if let previous = byDomain[domain] { remove(previous) }
        entries[address] = Entry(domain: domain, pins: 0, older: newest, newer: nil)
        if let newest { entries[newest]?.newer = address }
        newest = address
        if oldest == nil { oldest = address }
        byDomain[domain] = address
    }

    mutating func touch(_ address: Address) {
        guard newest != address, entries[address] != nil else { return }
        unlink(address)
        entries[address]?.older = newest
        entries[address]?.newer = nil
        if let newest { entries[newest]?.newer = address }
        newest = address
        if oldest == nil { oldest = address }
    }

    mutating func pin(_ address: Address, by delta: Int) {
        guard var entry = entries[address] else { return }
        entry.pins = max(0, entry.pins + delta)
        entries[address] = entry
    }

    /// Removes the least recently used unpinned entry (pinned ones are moved
    /// to the fresh end). Falls back to the oldest when everything is pinned.
    mutating func evict() -> Address? {
        var scanned = 0
        while let candidate = oldest, scanned < entries.count {
            if entries[candidate]?.pins ?? 0 == 0 {
                remove(candidate)
                return candidate
            }
            touch(candidate)
            scanned += 1
        }
        guard let fallback = oldest else { return nil }
        remove(fallback)
        return fallback
    }

    private mutating func remove(_ address: Address) {
        guard let entry = entries[address] else { return }
        unlink(address)
        entries.removeValue(forKey: address)
        if byDomain[entry.domain] == address { byDomain.removeValue(forKey: entry.domain) }
    }

    private mutating func unlink(_ address: Address) {
        guard let entry = entries[address] else { return }
        if let older = entry.older { entries[older]?.newer = entry.newer } else { oldest = entry.newer }
        if let newer = entry.newer { entries[newer]?.older = entry.older } else { newest = entry.older }
    }
}
