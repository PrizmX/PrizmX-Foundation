import Foundation
import PrizmXProtocols

/// Allocates addresses from `198.18.0.0/16` (skipping the gateway and FakeDNS
/// hosts) so geosite matching can recover the original domain from TUN IPs.
public final class FakeIPAllocator: @unchecked Sendable {
    public static let network = IPv4Address(198, 18, 0, 0)
    public static let gateway = IPv4Address(198, 18, 0, 1)
    public static let dns = IPv4Address(198, 18, 0, 2)
    /// Clash Meta default `fake-ip-range6`.
    public static let network6 = IPv6Address(high: 0xfd11_4514_1919_6472, low: 0)
    public static let gateway6 = IPv6Address(high: 0xfd11_4514_1919_6472, low: 1)
    public static let dns6 = IPv6Address(high: 0xfd11_4514_1919_6472, low: 2)

    private let lock = NSLock()
    private var next: UInt32 = IPv4Address(198, 18, 0, 3).rawValue
    private let last: UInt32 = IPv4Address(198, 18, 255, 254).rawValue
    private var domainToIP: [String: IPv4Address] = [:]
    private var ipToDomain: [UInt32: String] = [:]
    private var order: [UInt32] = []
    private var next6: UInt64 = 3
    private var domainToIP6: [String: IPv6Address] = [:]
    private var ip6ToDomain: [UInt64: String] = [:]
    private var order6: [UInt64] = []
    private let capacity: Int

    public init(capacity: Int = 4096) {
        self.capacity = max(16, capacity)
    }

    public func contains(_ address: IPv4Address) -> Bool {
        address.rawValue >= Self.network.rawValue && address.rawValue <= last
    }

    public func allocate(domain: String) -> IPv4Address {
        let key = domain.lowercased()
        lock.lock()
        defer { lock.unlock() }
        if let existing = domainToIP[key] { return existing }
        if order.count >= capacity {
            let evicted = order.removeFirst()
            if let name = ipToDomain.removeValue(forKey: evicted) {
                domainToIP.removeValue(forKey: name)
            }
        }
        let address = IPv4Address(rawValue: next)
        next = next == last ? IPv4Address(198, 18, 0, 3).rawValue : next &+ 1
        domainToIP[key] = address
        ipToDomain[address.rawValue] = key
        order.append(address.rawValue)
        return address
    }

    public func domain(for address: IPv4Address) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return ipToDomain[address.rawValue]
    }

    public func contains(_ address: IPv6Address) -> Bool {
        address.high == Self.network6.high && address.low >= 1
    }

    public func allocateIPv6(domain: String) -> IPv6Address {
        let key = domain.lowercased()
        lock.lock()
        defer { lock.unlock() }
        if let existing = domainToIP6[key] { return existing }
        if order6.count >= capacity {
            let evicted = order6.removeFirst()
            if let name = ip6ToDomain.removeValue(forKey: evicted) {
                domainToIP6.removeValue(forKey: name)
            }
        }
        if next6 < 3 || next6 == UInt64.max { next6 = 3 }
        let address = IPv6Address(high: Self.network6.high, low: next6)
        next6 &+= 1
        domainToIP6[key] = address
        ip6ToDomain[address.low] = key
        order6.append(address.low)
        return address
    }

    public func domain(for address: IPv6Address) -> String? {
        guard contains(address) else { return nil }
        lock.lock()
        defer { lock.unlock() }
        return ip6ToDomain[address.low]
    }

    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return ipToDomain.count
    }
}
