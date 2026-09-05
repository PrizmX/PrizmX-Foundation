import Foundation
import PrizmXProtocols

/// Allocates addresses from `198.18.0.0/16` (skipping the gateway and FakeDNS
/// hosts) so geosite matching can recover the original domain from TUN IPs.
public final class FakeIPAllocator: @unchecked Sendable {
    public static let network = IPv4Address(198, 18, 0, 0)
    public static let gateway = IPv4Address(198, 18, 0, 1)
    public static let dns = IPv4Address(198, 18, 0, 2)

    private let lock = NSLock()
    private var next: UInt32 = IPv4Address(198, 18, 0, 3).rawValue
    private let last: UInt32 = IPv4Address(198, 18, 255, 254).rawValue
    private var domainToIP: [String: IPv4Address] = [:]
    private var ipToDomain: [UInt32: String] = [:]
    private var order: [UInt32] = []
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
        if next == Self.gateway.rawValue || next == Self.dns.rawValue {
            next = IPv4Address(198, 18, 0, 3).rawValue
        }
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

    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return ipToDomain.count
    }
}
