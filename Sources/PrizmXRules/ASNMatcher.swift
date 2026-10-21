import Foundation
import PrizmXProtocols

/// Autonomous system numbers from a GeoLite2-ASN database (mihomo's
/// `ASN.mmdb`), for `IP-ASN` / `SRC-IP-ASN` rules.
public final class ASNMatcher: Sendable {
    private let database: GeoIPMatcher

    public convenience init(contentsOf url: URL) throws {
        try self.init(database: GeoIPMatcher(contentsOf: url))
    }

    public convenience init(data: Data) throws {
        try self.init(database: GeoIPMatcher(data: data))
    }

    private init(database: GeoIPMatcher) throws {
        // A country database reads fine but holds no ASN.
        guard database.databaseType?.contains("ASN") == true else { throw GeoIPError.invalidMetadata }
        self.database = database
    }

    public func lookup(ipv4 address: IPv4Address) -> UInt32? {
        database.record(ipv4: address) { GeoIPMatcher.readASNumber(&$0) }
    }

    public func lookup(ipv6 address: IPv6Address) -> UInt32? {
        database.record(ipv6: address) { GeoIPMatcher.readASNumber(&$0) }
    }
}
