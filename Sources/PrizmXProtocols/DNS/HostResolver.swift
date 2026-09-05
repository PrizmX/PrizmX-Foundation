import Darwin
import Foundation

/// Hostname lookup using the **process** resolver (`getaddrinfo`).
///
/// In the main app this is the user's real DNS (e.g. 114.114.114.114).
/// Inside the Packet Tunnel it is FakeDNS and must not be used for node dials.
public enum HostResolver: Sendable {
    public static func ipv4(_ domain: String) async -> [IPv4Address] {
        let name = domain.lowercased()
        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: lookupIPv4(name))
            }
        }
    }

    private static func lookupIPv4(_ domain: String) -> [IPv4Address] {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<addrinfo>?
        let status = domain.withCString { cName in
            getaddrinfo(cName, nil, &hints, &result)
        }
        defer { if result != nil { freeaddrinfo(result) } }
        guard status == 0 else { return [] }
        var addresses: [IPv4Address] = []
        var cursor = result
        while let info = cursor?.pointee {
            if info.ai_family == AF_INET, let raw = info.ai_addr {
                var sin = sockaddr_in()
                memcpy(&sin, raw, MemoryLayout<sockaddr_in>.size)
                let address = IPv4Address(networkOrder: sin.sin_addr.s_addr)
                if !addresses.contains(address) {
                    addresses.append(address)
                }
            }
            cursor = info.ai_next
        }
        return addresses
    }
}
