import Foundation
import Network
import os
import PrizmXProtocols

/// Relays non-A/AAAA FakeDNS queries (SRV, TXT, MX, PTR, HTTPS, …) verbatim
/// to the DNS client's `direct`-role nameservers — the same plane
/// fake-ip-filter names use — so the answer is real instead of NODATA.
///
/// Only plain-UDP nameservers can carry a raw message here; with a
/// DoH-only direct plane the query stays unanswered upstream (NODATA)
/// rather than leaking through some other resolver.
enum DNSForwarder {
    static let timeout: Duration = .seconds(3)

    /// UDP targets from the direct plane, in configured order.
    static func targets(_ settings: DNSSettings) -> [(address: String, port: UInt16)] {
        settings.endpoints(for: .direct).compactMap { endpoint in
            guard case .udp(let address, let port) = endpoint,
                  NameserverAddress.isUsableIPv4(address) else { return nil }
            return (address, port)
        }
    }

    /// First well-formed answer (same ID, QR set) from the targets, or nil.
    static func forward(_ query: Data, settings: DNSSettings) async -> Data? {
        guard query.count >= 12 else { return nil }
        for target in targets(settings) {
            if let answer = await exchange(query, address: target.address, port: target.port),
               isAnswer(answer, to: query) {
                return answer
            }
        }
        return nil
    }

    static func isAnswer(_ answer: Data, to query: Data) -> Bool {
        let a = [UInt8](answer.prefix(3))
        let q = [UInt8](query.prefix(2))
        return a.count == 3 && q.count == 2 && a[0] == q[0] && a[1] == q[1] && a[2] & 0x80 != 0
    }

    /// PTR names under the FakeIP ranges are answered locally (NODATA):
    /// asking upstream would leak which fake addresses are in use.
    static func isFakeIPReverseName(_ name: String) -> Bool {
        let lowered = name.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        if lowered.hasSuffix(".18.198.in-addr.arpa") || lowered == "18.198.in-addr.arpa" { return true }
        // fd11:4514:1919:6472::/64 nibbles, reversed.
        return lowered.hasSuffix("2.7.4.6.9.1.9.1.4.1.5.4.1.1.d.f.ip6.arpa")
    }

    private static func exchange(_ query: Data, address: String, port: UInt16) async -> Data? {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return nil }
        let parameters = NWParameters.udp
        parameters.preferNoProxies = true
        let connection = NWConnection(host: NWEndpoint.Host(address), port: nwPort, using: parameters)
        let result = await withCheckedContinuation { (continuation: CheckedContinuation<Data?, Never>) in
            let slot = OSAllocatedUnfairLock<CheckedContinuation<Data?, Never>?>(initialState: continuation)
            let finish: @Sendable (Data?) -> Void = { value in
                slot.withLock { current -> CheckedContinuation<Data?, Never>? in
                    defer { current = nil }
                    return current
                }?.resume(returning: value)
            }
            let timer = Task {
                try? await Task.sleep(for: timeout)
                finish(nil)
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.send(content: query, completion: .contentProcessed { error in
                        if error != nil { finish(nil) }
                    })
                    connection.receiveMessage { data, _, _, _ in
                        timer.cancel()
                        finish(data)
                    }
                case .failed, .cancelled:
                    finish(nil)
                default:
                    break
                }
            }
            connection.start(queue: .global(qos: .userInitiated))
        }
        connection.cancel()
        return result
    }
}
