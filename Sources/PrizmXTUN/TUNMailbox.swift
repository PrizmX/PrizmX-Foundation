import Foundation
import PrizmXProtocols
import SwiftTCP

/// Bridges SwiftTCP callbacks onto `TUNTCPStream` / `TUNUDPDatagram` mailboxes.
///
/// `PacketSink` / `TCPStreamHandler` / `UDPDatagramHandler` are invoked from
/// event-loop actors; this type is the only shared mutable surface.
final class TUNMailbox: PacketSink, TCPStreamHandler, UDPDatagramHandler, @unchecked Sendable {
    struct UDPReplyKey: Hashable, Sendable {
        var client: UInt32
        var clientPort: UInt16
        var destPort: UInt16
    }

    private let lock = NSLock()
    /// Hop stream callbacks off the TCP event loop so splice resume/send
    /// cannot re-enter `ingestBatch`.
    private let deliverQueue = DispatchQueue(label: "prizmx.tun.deliver", qos: .userInitiated)
    private let onOutput: @Sendable ([Data]) -> Void
    private let fakeIP: FakeIPAllocator?

    private var byteStream: (any TCPByteStream)?
    private var tcpStreams: [FlowKey: TUNTCPStream] = [:]
    private var udpFlows: [UDPReplyKey: FlowKey] = [:]
    private var tcpContinuation: AsyncStream<TUNTCPStream>.Continuation?
    private var udpContinuation: AsyncStream<TUNUDPDatagram>.Continuation?

    init(fakeIP: FakeIPAllocator?, onOutput: @escaping @Sendable ([Data]) -> Void) {
        self.fakeIP = fakeIP
        self.onOutput = onOutput
    }

    func attach(byteStream: any TCPByteStream) {
        lock.lock()
        self.byteStream = byteStream
        lock.unlock()
    }

    func setTCPContinuation(_ continuation: AsyncStream<TUNTCPStream>.Continuation?) {
        lock.lock()
        tcpContinuation = continuation
        lock.unlock()
    }

    func setUDPContinuation(_ continuation: AsyncStream<TUNUDPDatagram>.Continuation?) {
        lock.lock()
        udpContinuation = continuation
        lock.unlock()
    }

    func flow(for key: UDPReplyKey) -> FlowKey? {
        lock.lock()
        defer { lock.unlock() }
        return udpFlows[key]
    }

    func finishAll() {
        lock.lock()
        let streams = Array(tcpStreams.values)
        tcpStreams.removeAll()
        udpFlows.removeAll()
        let tcp = tcpContinuation
        let udp = udpContinuation
        tcpContinuation = nil
        udpContinuation = nil
        lock.unlock()
        deliverQueue.sync {
            for stream in streams {
                stream.finish()
            }
            tcp?.finish()
            udp?.finish()
        }
    }

    var consumesOnData: Bool { false }

    func write(bytes: Data, protocolFamily: UInt8) {
        _ = protocolFamily
        onOutput([bytes])
    }

    func writeBatch(_ items: [(Data, UInt8)]) {
        guard !items.isEmpty else { return }
        onOutput(items.map(\.0))
    }

    func onEstablished(flow: FlowKey) {
        lock.lock()
        if tcpStreams[flow] != nil {
            lock.unlock()
            return
        }
        guard let byteStream else {
            lock.unlock()
            return
        }
        let stream = TUNTCPStream(
            endpoint: Self.destination(flow: flow, fakeIP: fakeIP),
            flow: flow,
            byteStream: byteStream
        )
        tcpStreams[flow] = stream
        let continuation = tcpContinuation
        lock.unlock()
        deliverQueue.async {
            continuation?.yield(stream)
        }
    }

    func onData(flow: FlowKey, data: Data) {
        lock.lock()
        let stream = tcpStreams[flow]
        lock.unlock()
        guard let stream else { return }
        deliverQueue.async {
            stream.ingest(data)
        }
    }

    func onClosed(flow: FlowKey) {
        lock.lock()
        let stream = tcpStreams.removeValue(forKey: flow)
        lock.unlock()
        guard let stream else { return }
        deliverQueue.async {
            stream.finish()
        }
    }

    func onDatagram(flow: FlowKey, payload: Data) {
        if case .v4(let client) = flow.src.kind {
            let key = UDPReplyKey(client: client, clientPort: flow.srcPort, destPort: flow.dstPort)
            lock.lock()
            udpFlows[key] = flow
            lock.unlock()
        }
        lock.lock()
        let continuation = udpContinuation
        lock.unlock()
        continuation?.yield(
            TUNUDPDatagram(
                destination: Self.destination(flow: flow, fakeIP: fakeIP),
                source: Self.source(flow: flow),
                payload: payload
            )
        )
    }

    static func destination(flow: FlowKey, fakeIP: FakeIPAllocator?) -> Endpoint {
        endpoint(address: flow.dst, port: flow.dstPort, fakeIP: fakeIP)
    }

    static func source(flow: FlowKey) -> Endpoint {
        endpoint(address: flow.src, port: flow.srcPort, fakeIP: nil)
    }

    static func endpoint(address: IPAddress, port: UInt16, fakeIP: FakeIPAllocator?) -> Endpoint {
        switch address.kind {
        case .v4(let raw):
            let ipv4 = IPv4Address(rawValue: raw)
            if let fakeIP, let domain = fakeIP.domain(for: ipv4) {
                return Endpoint(domain: domain, port: port)
            }
            return Endpoint(host: .ipv4(ipv4), port: port)
        case .v6(let high, let low):
            return Endpoint(host: .ipv6(IPv6Address(high: high, low: low)), port: port)
        }
    }
}
