import Foundation
import os
import PrizmXCore
import PrizmXProtocols
import PrizmXRules
import SwiftTCP

public struct TUNStreamError: Error, Sendable, Equatable {
    public static let closed = TUNStreamError()
}

/// Bidirectional byte stream for one SwiftTCP TCP flow.
/// Conforms to `InboundStream` so `EngineTCPRelay` splices it.
public final class TUNTCPStream: InboundStream, @unchecked Sendable {
    public let endpoint: Endpoint
    let flow: FlowKey
    private let byteStream: any TCPByteStream
    private let lock = NSLock()
    private var buffer = Data()
    private var waiter: CheckedContinuation<Data?, Never>?
    private var closed = false

    init(endpoint: Endpoint, flow: FlowKey, byteStream: any TCPByteStream) {
        self.endpoint = endpoint
        self.flow = flow
        self.byteStream = byteStream
    }

    public func read() async -> Data? {
        await withCheckedContinuation { continuation in
            takeForRead(continuation)
        }
    }

    public func write(_ data: Data) async throws {
        guard !data.isEmpty else { return }
        var offset = 0
        while offset < data.count {
            let slice = data.subdata(in: offset..<data.count)
            let written = await byteStream.send(flow: flow, data: slice)
            if written <= 0 {
                throw TUNStreamError.closed
            }
            offset += written
        }
    }

    public func close() async {
        await byteStream.close(flow: flow)
    }

    func ingest(_ data: Data) {
        lock.lock()
        if let waiter {
            self.waiter = nil
            lock.unlock()
            waiter.resume(returning: data)
            creditAppReceive(data.count)
            return
        }
        buffer.append(data)
        lock.unlock()
    }

    func finish() {
        lock.lock()
        closed = true
        let waiter = self.waiter
        self.waiter = nil
        lock.unlock()
        waiter?.resume(returning: nil)
    }

    private func takeForRead(_ continuation: CheckedContinuation<Data?, Never>) {
        lock.lock()
        if !buffer.isEmpty {
            let data = buffer
            buffer.removeAll(keepingCapacity: true)
            lock.unlock()
            creditAppReceive(data.count)
            continuation.resume(returning: data)
            return
        }
        if closed {
            lock.unlock()
            continuation.resume(returning: nil)
            return
        }
        waiter = continuation
        lock.unlock()
    }

    private func creditAppReceive(_ bytes: Int) {
        guard bytes > 0 else { return }
        let flow = self.flow
        let stream = byteStream
        Task {
            await stream.creditAppReceive(flow: flow, bytes: bytes)
        }
    }
}

/// Reassembled UDP datagram from the TUN (destination is the original remote).
public struct TUNUDPDatagram: Sendable {
    public let destination: Endpoint
    public let source: Endpoint
    public let payload: Data
}

/// Swift façade over SwiftTCP. FakeIP DNS is intercepted here; everything else
/// is demuxed by `SwiftStack` (TCP / UDP / ICMP).
public actor TUNStack {
    public let fakeIP: FakeIPAllocator?
    private let mailbox: TUNMailbox
    private let fakeIPFilter: [String]
    private let dns: DNSClient?
    /// Clash-style FakeDNS split: Direct/REJECT → real/NODATA; proxy → FakeIP.
    private let dnsPolicy: (@Sendable (String) async -> Policy)?
    /// Clash `dns.ipv6`: FakeIPv6 pool + pass IPv6 into SwiftTCP.
    private let ipv6Enabled: Bool
    private var stack: SwiftStack?
    private var started = false
    private var pendingIngest: [Data] = []
    private var drainingIngest = false

    public init(
        fakeIP: FakeIPAllocator?,
        fakeIPFilter: [String] = [],
        dns: DNSClient? = nil,
        dnsPolicy: (@Sendable (String) async -> Policy)? = nil,
        ipv6: Bool = false,
        onOutput: @escaping @Sendable ([Data]) -> Void
    ) {
        self.fakeIP = fakeIP
        self.fakeIPFilter = fakeIPFilter
        self.dns = dns
        self.dnsPolicy = dnsPolicy
        self.ipv6Enabled = ipv6
        self.mailbox = TUNMailbox(fakeIP: fakeIP, onOutput: onOutput)
    }

    public func start() {
        guard !started else { return }
        started = true
        let tcp = TCPStackConfig(
            loopCount: max(1, min(2, ProcessInfo.processInfo.activeProcessorCount)),
            receiveWindow: MemoryWatchdog.maxBufferPerSession,
            maxConnections: MemoryWatchdog.maxTCPSessions
        )
        let config = SwiftStackConfig(
            tcp: tcp,
            udpMaxSessions: MemoryWatchdog.maxUDPSessions
        )
        let swift = SwiftStack(
            config: config,
            sink: mailbox,
            streams: mailbox,
            datagrams: mailbox
        )
        mailbox.attach(byteStream: swift)
        stack = swift
    }

    public func stop() async {
        mailbox.finishAll()
        await stack?.shutdown()
        stack = nil
        started = false
    }

    /// Async sequence of accepted TCP connections (already reassembled).
    public func tcpConnections() -> AsyncStream<TUNTCPStream> {
        let stream = AsyncStream.makeStream(of: TUNTCPStream.self)
        mailbox.setTCPContinuation(stream.continuation)
        return stream.stream
    }

    /// Async sequence of reassembled UDP datagrams (DNS :53 is intercepted earlier).
    public func udpDatagrams() -> AsyncStream<TUNUDPDatagram> {
        let stream = AsyncStream.makeStream(of: TUNUDPDatagram.self)
        mailbox.setUDPContinuation(stream.continuation)
        return stream.stream
    }

    /// ICMP port-unreachable so QUIC / HTTP3 fails immediately (TCP fallback).
    public func sendICMPPortUnreachable(
        client: IPv4Address,
        destination: IPv4Address,
        sourcePort: UInt16,
        destinationPort: UInt16
    ) {
        mailbox.write(
            bytes: ICMPReply.portUnreachable(
                client: client,
                destination: destination,
                sourcePort: sourcePort,
                destinationPort: destinationPort
            ),
            protocolFamily: AddressFamily.inet
        )
    }

    /// Send a UDP payload back toward the TUN client.
    public func sendUDP(destinationIP: UInt32, destinationPort: UInt16, sourcePort: UInt16, payload: Data) async {
        guard !payload.isEmpty else { return }
        let key = TUNMailbox.UDPReplyKey(
            client: destinationIP,
            clientPort: destinationPort,
            destPort: sourcePort
        )
        if let flow = mailbox.flow(for: key) {
            await stack?.sendDatagram(flow: flow, payload: payload)
            return
        }
        let reply = UDPDatagram(
            sourcePort: sourcePort,
            destinationPort: destinationPort,
            payload: payload
        ).encode(
            source: IPv4Address(rawValue: 0),
            destination: IPv4Address(rawValue: destinationIP)
        )
        mailbox.write(bytes: reply, protocolFamily: AddressFamily.inet)
    }

    /// Feed `packetFlow.readPackets` datagrams into SwiftTCP.
    public func input(packets: [Data]) async {
        if !started { start() }
        var forwarded: [Data] = []
        forwarded.reserveCapacity(packets.count)
        for packet in packets {
            if packet.first.map({ $0 >> 4 }) == 6 {
                if ipv6Enabled {
                    if await handleDNSIPv6IfNeeded(packet) { continue }
                    if packet.count > 6, packet[6] == 17 {
                        // No IPv6 UDP relay: fail fast (QUIC falls back to TCP)
                        // instead of letting SwiftTCP sessions hang.
                        if let reply = ICMPReply.ipv6Unreachable(original: packet) {
                            mailbox.write(bytes: reply, protocolFamily: 30)
                        }
                        continue
                    }
                    forwarded.append(packet)
                } else if let reply = ICMPReply.ipv6Unreachable(original: packet) {
                    mailbox.write(bytes: reply, protocolFamily: 30)
                }
                continue
            }
            if await handleDNSIfNeeded(packet) { continue }
            forwarded.append(packet)
        }
        guard !forwarded.isEmpty else { return }
        pendingIngest.append(contentsOf: forwarded)
        if pendingIngest.count > 512 {
            pendingIngest.removeFirst(pendingIngest.count - 512)
        }
        // FakeDNS must not wait on the TCP engine. A stuck ingest used to
        // freeze the packet pump — no DNS, no proxy, no Direct answers.
        if !drainingIngest {
            drainingIngest = true
            Task { await self.drainIngest() }
        }
    }

    private func drainIngest() async {
        while true {
            let batch = pendingIngest
            pendingIngest.removeAll(keepingCapacity: true)
            if batch.isEmpty {
                drainingIngest = false
                return
            }
            await stack?.ingestBatch(batch)
        }
    }

    /// One intercepted DNS query: wire id/question plus the UDP 4-tuple to
    /// answer back on. `client` is the TUN-side source, `server` the FakeDNS.
    private struct DNSQuery: Sendable {
        var id: UInt16
        var question: DNSMessage.Question
        var client: Endpoint
        var server: Endpoint

        var isIPv6: Bool {
            if case .ipv6 = server.host { return true }
            return false
        }
    }

    private func handleDNSIfNeeded(_ packet: Data) async -> Bool {
        guard let fakeIP, packet.count >= 28, packet[0] >> 4 == 4 else { return false }
        let ihl = Int(packet[0] & 0x0F) << 2
        guard packet[9] == 17, packet.count >= ihl + 8 else { return false }
        let destPort = UInt16(packet[ihl + 2]) << 8 | UInt16(packet[ihl + 3])
        guard destPort == 53 else { return false }
        let srcPort = UInt16(packet[ihl]) << 8 | UInt16(packet[ihl + 1])
        let payload = Data(packet[(ihl + 8)...])
        guard let parsed = DNSMessage.parseQuestion(payload) else { return false }
        let query = DNSQuery(
            id: parsed.id,
            question: parsed.question,
            client: Endpoint(
                host: .ipv4(IPv4Address(packet[12], packet[13], packet[14], packet[15])),
                port: srcPort
            ),
            server: Endpoint(
                host: .ipv4(IPv4Address(packet[16], packet[17], packet[18], packet[19])),
                port: destPort
            )
        )
        await answer(query: query, fakeIP: fakeIP)
        return true
    }

    private func handleDNSIPv6IfNeeded(_ packet: Data) async -> Bool {
        guard let fakeIP, packet.count >= 48, packet[0] >> 4 == 6, packet[6] == 17 else {
            return false
        }
        let dest = ipv6(packet, at: 24)
        guard dest == FakeIPAllocator.dns6 else { return false }
        let destPort = UInt16(packet[42]) << 8 | UInt16(packet[43])
        guard destPort == 53 else { return false }
        let srcPort = UInt16(packet[40]) << 8 | UInt16(packet[41])
        let payload = Data(packet[48...])
        guard let parsed = DNSMessage.parseQuestion(payload) else { return false }
        let query = DNSQuery(
            id: parsed.id,
            question: parsed.question,
            client: Endpoint(host: .ipv6(ipv6(packet, at: 8)), port: srcPort),
            server: Endpoint(host: .ipv6(dest), port: destPort)
        )
        await answer(query: query, fakeIP: fakeIP)
        return true
    }

    /// Clash-style FakeDNS split: DIRECT / filter → real record; proxy →
    /// FakeIP; REJECT → NODATA. AAAA only gets a real / FakeIPv6 answer when
    /// `dns.ipv6` is on; otherwise NODATA so Happy Eyeballs uses IPv4 FakeIP.
    private func answer(query: DNSQuery, fakeIP: FakeIPAllocator) async {
        let type = query.question.type
        let isA = type == 1
        let isAAAA = type == 28
        guard isA || isAAAA else {
            writeDNSReply(DNSMessage.response(id: query.id, question: query.question), to: query)
            return
        }
        // Clash fake-ip-filter: node domains / NTP / .lan always get a real record.
        let policy = await policyFor(query.question.name)
        if policy == .direct, let dns {
            if isAAAA, !ipv6Enabled {
                writeDNSReply(DNSMessage.response(id: query.id, question: query.question), to: query)
                return
            }
            replyReal(domain: query.question.name, aaaa: isAAAA, query: query, dns: dns)
            return
        }
        if policy == .reject {
            writeDNSReply(DNSMessage.response(id: query.id, question: query.question), to: query)
            return
        }
        if isA {
            let address = fakeIP.allocate(domain: query.question.name)
            writeDNSReply(
                DNSMessage.response(id: query.id, question: query.question, ipv4: address),
                to: query
            )
            return
        }
        if ipv6Enabled {
            let address = fakeIP.allocateIPv6(domain: query.question.name)
            writeDNSReply(
                DNSMessage.response(id: query.id, question: query.question, ipv6: address),
                to: query
            )
            return
        }
        writeDNSReply(DNSMessage.response(id: query.id, question: query.question), to: query)
    }

    private func policyFor(_ name: String) async -> Policy? {
        if FakeIPFilter.matches(name, patterns: fakeIPFilter) { return .direct }
        guard let dnsPolicy else { return nil }
        return await dnsPolicy(name)
    }

    /// Upstream-resolves DIRECT names off the packet path, then writes back.
    private func replyReal(domain: String, aaaa: Bool, query: DNSQuery, dns: DNSClient) {
        let mailbox = self.mailbox
        Task {
            let answer = await Self.realAnswer(domain: domain, aaaa: aaaa, query: query, dns: dns)
            let reply = Self.encode(answer, to: query)
            mailbox.write(bytes: reply, protocolFamily: query.isIPv6 ? 30 : AddressFamily.inet)
        }
    }

    private static func realAnswer(
        domain: String,
        aaaa: Bool,
        query: DNSQuery,
        dns: DNSClient
    ) async -> Data {
        if aaaa {
            let addresses = (try? await dns.resolveAAAA(domain, role: .direct)) ?? []
            return DNSMessage.response(id: query.id, question: query.question, ipv6: addresses.first)
        }
        let addresses = (try? await dns.resolveAll(domain, role: .direct)) ?? []
        return DNSMessage.response(id: query.id, question: query.question, ipv4: addresses.first)
    }

    private func writeDNSReply(_ answer: Data, to query: DNSQuery) {
        let reply = Self.encode(answer, to: query)
        mailbox.write(bytes: reply, protocolFamily: query.isIPv6 ? 30 : AddressFamily.inet)
    }

    /// UDP reply from the FakeDNS server back to the client (v4 or v6).
    private static func encode(_ answer: Data, to query: DNSQuery) -> Data {
        let datagram = UDPDatagram(
            sourcePort: query.server.port,
            destinationPort: query.client.port,
            payload: answer
        )
        switch (query.server.host, query.client.host) {
        case (.ipv4(let server), .ipv4(let client)):
            return datagram.encode(source: server, destination: client)
        case (.ipv6(let server), .ipv6(let client)):
            return datagram.encode(source: server, destination: client)
        default:
            return Data()
        }
    }

    private func ipv6(_ packet: Data, at offset: Int) -> IPv6Address {
        func word(_ index: Int) -> UInt64 {
            var value: UInt64 = 0
            for byte in 0..<8 {
                value = (value << 8) | UInt64(packet[offset + index + byte])
            }
            return value
        }
        return IPv6Address(high: word(0), low: word(8))
    }
}
