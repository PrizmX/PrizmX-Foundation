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
    private let dnsPolicy: (@Sendable (String) -> Policy)?
    private var stack: SwiftStack?
    private var started = false
    private var pendingIngest: [Data] = []
    private var drainingIngest = false

    public init(
        fakeIP: FakeIPAllocator?,
        fakeIPFilter: [String] = [],
        dns: DNSClient? = nil,
        dnsPolicy: (@Sendable (String) -> Policy)? = nil,
        onOutput: @escaping @Sendable ([Data]) -> Void
    ) {
        self.fakeIP = fakeIP
        self.fakeIPFilter = fakeIPFilter
        self.dns = dns
        self.dnsPolicy = dnsPolicy
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
                if let reply = ICMPReply.ipv6Unreachable(original: packet) {
                    mailbox.write(bytes: reply, protocolFamily: 30)
                }
                continue
            }
            if handleDNSIfNeeded(packet) { continue }
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

    private func handleDNSIfNeeded(_ packet: Data) -> Bool {
        guard let fakeIP, packet.count >= 28, packet[0] >> 4 == 4 else { return false }
        let ihl = Int(packet[0] & 0x0F) << 2
        guard packet[9] == 17, packet.count >= ihl + 8 else { return false }
        let destPort = UInt16(packet[ihl + 2]) << 8 | UInt16(packet[ihl + 3])
        guard destPort == 53 else { return false }
        let srcPort = UInt16(packet[ihl]) << 8 | UInt16(packet[ihl + 1])
        let payload = Data(packet[(ihl + 8)...])
        guard let parsed = DNSMessage.parseQuestion(payload) else { return false }
        let src = IPv4Address(packet[12], packet[13], packet[14], packet[15])
        let dest = IPv4Address(packet[16], packet[17], packet[18], packet[19])
        let question = parsed.question
        let queryID = parsed.id
        let wantsA = question.type == 1
        // Clash fake-ip-filter: node domains / NTP / .lan always get a real A.
        let filtered = wantsA && FakeIPFilter.matches(question.name, patterns: fakeIPFilter)
        let policy = filtered ? Policy.direct : dnsPolicy?(question.name)
        if wantsA, policy == .direct, let dns {
            replyRealA(
                domain: question.name,
                queryID: queryID,
                question: question,
                srcPort: srcPort,
                destPort: destPort,
                src: src,
                dest: dest,
                dns: dns
            )
            return true
        }
        if policy == .reject {
            let answer = DNSMessage.response(id: queryID, question: question, ipv4: nil)
            writeDNSReply(answer, srcPort: srcPort, destPort: destPort, src: src, dest: dest)
            return true
        }
        let address: IPv4Address? = wantsA ? fakeIP.allocate(domain: question.name) : nil
        let answer = DNSMessage.response(id: queryID, question: question, ipv4: address)
        writeDNSReply(answer, srcPort: srcPort, destPort: destPort, src: src, dest: dest)
        return true
    }

    private func replyRealA(
        domain: String,
        queryID: UInt16,
        question: DNSMessage.Question,
        srcPort: UInt16,
        destPort: UInt16,
        src: IPv4Address,
        dest: IPv4Address,
        dns: DNSClient
    ) {
        let mailbox = self.mailbox
        Task {
            let addresses = (try? await dns.resolveAll(domain, role: .direct)) ?? []
            let answer = DNSMessage.response(id: queryID, question: question, ipv4: addresses.first)
            let reply = UDPDatagram(
                sourcePort: destPort,
                destinationPort: srcPort,
                payload: answer
            ).encode(source: dest, destination: src)
            mailbox.write(bytes: reply, protocolFamily: AddressFamily.inet)
        }
    }

    private func writeDNSReply(
        _ answer: Data,
        srcPort: UInt16,
        destPort: UInt16,
        src: IPv4Address,
        dest: IPv4Address
    ) {
        let reply = UDPDatagram(
            sourcePort: destPort,
            destinationPort: srcPort,
            payload: answer
        ).encode(source: dest, destination: src)
        mailbox.write(bytes: reply, protocolFamily: AddressFamily.inet)
    }
}
