import Foundation
import Network

/// Network.framework TLS on a proxy's TCP connection (TLS 1.2 / 1.3).
public struct TLSSettings: Sendable, Hashable {
    /// SNI and verification name; `nil` falls back to the server domain.
    public var serverName: String?
    /// Clash `skip-cert-verify`: accept any server certificate.
    public var skipCertVerify: Bool
    /// Offered ALPN; `nil` lets the transport pick (`http/1.1` for
    /// WebSocket, `h2` for gRPC, none for raw TCP).
    public var alpn: [String]?

    public init(serverName: String? = nil, skipCertVerify: Bool = false, alpn: [String]? = nil) {
        self.serverName = serverName
        self.skipCertVerify = skipCertVerify
        self.alpn = alpn
    }
}

/// The framing a proxy protocol's bytes ride on, above TCP / TLS.
public enum StreamTransport: Sendable, Hashable {
    /// The protocol owns the TCP (or TLS) stream directly.
    case tcp
    /// RFC 6455 WebSocket binary frames.
    case webSocket(WebSocketSettings)
    /// HTTP upgrade handshake, then the raw stream.
    case httpUpgrade(HTTPUpgradeSettings)
    /// gRPC "gun" stream over HTTP/2 (h2 over TLS, h2c without).
    case grpc(GRPCSettings)

    /// Short name for logs and labels (`ws`, `httpupgrade`, …).
    public var name: String {
        switch self {
        case .tcp: "tcp"
        case .webSocket: "ws"
        case .httpUpgrade: "httpupgrade"
        case .grpc: "grpc"
        }
    }
}

/// How a proxy protocol reaches its server: TCP, optional TLS, then the
/// transport framing. The protocol's own handshake runs on top.
public struct StreamSettings: Sendable, Hashable {
    public var tls: TLSSettings?
    public var transport: StreamTransport

    public init(tls: TLSSettings? = nil, transport: StreamTransport = .tcp) {
        self.tls = tls
        self.transport = transport
    }

    /// ALPN offered in the TLS ClientHello.
    var effectiveALPN: [String]? {
        let configured = tls?.alpn ?? []
        switch transport {
        case .tcp:
            return configured.isEmpty ? nil : configured
        case .webSocket, .httpUpgrade:
            // The upgrade is HTTP/1.1; negotiating h2 would break it.
            let usable = configured.filter { $0 != "h2" }
            return usable.isEmpty ? ["http/1.1"] : usable
        case .grpc:
            return ["h2"]
        }
    }

    /// `Host` for HTTP-based transports: explicit host, else the TLS server
    /// name, else the server address.
    func httpHost(explicit: String?, server: Endpoint) -> String {
        if let explicit, !explicit.isEmpty { return explicit }
        if let name = tls?.serverName, !name.isEmpty { return name }
        switch server.host {
        case .domain(let domain): return domain
        case .ipv4(let address): return address.description
        case .ipv6(let address): return "[\(address)]"
        }
    }
}

/// A bidirectional byte stream under a proxy protocol: the raw connection,
/// or a framing stacked on it (WebSocket, gRPC, obfs).
///
/// `send` calls are serialized by the caller, as are `receive` calls; the
/// two directions run concurrently.
protocol ByteStream: AnyObject, Sendable {
    func send(_ data: Data) async throws
    /// Next chunk; `nil` at a clean end of stream.
    func receive() async throws -> Data?
    /// No more sends follow. Signals end-of-stream when the framing can do
    /// so without tearing down the downlink (TCP FIN); otherwise a no-op, and
    /// the relay's linger bound ends the flow. WebSocket, mux.cool and
    /// simple-obfs servers close both directions on an uplink end, so those
    /// layers send nothing.
    func finishWriting() async
}

extension NWStreamTransport {
    /// Dials `server` per `settings`: TCP, Network.framework TLS, then the
    /// transport handshake (installed as the transport's framing layer).
    /// The caller runs its protocol handshake next, then `markEstablished()`;
    /// on any failure here the transport is already closed.
    func dial(_ server: Endpoint, settings: StreamSettings) async throws {
        guard server.port > 0, let nwPort = NWEndpoint.Port(rawValue: server.port) else {
            throw OutboundError.invalidEndpoint(server)
        }
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.enableKeepalive = true
        tcp.keepaliveIdle = 20
        tcp.keepaliveInterval = 5
        tcp.keepaliveCount = 4
        tcp.connectionTimeout = 8
        var tlsOptions: NWProtocolTLS.Options?
        if let tls = settings.tls {
            tlsOptions = TLSClient.options(
                serverName: TLSClient.resolvedServerName(explicit: tls.serverName, server: server),
                skipVerification: tls.skipCertVerify,
                alpn: settings.effectiveALPN
            )
        }
        let parameters = NWParameters(tls: tlsOptions, tcp: tcp)
        parameters.preferNoProxies = true

        let host = try await DNSClient.resolve(server.host, role: .proxyServer)
        let nw = NWConnection(host: host, port: nwPort, using: parameters)
        attach(nw)
        do {
            try await waitUntilReady(nw)
            switch settings.transport {
            case .tcp:
                break
            case .webSocket(let options):
                let layer = WebSocketStream(
                    lower: socketStream,
                    settings: options,
                    host: settings.httpHost(explicit: options.host, server: server)
                )
                try await layer.connect()
                install(layer)
            case .httpUpgrade(let options):
                let layer = HTTPUpgradeStream(lower: socketStream)
                try await layer.connect(
                    settings: options,
                    host: settings.httpHost(explicit: options.host, server: server)
                )
                install(layer)
            case .grpc(let options):
                let layer = GRPCStream(lower: socketStream)
                try await layer.connect(
                    settings: options,
                    authority: settings.httpHost(explicit: nil, server: server),
                    tls: settings.tls != nil
                )
                install(layer)
            }
        } catch {
            failOpen(nw)
            throw error
        }
    }
}
