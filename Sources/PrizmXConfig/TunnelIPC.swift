import Foundation
import PrizmXCore

/// Versioned JSON IPC between the host app and the tunnel extensions
/// (`NEPacketTunnelProvider` / `NETransparentProxyProvider`).
///
/// The contract lives in Foundation so both sides — the app (via Kit) and
/// the network extensions — encode/decode the same types. Providers must not
/// answer with ad-hoc dictionaries.
public enum TunnelIPC: Sendable {
    public static let protocolVersion = 1

    public enum Method: String, Sendable, Codable {
        case fetchMetrics
        case selectNode
    }

    public struct Request: Sendable, Codable, Equatable {
        public var version: Int
        public var method: Method
        public var nodeID: String?
        public var groupName: String?

        public init(
            method: Method,
            nodeID: String? = nil,
            groupName: String? = nil,
            version: Int = TunnelIPC.protocolVersion
        ) {
            self.version = version
            self.method = method
            self.nodeID = nodeID
            self.groupName = groupName
        }
    }

    public struct Response: Sendable, Codable, Equatable {
        public var version: Int
        public var ok: Bool
        public var metrics: TrafficSnapshot?
        public var error: String?

        public init(
            ok: Bool,
            metrics: TrafficSnapshot? = nil,
            error: String? = nil,
            version: Int = TunnelIPC.protocolVersion
        ) {
            self.version = version
            self.ok = ok
            self.metrics = metrics
            self.error = error
        }

        public static func success(metrics: TrafficSnapshot? = nil) -> Response {
            Response(ok: true, metrics: metrics)
        }

        public static func failure(_ message: String) -> Response {
            Response(ok: false, error: message)
        }
    }

    public static func encode(_ request: Request) throws -> Data {
        try JSONEncoder().encode(request)
    }

    public static func encode(_ response: Response) throws -> Data {
        try JSONEncoder().encode(response)
    }

    public static func decodeRequest(from data: Data) throws -> Request {
        try JSONDecoder().decode(Request.self, from: data)
    }

    public static func decodeResponse(from data: Data?) throws -> Response {
        guard let data, !data.isEmpty else {
            throw TunnelIPCError.ipcFailed("empty provider response")
        }
        do {
            return try JSONDecoder().decode(Response.self, from: data)
        } catch {
            throw TunnelIPCError.ipcFailed("unrecognized provider payload")
        }
    }

    public static func metrics(from data: Data?) throws -> TrafficSnapshot {
        let response = try decodeResponse(from: data)
        if let metrics = response.metrics {
            return metrics
        }
        if response.ok {
            return TrafficSnapshot()
        }
        throw TunnelIPCError.ipcFailed(response.error ?? "provider error")
    }
}

/// Failures while exchanging `TunnelIPC` messages with a provider.
public enum TunnelIPCError: Error, Sendable, Equatable {
    case ipcFailed(String)
}
