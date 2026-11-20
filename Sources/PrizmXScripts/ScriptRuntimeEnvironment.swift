import Foundation
import os

/// Outbound HTTP request built from JS `$httpClient.{get,post,put,delete,head}`.
public struct ScriptHTTPRequest: Sendable, Equatable {
    public var method: String
    public var url: URL
    public var headers: [String: String]
    public var body: Data?
    public var timeout: TimeInterval

    public init(
        method: String,
        url: URL,
        headers: [String: String] = [:],
        body: Data? = nil,
        timeout: TimeInterval = 10
    ) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
        self.timeout = timeout
    }
}

/// Outbound HTTP response passed back to JS `callback(error, response, body)`.
public struct ScriptHTTPResponse: Sendable, Equatable {
    public var status: Int
    public var headers: [String: String]
    public var body: String

    public init(status: Int, headers: [String: String] = [:], body: String = "") {
        self.status = status
        self.headers = headers
        self.body = body
    }
}

public typealias ScriptHTTPHandler = @Sendable (ScriptHTTPRequest) async throws -> ScriptHTTPResponse
public typealias ScriptNotificationHandler = @Sendable (_ title: String, _ subtitle: String, _ body: String) -> Void

/// Key-value storage backing JS `$persistentStore.read` / `$persistentStore.write`.
public protocol ScriptPersistentStorage: Sendable {
    func read(key: String) -> String?
    @discardableResult
    func write(_ value: String?, forKey key: String) -> Bool
}

/// In-memory store for tests and isolated script evaluations.
public final class InMemoryScriptPersistentStore: ScriptPersistentStorage, @unchecked Sendable {
    private let values = OSAllocatedUnfairLock(initialState: [String: String]())

    public init(initial: [String: String] = [:]) {
        values.withLock { $0 = initial }
    }

    public func read(key: String) -> String? {
        values.withLock { $0[key] }
    }

    @discardableResult
    public func write(_ value: String?, forKey key: String) -> Bool {
        values.withLock { store in
            if let value {
                store[key] = value
            } else {
                store.removeValue(forKey: key)
            }
        }
        return true
    }
}

/// Atomic JSON file-backed store backing `$persistentStore` across launches.
public final class FileScriptPersistentStore: ScriptPersistentStorage, @unchecked Sendable {
    private let fileURL: URL
    private let state: OSAllocatedUnfairLock<[String: String]>

    public init(fileURL: URL) {
        self.fileURL = fileURL
        let loaded: [String: String]
        if let data = try? Data(contentsOf: fileURL),
           let decoded = try? JSONDecoder().decode([String: String].self, from: data) {
            loaded = decoded
        } else {
            loaded = [:]
        }
        self.state = OSAllocatedUnfairLock(initialState: loaded)
    }

    public func read(key: String) -> String? {
        state.withLock { $0[key] }
    }

    @discardableResult
    public func write(_ value: String?, forKey key: String) -> Bool {
        let snapshot: [String: String] = state.withLock { map in
            if let value {
                map[key] = value
            } else {
                map.removeValue(forKey: key)
            }
            return map
        }
        do {
            try FileManager.default.createDirectory(
                at: fileURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try encoder.encode(snapshot).write(to: fileURL, options: .atomic)
            return true
        } catch {
            return false
        }
    }
}

/// Read-only network snapshot exposed as JS `$network`.
public struct ScriptNetworkInfo: Sendable, Equatable {
    public var v4PrimaryAddress: String?
    public var v4PrimaryInterface: String?
    public var wifiSSID: String?

    public init(
        v4PrimaryAddress: String? = nil,
        v4PrimaryInterface: String? = nil,
        wifiSSID: String? = nil
    ) {
        self.v4PrimaryAddress = v4PrimaryAddress
        self.v4PrimaryInterface = v4PrimaryInterface
        self.wifiSSID = wifiSSID
    }
}

/// Host capabilities injected into `ScriptEngine`.
public struct ScriptEnvironmentContext: Sendable {
    public var httpClient: ScriptHTTPHandler
    public var persistentStore: any ScriptPersistentStorage
    public var notificationHandler: ScriptNotificationHandler?
    public var network: ScriptNetworkInfo
    public var version: String

    public init(
        httpClient: @escaping ScriptHTTPHandler = ScriptEnvironmentContext.defaultHTTPClient,
        persistentStore: any ScriptPersistentStorage = InMemoryScriptPersistentStore(),
        notificationHandler: ScriptNotificationHandler? = nil,
        network: ScriptNetworkInfo = ScriptNetworkInfo(),
        version: String = "1.0"
    ) {
        self.httpClient = httpClient
        self.persistentStore = persistentStore
        self.notificationHandler = notificationHandler
        self.network = network
        self.version = version
    }

    public static let `default` = ScriptEnvironmentContext()

    /// Ephemeral URLSession client (no keep-alive reuse across proxy switches).
    public static let defaultHTTPClient: ScriptHTTPHandler = { request in
        let config = URLSessionConfiguration.ephemeral
        let timeout = request.timeout.isFinite ? min(max(request.timeout, 1), 60) : 10
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout
        let session = URLSession(configuration: config)
        defer { session.finishTasksAndInvalidate() }

        var urlRequest = URLRequest(url: request.url, timeoutInterval: timeout)
        urlRequest.httpMethod = request.method
        for (header, value) in request.headers {
            urlRequest.setValue(value, forHTTPHeaderField: header)
        }
        urlRequest.httpBody = request.body

        let (data, response) = try await session.data(for: urlRequest)
        guard let http = response as? HTTPURLResponse else {
            return ScriptHTTPResponse(status: 0, headers: [:], body: String(decoding: data, as: UTF8.self))
        }
        var headers: [String: String] = [:]
        for (key, value) in http.allHeaderFields {
            headers[String(describing: key)] = String(describing: value)
        }
        return ScriptHTTPResponse(
            status: http.statusCode,
            headers: headers,
            body: String(decoding: data, as: UTF8.self)
        )
    }
}
