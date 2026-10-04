import Foundation
import Security

enum InteropHTTPError: Error, CustomStringConvertible {
    case status(Int, String)
    case mismatch(offset: Int)
    case shortBody(expected: Int, actual: Int)
    case badReply(String)

    var description: String {
        switch self {
        case .status(let code, let body): "HTTP \(code): \(body)"
        case .mismatch(let offset): "payload mismatch at byte \(offset)"
        case .shortBody(let expected, let actual): "body \(actual) of \(expected) bytes"
        case .badReply(let text): "unexpected reply: \(text)"
        }
    }
}

/// What one HTTP exchange measured.
struct TransferSample: Sendable {
    var bytes: Int
    var duration: Duration
    /// Request start to first response byte.
    var firstByte: Duration?
}

/// A real HTTP client (URLSession) whose traffic goes through one HTTP
/// proxy port: PrizmX's mixed-port or mihomo's. `https://web.test` is
/// trusted through the interop test CA only.
final class ProxyHTTPClient: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private var session: URLSession!
    private let anchors: [SecCertificate]

    init(proxyPort: UInt16, maxConnections: Int = 8, timeout: TimeInterval = 20) {
        anchors = Self.loadCA()
        super.init()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [
            "HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": Int(proxyPort),
            "HTTPSEnable": 1, "HTTPSProxy": "127.0.0.1", "HTTPSPort": Int(proxyPort),
        ]
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpMaximumConnectionsPerHost = maxConnections
        configuration.timeoutIntervalForRequest = timeout
        session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    }

    func invalidate() {
        session.invalidateAndCancel()
    }

    // MARK: Requests

    /// `GET /bytes?n=&seed=` over http or https, verified while streaming.
    func download(bytes count: Int, seed: UInt64, tls: Bool = false) async throws -> TransferSample {
        let scheme = tls ? "https" : "http"
        let url = URL(string: "\(scheme)://\(InteropEnvironment.webHost)/bytes?n=\(count)&seed=\(seed)")!
        let verifier = StreamingVerifier(expected: count, seed: seed)
        let start = ContinuousClock.now
        try await verifier.run(session.dataTask(with: url), client: self)
        return TransferSample(bytes: count, duration: ContinuousClock.now - start, firstByte: verifier.firstByte(since: start))
    }

    /// `POST /upload?seed=`: the target checks the body byte by byte.
    func upload(bytes count: Int, seed: UInt64) async throws -> TransferSample {
        var pattern = PayloadPattern(seed: seed)
        var request = URLRequest(url: URL(string: "http://\(InteropEnvironment.webHost)/upload?seed=\(seed)")!)
        request.httpMethod = "POST"
        let start = ContinuousClock.now
        let (data, response) = try await session.upload(for: request, from: pattern.next(count))
        let text = String(decoding: data, as: UTF8.self)
        try Self.check(response, body: text)
        guard text == "ok \(count)" else { throw InteropHTTPError.badReply(text) }
        return TransferSample(bytes: count, duration: ContinuousClock.now - start)
    }

    /// `GET /ping` round trip (request latency, small payload).
    func ping() async throws -> TransferSample {
        let start = ContinuousClock.now
        let (data, response) = try await session.data(from: URL(string: "http://\(InteropEnvironment.webHost)/ping")!)
        let text = String(decoding: data, as: UTF8.self)
        try Self.check(response, body: text)
        guard text == "pong" else { throw InteropHTTPError.badReply(text) }
        return TransferSample(bytes: data.count, duration: ContinuousClock.now - start)
    }

    static func check(_ response: URLResponse, body: String) throws {
        guard let http = response as? HTTPURLResponse else { throw InteropHTTPError.badReply("not HTTP") }
        guard http.statusCode == 200 else { throw InteropHTTPError.status(http.statusCode, body) }
    }

    // MARK: Delegate

    private let verifiers = NSLock()
    private var byTask: [Int: StreamingVerifier] = [:]

    fileprivate func register(_ verifier: StreamingVerifier, for task: URLSessionTask) {
        verifiers.lock(); byTask[task.taskIdentifier] = verifier; verifiers.unlock()
    }

    private func verifier(for task: URLSessionTask, remove: Bool = false) -> StreamingVerifier? {
        verifiers.lock(); defer { verifiers.unlock() }
        return remove ? byTask.removeValue(forKey: task.taskIdentifier) : byTask[task.taskIdentifier]
    }

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        verifier(for: dataTask)?.receive(response)
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        verifier(for: dataTask)?.feed(data)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        verifier(for: task, remove: true)?.finish(error)
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust
        else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        SecTrustSetAnchorCertificates(trust, anchors as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        if SecTrustEvaluateWithError(trust, nil) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    /// `Interop/certs/ca.crt` (generated by run.sh).
    private static func loadCA() -> [SecCertificate] {
        let url = InteropEnvironment.directory.appendingPathComponent("certs/ca.crt")
        guard let pem = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        let body = pem.components(separatedBy: "\n").filter { !$0.hasPrefix("-----") }.joined()
        guard let der = Data(base64Encoded: body),
              let certificate = SecCertificateCreateWithData(nil, der as CFData)
        else { return [] }
        return [certificate]
    }
}

/// Checks one download against the pattern as chunks arrive.
private final class StreamingVerifier: @unchecked Sendable {
    private let lock = NSLock()
    private var pattern: PayloadPattern
    private let expected: Int
    private var received = 0
    private var failure: Error?
    private var firstByteAt: ContinuousClock.Instant?
    private var continuation: CheckedContinuation<Void, Error>?

    init(expected: Int, seed: UInt64) {
        self.expected = expected
        self.pattern = PayloadPattern(seed: seed)
    }

    func run(_ task: URLSessionDataTask, client: ProxyHTTPClient) async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                lock.lock(); self.continuation = continuation; lock.unlock()
                client.register(self, for: task)
                task.resume()
            }
        } onCancel: {
            task.cancel()
        }
    }

    func receive(_ response: URLResponse) {
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        lock.lock(); defer { lock.unlock() }
        if code != 200, failure == nil { failure = InteropHTTPError.status(code, "") }
    }

    func feed(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        if firstByteAt == nil { firstByteAt = .now }
        guard failure == nil else { return }
        if let offset = pattern.firstMismatch(in: data) {
            failure = InteropHTTPError.mismatch(offset: received + offset)
        }
        received += data.count
    }

    func finish(_ error: Error?) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        var outcome = failure ?? error
        if outcome == nil, received != expected {
            outcome = InteropHTTPError.shortBody(expected: expected, actual: received)
        }
        lock.unlock()
        if let outcome {
            continuation?.resume(throwing: outcome)
        } else {
            continuation?.resume()
        }
    }

    func firstByte(since start: ContinuousClock.Instant) -> Duration? {
        lock.lock(); defer { lock.unlock() }
        return firstByteAt.map { $0 - start }
    }
}
