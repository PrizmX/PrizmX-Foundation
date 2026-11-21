import Foundation
import JavaScriptCore
import os

/// Failures from `ScriptEngine.evaluate`.
public enum ScriptError: Error, Equatable, Sendable, LocalizedError {
    case emptySource
    case exception(String)
    case timeout

    public var errorDescription: String? {
        switch self {
        case .emptySource:
            "Script source is empty."
        case .exception(let message):
            message
        case .timeout:
            "Script timed out."
        }
    }
}

/// One evaluation of a JavaScript source string.
public struct ScriptRequest: Sendable, Hashable {
    public var name: String
    public var source: String
    /// Injected as `$argument` when non-nil.
    public var argument: String?
    public var timeout: TimeInterval
    /// Optional per-run environment override (e.g. fresh `$network` snapshot).
    public var environment: ScriptEnvironmentContext?

    public init(
        name: String = "script",
        source: String,
        argument: String? = nil,
        timeout: TimeInterval = ScriptEngine.defaultTimeout,
        environment: ScriptEnvironmentContext? = nil
    ) {
        self.name = name
        self.source = source
        self.argument = argument
        self.timeout = timeout
        self.environment = environment
    }

    public static func == (lhs: ScriptRequest, rhs: ScriptRequest) -> Bool {
        lhs.name == rhs.name
            && lhs.source == rhs.source
            && lhs.argument == rhs.argument
            && lhs.timeout == rhs.timeout
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(name)
        hasher.combine(source)
        hasher.combine(argument)
        hasher.combine(timeout)
    }
}

/// Result of a finished evaluation.
public struct ScriptResult: Sendable, Hashable {
    public var value: ScriptValue
    public var logs: [String]

    public init(value: ScriptValue, logs: [String] = []) {
        self.value = value
        self.logs = logs
    }
}

/// Apple JavaScriptCore runtime used by Scripts.
///
/// Same engine family as Surge `engine=jsc`, Quantumult X, Loon, and Stash:
/// a fresh `JSVirtualMachine` + serial queue + context per run (`JSContext`
/// is not thread-safe), and `$done` to finish async work.
///
/// `$httpClient` / MITM hooks are not installed yet. `timeout` covers waits
/// for `$done` and timers. It cannot interrupt a synchronous infinite loop
/// (JavaScriptCore has no public watchdog); such a run keeps its own queue
/// busy, but the caller still gets `.timeout` and other runs are unaffected.
public final class ScriptEngine: @unchecked Sendable {
    public static let defaultTimeout: TimeInterval = 5
    /// Upper bound for one `setTimeout` delay.
    public static let maxTimerDelay: TimeInterval = 60

    public let environment: ScriptEnvironmentContext
    private let sessions = OSAllocatedUnfairLock(initialState: [ObjectIdentifier: Session]())

    public init(environment: ScriptEnvironmentContext = .default) {
        self.environment = environment
    }

    public func evaluate(source: String, name: String = "script") async throws -> ScriptResult {
        try await evaluate(ScriptRequest(name: name, source: source))
    }

    public func evaluate(_ request: ScriptRequest) async throws -> ScriptResult {
        let source = request.source.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !source.isEmpty else { throw ScriptError.emptySource }

        let state = RunState()
        // Each run gets its own queue and VM: contexts sharing a VM share its
        // lock, so a stuck script would otherwise block every later run.
        let queue = DispatchQueue(label: "prizmx.script.run")
        return try await withCheckedThrowingContinuation { continuation in
            state.bind(continuation)
            // Armed before the run starts so it fires even if the queue never
            // gets to run anything else.
            let timeout = request.timeout.isFinite ? max(request.timeout, 0.05) : Self.defaultTimeout
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout) {
                state.finish(.failure(ScriptError.timeout))
            }
            queue.async {
                self.begin(request, source: source, state: state, queue: queue)
            }
        }
    }

    private func begin(_ request: ScriptRequest, source: String, state: RunState, queue: DispatchQueue) {
        guard !state.isFinished else { return }
        guard let vm = JSVirtualMachine(), let context = JSContext(virtualMachine: vm) else {
            state.finish(.failure(ScriptError.exception("JavaScriptCore is unavailable.")))
            return
        }

        let session = Session(
            request: request,
            environment: request.environment ?? environment,
            source: source,
            context: context,
            queue: queue,
            state: state,
            engine: self
        )
        sessions.withLock { $0[ObjectIdentifier(session)] = session }
        state.onFinish { [weak session] in
            // Timers must not outlive the run (they retain JS values).
            queue.async { [weak session] in session?.teardown() }
        }
        session.install()
        session.evaluate()
    }

    fileprivate func drop(_ session: Session) {
        sessions.withLock { $0[ObjectIdentifier(session)] = nil }
    }
}

// MARK: - Session

private final class RunState: @unchecked Sendable {
    private struct Storage {
        var continuation: CheckedContinuation<ScriptResult, Error>?
        var pending: Result<ScriptResult, Error>?
        var resumed = false
        var finished = false
        var onFinish: (@Sendable () -> Void)?
    }

    private let storage = OSAllocatedUnfairLock(initialState: Storage())

    var isFinished: Bool {
        storage.withLock { $0.finished }
    }

    /// Runs `handler` once the run finishes (immediately if it already has).
    func onFinish(_ handler: @escaping @Sendable () -> Void) {
        let runNow = storage.withLock { box -> Bool in
            if box.finished { return true }
            box.onFinish = handler
            return false
        }
        if runNow { handler() }
    }

    func bind(_ continuation: CheckedContinuation<ScriptResult, Error>) {
        let pending: Result<ScriptResult, Error>? = storage.withLock { box in
            let none: Result<ScriptResult, Error>? = nil
            if let pending = box.pending {
                box.resumed = true
                box.pending = nil
                return pending
            }
            box.continuation = continuation
            return none
        }
        if let pending {
            continuation.resume(with: pending)
        }
    }

    func finish(_ result: Result<ScriptResult, Error>) {
        let (continuation, handler) = storage.withLock {
            box -> (CheckedContinuation<ScriptResult, Error>?, (@Sendable () -> Void)?) in
            if box.finished { return (nil, nil) }
            box.finished = true
            let handler = box.onFinish
            box.onFinish = nil
            if let continuation = box.continuation {
                box.resumed = true
                box.continuation = nil
                return (continuation, handler)
            }
            box.pending = result
            return (nil, handler)
        }
        continuation?.resume(with: result)
        handler?()
    }
}

/// One `JSContext`. All methods except `state.finish` run on the engine queue.
private final class Session: @unchecked Sendable {
    let request: ScriptRequest
    let environment: ScriptEnvironmentContext
    let source: String
    let context: JSContext
    let queue: DispatchQueue
    let state: RunState
    private weak var engine: ScriptEngine?

    private var logs: [String] = []
    private var lastValue: ScriptValue = .undefined
    private var pendingWork = 0
    private var nextTimer: UInt32 = 1
    /// Callbacks live here, not in the work items: a cancelled work item
    /// stays queued until its deadline and must not pin the JS value.
    private var timers: [UInt32: (work: DispatchWorkItem, callback: JSValue)] = [:]
    private var nextHTTPTask: UInt32 = 1
    private var httpTasks: [UInt32: (task: Task<Void, Never>, callback: JSValue)] = [:]
    private var calledDone = false

    init(
        request: ScriptRequest,
        environment: ScriptEnvironmentContext,
        source: String,
        context: JSContext,
        queue: DispatchQueue,
        state: RunState,
        engine: ScriptEngine
    ) {
        self.request = request
        self.environment = environment
        self.source = source
        self.context = context
        self.queue = queue
        self.state = state
        self.engine = engine
    }

    func install() {
        context.exceptionHandler = { [weak self] _, exception in
            guard let self, !self.state.isFinished else { return }
            self.fail(Self.message(from: exception))
        }

        let done: @convention(block) (JSValue?) -> Void = { [weak self] value in
            self?.complete(with: ScriptValue.from(value), fromDone: true)
        }
        let log: @convention(block) (String?) -> Void = { [weak self] line in
            self?.logs.append(line ?? "")
        }
        let setTimeout: @convention(block) (JSValue?, Double) -> UInt32 = { [weak self] callback, ms in
            self?.scheduleTimeout(callback, milliseconds: ms) ?? 0
        }
        let clearTimeout: @convention(block) (Double) -> Void = { [weak self] id in
            // `clearTimeout(undefined)` passes NaN; `UInt32(_:)` would trap.
            guard id.isFinite, id >= 0, id <= Double(UInt32.max) else { return }
            self?.clearTimeout(UInt32(id))
        }

        context.setObject(unsafeBitCast(done, to: AnyObject.self), forKeyedSubscript: "$done" as NSString)
        context.setObject(unsafeBitCast(log, to: AnyObject.self), forKeyedSubscript: "$__log" as NSString)
        context.setObject(unsafeBitCast(setTimeout, to: AnyObject.self), forKeyedSubscript: "$__setTimeout" as NSString)
        context.setObject(unsafeBitCast(clearTimeout, to: AnyObject.self), forKeyedSubscript: "$__clearTimeout" as NSString)

        let httpCall: @convention(block) (String?, JSValue?, JSValue?) -> Void = { [weak self] method, options, callback in
            self?.startHTTP(method: method ?? "GET", options: options, callback: callback)
        }
        let storeRead: @convention(block) (String?) -> Any? = { [weak self] key in
            guard let self, let key, !key.isEmpty else { return NSNull() }
            return self.environment.persistentStore.read(key: key) ?? NSNull()
        }
        let storeWrite: @convention(block) (JSValue?, String?) -> Bool = { [weak self] value, key in
            guard let self, let key, !key.isEmpty else { return false }
            let stringValue: String?
            if let value, !value.isUndefined, !value.isNull {
                stringValue = value.toString()
            } else {
                stringValue = nil
            }
            return self.environment.persistentStore.write(stringValue, forKey: key)
        }
        let notifyPost: @convention(block) (String?, String?, String?) -> Void = { [weak self] title, subtitle, body in
            guard let self else { return }
            let t = title ?? ""
            let s = subtitle ?? ""
            let b = body ?? ""
            let summary = [t, s, b].filter { !$0.isEmpty }.joined(separator: " — ")
            self.logs.append("[notify] \(summary)")
            self.environment.notificationHandler?(t, s, b)
        }

        context.setObject(unsafeBitCast(httpCall, to: AnyObject.self), forKeyedSubscript: "$__http" as NSString)
        context.setObject(unsafeBitCast(storeRead, to: AnyObject.self), forKeyedSubscript: "$__storeRead" as NSString)
        context.setObject(unsafeBitCast(storeWrite, to: AnyObject.self), forKeyedSubscript: "$__storeWrite" as NSString)
        let base64Encode: @convention(block) (String?) -> String = { input in
            Data((input ?? "").utf8).base64EncodedString()
        }
        let base64Decode: @convention(block) (String?) -> String = { input in
            guard let input, let data = Data(base64Encoded: input, options: .ignoreUnknownCharacters) else {
                return ""
            }
            return String(decoding: data, as: UTF8.self)
        }

        context.setObject(unsafeBitCast(notifyPost, to: AnyObject.self), forKeyedSubscript: "$__notify" as NSString)
        context.setObject(unsafeBitCast(base64Encode, to: AnyObject.self), forKeyedSubscript: "$__btoa" as NSString)
        let prizmxRouteTest: @convention(block) (String?, Double) -> Any = { [weak self] host, rawPort in
            guard let self,
                  let host = host?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !host.isEmpty,
                  let handler = self.environment.prizmx.routeTest
            else { return NSNull() }
            let port = rawPort.isFinite && rawPort >= 1 && rawPort <= 65535 ? Int(rawPort) : 443
            guard let match = handler(host, port) else { return NSNull() }
            var dict: [String: Any] = [
                "host": match.host,
                "port": match.port,
                "rule": match.rule,
                "policy": match.policy,
            ]
            if let resolved = match.resolvedNode {
                dict["resolvedNode"] = resolved
            }
            return dict as NSDictionary
        }
        let prizmxPolicies: @convention(block) () -> NSArray = { [weak self] in
            guard let self, let list = self.environment.prizmx.policies?() else { return [] }
            return list.map { item -> NSDictionary in
                var dict: [String: Any] = [
                    "name": item.name,
                    "mode": item.mode,
                    "members": item.members,
                ]
                if let selected = item.selected {
                    dict["selected"] = selected
                }
                return dict as NSDictionary
            } as NSArray
        }
        let prizmxSelectPolicy: @convention(block) (String?, String?) -> Bool = { [weak self] group, member in
            guard let self, let group, let member, !group.isEmpty, !member.isEmpty,
                  let handler = self.environment.prizmx.selectPolicy
            else { return false }
            return handler(group, member)
        }
        let prizmxEgress: @convention(block) () -> NSDictionary = { [weak self] in
            guard let self, let info = self.environment.prizmx.egress?() else { return [:] }
            return info as NSDictionary
        }

        context.setObject(unsafeBitCast(base64Decode, to: AnyObject.self), forKeyedSubscript: "$__atob" as NSString)
        context.setObject(unsafeBitCast(prizmxRouteTest, to: AnyObject.self), forKeyedSubscript: "$__prizmxRouteTest" as NSString)
        context.setObject(unsafeBitCast(prizmxPolicies, to: AnyObject.self), forKeyedSubscript: "$__prizmxPolicies" as NSString)
        context.setObject(unsafeBitCast(prizmxSelectPolicy, to: AnyObject.self), forKeyedSubscript: "$__prizmxSelectPolicy" as NSString)
        context.setObject(unsafeBitCast(prizmxEgress, to: AnyObject.self), forKeyedSubscript: "$__prizmxEgress" as NSString)

        if let argument = request.argument {
            context.setObject(argument, forKeyedSubscript: "$argument" as NSString)
        }

        context.setObject(
            [
                "name": request.name,
            ] as NSDictionary,
            forKeyedSubscript: "$script" as NSString
        )
        context.setObject(
            [
                "engine": "jsc",
                "app": "PrizmX",
                "system": Self.systemName,
                "version": environment.version,
            ] as NSDictionary,
            forKeyedSubscript: "$environment" as NSString
        )

        var v4: [String: Any] = [:]
        if let address = environment.network.v4PrimaryAddress { v4["primaryAddress"] = address }
        if let iface = environment.network.v4PrimaryInterface { v4["primaryInterface"] = iface }
        var wifi: [String: Any] = [:]
        if let ssid = environment.network.wifiSSID { wifi["ssid"] = ssid }
        context.setObject(
            [
                "v4": v4,
                "wifi": wifi,
            ] as NSDictionary,
            forKeyedSubscript: "$network" as NSString
        )

        context.evaluateScript(Self.prelude, withSourceURL: URL(string: "prizmx://script/prelude"))
        if let exception = context.exception {
            fail(Self.message(from: exception))
        }
    }

    func evaluate() {
        guard !state.isFinished else { return }
        let url = URL(string: "prizmx://script/\(request.name)")
        let raw = context.evaluateScript(source, withSourceURL: url)
        if let exception = context.exception {
            fail(Self.message(from: exception))
            return
        }
        lastValue = ScriptValue.from(raw)
        finishIfIdle()
    }

    private func scheduleTimeout(_ callback: JSValue?, milliseconds: Double) -> UInt32 {
        guard let callback, !state.isFinished else { return 0 }
        let id = nextTimer
        nextTimer = nextTimer == UInt32.max ? 1 : nextTimer + 1
        pendingWork += 1
        let work = DispatchWorkItem { [weak self] in
            guard let self, !self.state.isFinished,
                  let entry = self.timers.removeValue(forKey: id) else { return }
            self.pendingWork -= 1
            entry.callback.call(withArguments: [])
            if let exception = self.context.exception {
                self.fail(Self.message(from: exception))
                return
            }
            self.finishIfIdle()
        }
        timers[id] = (work, callback)
        queue.asyncAfter(deadline: .now() + Self.timerDelay(milliseconds), execute: work)
        return id
    }

    /// NaN / negative → 0; capped at `ScriptEngine.maxTimerDelay`.
    static func timerDelay(_ milliseconds: Double) -> TimeInterval {
        guard milliseconds.isFinite, milliseconds > 0 else {
            return milliseconds == .infinity ? ScriptEngine.maxTimerDelay : 0
        }
        return min(milliseconds / 1000, ScriptEngine.maxTimerDelay)
    }

    private func clearTimeout(_ id: UInt32) {
        guard let entry = timers.removeValue(forKey: id) else { return }
        entry.work.cancel()
        pendingWork = max(0, pendingWork - 1)
    }

    private func finishIfIdle() {
        guard !state.isFinished, !calledDone, pendingWork == 0 else { return }
        complete(with: lastValue, fromDone: false)
    }

    private func complete(with value: ScriptValue, fromDone: Bool) {
        guard !state.isFinished else { return }
        if fromDone { calledDone = true }
        state.finish(.success(ScriptResult(value: value, logs: logs)))
        teardown()
    }

    private func fail(_ message: String) {
        guard !state.isFinished else { return }
        state.finish(.failure(ScriptError.exception(message)))
        teardown()
    }

    /// Engine queue only.
    func teardown() {
        cancelTimers()
        context.exceptionHandler = nil
        engine?.drop(self)
    }

    private func startHTTP(method: String, options: JSValue?, callback: JSValue?) {
        guard !state.isFinished else { return }
        guard let parsed = Self.parseHTTPRequest(method: method, options: options, fallbackTimeout: request.timeout) else {
            if let callback, !callback.isUndefined, !callback.isNull {
                callback.call(withArguments: ["Invalid URL", NSNull(), ""])
                if let exception = context.exception {
                    fail(Self.message(from: exception))
                }
            }
            return
        }

        let id = nextHTTPTask
        nextHTTPTask = nextHTTPTask == UInt32.max ? 1 : nextHTTPTask + 1
        pendingWork += 1
        let handler = environment.httpClient
        let callbackRef = callback ?? JSValue(undefinedIn: context)!
        let task = Task.detached(priority: .utility) { [weak self] in
            let outcome: Result<ScriptHTTPResponse, Error>
            do {
                let response = try await handler(parsed)
                outcome = .success(response)
            } catch {
                outcome = .failure(error)
            }
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self, !self.state.isFinished,
                      let entry = self.httpTasks.removeValue(forKey: id)
                else { return }
                self.pendingWork = max(0, self.pendingWork - 1)
                if !entry.callback.isUndefined && !entry.callback.isNull {
                    switch outcome {
                    case .success(let response):
                        let respObj: NSDictionary = [
                            "status": response.status,
                            "statusCode": response.status,
                            "headers": response.headers,
                        ]
                        entry.callback.call(withArguments: [NSNull(), respObj, response.body])
                    case .failure(let error):
                        entry.callback.call(withArguments: [error.localizedDescription, NSNull(), ""])
                    }
                    if let exception = self.context.exception {
                        self.fail(Self.message(from: exception))
                        return
                    }
                }
                self.finishIfIdle()
            }
        }
        httpTasks[id] = (task, callbackRef)
    }

    private static func parseHTTPRequest(
        method: String,
        options: JSValue?,
        fallbackTimeout: TimeInterval
    ) -> ScriptHTTPRequest? {
        guard let options, !options.isUndefined, !options.isNull else { return nil }
        let urlString: String
        var headers: [String: String] = [:]
        var body: Data?
        var timeout = fallbackTimeout

        if options.isString {
            urlString = options.toString() ?? ""
        } else if let dict = options.toDictionary() {
            urlString = (dict["url"] as? String) ?? ""
            if let rawHeaders = dict["headers"] as? [AnyHashable: Any] {
                for (key, value) in rawHeaders {
                    headers[String(describing: key)] = String(describing: value)
                }
            }
            if let bodyString = dict["body"] as? String {
                body = Data(bodyString.utf8)
            } else if let bodyObj = dict["body"], JSONSerialization.isValidJSONObject(bodyObj) {
                body = try? JSONSerialization.data(withJSONObject: bodyObj)
            }
            if let rawTimeout = dict["timeout"] as? Double, rawTimeout.isFinite, rawTimeout > 0 {
                timeout = rawTimeout
            }
        } else {
            return nil
        }

        let trimmed = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed),
              let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https"
        else { return nil }

        return ScriptHTTPRequest(
            method: method.uppercased(),
            url: url,
            headers: headers,
            body: body,
            timeout: timeout
        )
    }

    private func cancelTimers() {
        for entry in timers.values { entry.work.cancel() }
        timers.removeAll()
        for entry in httpTasks.values { entry.task.cancel() }
        httpTasks.removeAll()
        pendingWork = 0
    }

    private static func message(from exception: JSValue?) -> String {
        exception?.toString() ?? "JavaScript exception"
    }

    private static var systemName: String {
        #if os(macOS)
        "macOS"
        #elseif os(iOS)
        "iOS"
        #elseif os(tvOS)
        "tvOS"
        #else
        "unknown"
        #endif
    }

    private static let prelude = """
    (function () {
      function stringify(value) {
        if (value === undefined) return "undefined";
        if (value === null) return "null";
        if (typeof value === "object") {
          try { return JSON.stringify(value); } catch (error) { return String(value); }
        }
        return String(value);
      }
      function join(args) {
        return Array.prototype.map.call(args, stringify).join(" ");
      }
      globalThis.console = {
        log: function () { $__log(join(arguments)); },
        info: function () { $__log(join(arguments)); },
        warn: function () { $__log(join(arguments)); },
        error: function () { $__log(join(arguments)); }
      };
      globalThis.setTimeout = function (fn, ms) { return $__setTimeout(fn, Number(ms) || 0); };
      globalThis.clearTimeout = function (id) { $__clearTimeout(id); };
      globalThis.btoa = function (s) { return $__btoa(String(s)); };
      globalThis.atob = function (s) { return $__atob(String(s)); };
      globalThis.$httpClient = {
        get: function (opts, cb) { $__http("GET", opts, cb); },
        post: function (opts, cb) { $__http("POST", opts, cb); },
        put: function (opts, cb) { $__http("PUT", opts, cb); },
        patch: function (opts, cb) { $__http("PATCH", opts, cb); },
        delete: function (opts, cb) { $__http("DELETE", opts, cb); },
        head: function (opts, cb) { $__http("HEAD", opts, cb); },
        options: function (opts, cb) { $__http("OPTIONS", opts, cb); }
      };
      globalThis.$persistentStore = {
        read: function (key) {
          var v = $__storeRead(String(key));
          return v === null ? null : String(v);
        },
        write: function (value, key) {
          return Boolean($__storeWrite(value, String(key)));
        }
      };
      globalThis.$notification = {
        post: function (title, subtitle, body) {
          $__notify(
            title === undefined || title === null ? "" : String(title),
            subtitle === undefined || subtitle === null ? "" : String(subtitle),
            body === undefined || body === null ? "" : String(body)
          );
        }
      };
      // Quantumult X compatibility shims (non-MITM APIs).
      globalThis.$prefs = {
        valueForKey: function (key) { return $persistentStore.read(key); },
        setValueForKey: function (value, key) { return $persistentStore.write(value, key); },
        removeValueForKey: function (key) { return $persistentStore.write(null, key); }
      };
      globalThis.$notify = function (title, subtitle, body) {
        $notification.post(title, subtitle, body);
      };
      globalThis.$task = {
        fetch: function (req) {
          return new Promise(function (resolve, reject) {
            var method = (req && req.method ? String(req.method) : "GET").toUpperCase();
            $__http(method, req, function (err, resp, body) {
              if (err) {
                reject({ error: String(err) });
              } else {
                resolve({
                  statusCode: resp ? resp.status : 0,
                  headers: resp ? resp.headers : {},
                  body: body
                });
              }
            });
          });
        }
      };
      // PrizmX-specific progressive extensions.
      globalThis.$prizmx = {
        version: ($environment && $environment.version) || "1.0",
        routeTest: function (host, port) {
          return $__prizmxRouteTest(String(host || ""), port === undefined ? 443 : Number(port));
        },
        policies: function () { return $__prizmxPolicies(); },
        selectPolicy: function (group, member) {
          return Boolean($__prizmxSelectPolicy(String(group || ""), String(member || "")));
        },
        egress: function () { return $__prizmxEgress(); }
      };
    })();
    """
}

extension ScriptValue {
    static func from(_ value: JSValue?) -> ScriptValue {
        from(value, depth: 0)
    }

    private static func from(_ value: JSValue?, depth: Int) -> ScriptValue {
        guard let value, !value.isUndefined else { return .undefined }
        if value.isNull { return .null }
        if value.isBoolean { return .bool(value.toBool()) }
        if value.isString { return .string(value.toString() ?? "") }
        if value.isNumber { return .number(value.toDouble()) }
        guard depth < 8 else { return .string("[Nested]") }
        if value.isArray, let items = value.toArray() {
            return .array(items.map { fromAny($0, depth: depth + 1) })
        }
        if value.isObject, let object = value.toObject() {
            return fromAny(object, depth: depth)
        }
        if let text = value.toString() {
            return .string(text)
        }
        return .undefined
    }

    private static func fromAny(_ any: Any, depth: Int) -> ScriptValue {
        switch any {
        case is NSNull:
            return .null
        case let value as JSValue:
            return from(value, depth: depth)
        case let value as String:
            return .string(value)
        case let value as NSNumber:
            if CFGetTypeID(value) == CFBooleanGetTypeID() {
                return .bool(value.boolValue)
            }
            return .number(value.doubleValue)
        case let value as [Any]:
            guard depth < 8 else { return .string("[Array]") }
            return .array(value.map { fromAny($0, depth: depth + 1) })
        case let value as [String: Any]:
            guard depth < 8 else { return .string("[Object]") }
            return .object(value.mapValues { fromAny($0, depth: depth + 1) })
        case let value as [AnyHashable: Any]:
            guard depth < 8 else { return .string("[Object]") }
            var object: [String: ScriptValue] = [:]
            for (key, item) in value {
                object[String(describing: key)] = fromAny(item, depth: depth + 1)
            }
            return .object(object)
        default:
            return .string(String(describing: any))
        }
    }
}
