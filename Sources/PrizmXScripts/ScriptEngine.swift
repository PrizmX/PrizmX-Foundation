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

    public init(
        name: String = "script",
        source: String,
        argument: String? = nil,
        timeout: TimeInterval = ScriptEngine.defaultTimeout
    ) {
        self.name = name
        self.source = source
        self.argument = argument
        self.timeout = timeout
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
/// one `JSVirtualMachine`, a serial queue (`JSContext` is not thread-safe),
/// a fresh context per run, and `$done` to finish async work.
///
/// `$httpClient` / MITM hooks are not installed yet. `timeout` covers waits
/// for `$done` and timers; it cannot interrupt a synchronous infinite loop
/// (JavaScriptCore has no public watchdog).
public final class ScriptEngine: @unchecked Sendable {
    public static let defaultTimeout: TimeInterval = 5

    private let queue = DispatchQueue(label: "prizmx.script")
    private var virtualMachine: JSVirtualMachine?
    private var sessions: [ObjectIdentifier: Session] = [:]

    public init() {}

    public func evaluate(source: String, name: String = "script") async throws -> ScriptResult {
        try await evaluate(ScriptRequest(name: name, source: source))
    }

    public func evaluate(_ request: ScriptRequest) async throws -> ScriptResult {
        let source = request.source.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !source.isEmpty else { throw ScriptError.emptySource }

        let state = RunState()
        return try await withCheckedThrowingContinuation { continuation in
            state.bind(continuation)
            queue.async {
                self.begin(request, source: source, state: state)
            }
        }
    }

    private func begin(_ request: ScriptRequest, source: String, state: RunState) {
        let vm: JSVirtualMachine
        if let virtualMachine {
            vm = virtualMachine
        } else if let created = JSVirtualMachine() {
            virtualMachine = created
            vm = created
        } else {
            state.finish(.failure(ScriptError.exception("JavaScriptCore is unavailable.")))
            return
        }
        guard let context = JSContext(virtualMachine: vm) else {
            state.finish(.failure(ScriptError.exception("JavaScriptCore is unavailable.")))
            return
        }

        let session = Session(
            request: request,
            source: source,
            context: context,
            queue: queue,
            state: state,
            engine: self
        )
        sessions[ObjectIdentifier(session)] = session
        session.install()
        session.evaluate()

        let timeout = max(request.timeout, 0.05)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout) { [weak session] in
            session?.timeout()
        }
    }

    fileprivate func drop(_ session: Session) {
        sessions[ObjectIdentifier(session)] = nil
    }
}

// MARK: - Session

private final class RunState: @unchecked Sendable {
    private struct Storage {
        var continuation: CheckedContinuation<ScriptResult, Error>?
        var pending: Result<ScriptResult, Error>?
        var resumed = false
    }

    private let storage = OSAllocatedUnfairLock(initialState: Storage())

    var isFinished: Bool {
        storage.withLock { $0.resumed }
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
        let continuation: CheckedContinuation<ScriptResult, Error>? = storage.withLock { box in
            let none: CheckedContinuation<ScriptResult, Error>? = nil
            if box.resumed { return none }
            if let continuation = box.continuation {
                box.resumed = true
                box.continuation = nil
                return continuation
            }
            box.pending = result
            return none
        }
        continuation?.resume(with: result)
    }
}

/// One `JSContext`. All methods except `state.finish` run on the engine queue.
private final class Session: @unchecked Sendable {
    let request: ScriptRequest
    let source: String
    let context: JSContext
    let queue: DispatchQueue
    let state: RunState
    private weak var engine: ScriptEngine?

    private var logs: [String] = []
    private var lastValue: ScriptValue = .undefined
    private var pendingWork = 0
    private var nextTimer: UInt32 = 1
    private var timers: [UInt32: DispatchWorkItem] = [:]
    private var calledDone = false

    init(
        request: ScriptRequest,
        source: String,
        context: JSContext,
        queue: DispatchQueue,
        state: RunState,
        engine: ScriptEngine
    ) {
        self.request = request
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
            self?.clearTimeout(UInt32(id))
        }

        context.setObject(unsafeBitCast(done, to: AnyObject.self), forKeyedSubscript: "$done" as NSString)
        context.setObject(unsafeBitCast(log, to: AnyObject.self), forKeyedSubscript: "$__log" as NSString)
        context.setObject(unsafeBitCast(setTimeout, to: AnyObject.self), forKeyedSubscript: "$__setTimeout" as NSString)
        context.setObject(unsafeBitCast(clearTimeout, to: AnyObject.self), forKeyedSubscript: "$__clearTimeout" as NSString)

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
                "system": Self.systemName,
            ] as NSDictionary,
            forKeyedSubscript: "$environment" as NSString
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
        nextTimer += 1
        pendingWork += 1
        let work = DispatchWorkItem { [weak self] in
            guard let self, !self.state.isFinished else { return }
            self.timers[id] = nil
            self.pendingWork -= 1
            callback.call(withArguments: [])
            if let exception = self.context.exception {
                self.fail(Self.message(from: exception))
                return
            }
            self.finishIfIdle()
        }
        timers[id] = work
        queue.asyncAfter(deadline: .now() + max(0, milliseconds / 1000), execute: work)
        return id
    }

    private func clearTimeout(_ id: UInt32) {
        guard let work = timers.removeValue(forKey: id) else { return }
        work.cancel()
        pendingWork = max(0, pendingWork - 1)
    }

    private func finishIfIdle() {
        guard !state.isFinished, !calledDone, pendingWork == 0 else { return }
        complete(with: lastValue, fromDone: false)
    }

    func timeout() {
        guard !state.isFinished else { return }
        state.finish(.failure(ScriptError.timeout))
        queue.async { [weak self] in
            self?.teardown()
        }
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

    private func teardown() {
        cancelTimers()
        engine?.drop(self)
    }

    private func cancelTimers() {
        for work in timers.values { work.cancel() }
        timers.removeAll()
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
