import Foundation
import Testing
import PrizmXScripts

@Test func evaluatesLastExpression() async throws {
    let result = try await ScriptEngine().evaluate(source: "1 + 1")
    #expect(result.value == .number(2))
    #expect(result.logs.isEmpty)
}

@Test func doneObject() async throws {
    let result = try await ScriptEngine().evaluate(
        source: "$done({ ok: true, n: 1 + 1 })"
    )
    #expect(result.value == .object(["ok": .bool(true), "n": .number(2)]))
}

@Test func capturesConsoleAndArgument() async throws {
    let result = try await ScriptEngine().evaluate(
        ScriptRequest(
            name: "arg",
            source: """
            console.log("hi", $argument)
            $done($argument)
            """,
            argument: "world"
        )
    )
    #expect(result.value == .string("world"))
    #expect(result.logs == ["hi world"])
}

@Test func setTimeoutDone() async throws {
    let result = try await ScriptEngine().evaluate(
        ScriptRequest(
            source: "setTimeout(() => $done(7), 20)",
            timeout: 1
        )
    )
    #expect(result.value == .number(7))
}

@Test func environmentIsJSC() async throws {
    let result = try await ScriptEngine().evaluate(
        source: "$done($environment.engine)"
    )
    #expect(result.value == .string("jsc"))
}

@Test func rejectsEmptySource() async {
    await #expect(throws: ScriptError.emptySource) {
        try await ScriptEngine().evaluate(source: "  \n")
    }
}

@Test func reportsException() async {
    await #expect(throws: ScriptError.exception("Error: boom")) {
        try await ScriptEngine().evaluate(source: #"throw new Error("boom")"#)
    }
}

@Test func timesOutWhenDoneNeverCalled() async {
    await #expect(throws: ScriptError.timeout) {
        try await ScriptEngine().evaluate(
            ScriptRequest(
                source: "setTimeout(() => {}, 2000)",
                timeout: 0.15
            )
        )
    }
}

@Test func clearTimeoutWithInvalidIDsDoesNotTrap() async throws {
    // Regression: `UInt32(NaN)` trapped the host app.
    let result = try await ScriptEngine().evaluate(
        source: """
        clearTimeout(undefined); clearTimeout(-1); clearTimeout(1e20);
        clearTimeout(Infinity); clearTimeout("x"); $done(1)
        """
    )
    #expect(result.value == .number(1))
}

@Test func setTimeoutClampsInvalidAndHugeDelays() async throws {
    let result = try await ScriptEngine().evaluate(
        ScriptRequest(
            source: """
            const far = setTimeout(() => {}, 1e12);
            clearTimeout(far);
            setTimeout(() => $done("ran"), NaN);
            """,
            timeout: 1
        )
    )
    #expect(result.value == .string("ran"))
}

@Test func stuckScriptTimesOutWithoutBlockingLaterRuns() async throws {
    let engine = ScriptEngine()
    // JavaScriptCore has no public watchdog: this loop keeps spinning on its
    // own queue for the rest of the test process, but must not block others.
    await #expect(throws: ScriptError.timeout) {
        try await engine.evaluate(ScriptRequest(source: "while (true) {}", timeout: 0.2))
    }
    let next = try await engine.evaluate(ScriptRequest(source: "$done(2)", timeout: 1))
    #expect(next.value == .number(2))
}
