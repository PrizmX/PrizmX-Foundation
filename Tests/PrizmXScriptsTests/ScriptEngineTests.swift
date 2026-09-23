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
