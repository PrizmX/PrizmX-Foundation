import Foundation
import Testing
import PrizmXScripts

@Test func httpClientGetAndPostRoundTrip() async throws {
    let env = ScriptEnvironmentContext(
        httpClient: { req in
            let bodyText = req.body.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            return ScriptHTTPResponse(
                status: 201,
                headers: ["X-Method": req.method],
                body: "\(req.method):\(req.url.path):\(req.headers["X-Test"] ?? "")|\(bodyText)"
            )
        }
    )
    let engine = ScriptEngine(environment: env)
    let result = try await engine.evaluate(ScriptRequest(
        name: "http-test",
        source: """
        $httpClient.post({
          url: "https://example.com/ping",
          headers: { "X-Test": "ok" },
          body: "hello"
        }, function(err, resp, data) {
          if (err) { $done({ err: err }); return; }
          $done({ status: resp.status, header: resp.headers["X-Method"], data: data });
        });
        """,
        timeout: 2
    ))
    #expect(result.value == .object([
        "status": .number(201),
        "header": .string("POST"),
        "data": .string("POST:/ping:ok|hello"),
    ]))
}

@Test func persistentStorePersistsAcrossRuns() async throws {
    let store = InMemoryScriptPersistentStore()
    let env = ScriptEnvironmentContext(persistentStore: store)
    let engine = ScriptEngine(environment: env)

    _ = try await engine.evaluate(source: #"$done($persistentStore.write("42", "answer"))"#)
    let second = try await engine.evaluate(source: #"$done($persistentStore.read("answer"))"#)
    #expect(second.value == .string("42"))

    _ = try await engine.evaluate(source: #"$done($persistentStore.write(null, "answer"))"#)
    let third = try await engine.evaluate(source: #"$done($persistentStore.read("answer"))"#)
    #expect(third.value == .null)
}

@Test func notificationAndNetworkContextExposed() async throws {
    actor Box { var items: [(String, String, String)] = []; func add(_ x: (String, String, String)) { items.append(x) } }
    let box = Box()
    let env = ScriptEnvironmentContext(
        notificationHandler: { t, s, b in Task { await box.add((t, s, b)) } },
        network: ScriptNetworkInfo(v4PrimaryAddress: "192.168.1.9", v4PrimaryInterface: "en0", wifiSSID: "HomeWiFi"),
        version: "0.0.15"
    )
    let result = try await ScriptEngine(environment: env).evaluate(
        source: """
        $notification.post("Title", "Sub", $network.wifi.ssid + "@" + $network.v4.primaryAddress);
        $done({ ssid: $network.wifi.ssid, ver: $environment.version });
        """
    )
    #expect(result.value == .object(["ssid": .string("HomeWiFi"), "ver": .string("0.0.15")]))
    #expect(result.logs == ["[notify] Title — Sub — HomeWiFi@192.168.1.9"])
}

@Test func cronScheduleMatchesFiveAndSixFieldExpressions() throws {
    var cal = Calendar(identifier: .gregorian)
    cal.timeZone = TimeZone(secondsFromGMT: 0)!
    // 2026-11-20 14:30:15 UTC (Friday = weekday 6 in Calendar -> cron 5)
    let date = DateComponents(calendar: cal, timeZone: cal.timeZone, year: 2026, month: 11, day: 20, hour: 14, minute: 30, second: 15).date!

    let five = try CronSchedule.parse("*/15 14 * * 5")
    #expect(five.matches(date, calendar: cal))

    let six = try CronSchedule.parse("15 30 14 * * 1-5")
    #expect(six.matches(date, calendar: cal))

    let miss = try CronSchedule.parse("0 12 * * *")
    #expect(!miss.matches(date, calendar: cal))

    #expect(throws: CronSchedule.ParseError.invalidFieldCount(3)) {
        _ = try CronSchedule.parse("* * *")
    }
}

@Test func qxCompatibilityShimsAndBase64Work() async throws {
    let kv = InMemoryScriptPersistentStore()
    let env = ScriptEnvironmentContext(
        httpClient: { req in
            ScriptHTTPResponse(status: 200, headers: ["X-OK": "1"], body: "\(req.method):\(req.url.host ?? "")")
        },
        persistentStore: kv
    )
    let engine = ScriptEngine(environment: env)
    let result = try await engine.evaluate(ScriptRequest(
        name: "qx-shim",
        source: """
        $prefs.setValueForKey(btoa("hello"), "k");
        var decoded = atob($prefs.valueForKey("k"));
        $notify("QX", "Sub", decoded);
        $task.fetch({ url: "https://example.org/", method: "PATCH" }).then(function (resp) {
          $done({ decoded: decoded, status: resp.statusCode, body: resp.body });
        });
        """,
        timeout: 2
    ))
    #expect(result.value == .object([
        "decoded": .string("hello"),
        "status": .number(200),
        "body": .string("PATCH:example.org"),
    ]))
    #expect(result.logs == ["[notify] QX — Sub — hello"])
}

@Test func prizmxNamespaceExposesRouteTestPoliciesAndSelection() async throws {
    let env = ScriptEnvironmentContext(
        version: "0.0.15",
        prizmx: ScriptPrizmXBridge(
            routeTest: { host, port in
                ScriptRouteMatch(
                    host: host,
                    port: port,
                    rule: "DOMAIN-SUFFIX,claude.ai,AI",
                    policy: "AI",
                    resolvedNode: "US-01"
                )
            },
            policies: {
                [ScriptPolicySummary(name: "AI", mode: "select", selected: "US-01", members: ["US-01", "JP-01"])]
            },
            selectPolicy: { group, member in
                group == "AI" && member == "JP-01"
            },
            egress: {
                ["ip": "203.0.113.10", "mode": "rule"]
            }
        )
    )
    let result = try await ScriptEngine(environment: env).evaluate(
        source: """
        var r = $prizmx.routeTest("api.claude.ai", 443);
        var p = $prizmx.policies();
        var switched = $prizmx.selectPolicy("AI", "JP-01");
        var e = $prizmx.egress();
        $done({
          policy: r.policy,
          node: r.resolvedNode,
          groupCount: p.length,
          switched: switched,
          ip: e.ip
        });
        """
    )
    #expect(result.value == .object([
        "policy": .string("AI"),
        "node": .string("US-01"),
        "groupCount": .number(1),
        "switched": .bool(true),
        "ip": .string("203.0.113.10"),
    ]))
}

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
