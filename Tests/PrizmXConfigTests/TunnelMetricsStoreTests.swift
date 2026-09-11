import Foundation
import Testing
import PrizmXConfig
import PrizmXCore
import PrizmXProtocols

@Test func tunnelMetricsStoreRoundTripsSnapshot() throws {
    let kit = FileManager.default.temporaryDirectory
        .appendingPathComponent("metrics-store-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: kit) }

    let snapshot = TrafficSnapshot(
        uploadBytesPerSecond: 12_000,
        downloadBytesPerSecond: 80_000,
        uplinkBytes: 1_000,
        downlinkBytes: 4_000,
        activeConnections: 3,
        directUplinkBytes: 100,
        directDownlinkBytes: 200,
        policyBytes: ["Proxies": TrafficByteCount(up: 900, down: 3_800)],
        activeFlows: [
            FlowRecord(
                endpoint: Endpoint(domain: "example.com", port: 443),
                via: "Proxies",
                uplinkBytes: 10,
                downlinkBytes: 20,
                attribution: FlowAttribution(
                    pid: 42,
                    processName: "Safari",
                    bundleID: "com.apple.Safari"
                )
            )
        ]
    )
    #expect(TunnelMetricsStore.save(snapshot, kitRoot: kit, writtenAt: 100))
    let loaded = TunnelMetricsStore.load(maxAge: 5, kitRoot: kit, now: 101)
    #expect(loaded == snapshot)
}

@Test func tunnelMetricsStoreRejectsStaleFile() {
    let kit = FileManager.default.temporaryDirectory
        .appendingPathComponent("metrics-stale-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: kit) }

    let snapshot = TrafficSnapshot(uplinkBytes: 9, downlinkBytes: 8)
    #expect(TunnelMetricsStore.save(snapshot, kitRoot: kit, writtenAt: 10))
    #expect(TunnelMetricsStore.load(maxAge: 3, kitRoot: kit, now: 14) == nil)
    #expect(TunnelMetricsStore.load(maxAge: 3, kitRoot: kit, now: 12) == snapshot)
}

@Test func tunnelMetricsStoreUsesBoundKitRoot() throws {
    let kit = FileManager.default.temporaryDirectory
        .appendingPathComponent("metrics-bound-\(UUID().uuidString)", isDirectory: true)
    defer {
        TunnelLog.bind(kitRoot: nil)
        try? FileManager.default.removeItem(at: kit)
    }
    TunnelLog.bind(kitRoot: kit)
    let snapshot = TrafficSnapshot(uplinkBytes: 7, downlinkBytes: 8)
    #expect(TunnelMetricsStore.save(snapshot, writtenAt: 50))
    #expect(TunnelMetricsStore.load(maxAge: 5, now: 51) == snapshot)
    #expect(
        FileManager.default.fileExists(
            atPath: kit.appendingPathComponent("tunnel/metrics.json").path
        )
    )
}

@Test func tunnelMetricsStoreClearRemovesFile() {
    let kit = FileManager.default.temporaryDirectory
        .appendingPathComponent("metrics-clear-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: kit) }

    #expect(TunnelMetricsStore.save(.zero, kitRoot: kit, writtenAt: 1))
    TunnelMetricsStore.clear(kitRoot: kit)
    #expect(TunnelMetricsStore.load(kitRoot: kit, now: 1) == nil)
}
