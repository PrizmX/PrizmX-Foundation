import Foundation
import Testing
import PrizmXConfig

/// App extension: App Group defaults. Pinned explicitly (no kit file to
/// read, no kit to write) so a concurrently bound `TunnelLog.kitRoot` in
/// another test cannot redirect it.
@Test func tunnelLifecycleDistinguishesUserStopFromKill() {
    let noKit = FileManager.default.temporaryDirectory
        .appendingPathComponent("prizmx-no-kit-\(UUID().uuidString)", isDirectory: true)
    TunnelLifecycleStore.markStarted(kitRoot: nil)
    #expect(!TunnelLifecycleStore.stopWasUserInitiated(kitRoot: noKit))

    TunnelLifecycleStore.markStopped(reason: TunnelLifecycleStore.userInitiatedReason, kitRoot: nil)
    #expect(TunnelLifecycleStore.stopWasUserInitiated(kitRoot: noKit))

    TunnelLifecycleStore.clearStop(kitRoot: noKit)
    #expect(!TunnelLifecycleStore.stopWasUserInitiated(kitRoot: noKit))

    TunnelLifecycleStore.markStarted(kitRoot: nil)
    TunnelLifecycleStore.markStopped(reason: 2, kitRoot: nil) // NEProviderStopReason.providerFailed
    #expect(!TunnelLifecycleStore.stopWasUserInitiated(kitRoot: noKit))
}

/// The open-core system extension runs as root and cannot reach the user's
/// App Group defaults: it records into the bound kit, where the app looks.
@Test func systemExtensionRecordsLifecycleInTheBoundKit() throws {
    let kit = FileManager.default.temporaryDirectory
        .appendingPathComponent("prizmx-kit-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: kit, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: kit) }
    let file = kit.appendingPathComponent(TunnelLifecycleStore.relativePath)

    TunnelLifecycleStore.markStarted(kitRoot: kit)
    #expect(FileManager.default.fileExists(atPath: file.path))
    #expect(!TunnelLifecycleStore.stopWasUserInitiated(kitRoot: kit))

    // Settings toggle: stopTunnel(.userInitiated) runs, so do not reconnect.
    TunnelLifecycleStore.markStopped(reason: TunnelLifecycleStore.userInitiatedReason, kitRoot: kit)
    #expect(TunnelLifecycleStore.stopWasUserInitiated(kitRoot: kit))

    // The app clears it before starting again.
    TunnelLifecycleStore.clearStop(kitRoot: kit)
    #expect(!FileManager.default.fileExists(atPath: file.path))

    // A killed extension never runs stopTunnel: reconnect.
    TunnelLifecycleStore.markStarted(kitRoot: kit)
    #expect(!TunnelLifecycleStore.stopWasUserInitiated(kitRoot: kit))
    TunnelLifecycleStore.markStopped(reason: 2, kitRoot: kit) // providerFailed
    #expect(!TunnelLifecycleStore.stopWasUserInitiated(kitRoot: kit))
}
