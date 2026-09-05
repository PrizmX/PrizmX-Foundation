import Foundation
import Testing
import PrizmXConfig

@Test func tunnelLifecycleDistinguishesUserStopFromKill() {
    TunnelLifecycleStore.markStarted()
    #expect(!TunnelLifecycleStore.stopWasUserInitiated())

    TunnelLifecycleStore.markStopped(reason: TunnelLifecycleStore.userInitiatedReason)
    #expect(TunnelLifecycleStore.stopWasUserInitiated())

    TunnelLifecycleStore.clearStop()
    #expect(!TunnelLifecycleStore.stopWasUserInitiated())

    TunnelLifecycleStore.markStarted()
    TunnelLifecycleStore.markStopped(reason: 2) // NEProviderStopReason.providerFailed
    #expect(!TunnelLifecycleStore.stopWasUserInitiated())
}
