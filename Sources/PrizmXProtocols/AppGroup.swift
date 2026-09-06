import Foundation

/// Canonical App Group shared by the app and the network extensions.
///
/// Platform split, by Apple's two rule sets:
/// - **macOS**: team-ID prefixed. macOS treats unprefixed `group.*`
///   containers as TCC-protected cross-app data for the extensions
///   (containermanagerd: "Group containers identifiers should be prefixed
///   by requestor's team ID"), which produced the "PrizmX.app would like
///   to access data from other apps" prompt on every tunnel start.
///   Team-prefixed groups are validated locally and are never registered
///   in the developer portal — Xcode shows them red, which is harmless.
/// - **iOS / tvOS**: portal-registered, and the portal only accepts the
///   `group.` prefix. (The iOS app is a shell today; this keeps the
///   Foundation iOS target correct for when it gains the tunnel.)
public enum PrizmXAppGroup: Sendable {
    #if os(macOS)
    public static let identifier = "N49M3Z72D3.group.app.prizmx"
    #else
    public static let identifier = "group.app.prizmx"
    #endif
}
