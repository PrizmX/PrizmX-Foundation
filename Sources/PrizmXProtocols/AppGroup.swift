import Foundation

/// Canonical App Group shared by the app and the network extensions.
///
/// The identifier is **team-ID prefixed**: macOS treats unprefixed
/// `group.*` containers as TCC-protected cross-app data for the extensions
/// (containermanagerd rejects them: "Group containers identifiers should be
/// prefixed by requestor's team ID"), which produced the
/// "PrizmX.app would like to access data from other apps" prompt on every
/// tunnel start.
public enum PrizmXAppGroup: Sendable {
    public static let identifier = "N49M3Z72D3.group.app.prizmx"
}
