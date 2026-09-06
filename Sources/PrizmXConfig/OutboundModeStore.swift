import Foundation
import PrizmXCore

/// App Group copy of the Rule / Global / Direct switch so the extension
/// starts in the same mode the UI last chose (Clash keeps this in memory;
/// we persist because the packet-tunnel process is not the app).
public enum OutboundModeStore: Sendable {
    public static let relativePath = "tunnel/outbound-mode.json"

    public struct State: Sendable, Codable, Equatable {
        public var mode: OutboundMode
        public var globalGroup: String?

        public init(mode: OutboundMode = .rule, globalGroup: String? = nil) {
            self.mode = mode
            self.globalGroup = globalGroup
        }
    }

    public static func load(
        appGroupIdentifier: String = TunnelConfigStorage.defaultAppGroupIdentifier,
        directoryName: String = TunnelConfigStorage.defaultDirectoryName
    ) -> State {
        guard let url = fileURL(
            appGroupIdentifier: appGroupIdentifier,
            directoryName: directoryName
        ),
            let data = try? Data(contentsOf: url),
            let state = try? JSONDecoder().decode(State.self, from: data)
        else { return State() }
        return state
    }

    public static func save(
        _ state: State,
        appGroupIdentifier: String = TunnelConfigStorage.defaultAppGroupIdentifier,
        directoryName: String = TunnelConfigStorage.defaultDirectoryName
    ) {
        guard let url = fileURL(
            appGroupIdentifier: appGroupIdentifier,
            directoryName: directoryName
        ) else { return }
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        guard let data = try? JSONEncoder().encode(state) else { return }
        try? data.write(to: url, options: .atomic)
    }

    public static func save(
        mode: OutboundMode,
        globalGroup: String?,
        appGroupIdentifier: String = TunnelConfigStorage.defaultAppGroupIdentifier,
        directoryName: String = TunnelConfigStorage.defaultDirectoryName
    ) {
        var state = load(
            appGroupIdentifier: appGroupIdentifier,
            directoryName: directoryName
        )
        state.mode = mode
        if let globalGroup, !globalGroup.isEmpty {
            state.globalGroup = globalGroup
        }
        save(
            state,
            appGroupIdentifier: appGroupIdentifier,
            directoryName: directoryName
        )
    }

    private static func fileURL(
        appGroupIdentifier: String,
        directoryName: String
    ) -> URL? {
        TunnelConfigStorage.containerURL(
            appGroupIdentifier: appGroupIdentifier,
            directoryName: directoryName
        )?.appendingPathComponent(relativePath)
    }
}
