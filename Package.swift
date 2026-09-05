// swift-tools-version: 6.3
//
// PrizmX-Foundation — PrizmX core library
//
// Module layout:
//   * PrizmXProtocols — unified outbound connection protocol interfaces and
//     core data models
//   * PrizmXRules     — lightweight rule parsing and routing match engine
//   * PrizmXNodes     — outbound node catalog, policy groups, connection factory
//   * PrizmXCore      — engine that dispatches an endpoint through Router + Nodes
//   * PrizmXConfig    — Clash YAML / sing-box JSON → Engine
//   * PrizmXTUN       — SwiftTCP userspace stack + FakeIP DNS + engine relay

import PackageDescription

let package = Package(
    name: "PrizmX-Foundation",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
        .tvOS(.v17),
    ],
    products: [
        .library(name: "PrizmXProtocols", targets: ["PrizmXProtocols"]),
        .library(name: "PrizmXRules", targets: ["PrizmXRules"]),
        .library(name: "PrizmXNodes", targets: ["PrizmXNodes"]),
        .library(name: "PrizmXCore", targets: ["PrizmXCore"]),
        .library(name: "PrizmXConfig", targets: ["PrizmXConfig"]),
        .library(name: "PrizmXTUN", targets: ["PrizmXTUN"]),
    ],
    dependencies: [
        .package(path: "../SwiftTCP"),
    ],
    targets: [
        .target(name: "PrizmXProtocols"),
        .target(
            name: "PrizmXRules",
            dependencies: ["PrizmXProtocols"]
        ),
        .target(
            name: "PrizmXNodes",
            dependencies: ["PrizmXProtocols"]
        ),
        .target(
            name: "PrizmXCore",
            dependencies: ["PrizmXProtocols", "PrizmXRules", "PrizmXNodes"]
        ),
        .target(
            name: "PrizmXConfig",
            dependencies: ["PrizmXProtocols", "PrizmXRules", "PrizmXNodes", "PrizmXCore"]
        ),
        .target(
            name: "PrizmXTUN",
            dependencies: [
                "PrizmXProtocols",
                "PrizmXCore",
                "PrizmXNodes",
                "PrizmXRules",
                .product(name: "SwiftTCP", package: "SwiftTCP"),
            ]
        ),
        .testTarget(name: "PrizmXProtocolsTests", dependencies: ["PrizmXProtocols"]),
        .testTarget(name: "PrizmXRulesTests", dependencies: ["PrizmXRules"]),
        .testTarget(name: "PrizmXTUNTests", dependencies: ["PrizmXTUN"]),
        .testTarget(
            name: "PrizmXIntegrationTests",
            dependencies: ["PrizmXCore", "PrizmXNodes", "PrizmXRules", "PrizmXProtocols"]
        ),
        .testTarget(
            name: "PrizmXConfigTests",
            dependencies: ["PrizmXConfig", "PrizmXCore", "PrizmXNodes", "PrizmXRules", "PrizmXProtocols"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
