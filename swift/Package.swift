// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "PIIVault",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "PIIVault", targets: ["PIIVault"]),
    ],
    targets: [
        .target(name: "PIIVault"),
        .executableTarget(name: "PIIVaultBenchmark", dependencies: ["PIIVault"]),
        .testTarget(name: "PIIVaultTests", dependencies: ["PIIVault"]),
    ]
)
