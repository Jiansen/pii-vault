// swift-tools-version: 6.0
// The Swift package at the repository root, so apps can depend on it by git URL
// (SwiftPM reads only a root manifest). It builds the same sources as swift/Package.swift,
// which stays the place to work on the Swift implementation and run its benchmark.
// The rule files are not bundled: ship spec/recognizers with the app (see swift/README.md).
import PackageDescription

let package = Package(
    name: "PIIVault",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "PIIVault", targets: ["PIIVault"]),
    ],
    targets: [
        .target(name: "PIIVault", path: "swift/Sources/PIIVault"),
        .testTarget(name: "PIIVaultTests", dependencies: ["PIIVault"], path: "swift/Tests/PIIVaultTests"),
    ]
)
