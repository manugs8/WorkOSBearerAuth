// swift-tools-version:6.0
import PackageDescription

// Swift 6 language mode enforces complete strict concurrency checking by default,
// which is the equivalent of the `SWIFT_STRICT_CONCURRENCY=complete` build setting
// used in Swift 5 mode.
let package = Package(
    name: "WorkOSBearerAuth",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "WorkOSBearerAuth", targets: ["WorkOSBearerAuth"])
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.115.0"),
        .package(url: "https://github.com/vapor/jwt-kit.git", from: "5.0.0"),
    ],
    targets: [
        .target(
            name: "WorkOSBearerAuth",
            dependencies: [
                .product(name: "Vapor", package: "vapor"),
                .product(name: "JWTKit", package: "jwt-kit"),
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "WorkOSBearerAuthTests",
            dependencies: [
                .target(name: "WorkOSBearerAuth"),
                .product(name: "VaporTesting", package: "vapor"),
            ],
            swiftSettings: swiftSettings
        ),
    ],
    swiftLanguageModes: [.v6]
)

var swiftSettings: [SwiftSetting] {
    [.enableUpcomingFeature("ExistentialAny")]
}
