// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "tattle",
    platforms: [.macOS("26.0")],
    dependencies: [
        .package(url: "https://github.com/groue/GRDB.swift.git", from: "7.0.0"),
    ],
    targets: [
        .target(
            name: "CSocketTable",
            path: "Sources/CSocketTable"
        ),
        .target(
            name: "CPacketCapture",
            path: "Sources/CPacketCapture"
        ),
        .target(
            name: "CCodePolicy",
            path: "Sources/CCodePolicy",
            linkerSettings: [.linkedFramework("Security"), .linkedFramework("CoreFoundation")]
        ),
        .executableTarget(
            name: "tattle",
            dependencies: [
                .product(name: "GRDB", package: "GRDB.swift"),
                "CSocketTable",
                "CPacketCapture",
                "CCodePolicy",
            ],
            path: "Sources/tattle"
        ),
        .executableTarget(
            name: "tattle-capture-broker",
            dependencies: ["CCodePolicy"],
            path: "Sources/tattle-capture-broker",
            linkerSettings: [.linkedFramework("Security"), .linkedFramework("CoreFoundation")]
        ),
        // Test fixture, not bundled by make app: a broker caller the tests sign as each case needs.
        .executableTarget(
            name: "tattle-broker-probe",
            dependencies: ["CPacketCapture"],
            path: "Tests/tattle-broker-probe"
        ),
        .testTarget(
            name: "tattleTests",
            // The executables are dependencies so a test run always has them built.
            dependencies: ["tattle", "tattle-capture-broker", "tattle-broker-probe"],
            path: "Tests/tattleTests",
            resources: [.copy("Fixtures/forged-signatures")]
        ),
    ]
)
