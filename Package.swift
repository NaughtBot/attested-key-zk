// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "attested-key-zk",
    platforms: [
        .iOS("18.0"),
        .macOS("26.0"),
    ],
    products: [
        .library(name: "AttestedKeyZK", targets: ["AttestedKeyZK"]),
    ],
    targets: [
        .binaryTarget(
            name: "CAttestedKeyZKAppleBinary",
            path: "AttestedKeyZKApple.artifactbundle"
        ),
        .binaryTarget(
            name: "CAttestedKeyZKAndroidBinary",
            path: "AttestedKeyZKAndroid.artifactbundle"
        ),
        .target(
            name: "CAttestedKeyZK",
            path: "Sources/CAttestedKeyZK",
            publicHeadersPath: "include"
        ),
        .target(
            name: "AttestedKeyZK",
            dependencies: [
                "CAttestedKeyZK",
                .target(
                    name: "CAttestedKeyZKAppleBinary",
                    condition: .when(platforms: [.iOS, .macOS])
                ),
                .target(
                    name: "CAttestedKeyZKAndroidBinary",
                    condition: .when(platforms: [.android])
                ),
            ],
            path: "bindings/swift/Sources/AttestedKeyZK",
            linkerSettings: [
                .linkedLibrary("c++"),
            ]
        ),
        .testTarget(
            name: "AttestedKeyZKTests",
            dependencies: ["AttestedKeyZK"],
            path: "bindings/swift/Tests/AttestedKeyZKTests"
        ),
    ]
)
