// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "T2T",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "T2T", targets: ["T2T"])],
    targets: [
        .executableTarget(
            name: "T2T",
            path: "Sources/T2T",
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("WebKit"),
                .linkedFramework("AVFoundation"),
                
                .linkedFramework("ApplicationServices"),
            ]
        )
    ]
)
