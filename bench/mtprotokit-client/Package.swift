// swift-tools-version:5.9

import Foundation
import PackageDescription

let packageDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let defaultLibcrypto = packageDirectory
    .appendingPathComponent("../../../../../../core-xprojects/openssl/build/openssl/lib/libcrypto.a")
    .standardizedFileURL
    .path
let libcrypto = ProcessInfo.processInfo.environment["MTPROTOKIT_BENCH_LIBCRYPTO"] ?? defaultLibcrypto

let useSwiftPMDefaultFlags = ProcessInfo.processInfo.environment["MTPROTOKIT_BENCH_SWIFTPM_FLAGS"] != nil

let productionCSettings: [CSetting] = useSwiftPMDefaultFlags ? [] : [
    .define("NDEBUG"),
    .define("NS_BLOCK_ASSERTIONS", to: "1"),
    .unsafeFlags(["-Os"], .when(configuration: .release)),
]

let package = Package(
    name: "MTProtoKitBench",
    platforms: [.macOS(.v10_15)],
    products: [
        .executable(name: "mtprotokit-bench", targets: ["MTProtoKitBench"]),
    ],
    dependencies: [
        .package(path: "../../../../submodules/EncryptionProvider"),
    ],
    targets: [
        .target(
            name: "MtProtoKit",
            dependencies: [
                .product(name: "EncryptionProvider", package: "EncryptionProvider"),
            ],
            path: "Vendor/MtProtoKit",
            exclude: ["BUILD", "Package.swift", "Tests"],
            sources: ["Sources"],
            publicHeadersPath: "PublicHeaders",
            cSettings: [
                .headerSearchPath("PublicHeaders"),
            ] + productionCSettings
        ),
        .target(
            name: "OpenSSLEncryption",
            path: "Vendor/OpenSSLEncryptionProvider",
            exclude: ["BUILD", "Package.swift"],
            sources: ["Sources"],
            publicHeadersPath: "PublicHeaders",
            cSettings: [
                .headerSearchPath("PublicHeaders"),
                .headerSearchPath("SharedHeaders/openssl/include"),
                .headerSearchPath("SharedHeaders/EncryptionProvider"),
            ] + productionCSettings
        ),
        .executableTarget(
            name: "MTProtoKitBench",
            dependencies: [
                "MtProtoKit",
                "OpenSSLEncryption",
            ],
            path: "Sources/MTProtoKitBench",
            linkerSettings: [
                .linkedLibrary("z"),
                .linkedFramework("Security"),
                .linkedFramework("SystemConfiguration"),
                .linkedFramework("CFNetwork"),
                .unsafeFlags([libcrypto]),
            ]
        ),
    ]
)
