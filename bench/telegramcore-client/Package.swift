// swift-tools-version:5.9

import Foundation
import PackageDescription

let packageDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let submodules = "../../../../submodules"
let defaultLibcrypto = packageDirectory
    .appendingPathComponent("../../../../../../core-xprojects/openssl/build/openssl/lib/libcrypto.a")
    .standardizedFileURL
    .path
let libcrypto = ProcessInfo.processInfo.environment["MTPROTOKIT_BENCH_LIBCRYPTO"] ?? defaultLibcrypto

let package = Package(
    name: "TelegramCoreBench",
    platforms: [.macOS(.v10_15)],
    products: [
        .executable(name: "telegramcore-bench", targets: ["TelegramCoreBench"]),
    ],
    dependencies: [
        .package(name: "TelegramCore", path: "\(submodules)/TelegramCore"),
        .package(name: "MTProtoRustEngine", path: "\(submodules)/MTProtoRustEngine"),
        .package(name: "MtProtoKit", path: "\(submodules)/MtProtoKit"),
        .package(name: "SSignalKit", path: "\(submodules)/SSignalKit"),
        .package(name: "Postbox", path: "\(submodules)/Postbox"),
        .package(name: "TelegramApi", path: "\(submodules)/TelegramApi"),
        .package(name: "EncryptionProvider", path: "\(submodules)/EncryptionProvider"),
    ],
    targets: [
        .target(
            name: "OpenSSLEncryption",
            dependencies: [
                .product(name: "EncryptionProvider", package: "EncryptionProvider"),
            ],
            path: "Vendor/OpenSSLEncryptionProvider",
            exclude: ["BUILD", "Package.swift"],
            sources: ["Sources"],
            publicHeadersPath: "PublicHeaders",
            cSettings: [
                .headerSearchPath("PublicHeaders"),
                .headerSearchPath("SharedHeaders/openssl/include"),
                .define("NDEBUG"),
            ]
        ),
        .executableTarget(
            name: "TelegramCoreBench",
            dependencies: [
                "OpenSSLEncryption",
                .product(name: "TelegramCore", package: "TelegramCore"),
                .product(name: "MTProtoRustEngine", package: "MTProtoRustEngine"),
                .product(name: "MtProtoKit", package: "MtProtoKit"),
                .product(name: "SwiftSignalKit", package: "SSignalKit"),
                .product(name: "Postbox", package: "Postbox"),
                .product(name: "TelegramApi", package: "TelegramApi"),
                .product(name: "EncryptionProvider", package: "EncryptionProvider"),
            ],
            path: "Sources/TelegramCoreBench",
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
