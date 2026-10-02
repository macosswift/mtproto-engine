load("@rules_cc//cc:objc_library.bzl", "objc_library")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_static_library")

# Pinned, not inherited: rules_rust follows the compilation mode, so under
# --configuration=debug_* the engine would otherwise build at -Copt-level=0. The third-party crates
# with hot non-generic code (sha2, sha1, miniz_oxide, num-bigint, ...) get the same pin through
# crate annotations in MODULE.bazel.
#
# NO -Clto, deliberately. Every rust_static_library in the app embeds the same std object
# members, and ld64 pulls an archive member only to resolve a still-undefined symbol, so the
# app links ONE std shared by wallet-engine, tlottie and this engine. LTO would internalize std
# into this archive's objects and duplicate it.
#
# -Cpanic=abort: a panic cannot unwind across `extern "C"` anyway.
_ENGINE_RUSTC_FLAGS = [
    "-Copt-level=3",
    "-Ccodegen-units=1",
    "-Cpanic=abort",
]

rust_library(
    name = "mtproto_core",
    crate_name = "mtproto_core",
    crate_root = "crates/mtproto-core/src/lib.rs",
    srcs = glob(["crates/mtproto-core/src/**/*.rs"]),
    edition = "2024",
    rustc_flags = _ENGINE_RUSTC_FLAGS,
    version = "0.1.0",
    deps = [
        "@mtproto_engine_crates//:aes",
        "@mtproto_engine_crates//:base64",
        "@mtproto_engine_crates//:flate2",
        "@mtproto_engine_crates//:getrandom",
        "@mtproto_engine_crates//:hmac",
        "@mtproto_engine_crates//:num-bigint",
        "@mtproto_engine_crates//:num-integer",
        "@mtproto_engine_crates//:num-traits",
        "@mtproto_engine_crates//:sha1",
        "@mtproto_engine_crates//:sha2",
        "@mtproto_engine_crates//:thiserror",
        "@mtproto_engine_crates//:zeroize",
    ],
)

rust_library(
    name = "mtproto_engine",
    crate_name = "mtproto_engine",
    crate_root = "crates/mtproto-engine/src/lib.rs",
    srcs = glob(["crates/mtproto-engine/src/**/*.rs"]),
    edition = "2024",
    rustc_flags = _ENGINE_RUSTC_FLAGS,
    version = "0.1.0",
    deps = [
        ":mtproto_core",
        "@mtproto_engine_crates//:libc",
        "@mtproto_engine_crates//:mio",
    ],
)

rust_static_library(
    name = "mtproto_engine_ffi_archive",
    crate_name = "mtproto_engine_ffi",
    crate_root = "crates/mtproto-ffi/src/lib.rs",
    srcs = glob(["crates/mtproto-ffi/src/**/*.rs"]),
    edition = "2024",
    rustc_flags = _ENGINE_RUSTC_FLAGS,
    version = "0.1.0",
    deps = [
        ":mtproto_engine",
        "@mtproto_engine_crates//:zeroize",
    ],
)

# Same module name as the macOS MTProtoEngineFFI.xcframework, so the Swift wrapper's
# `import MTProtoEngineFFI` compiles unchanged on both platforms.
objc_library(
    name = "MTProtoEngineFFI",
    module_name = "MTProtoEngineFFI",
    enable_modules = True,
    hdrs = ["crates/mtproto-ffi/include/mtproto_engine.h"],
    deps = [":mtproto_engine_ffi_archive"],
    visibility = ["//visibility:public"],
)
