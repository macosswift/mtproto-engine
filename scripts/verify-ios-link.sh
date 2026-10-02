#!/bin/sh
# Checks a linked, unstripped Mach-O (e.g. TelegramUIFramework of a debug_sim_arm64 build) for the
# three properties the Bazel build of the Rust MTProto engine must keep. None of them is a build
# error when lost: the crates silently fall back to software crypto (~15x slower), or std is
# duplicated.
#   1. one copy of the Rust standard library (core, alloc, std), shared by every Rust library;
#   2. ARMv8 AES instructions in the engine's own AES code (`--cfg aes_armv8` on the `aes` crate);
#   3. ARMv8 SHA-256 instructions in the `sha2` crate's compression (feature `asm`).
# 2 and 3 look at instructions, not symbol names: at -Copt-level=3 the backends' `target_feature`
# functions are inlined into their callers (aes::armv8 into mtproto_core's AES-IGE/CTR,
# sha2::sha256::aarch64 into sha2::sha256::compress256), so their own symbols disappear.
# Check 3 cannot tell the engine's sha2 from wallet-engine's (both crates are named sha2); wallet-engine
# builds sha2 without `asm` today, so its compression has no SHA-256 instructions.
# Disassembling the whole binary takes a minute or two.
set -eu
BIN="${1:?usage: verify-ios-link.sh <Mach-O binary>}"
SYMS="$(mktemp)"
COUNTS="$(mktemp)"
trap 'rm -f "$SYMS" "$COUNTS"' EXIT
nm "$BIN" | awk '{print $NF}' | grep '^__R' > "$SYMS" || true
if [ ! -s "$SYMS" ]; then
    echo "FAIL: no Rust symbols in $BIN (stripped binary?)"
    exit 1
fi
status=0
for crate in 4core 5alloc 3std; do
    copies=$(grep -oE "Cs[0-9A-Za-z]{1,13}_${crate}[0-9]" "$SYMS" | sed -E 's/[0-9]$//' | sort -u | wc -l | tr -d ' ')
    if [ "$copies" = "1" ]; then
        echo "ok: one ${crate#?}"
    else
        echo "FAIL: $copies copies of ${crate#?}"
        status=1
    fi
done
# "<count> <instruction> <function>" for every AES / SHA-256 instruction, attributed to the function
# label that precedes it in the disassembly.
otool -arch arm64 -tV "$BIN" | awk '
    /^[^ \t0-9].*:$/ { current = $0; next }
    /\t(aese|aesd|sha256h|sha256h2)\./ { split($2, parts, "."); counts[parts[1] " " current]++ }
    END { for (key in counts) print counts[key], key }
' > "$COUNTS"
aes=$(grep -E ' (aese|aesd) .*12mtproto_core' "$COUNTS" | awk '{ sum += $1 } END { print sum + 0 }')
if [ "$aes" -gt 0 ]; then
    echo "ok: $aes ARMv8 AES instructions in mtproto_core"
else
    echo "FAIL: no aese/aesd in mtproto_core (is --cfg aes_armv8 applied to the aes crate?)"
    status=1
fi
sha=$(grep -E ' sha256h2? .*_4sha26sha256' "$COUNTS" | awk '{ sum += $1 } END { print sum + 0 }')
if [ "$sha" -gt 0 ]; then
    echo "ok: $sha ARMv8 SHA-256 instructions in sha2::sha256"
else
    echo "FAIL: no sha256h in sha2::sha256 (is the sha2 asm feature enabled?)"
    status=1
fi
exit $status
