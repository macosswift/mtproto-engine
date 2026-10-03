#!/bin/sh
# Builds tdlib-bench against a tdlib source tree and its CMake build of `tdcore`.
# usage: build.sh <tdlib source> <tdlib build dir> <openssl prefix> <output binary>
set -e
TD="$1"
TD_BUILD="$2"
OPENSSL="$3"
OUT="$4"
HERE="$(cd "$(dirname "$0")" && pwd)"
OBJ="$(mktemp -d)"
INCLUDES="-I$TD -I$TD/tdutils -I$TD/tdactor -I$TD/tdnet -I$TD/tddb -I$TD/tdtl -I$TD/td/generate/auto -I$TD_BUILD/tdutils -I$TD_BUILD -I$OPENSSL/include"
for source in main Global; do
  clang++ -std=c++17 -O2 -c "$HERE/$source.cpp" -o "$OBJ/$source.o" $INCLUDES
done
clang++ -o "$OUT" "$OBJ/main.o" "$OBJ/Global.o" \
  "$TD_BUILD/libtdcore.a" "$TD_BUILD/libtdapi.a" "$TD_BUILD/libtdmtproto.a" "$TD_BUILD/tdnet/libtdnet.a" \
  "$TD_BUILD/tddb/libtddb.a" "$TD_BUILD/sqlite/libtdsqlite.a" "$TD_BUILD/tdactor/libtdactor.a" \
  "$TD_BUILD/tde2e/libtde2e.a" "$TD_BUILD/tdutils/libtdutils.a" "$OPENSSL/lib/libssl.a" "$OPENSSL/lib/libcrypto.a" \
  -lz -framework Security -framework CoreFoundation -framework SystemConfiguration
rm -rf "$OBJ"
