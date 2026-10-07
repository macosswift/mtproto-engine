# Coverage-guided fuzzing (cargo-fuzz / libFuzzer)

`crates/mtproto-fuzz` runs seeded generators on the pinned stable toolchain; the targets here are
coverage-guided and need nightly (`rustup toolchain install nightly`, `cargo install cargo-fuzz`).
This directory is its own workspace, so the main workspace, its lockfile and its lints are untouched.

```sh
# seed corpora (valid service messages naming live msg_ids, valid handshake answers, HTTP/WS streams)
cargo +nightly run --manifest-path fuzz/Cargo.toml --features seeds --bin write-seeds

# one target, 15 minutes, no sanitizer (the crates forbid unsafe code; ASan only slows them down)
RUSTFLAGS="--cfg aes_armv8" cargo +nightly fuzz run -O --debug-assertions -s none session -- \
    -dict=fuzz/dict/mtproto.dict -max_total_time=900 -max_len=16384 -timeout=10 -rss_limit_mb=2048

# replay a crash, then minimize it
cargo +nightly fuzz run -O --debug-assertions -s none session fuzz/artifacts/session/crash-…
cargo +nightly fuzz tmin -O --debug-assertions -s none session fuzz/artifacts/session/crash-…

# replay the triaged inputs kept as regressions (each runs once and must pass)
cargo +nightly fuzz run -O --debug-assertions -s none route_memory fuzz/regressions/route_memory/*
```

`RUSTFLAGS` replaces `.cargo/config.toml`'s flags, hence `--cfg aes_armv8` (hardware AES) above. Use
`fuzz/dict/http.dict` for `http_response` and `websocket`.

| Target | Surface | Checked beyond "no panic" |
|---|---|---|
| `session` | `Session::handle_packet` with packets sealed with the session's real key, timers, reconnects, quick acks, HTTP mode | the client's own packets always decrypt and parse, msg_ids are divisible by 4, footprint and event counts stay bounded, no endless transmit loop, timeouts are finite |
| `session_liveness` | `session`'s hostile operations (TCP), then an honest server that answers every query, ping, salt and state request, re-sending answers a dropped connection lost | every request still open settles (answer or error) within 450 simulated seconds |
| `rpc` | the same through `RpcClient` (rpc_error classes, flood waits, migrations, init wrapping, verification) | as `session` |
| `service_tl` | `ServiceMessage::parse`, `parse_rpc_result_limited`, gzip, handshake TL types | gunzip budgets hold; every handshake type re-serializes to bytes that parse to the same value |
| `http_response` | `HttpResponseReader`, `HttpConnectHandshake` | hostile bytes stay within the head/body caps; responses built from fuzzer choices parse back exactly under any split |
| `websocket` | `WsHandshake`, `WsDeframer`, `encode_ws_frames` | at most one control frame is buffered; server frames round trip under any split; client framing has the exact size |
| `codec` | abridged / intermediate / padded intermediate, both directions | `pending_frame_len` names the frame `decode` takes; frames round trip under any split |
| `obfuscated2` | `TransportStream` (obfuscated2, MTProxy `dd`/`ee`) against a server built on `accept_obfuscated_header` | client and server carry each other's frames intact through any chunking |
| `fake_tls` | `client_hello`, `verify_server_hello`, `TlsRecordReader` | every hello proves the secret; a valid server hello verifies under any split |
| `handshake` | the DH exchange in three stages: fuzzed `res_pq`; fuzzed plaintext of `server_DH_inner_data` sealed with the real temporary key; fuzzed `dh_gen_*` hashed with the real auth key | the client's answers decrypt and hash correctly; no bad answer moves the exchange on; the agreed key and salt are the server's |
| `route_memory` | `RouteHints::load` / `export` and the per-network state machine | export → load → export is stable; at most `NETWORKS_REMEMBERED` networks |
| `socks5` | `Socks5Handshake` | the connect request matches the target; `NeedMore` consumes nothing |
| `salts` | `SaltState` with non-finite and inverted times, `future_salts` | `all()` is sorted; `next_change_time` is after now; an invalid salt always asks for future salts |
| `message` | `decrypt_message` (2.0 and 1.0), `decode_plain_message` | unsealed or tampered packets never decrypt; own packets round trip |

Session and rpc inputs name run-time values through 8-byte placeholders that the harness replaces before
sealing (`0x7fff_ffff_ffff_<kind><index>`, see `src/lib.rs`): the client's msg_ids, its queries, pings,
`get_future_salts` and state requests, the session id and the salt. `MTPROTO_FUZZ_TRACE=1` makes the session
targets print each operation, and the honest server's rounds, when replaying an input.
