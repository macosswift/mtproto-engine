# MTProto engine (Rust)

A from-scratch MTProto 2.0 client engine for Telegram iOS and macOS, built to replace MtProtoKit
behind the `NetworkEngine` seam in TelegramCore. MtProtoKit stays the default; the engine is chosen
in Developer settings ("Network Engine") and takes effect after a restart. Both engines read and
write the same persisted state through `MTContext`, so switching never logs the account out.

The design follows tdlib where tdlib and MtProtoKit disagree, keeps every behaviour TelegramCore
depends on (see `docs/research/integration.md`), and fixes the MtProtoKit defects catalogued in
`docs/research/mtprotokit.md` §10.

## Crates

| Crate | Role |
|---|---|
| `mtproto-core` | Sans-IO protocol core, `#![forbid(unsafe_code)]`: crypto (AES-IGE/CTR, MTProto 2.0/1.0 KDF, RSA_PAD, DH checks, pq factorization), TL reader/writer and service messages, transports (abridged, intermediate, padded intermediate, obfuscated2, MTProxy simple/`dd`/`ee` fake-TLS, SOCKS5), auth key handshake, the session state machine and the RPC policy layer. Deterministic: time and randomness are injected. |
| `mtproto-engine` | Runtime: a small pool of mio reactor threads that own sessions and sockets, timers, connection management (address failover, backoff, proxies, pause/resume, idle disconnect), progress and usage accounting. Thread-safe handle callable from any thread. |
| `mtproto-ffi` | C ABI (`include/mtproto_engine.h`) and static library used by the Swift wrapper. |
| `mtproto-testserver` | In-process fake Telegram server with fault injection; library for tests and a standalone binary. |
| `mtproto-netsim` | TCP impairment proxy: latency, jitter, bandwidth, fragmentation, retransmit-like stalls, resets, blackholes, refused connects, outages. |
| `mtproto-bench` | Benchmark orchestrator and the Rust benchmark client (`docs/bench/client-spec.md`). |

The Swift side lives in `submodules/MTProtoRustEngine` (wrapper implementing `NetworkEngineFactory`)
and `submodules/TelegramCore/Sources/Network/NetworkEngine.swift` (the seam).

## Threading

MtProtoKit runs every session of every account, all parsing and all crypto on one process-wide
serial queue, so a large media download delays update delivery on the main session. The engine
instead:

- runs `EngineConfig::worker_threads` reactor threads (2–4 by default). Main sessions (updates,
  user requests) are pinned to the first thread; download/upload/CDN sessions are spread over the
  others, so decrypting a 512 KB file part never blocks the main session;
- owns each session on exactly one thread (actor style, no locks on the hot path);
- accepts commands from any thread through a channel plus a mio waker, never blocking the caller;
- delivers events on the session's thread; the Swift wrapper hops to its own per-session queue.

## Protocol behaviour (highlights)

- **Delivery**: after a reconnect, queries that were sent but not acknowledged are retransmitted at
  once under their original msg_id and seqno. The server deduplicates by msg_id within a session and
  re-delivers the cached answer of a query it already ran (verified against production with
  `examples/live_dedupe.rs`), so recovery takes one round trip and non-idempotent calls still run once.
  tdlib asks `msgs_state_req` first (two round trips); MtProtoKit re-sends with a new msg_id, which
  executes the query again. Messages older than `RETRANSMIT_WINDOW` (240 s, the server accepts 300 s),
  and retransmissions the server refused with a `bad_msg_notification`, fall back to `msgs_state_req`.
- **Salts**: `get_future_salts` keeps a rolling set; MtProtoKit never requests future salts and stalls
  roughly every 30 minutes on `bad_server_salt`.
- **Liveness**: `ping_delay_disconnect` with tdlib's online/offline timing plus read timeouts, so dead
  connections are detected even without traffic (MtProtoKit has no keepalive).
- **Robust parsing**: unknown constructors are delivered as updates and never reset the session;
  server `msg_resend_req`, `msgs_all_info`, `msgs_state_req` are handled.
- **Errors**: see `docs/protocol-coverage.md` for the full matrix of transport errors, service
  messages, `bad_msg_notification` codes and RPC error classes with their tests.

## Building

```sh
PATH=$HOME/.cargo/bin:$PATH cargo test --workspace          # all tests
PATH=$HOME/.cargo/bin:$PATH cargo build --release -p mtproto-ffi --target aarch64-apple-darwin
```

The toolchain is pinned in `rust-toolchain.toml`. `.cargo/config.toml` enables the ARMv8 AES
instructions (`aes_armv8`) and `mtproto-core` enables the hardware SHA-256 backend on aarch64;
without them crypto runs about 15x slower. macOS packaging: `core-xprojects/mtproto-engine` in the
Telegram-Mac repo builds `MTProtoEngineFFI.xcframework` (arm64 + x86_64, macOS 10.13).

## Testing

- Unit and property tests in every module of `mtproto-core` (crypto vectors, TL, framing, every
  session and RPC policy path, fuzzing of parsers with proptest).
- `mtproto-core/tests/handshake.rs`: DH handshake against a fake server, including tampering and
  failure cases.
- `mtproto-engine/tests/engine.rs`: the full runtime against the fake server over real sockets
  (concurrency across threads, exactly-once recovery after dropped connections, flood waits and 5xx,
  -404 key replacement, salts, proxies SOCKS5/MTProxy/fake-TLS, pause, idle disconnect, progress).
- `mtproto-ffi/tests/ffi.rs`: the C ABI end to end, plus a clang-compiled check that every struct in
  the header has the same layout as the Rust definitions.
- `mtproto-core/examples/live_probe.rs`, `live_rpc.rs`: handshake and RPC against real test and
  production datacenters. `live_dedupe.rs` probes how production treats a re-sent msg_id (the basis
  of the retransmission design).
- `submodules/MTProtoRustEngine` (`swift test`): the Swift wrapper's mapping and bridge tests, and
  end-to-end tests that drive `MTContext` → `RustNetworkSession` → the engine → the
  `mtproto-testserver` binary (build it first with `cargo build --release -p mtproto-testserver`).

### Hostile input, fuzzing and soak

- `crates/mtproto-fuzz`: stable-toolchain, seed-reproducible fuzzer with structure-aware generators for every
  parser and state machine (TL, gzip, framing, obfuscated2/fake-TLS streams, SOCKS5, proxy secrets, `pq`, the
  handshake against a tampering MITM, session and RPC layers fed validly encrypted hostile packets including
  amplification packets, and a 30–90-day `soak`). Each case is checked for panics (overflow checks on), time,
  memory, livelock and protocol invariants (no forged packet or key accepted, exactly-once delivery).

  ```sh
  cargo build --profile fuzz -p mtproto-fuzz
  ./target/fuzz/mtproto-fuzz --cases 1000000 --jobs 8          # all targets
  ./target/fuzz/mtproto-fuzz --target session --seed 42 --cases 1   # reproduce one case
  ```

  `cargo test -p mtproto-fuzz` runs a short pass of every target.
- `mtproto-testserver` hostile faults (`Fault::HOSTILE`, `Fault::LOOPS`): garbage, tampered msg_key, foreign
  session, even msg_id, detailed-info fan-out, gzip bombs, huge vector counts, salt floods and storms, replays,
  unknown results, deep nesting, transport codes, oversized and truncated frames, quick-ack noise, and requests the
  server rejects forever (salt, clock and resend loops). `engine::hostile_server_faults_never_break_exactly_once_delivery`
  runs each against the engine; `mtproto-bench tc --suite hostile[-quick]` runs them through TelegramCore for both
  engines.
- `mtproto-bench soak --minutes N`: the engine under continuous load with chaos, network flaps, connection resets
  and session churn against a test server in a child process; samples RSS, live heap, threads and descriptors.

## Benchmarks

```sh
cargo build --release -p mtproto-bench
./target/release/mtproto-bench run --suite quick [--real] [--mtprotokit bench/mtprotokit-client/.build/release/mtprotokit-bench] --out report
```

Each engine's client runs as a separate process against the fake server (or a real DC with `--real`)
behind `mtproto-netsim`, so CPU time, peak RSS, latency percentiles, throughput, server-side
duplicate executions and recovery after outages are measured identically for both engines.

### Through TelegramCore

```sh
(cd bench/telegramcore-client && swift build -c release -Xswiftc -enable-testing)
./target/release/mtproto-bench tc --telegramcore bench/telegramcore-client/.build/release/telegramcore-bench [--suite quick|full|torture] [--only NAME] [--engines rust,mtprotokit]
```

`telegramcore-bench` starts the real TelegramCore network stack (`initializedNetwork`, the engine
chosen by `NetworkEngineSettings` exactly like the Developer switch, `MultiplexedRequestManager`,
`Download`, `multipartFetchV2`, `Network.request`) against a fake cluster: main DC 2, file DC 4 (the
authorization is exported and imported) and CDN DC 203 (`upload.fileCdnRedirect`, AES-CTR parts,
`upload.getCdnFileHashes`, `upload.cdnFileReuploadNeeded`), each behind its own `mtproto-netsim`.
Rebuild `MTProtoEngineFFI.xcframework` first, otherwise the bench links the previous engine.

- `--suite quick|full`: downloads (photos, DC 4 videos, CDN), scrolling with cancellations, main-session
  probes during downloads, small requests; on perfect, broadband, 3G, lossy, flaky, blackhole and outage
  networks. The report adds served/needed bytes and re-fetched parts.
- `tc/bigfile*/wan`: one 40–80 MB file at a time over a 100 ms RTT, 200 Mbit/s path, direct and through
  the CDN. This is where the in-flight window decides throughput.
- `tc/cdn-hostile/*`: the CDN corrupts data, asks for a reupload forever, returns no hashes, or rejects
  the file token. A client must finish from the file's own DC without accepting a single bad byte.

The fake file DC redirects to the CDN only when `upload.getFile` sets `cdn_supported`, like the real
server. TelegramCore sets it only with the Rust engine, so the CDN rows compare the Rust engine's CDN
path with MtProtoKit downloading the same file directly.
- `--suite torture`: numbered calls through `Network.request` while the server injects one fault class
  at 1 % (or all of them mixed), plus a clean million-call run. Columns: wrong results, double
  completions, server-side duplicate executions, req/s, CPU, peak RSS and how the process exited.
