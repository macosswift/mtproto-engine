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
- **HTTP**: `TransportPreference::Http` speaks MTProto over HTTP/1.1 keep-alive (port 80, or each address's
  own), and `Auto` stays on TCP but moves to HTTP while no TCP route answers and back once one does. Queries
  travel in requests that wait briefly for their own answers, staggered long polls catch the rest, acks go out
  within 20 ms, and a lost request resends only what it carried. HTTP proxies are `ProxyConfig::Http`: TCP goes
  through CONNECT, HTTP is forwarded, and `Auto` forwards when CONNECT is refused. Behaviour and the production
  facts it relies on: `docs/protocol-coverage.md` §17.
- **PFS**: with `SessionSetup::pfs` (or `Engine::enable_pfs`) the engine makes temporary keys itself, binds
  them with `auth.bindTempAuthKey` before anything else goes out, replaces them before they expire at a quiet
  moment, and replaces them silently when the server loses them (§13).
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

### Fuzzing and coverage

- `crates/mtproto-fuzz`: seeded generators and long soaks on the stable toolchain (`cargo run --release -p
  mtproto-fuzz -- --list`).
- `fuzz/`: coverage-guided cargo-fuzz targets (nightly) for every parser that faces the network (service
  messages, HTTP, WebSocket, the four framings, obfuscated2 and fake-TLS, SOCKS5, route memory, salts), the
  session and RPC layers fed packets sealed with the session's real key, the handshake past its RSA and
  nonce checks, and a liveness target where an honest server must settle every request left open by hostile
  input. How to run them and what each checks: `fuzz/README.md`.
- Coverage: `cargo install cargo-llvm-cov`, `rustup component add llvm-tools-preview`, then
  `cargo llvm-cov --workspace --no-fail-fast --summary-only` (about 30 minutes; `-p mtproto-core` alone takes one).

### Security bench

`security/requirements.tsv` maps every documented MTProto security requirement and every tdlib check to
the tests that pin it; `./scripts/security-bench.py` runs the workspace tests and reports each
requirement as pass, fail or untested. See `security/README.md`.

### Hostile input, fuzzing and soak

- `crates/mtproto-fuzz`: stable-toolchain, seed-reproducible fuzzer with structure-aware generators for every
  parser and state machine (TL, gzip, framing, obfuscated2/fake-TLS streams, SOCKS5, proxy secrets, RSA keys from PEM/DER, `pq`, the
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
- Session explorer (`crates/mtproto-engine/src/session_explorer_tests.rs`): seeded, simulated-time runs of one to
  three sessions (TCP, HTTP, Auto; with and without engine PFS) against random host commands (calls, cancels, retry
  decisions, network and pause flips, proxy, address, transport and key changes, `destroy_auth_key`) and network
  or server faults (blackholes, resets, dropped answers, portal pages, refused or ignored binds, lost keys, DNS
  changes, clock jumps). After every turn it checks that no session spins, every call ends once the route heals,
  nothing runs twice and nothing panics; failing seeds shrink to a minimal event list. `explorer_quick` runs in
  `cargo test`; the long run is `EXPLORER_SEEDS=300 EXPLORER_JOBS=8 cargo test --release -p mtproto-engine --lib
  explorer_long -- --ignored`.
- `mtproto-bench soak --minutes N`: the engine under continuous load with chaos, network flaps, connection resets
  and session churn against a test server in a child process; samples RSS, live heap, threads and descriptors.

## Benchmarks

```sh
cargo build --release -p mtproto-bench
./target/release/mtproto-bench run --suite quick|full|weak [--online] [--real] [--repeat N] \
    [--mtprotokit bench/mtprotokit-client/.build/release/mtprotokit-bench] [--tdlib TDLIB_BENCH] --out report
```

Each engine's client runs as a separate process against the fake server (or a real DC with `--real`)
behind `mtproto-netsim`, so CPU time, peak RSS, latency percentiles, throughput, server-side
duplicate executions and recovery after outages are measured identically for every engine. Rounds
of a scenario use the same link seed for every engine.

- `--suite weak` is the raw form of the TelegramCore weak suite below: its twelve links, each with
  steady calls, calls during a download, an upload in three parallel parts and calls during it.
- `--online` marks the user online, as an app in the foreground does: the main session keeps its
  short, round-trip-based keepalive (and tdlib its foreground timers).
- `--tdlib` adds tdlib's own `Session` stack, built with `bench/tdlib-client/build.sh <tdlib source>
  <tdlib CMake build with target tdcore> <OpenSSL prefix> <output>`. Its connector follows tdlib's
  `ConnectionCreator::client_loop` for one address; it has no real-server mode.
- An engine whose client cannot run a scenario is skipped with a note: the MtProtoKit client has no
  upload workloads and no `--online`.

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

### Weak networks

```sh
./target/release/mtproto-bench tc --telegramcore <telegramcore-bench> --suite weak[-full] [--telemetry DIR] [--jobs 3]
```

Twelve links users actually have (`gprs`, `edge`, `edge-flaky`, `3g`, `satellite`, `lossy-heavy`,
`train`, whose tunnels stop the whole link for 6 s and refuse new connections while live ones wait
it out, `handover` between Wi-Fi and cellular, `uplink-starved` with a 64 kbit/s uplink,
`blackholes`, `bufferbloat`, whose 256 kbit/s uplink sits behind a 3 s first-in, first-out modem
buffer, and `bufferbloat-down`, whose 1 Mbit/s downlink sits behind a 5 s base-station buffer, so
answers and pongs wait seconds behind a download; its 512 kbit/s uplink queues the same way), each with seven workloads: small calls (`rpc`, long enough for every periodic tunnel,
reset or blackhole to strike), calls while downloading (`rpc-under-load`, head-of-line blocking)
and while uploading (`rpc-during-upload`), downloads, and uploads through TelegramCore's
`multipartUpload` in its usual parts and in 256 KB parts (`large-parts`, most of a minute each on
the slowest links), and two such uploads at once (`shared-uplink`). The three kinds of calls also
run with the user online (`rpc-online`, `rpc-under-load-online`, `rpc-during-upload-online`), as
while the app is in front: the main session then pings every round trip and gives up on silence
after a few. One more scenario,
`nat/after-pauses`, makes a call and downloads a file every 45 s through a carrier NAT that forgets
connections idle for 30 s (netsim `idle_timeout`), so each round starts on connections that died
silently. Every uploaded 1 KB block names its
index and file, so the test server checks each part's bytes, position and file, and an upload the
client reports done counts as bad data unless the server holds all of it. Transfers are sized to
each link (uploads also to its round trip, since small files go 16 KB parts three at a time) so
every run moves for a comparable time. The table adds re-sent parts, the client's CPU time and,
with `--telemetry`, the failure records the client's `NetworkTelemetry` wrote (stalls after 20 s,
every request watched); the dumps stay in `DIR` for `replay`. A closing section lists the scenarios
where the Rust engine did worse than MtProtoKit: more failed or hung requests, any bad data, more
failure records with as many failures, a p95 25% and 100 ms worse when both completed at least 20
calls per run (files do not count), 20% less throughput (up to the last file done, when nothing
failed, so calls still in flight after it do not count), or half as much CPU again and a second
more, as a worker spinning on a timer would use.

### Replaying field failures

TelegramCore's `NetworkTelemetry` records every failed, abandoned, slow or stalled request with the
context needed to reproduce it, and reports the records through `help.saveAppLog` while the server
enables it (`network_telemetry_enabled`). `replay` turns such records back into bench runs:

```sh
./target/release/mtproto-bench replay --records failures.json --telegramcore bench/telegramcore-client/.build/release/telegramcore-bench [--engines rust,mtprotokit] [--max-cases 5] [--rounds 1] [--only NAME] [--plan]
```

- Input: `failures.jsonl` from an account directory (`network-telemetry/`), a JSON array of records,
  reported `{"records": [...]}` chunks, or an array of app log events.
- Records are grouped by failure class, session role, API method and link class (the round trip
  rounded up to a power of two, or for a transfer without one the rate it moved at; cellular;
  proxy), so users on different networks are not averaged. Each group gets a simulated link
  (latency and jitter from the round trip: the main session's p50/p90 when the record carries it,
  the record's own for small calls, never a transfer's, which is mostly the bytes; a cellular link when the records were
  cellular, the reconnect cadence and connect time from the connection timelines, an outage when the
  connection was down at the failure, a SOCKS5 proxy when one was used, the user online when they
  mostly were), a workload with as many requests in flight as the records estimated (`in_flight`),
  and candidate server faults for the class (`stalled`: salt rotation, transport floods, clock warps,
  lost answers, stalls, new sessions, copies).
- Each case also lists the connections the Rust engine gave up on shortly before its failures and
  why (`probe_timeout`, `racer_won`, `session_error`, …, `(unanswered)` when the session never took a
  packet from it), each drop counted once: which of the engine's checks cut the user's connections.
- A timeline cannot tell a network that drops connections from a client that reconnects because of
  what the server sent, so the network-only candidate runs the measured link with its reconnects and
  outage, and each fault candidate runs the measured link without them.
- Calls run for a fixed time, long enough for the measured outage, two reconnect cycles and a stall
  to happen while requests wait, and transfers are sized to keep the measured link busy as long.
  Upload records replay as uploads, `upload.saveBigFilePart` ones in big parts, or in 256 KB parts on
  links too slow for a 10 MB file within the run; download records
  use files on the main DC, where the faults are injected; proxied cases go through the SOCKS5 proxy
  on the measured link.
- Every candidate runs on each engine with the client's own telemetry on (`TC_BENCH_TELEMETRY=1`,
  stalls after 6 s for calls and 20 s for transfers, every request watched) and dumps the client's
  records; the table says whether a run recorded the same failure class, which classes it recorded,
  and how many requests failed or hung.
- `--plan` prints the derived cases without running them. Faults are injected on the main DC only;
  4xx answers (`client`, `auth`, `migrate`) are server decisions, so their cases replay only the link.

### Triage of many reports

```sh
./target/release/mtproto-bench triage --records DIR_OR_FILE [--records …] --telegramcore BIN [--engines rust,mtprotokit] [--max-cases 10] [--save CASES_DIR] [--plan]
./target/release/mtproto-bench triage --check CASES_DIR --telegramcore BIN [--engines rust,mtprotokit]
```

- `--records` takes files or directories of them (any input `replay` reads), each record marked
  with the `report_id` of the chunk it came in or the path of the file it was read from.
- Cases are ranked by how many reports share them, then by records, and the table gives the records
  per engine and the drops the Rust engine reported.
- Each of the top cases replays explanation by explanation, network alone first, until every engine
  reproduced it or none is left; the verdict says whether it reproduced on Rust only, MtProtoKit only,
  both or neither, and with what.
- `--save` writes each reproduced case to `CASES_DIR`, named after the case without `replay/` and
  with every character but ASCII letters, digits, `.` and `-` turned into `_`. It holds the records and,
  per engine, the outcome with the explanation and seed it was replayed with (`"expect": {"rust":
  {"reproduces": true, "explanation": "network only", "seed": 9000}, …}`); an engine that did not
  reproduce the case keeps the explanation that reproduced it on another engine. An existing file is
  kept, so expectations edited by hand survive.
- `--check` replays every saved case on each engine with that engine's explanation and seed and
  compares: a case that reproduces where it is expected not to is a REGRESSION (exit status 1); one
  that no longer reproduces where it is expected to is reported as fixed, or flaky. Set the engine's
  `"reproduces"` to false once its failure is fixed, so the case guards the fix from then on.

`telegramcore-bench` also takes `TC_BENCH_TELEMETRY=0|1`, `TC_BENCH_STALLED_AFTER=SECONDS`,
`TC_BENCH_WATCH_EVERY=N` (a power of two) and `TC_BENCH_TELEMETRY_DUMP=PATH` (the records plus
`failure_counts`, which are not capped like the records) in any suite, `TC_BENCH_UPLOAD_LARGE_PARTS=1`
to upload files under 10 MB in 256 KB parts (`useLargerParts`; TelegramCore sends a file already in
memory in 512 KB `saveBigFilePart` parts only over 10 MB, which replay uses when the measured link
carries it within the run), and with `TC_BENCH_STDERR=1`
prints a `telemetry:` line per run (requests, failures by class, disconnects). With `tc-torture`,
`--requests 0` calls for `--duration` seconds instead of a fixed number of times.
