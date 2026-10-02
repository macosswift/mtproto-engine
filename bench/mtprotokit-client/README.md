# MtProtoKit benchmark client

`mtprotokit-bench` drives Telegram's Objective-C MtProtoKit the way TelegramCore does. It implements
the benchmark contract in [`docs/bench/client-spec.md`](../../docs/bench/client-spec.md), so the
orchestrator (`mtproto-bench run --mtprotokit <path>`) can run it head to head with the Rust engine's
client (`mtproto-bench client`). Both run as separate processes and are measured the same way (`wait4`).

Nothing in MtProtoKit, EncryptionProvider, OpenSSLEncryptionProvider or TelegramCore is modified.

## Build

```sh
cd third-party/mtproto-engine/bench/mtprotokit-client
swift build -c release
# binary: .build/release/mtprotokit-bench
```

### Compiler flags

`Vendor/MtProtoKit` and `Vendor/OpenSSLEncryptionProvider` are symlinks into `submodules/`. This package
compiles their unmodified sources as its own targets instead of depending on their `Package.swift`
manifests. A root package cannot set compiler flags for a dependency, and the flags matter here. The
sources are built the way the app builds them:

- `-Os`: Xcode's Release configuration for package targets in the macOS app, and Bazel `opt` on iOS.
- `NDEBUG` and `NS_BLOCK_ASSERTIONS=1`: Bazel `opt` sets both. The `-Os` flag is release-only; the two
  defines are set in debug builds too.

SwiftPM's own release flags, which you get when you depend on `submodules/MtProtoKit/Package.swift`, are
`-O2` with assertions on. On fake `media` (256 MiB, six runs each) that build has a median peak RSS of
**287 MB, against 21 MB with production flags**, and about 20% less CPU (0.72 s against 0.87 s).
At `-O2`, autoreleased buffers on MtProtoKit's queues pile up instead of being freed. A comparison built
with SwiftPM's defaults would therefore misstate MtProtoKit's memory and CPU. To reproduce that build,
set `MTPROTOKIT_BENCH_SWIFTPM_FLAGS=1`. Use a separate `--scratch-path` or `rm -rf .build` first, because
the variable is read when the manifest is evaluated.

`EncryptionProvider` (headers plus an empty `.mm`) is still a normal path dependency. OpenSSL's
`libcrypto.a`, needed by `OpenSSLEncryptionProvider`, comes from the macOS app checkout:
`<telegrammacos>/core-xprojects/openssl/build/openssl/lib/libcrypto.a`, a universal arm64/x86_64 static
library, found relative to `Package.swift`. Point `MTPROTOKIT_BENCH_LIBCRYPTO` at another
`libcrypto.a` to build elsewhere.

## Run

Fake mode, against the test server:

```sh
cd third-party/mtproto-engine
cargo build --release -p mtproto-testserver
./target/release/mtproto-testserver            # prints {"address","key_hex","salt"}; `stats`, `quit` on stdin
bench/mtprotokit-client/.build/release/mtprotokit-bench \
    --engine-label mtprotokit --mode fake --address 127.0.0.1:PORT --dc 2 \
    --key-hex KEY --salt SALT --workload small --requests 3000 --concurrency 128 --deadline 60
```

To go through MTProxy, add `--secret HEX` and start the server with the same `--secret`. A `dd…`
secret uses padded intermediate framing and an `ee…` secret uses fake TLS. Fake TLS currently needs a
server fix; see the validation notes.

Real mode. The client runs MtProtoKit's own DH handshake with its built-in production RSA key:

```sh
mtprotokit-bench --mode real --address 149.154.167.51:443 --dc 2 \
    --workload real-config --requests 5 --concurrency 1 --deadline 60
```

Through the orchestrator:

```sh
cargo run --release -p mtproto-bench -- run --mtprotokit bench/mtprotokit-client/.build/release/mtprotokit-bench --suite quick
```

Arguments, workloads, call encoding and the output line are exactly those of the contract. There is one
extra, optional argument: `--temp-keys 0|1`, real mode only, default `0` (see below).

Environment variables:

| Variable | Effect |
|---|---|
| `MTPROTOKIT_BENCH_LOG=1` | Enables MtProtoKit logging, written to stderr together with session state changes |
| `MTPROTOKIT_BENCH_NO_LOG_SINK=1` | Registers no MtProtoKit logging functions at all. This is not production-like; see the logging row below |

stdout carries exactly one line: the JSON report. At startup, file descriptor 1 is redirected to
stderr, so nothing a library prints can reach stdout.

stderr gets a one-line summary and the first five request failures (all failures with
`MTPROTOKIT_BENCH_LOG`).

The exit code is 0 whenever a report is printed, including when requests failed.

## How MtProtoKit is set up, and the production code it mirrors

TelegramCore references are under `submodules/TelegramCore/Sources/Network/`.

| Piece | Bench | Production |
|---|---|---|
| `MTContext` | `MTContext(serialization:encryptionProvider:apiEnvironment:isTestingEnvironment: false, useTempAuthKeys:)` with `OpenSSLEncryptionProvider` | `initializedNetwork` in `Network.swift` |
| `MTSerialization` | `currentLayer` = 230. `parseMessage` boxes the raw body; it returns nil only for bodies under 4 bytes. `exportAuthorization`, `importAuthorization` and `requestNoop` encode the real TL. `requestDatacenterAddress` encodes `help.getConfig`, and its parser returns nil because the fake server has no config | `State/Serialization.swift` (`Api.parse`) |
| `MTApiEnvironment` | `MTApiEnvironment(deviceModelName:)`, `apiId` 9, `appVersion` "1.0", `langPack` "macos", `layer` 230, `disableUpdates` false, `withUpdatedLangPackCode("en")`, `withUpdatedNetworkSettings(reducedBackupDiscoveryTimeout: false)` | same calls in `initializedNetwork` |
| MTProxy | `withUpdatedSocksProxySettings(MTSocksProxySettings(ip: host, port: port, username: nil, password: nil, secret: secretBytes))`. The DC 2 address is then `149.154.167.51:443`, as in the Rust client | `ProxyServerSettings.mtProxySettings` (`Settings/ProxySettings.swift`) |
| Addresses | `setSeedAddressSetForDatacenterWithId(2, [--address])` | seed list, port 443 |
| Keychain | in-memory `MTKeychain` that archives with `NSKeyedArchiver` and reads with `MTDeprecated.unarchiveDeprecated`, like TelegramCore's `Keychain` | `Keychain` class in `Network.swift`, backed by Postbox |
| Fake-mode key | `updateAuthInfoForDatacenterWithId(2, selector: .persistent)` with the `--key-hex` key. `authKeyId` is the last 8 bytes of `MTSha1(key)` read little-endian, exactly what `MTDatacenterAuthMessageService` stores. `validUntilTimestamp` is `INT32_MAX`. One `MTDatacenterSaltInfo` holds `--salt`, valid from now−1 day to now+1 day (`seconds << 32`). There are no attributes, so the first request carries `initConnection` | key created by the handshake |
| Main session | `MTProto(context, 2, usage, requiredAuthToken: nil, master: 0)` with `useTempAuthKeys = context.useTempAuthKeys` and `checkForProxyConnectionIssues = true`. It has an `MTProtoDelegate` connection-status delegate, an `MTRequestMessageService` with delegate and `didReceiveSoftAuthResetError`, and an update-sink `MTMessageService`, then `resume()` | `MtProtoKitSession` role `.main` (`MtProtoKitEngine.swift`), resumed by `shouldKeepConnection` |
| Worker sessions (`media`/`mixed`) | one `MTProto` per worker, with its own session and TCP connection. `media = true`, `cdn = false`, `useTempAuthKeys = context.useTempAuthKeys`, `getLogPrefix`, and no required auth token because DC 2 is the master DC. `MTRequestMessageService.forceBackgroundRequests = true` (`invokeWithoutUpdates`), request-service delegate, then `resume()` | `MtProtoKitSession` role `.worker(masterDatacenterId:isMedia: true, isCdn: false)`, created by `Download` / `Network.download(datacenterId:isMedia:)` |
| Small calls | `dependsOnPasswordEntry = false`, `needsTimeoutTimer = false`, `expectedResponseSize = 0`. `shouldContinueExecutionWithErrorContext` is `networkRequestErrorPolicy(automaticFloodWait: true, failOnServerErrors: false)`, which is always true, so FLOOD_WAIT and 500 are retried inside MtProtoKit. No quick-ack, progress or dependency callbacks | `Network.request` (`NetworkEngineRequestOptions()`) → `MtProtoKitRequestService.add` |
| Media parts | same, plus `expectedResponseSize = --part-size` and `needsTimeoutTimer = true` | `Download.part` / `Download.rawRequest` via `MultiplexedRequestManager`: `expectedResponseSize: limit` and `needsTimeoutTimer: useRequestTimeoutTimers`. `Account.swift` sets that flag to true unless `ios_killswitch_disable_request_timeout` is set |
| Logging | MtProtoKit logging functions registered, `MTLogSetEnabled(false)` | `NetworkRegisterLoggingFunction()`; logs stay off unless the user turns them on. Registering the functions matters: whenever one is registered, `MTShortLog` formats strings for every outgoing message |
| Usage accounting | `MTNetworkUsageCalculationInfo` per session, with a `network-stats` file in a temp directory and the same key layout: generic category for main, video for workers | `usageCalculationInfo(basePath:category:)` |

MtProtoKit's defaults are left alone. That covers containers, acks, padding, the transport choice
(obfuscated abridged, or padded intermediate for `dd`/`ee`), the GCDAsyncSocket socket interface,
actualization pings, resends and salt handling. All `MTProto` instances share MtProtoKit's process-wide
`managerQueue` and `tcpQueue`, as in the app.

Each response is checked as the contract requires:

- small calls: the tag;
- sized calls: tag 1012 and the payload length;
- real mode: any non-error body of at least 4 bytes.

The parser copies the payload out of the response, as both TelegramCore's TL parser and the Rust client
do. A request counts as failed on a failed check, on an `MTRpcError`, or if it is still pending at
`--deadline`.

The workload loops follow the Rust client (`crates/mtproto-bench/src/client.rs`):

- the same tags (`1 + index % 900`) and the same 8-byte request-index payload;
- the same issue order and outstanding limits;
- the same `getConfig`/`getNearestDc` alternation.

Waits are capped at 100 ms for `latency`, `small` and `real-config`, 10 ms for `media` and `mixed`, and
5 ms for `steady`, as in the Rust client. The driver also wakes up for the next scheduled probe or
`steady` request, so issue times are on schedule rather than up to one wait late.

The driver runs on its own thread and waits on a condition variable that request completions signal.
Completions run on MtProtoKit's `managerQueue`, as in the app. The main thread runs `dispatchMain()`, so
main-queue work behaves as in an application. Timestamps come from the monotonic uptime clock. Sessions
stay alive until the process exits, so no teardown runs while the report is written.

A time profile of `small` at 128 outstanding shows the harness costs little. The driver thread is idle
about 93% of the time. The completion callback takes about 5% of `managerQueue`. That queue is saturated
by MtProtoKit itself; for example, about 29% of its samples are in
`-[MTSessionInfo assignTransactionId:toScheduledMessageConfirmationsWithIds:]`.

## Differences from production

Some of these cannot be avoided; others are deliberate choices.

1. **No TelegramCore above MtProtoKit.** There are no Signals, no `MultiplexedRequestManager` and no
   `retryRequest`. TelegramCore's `Download.part` retries a failed part forever at the Signal level, but
   the contract wants failures counted, so the bench does not retry. MtProtoKit's own internal retries
   still happen: flood wait, 500, resend after reconnect, and the request-timeout reset.
2. **No temporary keys by default.** Production sets `useTempAuthKeys = true`: a temp key per
   connection, bound with `auth.bindTempAuthKey`. The fake server cannot bind temp keys, so fake mode
   uses the persistent key. Real mode also defaults to the persistent key only, because the Rust
   reference client does not create temp keys (`temporary_expires_in: None`) and the handshake work
   should be equal. `--temp-keys 1` turns on the production behaviour: one more DH handshake plus a bind
   before the first request.
3. **Real-mode handshake shape.** MtProtoKit runs the DH exchange on a separate throwaway `MTProto`
   with its own TCP connection. The main session then reconnects and sends a time-fix ping, which the
   server answers with `bad_server_salt`, and only then sends the first request. That makes three TCP
   connections and an extra round trip before the first answer: 1.6 s and 2.5 s to DC 2 in our two runs.
   This is MtProtoKit's real behaviour, but take it into account when comparing first-request latency.
4. **No `initConnection` params.** Once it has app configuration, production sends `systemCode` (the
   app config JSON, `initConnection` flag 1). The fake server cannot parse JSON params, so the bench sends
   none, and neither does the Rust client. `MTApiEnvironment` reads `systemLangCode` and `systemVersion`
   from the host, for example `en-GB` and `26.4`. They add a few bytes to the first request only.
5. **Not wired up:**
   - backup address discovery (DoH);
   - APNS and reCAPTCHA verification;
   - the `NetworkHelper` context listener, so `isContextNetworkAccessAllowed` defaults to allowed and
     there are no CDN keys;
   - the Network.framework socket interface, used only by beta builds on macOS 14+;
   - the WEB proxy carrier;
   - Postbox-backed keychain I/O.

   Apart from keychain I/O, these only act on connection problems or in other configurations. Under
   long fake outages, though, production would also start backup discovery, and the bench does not.
6. **Process startup is part of the measurement.** Start-up of the Swift runtime, Foundation, OpenSSL
   and MtProtoKit counts toward CPU time and RSS. It costs about 10 MB of RSS and a few ms of CPU.

## Notes from validation (2026-10-01)

- **Pass/fail.** Every workload passes in fake mode, both direct and through `dd` and `ee` secrets.
  Real mode passes against `149.154.167.51:443` (5/5 in each of two runs). The orchestrator's quick suite
  runs end to end with this client.
- **Fake TLS needs a server fix.** MtProtoKit's current ClientHello template is Chrome-like, with an
  X25519MLKEM768 key share, and comes to about 1.5 KB (1520 and 1534 bytes observed). `mtproto-testserver`
  reads exactly `CLIENT_HELLO_LEN` (517) bytes and checks the HMAC over those, so it closes every
  MtProtoKit fake-TLS connection. The symptoms are that `connections` grows, `executions` stays 0, and
  every request fails at the deadline. Real MTProxy servers read the record length instead.

  The fix is in the server:

  1. Read the 5-byte record header.
  2. Read the record's length from it.
  3. Compute the HMAC over the whole record, with bytes 11..43 zeroed.

  The validation runs used a scratch copy of the server with that change.
- **Fake-TLS CPU.** MtProtoKit's fake-TLS path is CPU-heavy: about 2.3 s of CPU for 128 MiB, against
  0.45 s without TLS. Throughput through the fake server drops from about 600 MB/s to about 240 MB/s.
  This is MtProtoKit's own cost.
- **`media/flaky` livelocks MtProtoKit.** It completed only 5–6 of 24 parts, with about 480 duplicate
  server executions and 201 connections. Two behaviours combine here:
  - After a reconnect, MtProtoKit re-sends every in-flight request with a new msg_id.
  - The fake server re-pushes every unacknowledged answer on each new connection.

  About 170 full 512 KB answers arrived for old msg_ids and were dropped with "didn't match any request".
  With 2–6 s connection lifetimes at 1 MB/s, little useful data gets through. The root cause is
  MtProtoKit's policy. How strongly it shows depends on whether real DCs re-push unacknowledged
  `rpc_result`s on a new connection the way the fake server does.
- **`steady/fake-tls-proxy-flaky`: one request is never answered.** It was written onto a fake-TLS
  connection that the netsim closed during the TLS handshake. Its write completion never fires, so
  MtProtoKit never re-sends it, and it stays pending until the deadline. This is defect H4 in
  `docs/research/mtprotokit.md`. Because the client stays connected until the deadline, the scenario also
  shows many more connections for MtProtoKit (28 against 4).
