# Swift integration (`MTProtoRustEngine`)

How the Rust engine is wired into TelegramCore's `NetworkEngine` seam on macOS (and later iOS).
Companion to `research/seam-implementation.md` (the seam and its 14 rules) and
`research/integration.md` (the contract TelegramCore relies on, persistence invariants, risks).

Path prefixes: `TC/` = `submodules/telegram-ios/submodules/TelegramCore/Sources/`,
`PKG/` = `submodules/telegram-ios/submodules/MTProtoRustEngine/`, `MAC/` = macOS repo root.

## 1. Architecture

```
TelegramCore Network / Download
   │  NetworkEngineFactory.makeEngine(context:isAppExtension:)   (TC/Network/Network.swift resolveNetworkEngine)
   ▼
RustNetworkEngineFactory ── RustNetworkEngine(context) ── makeSession(dc, role, usage, delegate)
                                                              │
                                     RustNetworkSession (one per MTProto session; own serial Queue)
                                     ├─ RustRequestService      (weak session; NetworkEngineRequestService)
                                     ├─ RustContextListener     (MTContextChangeListener -> session queue)
                                     ├─ RustEngineMailbox       (weak session + queue, registered by handle)
                                     └─ MTNetworkUsageManager   (data-usage file, per usage category)
                                                              │ C ABI (mtproto_engine.h)
RustEngineRuntime (process-wide, lazy) ── mt_engine_create(0 = engine default threads)
   ├─ handle -> mailbox table (NSLock)
   ├─ C event trampoline (engine thread): copies the event, wraps the payload, posts to the mailbox queue
   ├─ C log trampoline -> Logger.shared ("MTProtoRust")
   └─ MTNetworkAvailability -> mt_engine_set_network_available / mt_engine_reset_connections
```

- One engine per process, created on the first `makeEngine` (`RustEngineRuntime.shared`). It is never
  destroyed. All accounts share it; every account still has its own `MTContext` and sessions.
- `MTContext` stays the single owner and writer of persisted state. The engine never generates keys
  for TelegramCore (`generate_key = 0`); `MTContext` creates and binds them and the session installs
  them with `mt_session_set_auth_key`.
- The factory declines (TelegramCore then uses MtProtoKit) in app extensions, when the engine fails to
  start or reports an unknown ABI version, when the active proxy is a WEB proxy, and when
  `apiEnvironment.datacenterAddressOverrides` is set.

Files (`PKG/`):

| File | Contents |
|---|---|
| `Package.swift` | binary target `MTProtoEngineFFI` (`MTProtoEngineFFI.xcframework`, gitignored), targets `MTProtoRustEngineMapping` (pure Swift), `MTProtoRustEngine` (TelegramCore, MtProtoKit, SwiftSignalKit), two test targets |
| `Sources/MTProtoRustEngineMapping/RustEngineMapping.swift` | Pure decisions with no Telegram dependency: request flags, salt conversions, dependency selection, cumulative error state, parse failure policy, missing-key table, roles, obfuscation tag, address order, connection flags, `updatesTooLong` detection, verification literals |
| `Sources/MTProtoRustEngine/RustNetworkEngine.swift` | `RustNetworkEngineFactory` (public), `RustNetworkEngine` |
| `Sources/MTProtoRustEngine/RustNetworkSession.swift` | `RustNetworkSession`, `RustRequestService`, `RustPendingRequest` |
| `Sources/MTProtoRustEngine/RustEngineRuntime.swift` | process-wide engine, trampolines, routing, network availability, logging helpers |
| `Sources/MTProtoRustEngine/RustContextListener.swift` | `MTContextChangeListener` forwarding to the session queue |
| `Sources/MTProtoRustEngine/RustEngineEvent.swift` | Swift copy of `MTEvent` |
| `Sources/MTProtoRustEngine/RustEngineArena.swift` | scoped C memory for FFI arguments (zeroed on release), string/payload helpers |

## 2. Building

- `MAC/core-xprojects/mtproto-engine/mtproto-engine/build.sh SOURCE BUILD PACKAGE` runs
  `cargo build -p mtproto-ffi --release --locked` for `aarch64-apple-darwin` and `x86_64-apple-darwin`
  with `MACOSX_DEPLOYMENT_TARGET=10.13`, `lipo`s the two `libmtproto_engine_ffi.a`, and creates
  `PKG/MTProtoEngineFFI.xcframework`. The headers sit in `Headers/MTProtoEngineFFI/` (`mtproto_engine.h`
  plus `module.modulemap`, module `MTProtoEngineFFI`): Xcode copies every static xcframework's
  `Headers` into one `include/` directory, and a top-level `module.modulemap` would collide with
  `wallet_engineFFI.xcframework`'s ("Multiple commands produce .../include/module.modulemap").
- `MAC/core-xprojects/mtproto-engine/MTProtoEngine.xcodeproj` (shared scheme `MTProtoEngine`) has a
  Run Script that calls `build.sh` when `core-xprojects/mtproto-engine/build` or the xcframework is
  missing, exactly like `WalletEngine.xcodeproj`.
- `MAC/scripts/configure_frameworks.sh` builds it as library `mtproto-engine` / `MTProtoEngine`;
  `MAC/scripts/framework-inputs.sh` fingerprints `submodules/telegram-ios/third-party/mtproto-engine`
  plus `cargo --version` and deletes the xcframework when the inputs change.
- Ignored and never committed: `MAC/core-xprojects/mtproto-engine/build` (app `.gitignore`),
  `PKG/MTProtoEngineFFI.xcframework`, `PKG/.build`, `PKG/.swiftpm` (`PKG/.gitignore`). CI:
  `MAC/buildbox/build-mac.sh` excludes the xcframework from its `rsync --delete`.
- The package is linked to the **Telegram** app target only (Packages group + Frameworks phase +
  `packageProductDependencies` in `Telegram.xcodeproj`). TelegramShare does not link it, and
  `MAC/TelegramShare/ShareViewController.swift` passes no factory. `MAC/Telegram-Mac/app/AppDelegate.swift`
  passes `networkEngineFactory: RustNetworkEngineFactory()`. On iOS, `TelegramUI/Sources/AppDelegate.swift`
  passes it too; the Bazel targets are `//third-party/mtproto-engine:MTProtoEngineFFI` and
  `//submodules/MTProtoRustEngine:MTProtoRustEngine` (see the iOS bullet below).
- Manual rebuild: `sh core-xprojects/mtproto-engine/mtproto-engine/build.sh submodules/telegram-ios/third-party/mtproto-engine core-xprojects/mtproto-engine/build submodules/telegram-ios/submodules/MTProtoRustEngine`
  (needs `cargo` on `PATH` or in `~/.cargo/bin`).
- Tests: `cd PKG && swift test` (builds TelegramCore once, several minutes cold; then seconds).
- iOS (Bazel): `third-party/mtproto-engine/BUILD` builds `mtproto_core` and `mtproto_engine` as
  `rust_library` and `mtproto_engine_ffi_archive` as `rust_static_library` with pinned
  `-Copt-level=3 -Ccodegen-units=1 -Cpanic=abort` and **no LTO**, from the `mtproto_engine_crates`
  crate_universe repository pinned `=` to `Cargo.lock` (`MODULE.bazel`; `--cfg aes_armv8`, sha2's
  `asm` feature and `-Copt-level=3` for the crates with non-generic hot code are applied there by
  hand). `scripts/verify-ios-link.sh <unstripped binary>` checks
  one shared std and the ARMv8 AES / SHA-256 backends. The mapping tests run as the host `swift_test`
  `//submodules/MTProtoRustEngine:MTProtoRustEngineMappingTests`. Linking the engine costs
  +435,385 bytes of `release_arm64` `.ipa` and +853,904 bytes of `TelegramUIFramework` (measured
  2026-10-02 against `a4dc711011`).

The release profile uses thin LTO, so the archive members carry an `__LLVM,__bitcode` section that
Apple's `nm` cannot read (`nm --no-llvm-bc` works). The linker ignores it. That is the macOS
xcframework only; the iOS Bazel build has no LTO on purpose (§14, risk 5).

## 3. Threading

| Activity | Thread |
|---|---|
| `makeSession` (reads `MTContext` synchronously, `mt_session_create`) | caller (`Network.queue`, `Download` creator) |
| `add` | any; builds flags, then `queue.async` (runs inline when already on the session queue, which is how SwiftSignalKit queues behave) |
| dispose of a request | any; sets an atomic `cancelled` flag immediately, then `queue.async` to cancel in the engine |
| engine callbacks | engine reactor thread: copy strings/salts, wrap the payload, look up the mailbox under a lock, `queue.async`; nothing else runs there |
| event handling, request callbacks, sink delivery, delegate calls, `MTContext` writes | the session's serial queue (never the main thread) |
| `MTContextChangeListener` callbacks | `MTContext` queue, forwarded with `queue.async` |
| network availability | `MTNetworkAvailability` queue, straight into the engine |

Callbacks of one session are serialized and in receive order; different sessions run in parallel
(MtProtoKit uses one global queue). Session creation holds the routing lock across
`mt_session_create`, so the first events of a new handle cannot overtake its registration.

Payloads: each non-null `MTBuffer` is wrapped at once in `Data(bytesNoCopy:deallocator: .custom { mt_buffer_free })`
(zero-length buffers are freed immediately), so it is freed exactly once whether the event is
handled, dropped for an unknown handle, or dropped because the session is gone.

## 4. Requests

| `NetworkEngineRequest` | `MTRequest` / behaviour |
|---|---|
| always | `DelegateRetryDecisions`; no `AutomaticFloodWait`, `RetryServerErrors`, `ReportFloodWait` |
| `acknowledged != nil` | `QuickAck`; `Acknowledged` events call it (may fire repeatedly) |
| `progress != nil` | `Progress`; `Progress` events call `progress(Float(value1), Int(value2))` |
| `options.needsTimeoutTimer` | `TimeoutTimer` (engine `request_timeout = 5 s`) |
| worker session or `apiEnvironment.disableUpdates` | `WithoutUpdates` |
| `options.expectedResponseSize` | `expected_response_size` (negative -> 0) |
| `dependsOn` | `invoke_after` = engine id of the newest active request in the engine that `dependsOn(metadata)` accepts |
| `RetryDecisionRequired` | `shouldContinueAfterError(NetworkEngineErrorContext(integer1, text2 or nil, integer2))` -> `mt_session_decide_retry` |
| `Completed` | `parse(payload)`; non-nil -> `.success(result, info)` with `timestamp = value1`, `duration = value2`, `networkType = 0` |
| `parse` returns nil | `mt_session_invalidate_initialization` and the auth info's `apiInitializationHash` set to `""` in `MTContext`; then `500 TL_PARSING_ERROR` through `shouldContinueAfterError`; on `true` the same payload is resubmitted (new engine id) after 2 s; at most 3 attempts, then `.failure(500 TL_PARSING_ERROR)` |
| `Failed` | `.failure(MTRpcError(code, text), info)` |
| dispose | flag set, request removed, `mt_session_cancel`; later events for it are dropped |

The error context is cumulative per request across resubmissions (`RustEngineErrorState`): the last
flood wait seconds/text stay set, server error counts of earlier submissions and parse failures are
added. Requests of a session that is gone (`RustRequestService.session == nil`) are accepted and never
complete, as the seam requires.

Workers that need an imported authorization (`dc != master`, not CDN) keep new requests in Swift
until an auth key is installed, then install the key, re-assert `mt_session_set_auth_token_ready`
and send them (see 9).

## 5. Event mapping

| Event | Handling |
|---|---|
| `Completed`, `Failed`, `RetryDecisionRequired`, `Acknowledged`, `Progress` | section 4 |
| `FloodWaitReported`, `Pong`, `Closed` | ignored (`ReportFloodWait` is never requested) |
| `VerificationRequired` | APNS: `context.performExternalRequestVerification(withNonce:)`; reCAPTCHA: `performExternalRecaptchaRequestVerification(withMethod:siteKey:)`. First value -> `mt_session_resolve_apns(nonce, value)` / `mt_session_resolve_recaptcha(value)` (nil -> empty string, as MtProtoKit encodes it), including TelegramCore's own 15 s timeout literals. Signal completes or errors without a value, or 20 s pass: `mt_session_fail_request(403, "APNS_PUSH_TIMEOUT" / "RECAPTCHA_TIMEOUT")` |
| `AuthorizationRequired` | main session only: logged to the log and short log, then `delegate.networkSessionAuthorizationRequired()` (MtProtoKitEngine does the same; `Network` logs the account out). The engine emits it only for a main-session `401` that is not `SESSION_PASSWORD_NEEDED`; `AUTH_KEY_PERM_EMPTY` never gets here |
| `SoftAuthReset` | main only: `delegate.networkSessionSoftAuthReset()` |
| `AuthTokenRequired` | worker token re-transfer: `updateAuthTokenForDatacenter(dc, nil)` + `authTokenForDatacenter(withIdRequired: dc, authToken: required token, masterDatacenterId:)`; marks the token missing |
| `Failed` with `401`, not `SESSION_PASSWORD_NEEDED`, on a worker | the same re-transfer before completing (skipped when the previous event was `AuthTokenRequired`, which newer engine builds emit for every such 401) |
| `TemporaryKeyRejected` (`AUTH_KEY_PERM_EMPTY`) | handleMissingKey (section 9); the session is held paused until a replacement key is installed |
| `AuthKeyInvalid` (`-404`) | handleMissingKey; the engine has already dropped its key and re-queued the requests |
| `AuthKeyRequired` | install the context's key for the session selector if present (and not the rejected one); otherwise wait for it and, while resumed, `authInfoForDatacenter(withIdRequired:isCdn:selector:allowUnboundEphemeralKeys: false)` |
| `InitHashStored` / `InitHashCleared` | write/remove `authKeyAttributes["apiInitializationHash"]` in `MTContext` (only if the context still holds the installed key) |
| `UpdatesReset` | every sink: `networkSessionDidReset()` |
| `Update` | `context.serialization.parseMessage(payload)` -> every sink `networkSessionDidReceive(message:)`, in order. An `updatesTooLong` directly after `UpdatesReset` is skipped, because the engine emits that reset for it and the sink would reset twice |
| `TimeDifferenceUpdated` | `context.setGlobalTimeDifference(value1)` |
| `SaltsUpdated` | merged into the installed key's auth info with `mergeSaltSet(_:forTimestamp: context.globalTime())` and written back (section 6) |
| `ConnectionState` | main only, to `networkSessionConnectionStateChanged` (deduplicated); `proxyAddress` is the proxy's `ip` like MtProtoKit. While the session is held for a replacement key or an unsupported proxy and not paused by TelegramCore: reported as connecting (`isNetworkAvailable` from reachability, `proxyHasConnectionIssues` for the proxy case). Also drives the connection watchdog |
| `NetworkUsage` | `MTNetworkUsageManager(info: usageCalculationInfo)`: `addIncomingBytes`/`addOutgoingBytes`, interface `Other` |
| `AddressResult` | `reportTransportSchemeSuccess` / `reportTransportSchemeFailure` for the scheme at that index |
| `AuthKeyCreated`, `AuthKeyCreationFailed`, `TransportFlood` | logged only (`AuthKeyCreated` cannot happen with `generate_key = 0`; its payload is freed) |

## 6. MTContext reads and writes

| Read | When | Use |
|---|---|---|
| `apiEnvironment` | session creation, `contextApiEnvironmentUpdated` | `MTEnvironment`: `layer = serialization.currentLayer()`, `apiId`, `deviceModel`, `systemVersion`, `appVersion`, `systemLangCode`, `langPack`, `langPackCode`, proxy iff `socksProxySettings.secret != nil` (`ip`, `port`), params iff `systemCode != nil`, `init_hash = apiInitializationHash` (MtProtoKit's string, unchanged), `disableUpdates`. Proxy (`MTProxy`): SOCKS5 or MTProxy from `socksProxySettings` |
| `transportSchemesForDatacenter(withId:media:enforceMedia:false isProxy:)` + `chooseTransportSchemeForConnection` | creation, resume, `contextDatacenterTransportSchemesUpdated` | address list: chosen scheme first, other IPv4, IPv6 only when MTContext would try IPv6; per-address secrets passed. Empty -> `transportSchemeForDatacenter(withIdRequired:media:)` |
| `authInfoForDatacenter(withId:selector:)` | creation, `AuthKeyRequired` | key (256 bytes), salts (`MTDatacenterSaltInfo` message ids / 2^32 -> seconds), `apiInitializationHash` attribute |
| `authTokenForDatacenter(withId:)` | creation, resume | token readiness of foreign-DC workers (`NSNumber(dc)`) |
| `globalTimeDifference()` | creation | engine time difference |
| `useTempAuthKeys`, `isTestingEnvironment`, `serialization` | creation | selector, obfuscation tag, layer, `parseMessage`, `requestNoop` |

| Write (all through `MTContext` mutators, never the keychain) | Trigger |
|---|---|
| `setGlobalTimeDifference` | `TimeDifferenceUpdated` |
| `updateAuthInfoForDatacenter` with merged salts (same key id only) | `SaltsUpdated` |
| `updateAuthInfoForDatacenter` with `apiInitializationHash` set/removed/`""` (same key id only) | `InitHashStored`, `InitHashCleared`, unparsable result |
| `performBatchUpdates { updateAuthInfo(nil, selector); authInfoForDatacenter(withIdRequired:) }` | handleMissingKey for ephemeral and CDN keys |
| `removeTokenForDatacenter` | handleMissingKey on a foreign-DC worker |
| `updateAuthTokenForDatacenter(nil)` + `authTokenForDatacenter(withIdRequired:)` | worker 401 |
| `authTokenForDatacenter(withIdRequired:)`, `authInfoForDatacenter(withIdRequired:)` | resume, `contextDatacenterAuthTokenTransferFailed`, `contextDatacenterAuthInfoRequestFailed` |
| `checkIfLoggedOut` | handleMissingKey for a persistent non-CDN key (unreachable today: TelegramCore always uses temporary keys outside CDN) |
| `reportTransportSchemeSuccess/Failure`, `invalidateTransportScheme` | `AddressResult`, 20 s connection watchdog |

Read-modify-write of an auth info runs inside one `performBatchUpdates` block on the context queue.
The persistent key of the master DC is never created, replaced or removed (integration.md 4.4 (1)).

Listener callbacks used: `contextDatacenterAuthInfoUpdated` (declared on a base class so its
parameter can be optional: MTContext passes nil there despite the header), `contextDatacenterAuthTokenUpdated`,
`contextDatacenterAuthInfoRequestFailed`, `contextDatacenterAuthTokenTransferFailed`,
`contextDatacenterTransportSchemesUpdated`, `contextApiEnvironmentUpdated`. Not implemented on
purpose: `isContextNetworkAccessAllowed`, `fetchContextDatacenterPublicKeys`, `contextLoggedOut`
(MTContext uses the last listener that answers them; `NetworkHelper` owns them).

`contextApiEnvironmentUpdated`: `mt_session_update_environment` with a `help.test` built by
`serialization.requestNoop` (flags `AutomaticFloodWait` [+ `WithoutUpdates`], no error gate, as
MtProtoKit's no-op); the engine sends it only when the init hash changed. Proxy changed ->
`mt_session_set_proxy` (WEB proxy: hold, see 10); only `langPackCode` changed -> the connection is
reset (pause + resume), as MtProtoKit resets its transport.

## 7. Session roles and setup

| `NetworkEngineSessionRole` | engine role | selector | other setup |
|---|---|---|---|
| `.main` | `Main` | `ephemeralMain` (`ephemeralMedia` if its addresses prefer media) | `keep_connected = 1` |
| `.worker`, `dc == master` | `Worker` | by the address class | idle disconnect 60 s |
| `.worker`, `dc != master`, not CDN | `WorkerRequiringAuthToken` | by the address class | token `NSNumber(dc)` from `master` |
| `.worker`, CDN | `Cdn` | `persistent` | |

All sessions: created paused, `framing = Abridged` (the engine switches to padded intermediate for
`dd`/`ee` secrets), `online = 0`, `request_timeout = 5`, `time_difference` from the context,
obfuscation tag `dc` (+10000 in the test environment, negative for media addresses). The selector and
the obfuscation tag follow the address class, as MtProtoKit picks the selector per transport scheme: when
an address update moves a session between media and other addresses, it pauses the engine session,
sets the new tag and addresses, and installs the context's key for the new selector, or holds until that
key exists. A backup config fetch can drop a datacenter's media addresses; a session that kept the media
selector then sent its media key to a main address, got `-404`, and could not get a replacement, because
media keys are only created on media addresses (`enforceMedia`).

Pause: `setPaused` from TelegramCore is combined with two internal holds (replacement key pending,
unsupported proxy); the engine is paused while any is set. Resume re-reads schemes, re-asks for an
awaited key and for a missing token. `stop()` (workers) and `deinit` (main) unregister the handle,
`mt_session_destroy` and remove the context listener; pending requests then never complete, as with
MtProtoKit's `stop()`.

## 8. Logging

Tag `MTProtoRust`, prefix `[MTProtoRust#<handle> dc<N> <main|worker|media|cdn>]`. Per-request lines
and engine info/debug lines only when `MTLogEnabled()` (the network logging switch); engine
errors/warnings, pause/resume, 401s, key loss, proxy changes and verification go to the log and the
short log. `Logger` itself drops everything when file and console logging are off.

## 9. Keys and tokens (MtProtoKit `handleMissingKey`, `mtprotokit.md` 3.7.2)

| Condition (first match) | Action |
|---|---|
| CDN session | drop the selector's key and require a new one (`isCdn: true`) |
| foreign-DC worker | `removeTokenForDatacenter(dc)`, drop and require the key, mark the token missing |
| ephemeral selector | drop and require the key |
| otherwise (persistent key) | `context.checkIfLoggedOut(dc)` only; the same key is reinstalled on `AuthKeyRequired` |

While waiting, the rejected key id is remembered so a context key with that id is never reinstalled.
If the context already holds a different key for the selector when a key is rejected (another session
replaced it), that key is installed instead of being dropped; MtProtoKit drops whatever the context
holds, which costs an extra key exchange and bind (integration.md R14).
A key arriving through `contextDatacenterAuthInfoUpdated` for the awaited selector is installed
(`mt_session_set_auth_key`), the hold is released, held requests are sent, and a foreign-DC worker
re-asserts its token gate. A nil update for the selector from another session puts the session into
the same waiting state (MtProtoKit drops its cached key there too); non-nil updates with another key
are ignored while the installed key works (MtProtoKit never revalidates its cached key either).

Tokens: a foreign-DC worker starts with the token gate closed when the context has no token, asks for
a transfer on resume, and opens the gate on `contextDatacenterAuthTokenUpdated` with `NSNumber(dc)`.

## 10. Connection management

- Reachability: one `MTNetworkAvailability`; every change calls `mt_engine_set_network_available`,
  and when available `mt_engine_reset_connections` (MtProtoKit drops each connection on any change).
- Watchdog: when a session wants a connection (resumed, has addresses, main or with active requests,
  network available) and has not received a packet for 20 s, the first scheme gets
  `reportTransportSchemeFailure` + `invalidateTransportScheme(isProbablyHttp: false, media:)`, which
  starts MTContext's scheme discovery and backup address discovery (MtProtoKit's 20 s transport
  watchdog). It re-arms after the next healthy connection.
- Proxies: SOCKS5 (with credentials) and MTProxy (plain, `dd`, `ee`) are carried by the engine. A WEB
  proxy cannot be: the factory declines at start, and a session that sees one later stays paused and
  reports "connecting, proxy has issues" instead of connecting directly (fail closed).

## 11. Deviations from MtProtoKit

| Behaviour | MtProtoKit | Rust wrapper | Why |
|---|---|---|---|
| Unparsable result | retried every 2 s while the gate allows | at most 3 attempts | requested cap; a deterministic parse failure otherwise loops forever |
| APNS / reCAPTCHA verification without a value | request parked forever (macOS verifiers complete empty) | fails with `403 APNS_PUSH_TIMEOUT` / `403 RECAPTCHA_TIMEOUT` | requested; uses TelegramCore's literals |
| `AUTH_KEY_PERM_EMPTY` | drops the whole packet, transport reset, waits for a key with no transactions | engine parks the request (backoff); wrapper pauses the session until the replacement key arrives | same effect without an FFI to drop a key without losing requests |
| Callback queue | one global manager queue | one serial queue per session | parallelism; ordering per session is kept |
| Liveness | 12 s response timer after a write, no pings | engine pings with tdlib's timing, `online` following `Network.isUserOnline` (wired on iOS only; macOS stays offline-timed): online, ping every ~1–2 s and disconnect after ~5–7 s; offline (background, secondary accounts) ~60 s and ~135 s without reads; 5 s timer only for `needsTimeoutTimer` | see risks |
| Worker connections | kept while resumed | idle workers disconnect after 60 s | engine default; reconnect on the next request |
| Token gating | only at transport reset; a 401 parks only that request | engine gates every request while the token is missing | engine semantics; same outcome once the token arrives |
| IPv6 | chosen per connection by scheme stats | IPv6 addresses appended only when MTContext would consider IPv6 at creation/refresh | the engine cycles a fixed list |
| SOCKS5 + per-address secret | address secret used through SOCKS5 | ignored by the engine | engine `proxy_secret` returns nil for SOCKS5 |
| `-503` and other negative codes | surfaced | engine asks for a retry decision (server error) | engine semantics |
| Main session lifetime | retained forever by the update-service cycle | destroyed with its `Network` | no cycle needed; sockets close |
| Duplicate reset for `updatesTooLong` | one `.reset` | one `.reset` (wrapper skips the second) | engine emits both |
| Cancelling an in-flight request with `expectedResponseSize >= 512 KB` | new session id + transport reset | engine sends `rpc_drop_answer` and resets the connection, session kept | engine semantics |
| Proxy connection issues | `MTConnectionProbing` (proxy unreachable while the internet is reachable) | engine flag: proxy set, not connected, 3+ failed attempts | engine semantics |
| Key rejected while the context already has a newer key | drops it and asks for another | installs the newer key | avoids rebind storms (R14) |
| Network type | wifi/cellular per socket | cellular when the socket's local address is on a `pdp_ip*` interface | same accounting (`72d7e51f95`) |
| Main-session `401` | logs out | logs out (`rustEngineAuthorizationRequiredAction`) | R1's `checkIfLoggedOut` probe cannot confirm it: its `EphemeralMain` auth action completes on the stored temporary key without contacting the server (§14, risk 1) |

## 12. Known gaps and FFI requests

Status (2026-10-02): items 1, 2, 4, 5 and 6 are fixed in the engine by `72d7e51f95` (token gate
across key swaps, `set_auth_key(None)` keeps requests, live `set_obfuscation_dc_id`, connect
timeouts report the address, `NetworkUsage` reports cellular). Item 7 is addressed by
`RustEngineEndToEndTests`, which drives the `mtproto-testserver` binary. Item 8: the iOS Bazel
targets exist (§2); `build.sh` still builds no iOS slices, which iOS does not use. Item 3 remains
open. The design agreed for iOS: mirror MtProtoKit's selection, i.e. own sockets when
`context.makeTcpConnectionInterface` is nil and the injected interface (Network.framework,
the WEB proxy carrier) when set; a host-stream C ABI (`open`/`write`/`read`/`close` callbacks,
host-to-engine `connected`/`received`/`closed` keyed by session and a never-reused `conn_id`, one
outstanding read as back-pressure); an optional `readAvailableDataWithMaxLength:` on
`MTTcpConnectionInterface`; no name resolution in Rust on that path (it would leak the WEB relay's
hostname); the engine as the only byte counter; the carrier paired with the WEB proxy setting
exactly as `MTTcpConnection` does; iOS only.

1. **Token gate lost on key install.** `RpcClient::new` starts with `auth_token_ready = true` and
   `SessionRuntime::set_auth_token_ready` is a no-op without an `rpc`. Requests the engine re-queued
   after `-404` are dispatched during `install_key`, before the following `SetAuthTokenReady(false)`,
   so a foreign-DC worker can send them without an imported authorization (one extra `401` and
   re-transfer; nothing is lost). Fix: keep the flag in `SessionRuntime` and pass it to `RpcClient::new`.
2. **`mt_session_set_auth_key` with an empty key drops all requests** (`set_auth_key(None)` discards the
   `RpcClient`). The wrapper never calls it; an FFI to drop a key while keeping requests (as `-404`
   does) would replace the pause hold.
3. **No injected transport.** `context.makeTcpConnectionInterface` (NWConnection on macOS 14+, WEB
   proxy carrier) cannot be used; the engine always opens its own sockets. Needs a byte-stream
   callback interface in the C ABI.
4. **No `AddressResult` on connect timeouts**, hence the Swift watchdog.
5. **Network interface** is not reported with `NetworkUsage`; iOS cellular accounting needs it.
6. iOS: no Bazel `BUILD` for the package or the xcframework, no iOS slices in `build.sh`.

## 13. Tests

- `MTProtoRustEngineMappingTests` (pure Swift): flag mapping, salt conversions (msg id <-> seconds,
  placeholder salts), dependency selection, cumulative error context, parse failure cap, missing-key
  table, worker 401 rule, roles, obfuscation tag, address order, connection flags, `updatesTooLong`,
  verification literals.
- `MTProtoRustEngineTests`: arena and string bridging, `MTEvent` copy, event kinds and flags against
  the C header, listener selectors as the Objective-C runtime sees them, engine start and request ids,
  raw session create/destroy through the routing table. `RustEngineEndToEndTests` runs
  `RustNetworkSession` against the `mtproto-testserver` binary (`cargo build -p mtproto-testserver`
  first): completion, cancellation, flood waits, dropped connections, salt changes, a worker sharing the
  main session's engine, and a media worker following its addresses between media and main keys. It
  needs the shared logger that `RustEngineBridgeTests` installs, so run the whole test target.

## 14. Risks (not yet exercised at runtime)

1. **Logout path.** `AuthorizationRequired` is forwarded exactly like MtProtoKitEngine does, so any main
   session `401` other than `SESSION_PASSWORD_NEEDED` logs the account out. If the engine ever sends a
   request with a key the server does not associate with the authorization and gets
   `AUTH_KEY_UNREGISTERED` instead of `AUTH_KEY_PERM_EMPTY`, that is irreversible. integration.md R1's
   suggestion, routing the callback through `MTContext.checkIfLoggedOut`, does **not** work and was
   withdrawn (2026-10-02): `checkIfAuthKeyRemovedWithContext` runs an `EphemeralMain` auth action, and
   `-[MTDatacenterAuthAction execute:]` completes at once when the context stores a key for that
   selector, which the main session's own temporary key always is. The probe never reaches the server,
   always reports "not removed", and a session terminated from another device never logged out. A
   working safety net needs a different confirmation (for example a rebind of a fresh temporary key
   and logging out on a second `401`).
2. **Liveness.** Sessions follow `Network.isUserOnline` (`Account.shouldKeepOnlinePresence`, wired on iOS
   only). Online, a
   dead connection is dropped after about `2.5 × max(2, 1.5·rtt + 1)` s; offline (background, secondary
   accounts) it still takes ~60–135 s, where MtProtoKit closes after 12 s without a response. The online
   ping cadence keeps the cellular radio active while the app is in front. Reachability changes and
   sleep/wake (pause/resume) still reconnect at once.
3. **Foreign-DC token race** (gap 1): fixed by `72d7e51f95`; the token gate now survives a key swap.
4. **Transport.** No NWConnection and no WEB proxy carrier. On macOS a WEB proxy chosen while running
   moves a Rust network to MtProtoKit live (`SwitchingNetworkEngine`), and turning it off moves it
   back. On iOS there is no live switching: the Rust sessions hold ("connecting, proxy has issues")
   until the next launch, when the factory declines and MtProtoKit is used.
5. **Several Rust static libraries** (wallet, tlottie, MTProto) share one copy of the Rust standard
   library in the iOS app: they are built by the same `rules_rust` toolchain, so each archive embeds
   identical std members and ld64 loads a member only for a still-undefined symbol (measured: one
   `core`/`alloc`/`std` crate in `TelegramUIFramework`). That breaks if a library is LTO'd into its own
   archive (std is then internalized and duplicated, as in the macOS xcframework) or built by another
   toolchain. `scripts/verify-ios-link.sh` checks it.
6. The xcframework is built from whatever is in `third-party/mtproto-engine`; the framework stamp
   changes with every edit there, so `configure_frameworks.sh` rebuilds it.
