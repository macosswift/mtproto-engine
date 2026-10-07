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
- `MTContext` stays the single owner and writer of persisted state. With temporary keys on (every
  non-CDN session in TelegramCore), the engine runs PFS itself (section 9a): it makes and binds its
  temporary keys over whichever transport works, HTTP included, and the session writes them to
  `MTContext`, which keeps them for other sessions, later launches and MtProtoKit. CDN sessions still
  take their keys from `MTContext` (`generate_key = 0`) and install them with `mt_session_set_auth_key`.
- Every non-CDN session runs `MTTransportAuto`: TCP while it answers, HTTP on port 80 while it does not.
- Route memory: the runtime names the network the device is on (`mt_engine_set_network`, a salted hash
  of the active interfaces' IPv4 networks and IPv6 /64s plus their services' routers on macOS; VPN
  tunnels, virtual machine links and link-local addresses ignored, cellular alone is one network) at
  start and whenever the system reports an interface or route change (SCDynamicStore on macOS,
  NWPathMonitor on iOS), all on one serial queue. It loads the stored memory at start
  (`mt_engine_set_route_memory`) and stores what `MTEventKindRouteMemoryChanged` (session 0, reported
  in the order the memory changed) reports in `UserDefaults` (`mtproto.routeMemory.v1`). On a network
  where TCP did not get through in the last 7 days, Auto sessions without a proxy try HTTP after 0.3 s
  of TCP silence instead of 2.5 s; the network is forgotten as soon as such a session's TCP connection
  there answers. Sessions behind a proxy neither learn nor use the memory.
- Telegram Web's endpoints: on macOS 10.14+ and iOS 12+ the runtime registers a stream host
  (`RustStreamHost`, `mt_engine_set_stream_host`) that opens TLS streams with Network.framework: the
  web host as SNI, ALPN `http/1.1`, no certificate check (TLS only disguises the connection; MTProto
  protects what it carries), and the system's own TLS stack, so the ClientHello is the platform's.
  Every non-CDN session gets Telegram Web's endpoints for its datacenter
  (`mt_session_use_telegram_web`: `{pluto,venus,aurora,vesta,flora}.web.telegram.org`, the `-1` fronts
  for sessions other than the main one, `/apiws` and `/apiw1`, `/apiws_test` and `/apiw_test1` on the
  test servers). Once TCP is silent, Auto probes the WebSocket endpoint beside plain HTTP, and HTTPS
  once the WebSocket fails or stays silent for 1.5 s. A WebSocket that answers carries the session's
  stream transport as TCP would (obfuscated, pings at least every 45 s because the fronts close idle
  WebSockets after 91 s), until a TCP recheck answers or it fails twice in a row; HTTP sessions use
  HTTPS as one more route. A proxy turns them off. The engine opens, writes, confirms and closes host streams like sockets: writes wait while 1 MB
  is unconfirmed (`mt_stream_sent`), and the host stops receiving at 4 MB held until `resume`.
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
| `FloodWaitReported`, `Pong` | ignored (`ReportFloodWait` is never requested); a `Pong` counts as hearing the server for the local health check (section 9c) |
| `Released` (ABI 5) | only after `mt_session_drain` (section 9c): flag 0 moves the request to the replacement session after `value1` seconds (what is left of a flood wait); `MTReleasedMayHaveRun` asks the request's `shouldContinueAfterError` with one more server error and moves it if allowed, fails it with `500 ENGINE_SWITCHED` otherwise |
| `Closed` | after `mt_session_drain`: the drain is over, `movePendingRequests`' completion runs; otherwise ignored |
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
| `ConnectionDropped` | every observer from `observeConnectionDrops` gets `NetworkEngineConnectionDrop(reason: text, answered: flags & 1, age: value1)`; `RecordingNetworkEngine` feeds them to `NetworkTelemetry` (drops per role and reason, and the latest on failure records). `text` is the reason (`probe_timeout`, `racer_won`, `session_error`, …), `answered` whether the session took a packet from the connection, `age` seconds since it started connecting |
| `AuthKeyCreated` | `flags` says which key (ABI 4: `MTAuthKeyCreatedTemporary` or `MTAuthKeyCreatedPermanent`), `code` the `dc` its handshake carried; only keys the session keeps are reported. PFS sessions: a temporary key is held until `TemporaryKeyInUse` names it (a permanent key cannot come: the session never allows the engine to make one). The key maker of section 9b hands its permanent key to `MTContext`. Other sessions: logged only |
| `TemporaryKeyInUse` | the key the session talks under (salts and init hash go to its auth info). One the session made (`flags & 1 == 0`), for the address class the session has now (`code` is the obfuscation id it was made for), is written to the class's ephemeral selector with `rustEngineBoundTo` = the permanent key id in `request_id`, unless the context keeps a longer-lived key bound to the same permanent key |
| `TemporaryKeyDropped` | the context's key for the selector is removed if it is that key |
| `PermanentKeyInvalid` | PFS sessions, unless the key was installed into the session less than 60 s ago, since the session last had none: on another datacenter (and for the session that imports an authorization) the permanent key and its token are dropped and made anew; on the home datacenter, refused binds alone are no verdict. While the engine's actions are installed (`RustEngineActions`) and MTContext has their factories, the report is noted in the context registry and `context.checkIfLoggedOut(dc)` runs the engine's key check of section 9b, which logs out only on the full evidence and the validation call there. While MtProtoKit runs the key actions (a session draining after a switch to MtProtoKit), the report starts nothing: MtProtoKit's probe would decide on one refused bind |
| `TemporaryKeyBound`, `TemporaryKeyBindFailed` | PFS sessions: noted in the context registry against the installed permanent key (a bind accepted; a fresh key refused with `ENCRYPTED_MESSAGE_INVALID`), the evidence the logout check weighs (section 9b); logged |
| `AuthKeyCreationFailed`, `TransportFlood` | logged only |
| `AuthKeyDestroyed` (28) | not mapped (`RustEngineEventKind` has no case, so the event is dropped): TelegramCore never calls `mt_session_destroy_auth_key` yet |

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
The bridge never creates, replaces or removes the master DC's persistent key itself (integration.md 4.4 (1)); with engine PFS it writes only temporary keys (section 9a).

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
| authorization import (section 9b) | `Worker` | by the address class | no token gate |
| key maker / logout check (section 9b) | `Worker` | none (makes the permanent key / checks the given one) | no requests; Auto + Telegram Web |

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
| otherwise (persistent key) | `context.checkIfLoggedOut(dc)` only (a fresh key exchange and bind; MtProtoKit's logs out on `ENCRYPTED_MESSAGE_INVALID`, the engine's only as section 9b says); the same key is reinstalled on `AuthKeyRequired` |

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

## 9a. PFS in the engine

A non-CDN session with `useTempAuthKeys` and MtProtoKit's RSA keys (`MTDatacenterAuthDefaultPublicKeys`)
is created with `pfs_lifetime = tempKeyExpiration` (24 h) and `pfs_make_permanent_key = 0`:

- Its key is the context's persistent key. Permanent keys still come only from `MTContext`, the one
  maker per datacenter; a second maker in the session would race it and could leave a temporary key
  bound to a permanent key the context no longer holds. Without one the engine asks (`AuthKeyRequired`)
  and the session requests the persistent key from the context, whose action makes it over the engine
  while Rust carries the network (section 9b), over MtProtoKit's TCP otherwise.
- The temporary key the context keeps for the session's address class (`ephemeralMain`, or
  `ephemeralMedia` for media addresses) goes in as `pfs_temporary_key` when it is bound to that
  permanent key (attribute `rustEngineBoundTo`; MtProtoKit's keys carry none) and has more than 5 minutes
  left; the session then talks under it without a handshake (a key without the attribute is bound once
  more first: Telegram moves the binding of a key that carried initConnection to this permanent key, and
  answers CONNECTION_NOT_INITED for one that never did, which the engine replaces with a key of its own;
  once bound, the bridge marks the context's copy with `rustEngineBoundTo`). A key with no expiry is never
  taken as a temporary key. `MTTemporaryKey.bound_to` carries the binding: the engine refuses an offer
  bound to another permanent key, and drops what it kept when the permanent key changes.
- Whenever the context gets another key for that selector (another session, MtProtoKit's refresh), it is
  offered with `mt_session_offer_temporary_key`; the engine keeps it and takes it the next time it needs a
  key (expiry, the server dropping the old one, a class change) instead of a handshake.
- Keys the engine made are written with `rustEngineBoundTo` = the permanent key the engine reports in
  `TemporaryKeyInUse` (`request_id`). MTContext's temporary-key refresher skips keys with that attribute:
  the engine rotates them itself, over HTTP too, and two refreshers would make two keys a day.
- An address class change sends the new obfuscation id first: the engine drops the temporary key of the
  old class and the session offers the context's key for the new class. Calls in flight when a
  temporary key has to go (a class change, or no quiet moment before the key's end) fail in the engine
  as `500 TEMP_KEY_ROTATED`; the session sends them again under the new key when the request's
  `shouldContinueAfterError` allows a server error, as MtProtoKit re-sends after a key change, and fails
  them otherwise. Keys are made with the obfuscation id as the handshake's `dc` (test offset, negative for
  media), as MtProtoKit and tdlib do.
- `AUTH_KEY_PERM_EMPTY` and `-404` are handled inside the engine (rebind or a new temporary key); the
  session never drops the permanent key for them.

## 9b. MTContext's actions over the engine

`MTContext` makes every auth key and transfers every authorization through one action per datacenter
and selector (per datacenter for a transfer), with its own backoff and wake-ups for the connections
that wait. MtProtoKit's actions use its TCP transports only, so on a network where only plain HTTP or
Telegram Web reach Telegram a fresh login, the first use of another datacenter and the logout check
never concluded. The bridge therefore gives the context actions that run on the engine
(`RustEngineActions`, MtProtoKit's public `MTExternalActions.h`): `authActionFactory` and
`transferAuthActionFactory`. `NetworkEngine.activate()` installs them when a network starts on the
Rust engine and whenever a live switch moves it there; `deactivate()` removes them when it moves to
MtProtoKit (`SwitchingNetworkEngine` deactivates the old engine before activating the new one) and ends
every action still running on the engine (and any MTContext makes from its factories until they are
cleared or replaced on MTContext's queue), which reports a failure, so MtProtoKit takes those keys and transfers over after MTContext's
backoff (1 s after a first failure, at most 60 s) instead of waiting behind them (the kill switch must
reach a login). App
extensions never get them. `MTContext` stays the only coordinator and the only writer of keys and tokens.

- **Permanent keys** (persistent selector, not a CDN): a key-only engine session (`generate_key = 1`,
  no temporary expiry, role `Worker`, no requests, MtProtoKit's RSA keys, the context's main addresses
  and proxy, Auto transport with Telegram Web) makes the key. The bridge takes the time difference the
  handshake measured when the context's differs from it by more than 10 s (the sessions correct it
  precisely) and calls `-[MTDatacenterAuthAction completeWithAuthKey:timestamp:serverSalt:]`, which
  stores it exactly as MtProtoKit stores its own, unless the context got a permanent key for the
  datacenter meanwhile (compare-and-set: the key sessions already use is never replaced). The engine
  backs off failed handshakes 1 to 60 s; an attempt with no key after 300 s fails, and `MTContext` asks
  again with its backoff. `UnauthorizedAccount`'s key prefetch asks
  for permanent keys only with the Rust engine, so MtProtoKit's parked temporary-key actions do not open
  TCP connections on a blocked network.
- **The logout check** (`checkIfLoggedOut`, `probedPermanentKey`). The engine's `PermanentKeyInvalid` on
  the home datacenter starts it only while these actions are installed. Otherwise (MtProtoKit's actions,
  for example a session draining after a switch to MtProtoKit) it starts nothing, because MtProtoKit's
  probe would decide on one refused bind. The gate (`rustEngineStartLogoutCheck`) is decided on
  MTContext's queue: it needs the registry to name the engine's actions and the factories set there to be
  theirs, and the check reads the factory in the same block. `activate` and `deactivate` change the registry at once and
  write the factories only on that queue, in order. A check that passes the gate therefore always gets
  the engine's action, never MtProtoKit's; if the engine was deactivated meanwhile, that action ends at
  once. The check is a PFS engine session with the probed
  key, `pfs_lifetime = 3600`, no permanent key of its own and no offered temporary key, sends nothing
  but its bind. `TemporaryKeyBound`: the key is known (noted in the context registry). A bind refused with
  `400 ENCRYPTED_MESSAGE_INVALID` leads on only when the context registry also has, for that key: the
  engine's `PermanentKeyInvalid` (two fresh keys refused while the key was older than the engine's 60 s
  immunity, and not taken by the bridge for a key installed into the session less than a minute ago,
  since the session last had none), at most
  5 minutes old; a
  session's refused bind under the key, starting a refusal episode (refusals more than 300 s apart start
  a new one), watched for at least 10 s; and no sign within the last day that the server knows the key
  (tdlib's immunity, since a datacenter incident can hide a known key, `-404`s included). A sign is any
  of:
  - a call's result, cancelled or not;
  - a server error other than `401`, other than `PROTOCOL_ERROR_*`, and other than the errors the engine
    or the bridge make up for a call that may never have reached the server;
  - an update;
  - an accepted bind;
  - any answer to an earlier validation call (below).

  tdlib with PFS counts accepted binds only. The bridge also counts answers, because a launch reuses the
  stored temporary key and binds nothing. As a result, a temporary key of a permanent key the server
  destroyed, which still answers calls that need no authorization (R5-2), keeps the immunity going until
  it expires. An authorized account is logged out by its main session's `401` meanwhile.

  A session that stops leaves its last sign behind, and times come from `CLOCK_MONOTONIC_RAW`, which
  never steps and counts time asleep. Then, as tdlib validates its main key after a refused bind, a
  non-PFS engine session with no RSA keys sends `help.test` (without updates) under the permanent key
  itself:
  - any answer, an error included, keeps the account: a `401` under the permanent key itself, and
    `PROTOCOL_ERROR_*` (raised after service messages the server encrypted under the key). Refused binds
    alone are no proof: the server refuses them for a while for other reasons too, and so would a bug in
    the engine's own bind code;
  - only `AuthKeyInvalid` (`-404` twice, the second on a fresh connection), with the evidence still
    holding when it comes, confirms the key unknown and logs out;
  - no answer gives no verdict. Other bind refusals give no verdict; 5xx and 420
  are retried by the engine three times, then no verdict. Nothing the check makes is stored. Before
  login the verdict replaces the home key (`Network.permanentKeyUnknown`, Rust only) instead of logging
  anything out.
- **Authorization transfer**: `auth.exportAuthorization` goes to the master datacenter through the
  context's running main session (no new connection or key), or a short-lived worker there; the import
  goes to the destination through a short-lived worker that imports it itself (engine role `Worker`, no
  token gate), takes the destination's permanent key from the context like any session (the engine makes
  it when there is none) and asks for its temporary key as usual. The token goes to the context only if
  the destination's permanent key is still the one the import ran under (checked and written in one
  context transaction). After a failed import the bytes are never sent again: `AUTH_BYTES_INVALID` or a
  server error (`TEMP_KEY_ROTATED` included) gets one fresh export per attempt (a flood wait is waited
  out, and the engine's retransmission keeps the message id, which the server runs once); any other
  failure, and an attempt not done within 120 s, fails the transfer, which `MTContext` retries with its
  backoff (1, 2, 4 … 60 s).

## 9c. Live engine switch: the drain

`SwitchingNetworkEngine` (macOS) moves a network between engines live: the server's kill switch, the
local health check below, the Developer picker. Every session gets a replacement at once; the old one
hands its requests over with `NetworkEngineSession.movePendingRequests(to:deadline:completion:)`, the
deadline being the switch's drain timeout (5 s), and stops when the completion runs. Requests go to the
session current when each one moves, so a request released after a further switch skips a session that
drains in turn.

- **Rust** (`mt_session_drain`, engine `session_drain.rs`): a request that never reached the server is
  released at once (`Released`, flag 0) and moves. One the server may have stays in the old session: it
  goes out again only under its own msg_id (the server never runs a msg_id twice) and an answer that
  comes completes it there. The draining session sends no request it had not sent before; pings,
  acknowledgements and the service messages about its requests still go. A request that would have to go
  under a new msg_id is released instead: as never run when the server said it did not get it or
  rejected its only copy, as possibly run after a covering `new_session_created`, a local session reset,
  a `msgs_state_info` "nothing known" (status 1, also what a server that forgot an old msg_id says) or a
  key change (the answer could never come under another key; no new key is made). Once a copy may have
  run, the request stays possibly run, also when it went back to the queue before the drain began or
  was taken back to be wrapped with `initConnection` again. One exception, the same as without a switch:
  when the server answers a later copy in the same session with an error the request is retried for (a
  flood wait, a server error, `AUTH_KEY_PERM_EMPTY`), that answer counts, and the request leaves as never
  run (MtProtoKit likewise); a copy that went out under an earlier session or before a re-wrap keeps the
  request possibly run. A request chained
  with `invoke_after` to one still waiting stays until that one is answered or released, so the chain
  moves in its order. A request chained to one that leaves with a wait (a flood wait) is released with
  no wait of its own and can reach the new session first: without a switch a dependent that has not
  gone out is not held either, but one the server already answered with `MSG_WAIT_*` would be. The deadline grows by 5 s while answers keep arriving, 30 s at most; then every
  request left is released (possibly run if it ever went out) and the engine sends `Closed`. A request
  sent to the session afterwards is released at once. The bridge moves held and resubmitted requests
  itself, leaves an engine report that the permanent key is unknown to the replacement (B2 review L7:
  after a switch to MtProtoKit, MtProtoKit's probe would judge it on a single refusal), writes no
  temporary key to the context while draining, stops its connection watchdog, and has a backstop 15 s
  past the longest drain.
- **MtProtoKit** (`-[MTRequestMessageService handOverRequests:]`): the same split by `MTRequest.requestContext`
  and `MTRequest.mayHaveReachedServer` (set whenever the request goes out under a message id, cleared
  when the server answers it with an error after which it goes again): a request with no message id
  leaves at once, as possibly run if it went out before (a transport reset just before the switch drops
  every message id); one with a message id waits for its answer and is sent again only under that id;
  one that loses its message id meanwhile leaves as possibly run; one the server answered with an error
  it is retried for leaves as never run, after its wait. The adapter runs the deadline the same way.
- **Possibly run** follows the request's own policy, as `500 TEMP_KEY_ROTATED` does after a key rotation:
  `shouldContinueAfterError` with one more server error; most of TelegramCore's requests allow a server
  error, so such a call can still run twice when the old session never gets its answer. A call whose
  policy refuses fails with `500 ENGINE_SWITCHED` and runs once.
- **Temporary keys**: when the network leaves the Rust engine, the temporary key its main sessions keep
  in the context (`rustEngineBoundTo`) is removed from the context (the draining session keeps its copy),
  so MtProtoKit's replacement makes and binds a key of its own and two main sessions of the account never
  talk under one temporary key. A switch to Rust shares MtProtoKit's key with the draining MtProtoKit
  session for the drain (30 s at most), as MtProtoKit's own sessions of one datacenter share it: MtProtoKit
  takes whatever key the context holds for its selector, so a key of the engine's own written there would
  move the draining session onto it anyway, after dropping its connection and with it the answers the
  drain waits for.

**Local health check** (`NetworkLivenessMonitor`, macOS, a network that can switch, Rust only): when the
main session has heard nothing from the server for 45 s of awake time, resumed, carrying the network
(the window starts again at a switch to Rust) and with the network available all along, and has no
answered connection (a session on one is never judged, whatever it waits for: the engine drops a
connection the server stops answering, and only then is the session judged), MtProtoKit's TCP
asks the same datacenter's addresses for a `res_pq` (10 s, through the context's proxy; never through a
WEB proxy). If it answers and the engine still heard nothing, the network reports it to
`NetworkTelemetry` (failure class `engine_fallback`, method `engine.local_health`, with the engine's
latest connection drops) and moves to MtProtoKit until the next launch (`disableRustEngine`,
`local-health`). One probe per network (`RustNetworkIdentity`) per 10 minutes, process-wide. The bridge
reports what it heard (`serverActivity`): the latest answer, update, pong, bind answer or answered
connection, or the moment it lost an answered connection (an idle session pings every minute or so,
so a key rotation's reconnect must not find it silent since its last pong), how long requests have
waited (reported, not judged), and whether the connection answered. The bridge's clock runs through
sleep, so the monitor starts its window again at every wake, also one no reachability change marks.
Over HTTP an open connection stays "answered", so an HTTP-carried session is never judged; MtProtoKit's
TCP probe would mostly fail there anyway. The probe limit is per network for the whole process: after
one account's probe, another account's silent session waits up to ten minutes for its own.

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
| Main session lifetime | retained forever by the update-service cycle | destroyed with its `Network` | no cycle needed; sockets close |
| Duplicate reset for `updatesTooLong` | one `.reset` | one `.reset` (wrapper skips the second) | engine emits both |
| Cancelling an in-flight request with `expectedResponseSize >= 512 KB` | new session id + transport reset | engine sends `rpc_drop_answer` and resets the connection, session kept | engine semantics |
| Proxy connection issues | `MTConnectionProbing` (proxy unreachable while the internet is reachable) | engine flag: proxy set, not connected, 3+ failed attempts | engine semantics |
| Key rejected while the context already has a newer key | drops it and asks for another | installs the newer key | avoids rebind storms (R14) |
| Network type | wifi/cellular per socket | cellular when the socket's local address is on a `pdp_ip*` interface | same accounting (`72d7e51f95`) |
| Main-session `401` | logs out | logs out (`rustEngineAuthorizationRequiredAction`) | the `401` is the server's verdict; R1's `checkIfLoggedOut` probe, a key exchange and bind (over the engine while its actions are installed, over MtProtoKit's TCP otherwise), can only say less |

## 12. Known gaps and FFI requests

Status (2026-10-06): items 1, 2, 4, 5 and 6 are fixed in the engine by `72d7e51f95` (token gate
across key swaps, `set_auth_key(None)` keeps requests, live `set_obfuscation_dc_id`, connect
timeouts report the address, `NetworkUsage` reports cellular). Item 7 is addressed by
`RustEngineEndToEndTests`, which drives the `mtproto-testserver` binary. Item 8: the iOS Bazel
targets exist (§2); `build.sh` still builds no iOS slices, which iOS does not use. Item 3 is fixed
for everything but plain TCP through an injected interface: the host-stream ABI carries Telegram
Web's HTTPS (HT13) and WebSocket (HT14) endpoints and the WEB proxy carrier (`RustCarrierStreams`),
so a WEB proxy no longer needs MtProtoKit. The design agreed for iOS: mirror MtProtoKit's selection, i.e. own sockets when
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
2. **`mt_session_set_auth_key` with an empty key** (fixed by `72d7e51f95`): it keeps the requests now
   (it used to discard the `RpcClient`). The wrapper still never calls it and holds the session paused
   instead.
3. **Injected transport** (mostly fixed): host streams carry Telegram Web's HTTPS and WebSocket
   endpoints and the WEB proxy carrier; plain TCP still uses the engine's own sockets, never
   `context.makeTcpConnectionInterface` (NWConnection on macOS 14+).
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
  main session's engine, and a media worker following its addresses between media and main keys.
  `RustEngineContextActionsTests` (`--api` starts a second server, datacenter 4, sharing exports and
  imports) covers section 9b: a fresh login over HTTP and over Telegram Web only, the test offset, the
  compare-and-set against another maker in either order, MtProtoKit taking over an engine-made key,
  the logout check's verdicts. It logs out exactly once for a forgotten key, over HTTP and over Telegram
  Web only. It logs nobody out for:
  - a bind that succeeds;
  - server errors, or no answer;
  - no report from the engine;
  - calls completing under the key;
  - refused binds after the key was answered under (including an incident that hides the key, `-404`s
    and all, without validating it: nothing reaches the server under the key itself, and the test
    server's `hidden_key_rejections` stays 0);
  - refused binds from the start, when the validation call is answered, with a result or with a `401`;
  - a validation call that gets no answer (the test server's `help-test ok|silent|error <code> <text>`,
    and `help_tests` in `stats`).

  It also pins the immunity's accepted limit, as in tdlib: a fresh context logs out once when the server
  refuses binds and answers `-404` under the key itself (`hide-permanent-keys on`; at least two
  `hidden_key_rejections`, the validation's).
  `RustEngineEndToEndTests` checks that a report starts no check while MtProtoKit runs the key actions,
  including from a session draining after a switch to MtProtoKit.

  It also covers a switch to MtProtoKit ending a key
  maker the engine cannot finish, a key maker giving up, and transfers over HTTP, through the main
  session, cancelled, and with an import refused (`AUTH_BYTES_INVALID`, `500`) or an export refused.
  `RustContextRegistryTests` pins the evidence rules without sessions, and the ordering on MTContext's
  queue: the gate (`rustEngineStartLogoutCheck`), and the factory writes of `activate` and `deactivate`.
  `RustEngineDrainTests` covers section 9c: R3-C (a call the server ran is not run again by a switch:
  it fails with `500 ENGINE_SWITCHED` under a refusing policy), a call whose policy allows a server
  error moving at the deadline, an answer completing on the draining session, never-sent requests
  moving at once, the replacement's own temporary key, and MtProtoKit handing over to Rust. MtProtoKit's TCP connections are
  counted through `makeTcpConnectionInterface`: none while the engine makes keys and transfers. The tests
  need the shared logger that `RustEngineBridgeTests` installs, so run the whole test target.

## 14. Risks (not yet exercised at runtime)

1. **Logout path.** `AuthorizationRequired` is forwarded exactly like MtProtoKitEngine does, so any main
   session `401` other than `SESSION_PASSWORD_NEEDED` logs the account out. If the engine ever sends a
   request with a key the server does not associate with the authorization and gets
   `AUTH_KEY_UNREGISTERED` instead of `AUTH_KEY_PERM_EMPTY`, that is irreversible. integration.md R1's
   suggestion, routing the callback through `MTContext.checkIfLoggedOut`, was withdrawn (2026-10-02):
   the probe's `EphemeralMain` auth action completed at once on the key the context stored for that
   selector, never reached the server, and always reported "not removed". Since 2026-10-06 the probe
   carries `replacesExistingKey` and `probedPermanentKey` and really makes a fresh temporary key, binds it
   to the probed permanent key and never stores it, giving up without a verdict after 120 s. The bridge
   starts it for the engine's `PermanentKeyInvalid` on the home datacenter only while the engine's actions
   are installed: it then runs over the engine and weighs the evidence and the validation call of section
   9b. Refused binds alone never log out. A `401` is the server's own verdict, so that path stays a direct
   logout.
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

## 15. FFI ownership and lifetime

The C ABI in `crates/mtproto-ffi/include/mtproto_engine.h` follows these rules. Any other host must
follow them too.

- **Version.** `mt_engine_abi_version()` must equal the version the host was built against (5: ABI 5
  added `mt_session_drain` and `MTEventKindReleased`).
- **Engine.** `mt_engine_create` returns an owned pointer. `mt_engine_destroy` releases it:
  - Delivery stops at once. A secret payload that is already queued is zeroized, not delivered.
  - The worker threads are shut down and joined.
  - After it returns, no callback runs and the pointer must not be used again.
  - Never call it from inside a callback: the calling worker cannot join itself.
  - Every other function treats a null engine pointer as a no-op (returning 0 where it returns a value).
- **Sessions.** Handles come from a counter and are never reused. Calls with an unknown or destroyed
  handle are ignored. Events for a handle can still arrive after `mt_session_destroy` returns; the host
  drops them, and still frees their payloads.
- **Inputs.** Every pointer passed in, and the memory it points to, is read only during the call, and
  the engine copies what it keeps:
  - covered: `MTString`, `MTBytes`, address and salt arrays, `MTSessionSetup`, `MTRequest`, `MTEnvironment`;
  - strings are UTF-8, and invalid sequences are replaced, not rejected;
  - the host may free or reuse its buffers as soon as the call returns. It should wipe its own copies of
    secrets: auth keys passed to `mt_session_set_auth_key`, and proxy secrets.
- **Callbacks.**
  - `on_event` and `on_log` run on engine worker threads. Different sessions can call back
    concurrently; events of one session arrive in order.
  - `event`, and every `MTString` inside it or passed to `on_log`, is valid only until the callback returns.
  - Callbacks should copy what they need and return quickly. They may call `mt_session_*` functions, which only queue a command for the worker.
- **Payloads.**
  - A non-null `event->payload` is owned by the host, which must free it exactly once with
    `mt_buffer_free`, including when it ignores the event.
  - Buffers that carry key material are zeroized on free.
  - `mt_buffer_data` is valid until that free.
