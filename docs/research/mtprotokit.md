# MtProtoKit behavioural spec (parity target for the Rust MTProto engine)

Status: research document, 2026-10-01. Source of truth: `submodules/telegram-ios/submodules/MtProtoKit` at the
worktree HEAD (last MtProtoKit commit `7197e51294`, 2026-09-30). Nothing here is aspirational: every rule
describes what the Objective-C code does today, including where that deviates from the official MTProto
documentation or TDLib. Deviations and defects are flagged inline and collected in section 10.

## Conventions

- `MTProto.m:123` = `MtProtoKit/Sources/MTProto.m`, line 123.
- `h/MTProto.h:45` = `MtProtoKit/PublicHeaders/MtProtoKit/MTProto.h`, line 45.
- `Tests/X.m:12` = `MtProtoKit/Tests/X.m`, line 12.
- `TC/...` = `submodules/telegram-ios/submodules/TelegramCore/Sources/...`.
- Line numbers are for the HEAD above; they drift, the symbol names next to them do not.
- "Must" in a rule means the Rust engine needs the same observable behaviour for parity; "(bug)" marks
  behaviour we should consciously decide whether to copy.
- Byte orders are little-endian unless stated; TL constructor ids are written as the 32-bit value
  (`0x62d6b459`), which goes on the wire little-endian.
- GCDAsyncSocket and PingFoundation internals are out of scope except where their behaviour leaks into
  MtProtoKit (socket options, SOCKS, timeouts).

## Contents

0. Architecture overview
1. Public API surface and threading model
2. MTContext, persistent state and context-level actions
3. MTProto session state machine
4. MTRequestMessageService and the request lifecycle
5. Auth key generation and temp-key binding
6. Transport layer
7. MTEncryption and crypto primitives
8. MTApiEnvironment, network usage accounting, keychain
9. Existing ObjC tests as regression cases
10. Suspected bugs and fragile spots

Each section ends with its own constants table (`### N.z`), with the value, the file:line and the meaning.

## Findings at a glance

- The engine is four process-global serial queues, a pull-based transaction model (MTProto polls its
  message services on every transport transaction) and per-connection bookkeeping keyed by the TCP
  connection id. Retransmission is always "new msg_id after any connection change" (§3.14, §4.12).
- Salts and time are learned almost exclusively from `bad_server_salt` answering a time-fix ping;
  `get_future_salts` is never sent and handshake salts are discarded, so each new key and every ~30 min costs
  a stalled round trip (§3.8, §10 H2).
- Twelve high-severity defects are listed in §10.1. The ones most likely to show up in the field: a `-429`
  mutes a connection for good (H1), one unknown constructor resets the session (H3), queued writes on a
  fake-TLS/SOCKS connection that fails its handshake are never completed (H4), and temp-key connections never
  detect logout (H5).
- Persisted state is NSKeyedArchiver data under fixed keychain keys that TelegramCore also reads directly;
  a switchable Rust engine must not write a different format under those keys (§10.4).
- All 75 ObjC tests are regression tests for bugs fixed in September 2026. They run only on the Bazel iOS
  simulator, never in the macOS build; §9 turns each into a protocol-level Rust test and lists the gaps.

## 0. Architecture overview

This section is a map. Every statement here is specified in detail, with references, in the section named
in brackets.

### 0.1 Object graph

```
TelegramCore (Swift)
  Network ─────────┬── MTContext  (one per account network; shared by every MTProto of that account)  [§2]
                   │     ├─ auth keys per (dc, selector)   Persistent / EphemeralMain / EphemeralMedia
                   │     ├─ address sets, manual schemes, scheme stats, auth tokens, CDN RSA keys
                   │     ├─ globalTimeDifference, MTApiEnvironment (incl. proxy), keychain (Postbox)
                   │     └─ actions: MTDatacenterAuthAction, MTDatacenterTransferAuthAction,
                   │                 MTDiscoverDatacenterAddressAction, scheme discovery, backup discovery
                   │
                   ├── main MTProto (dc = master, useTempAuthKeys, checkForProxyConnectionIssues)      [§3]
                   │     ├─ MTRequestMessageService (API calls)                                         [§4]
                   │     ├─ TelegramCore UpdateMessageService (receives Api.Updates)
                   │     ├─ MTResendMessageService* (transient, one per msg_resend_req)
                   │     ├─ MTTimeSyncMessageService (transient, effectively dead)                     [§3.8]
                   │     └─ MTTcpTransport (is itself a message service)                                [§6]
                   │           └─ MTTcpConnection (0..1 at a time, new object per dial)
                   │                 └─ MTTcpConnectionInterface: GCDAsyncSocket | Network.framework | WEB carrier
  Download workers ── MTProto per (dc, media, cdn, tag), requiredAuthToken on non-master DCs,
                      forceBackgroundRequests (invokeWithoutUpdates), paused/resumed with the app

Throwaway MTProtos created inside MtProtoKit:
  - DH handshake proto (useUnauthorizedMode) + MTDatacenterAuthMessageService                         [§5]
  - bind proto (useExplicitAuthKey = new temp key, reuses the handshake TCP connection)               [§5.7]
  - transfer protos: auth.exportAuthorization on master, auth.importAuthorization on target           [§2.6]
  - help.getConfig protos: unknown-DC discovery, backup-address config fetch (own temp MTContext)     [§2.9, §2.10]
  - probe connections (raw MTTcpConnection + req_pq_multi): scheme discovery, proxy ping/probing      [§2.9.1, §6.18]
```

### 0.2 Threads

Four process-global serial queues carry almost everything, shared by every account [§1.2]:
`com.mtproto.MTContextQueue` (all MTContext state and listener callbacks), `org.mtproto.managerQueue` (every
MTProto, every message service, every MTRequest callback, every MTProtoDelegate callback),
`org.mtproto.tcpTransportQueue` and `org.mtproto.tcpQueue` (transport and sockets). `MTQueue dispatchOnQueue:`
runs inline when already on the target queue, so most calls are re-entrant. MTContext getters are synchronous
`dispatch_sync` onto the context queue and are called from all other queues and from Swift.

### 0.3 Life of a connection (main MTProto)

1. `MTProto init` registers as a context listener, creates a random session and starts **Paused** [§3.4].
2. `resume` → `resetTransport`: no scheme list → `AwaitingDatacenterScheme` and ask the context; required token
   missing → `AwaitingDatacenterAuthToken` and ask for a transfer; otherwise create an `MTTcpTransport` with the
   scheme list frozen at that moment [§3.4, §6.3, §6.17].
3. A transaction request makes the transport dial: the context picks a scheme (reverse order, minimum failure
   timestamp, IPv6 only if it answered in the last hour) [§2.8, §6.17]; the connection resolves proxy
   hostnames, dials with a 12 s connect timeout, and runs SOCKS5 or the fake-TLS hello first if configured
   [§6.5, §6.11, §6.12].
4. "Opened" is reported at TCP connect (after the SOCKS reply for SOCKS5, before the ServerHello for fake-TLS).
   The transport asks MTProto for a transaction, attaching one **actualization ping** per connection [§6.3].
5. MTProto looks up the auth key for the selector; if missing it sets `AwaitingDatacenterAuthorization` and asks
   the context, which runs DH (+ bind for temp keys) [§3.7, §5]. A new key has salt 0, so the first send is a
   time-fix `ping` that is answered by `bad_server_salt`, which supplies the salt (valid 30 min) and the time
   difference [§3.8, §5.8].
6. Normal traffic: services are polled, acks prepended, messages packed into containers of up to 3072 body bytes,
   encrypted with MTProto 2.0, framed (abridged, or padded intermediate for dd/ee secrets), obfuscated with
   AES-CTR, optionally wrapped in TLS records, written [§3.9, §6.6, §6.7, §7.2].
7. Incoming frames are decrypted, the session id checked, the container split; service messages are handled
   inside MTProto, everything else goes to the services in reverse registration order [§3.11].
8. Failure paths: a connection close reschedules a dial with 0/1/4/8 s backoff and makes every request sent on
   that connection resend with a new msg_id [§6.4, §4.12]; a transport error code (-404 key unknown, -429
   flood) has its own handling [§3.11.1]; 20 s without a decodable frame reports connection problems, which
   drive scheme discovery, backup-address discovery and proxy probing [§2.8, §3.20, §6.18].

### 0.4 Life of a request

`MTRequest` (payload, response parser, flags) → `addRequest:` → next transaction: wrapped as
`[invokeAfterMsg] [invokeWithReCaptcha] [invokeWithApnsSecret] [invokeAfterMsg] [invokeWithoutUpdates]
[invokeWithLayer initConnection] payload` [§4.4] → msg_id assigned (`prepared`) → written (`completion` with the
connection id) → `rpc_result` matched by `req_msg_id` → `responseParser` → `completed(result | error)`.
Errors that MtProtoKit handles itself instead of surfacing: 500/-500 (retry after 2 s if the gate allows),
FLOOD_WAIT_X/420 (wait X s), MSG_WAIT_TIMEOUT, CONNECTION_NOT_INITED, APNS/reCAPTCHA verification, and
SESSION_REVOKED/AUTH_KEY_UNREGISTERED on token-carrying workers; `401 AUTH_KEY_PERM_EMPTY` is intercepted in
MTProto. Everything else, including every `*_MIGRATE_X`, is surfaced to TelegramCore [§4.9].

### 0.5 Life of a key

Persistent key per DC (never expires, created once per install) → per connection a temp key (`EphemeralMain`,
or `EphemeralMedia` for media addresses) with `expires_in = 86400 s`, bound to the persistent key with
`auth.bindTempAuthKey` over the same TCP connection [§5.6, §5.7]. Temp keys are persisted and pruned only at
launch; expiry at runtime is discovered when the server answers `-404`, which drops and recreates the key (and,
on non-master DCs, the imported authorization) [§3.7.2, §5.6]. CDN connections use a persistent key per CDN DC
with RSA keys from `help.getCdnConfig` [§5.3].

### 0.6 Observable behaviour a parity test must pin

These are the behaviours that TelegramCore or the user can see, collected from the sections below:

1. Connection status flags (`isNetworkAvailable`, `isConnected`, `isUpdatingConnectionContext`,
   `isPerformingServiceTasks`, `proxyHasConnectionIssues`) and when each flips [§3.22]. TelegramCore derives
   "Waiting for network / Connecting / Updating / Online" from them.
2. Request semantics: at-least-once with a new msg_id after any connection loss; which errors are retried and
   with which delays; 401 → `requestMessageServiceAuthorizationRequired` (logout on the main connection) [§4].
3. `globalTime` (server-corrected clock) and its persistence [§2.12].
4. Persisted state: keychain keys, groups and NSKeyedArchiver class layouts; TelegramCore's account backup reads
   `persistent:datacenterAuthInfoById` itself [§1.9, §2.3, §8.7].
5. Wire format choices that proxies and DPI see: obfuscated abridged vs padded intermediate, padding ranges, the
   fake-TLS ClientHello bytes, SOCKS5 messages [§6].
6. Network usage counters in `network-stats` [§8.6].
7. Crypto exports that TelegramCore calls directly (secret chats, calls, SRP, CDN, Passport) [§7.1].

## 1. Public API surface and threading model

References: `X.m:N` is `Sources/X.m`; `h/X.h:N` is `PublicHeaders/MtProtoKit/X.h`. "TC" means TelegramCore
(`submodules/TelegramCore/Sources`), "Mac" means the macOS app plus `packages/`. Usage tags:
**[TC]** called or implemented by TelegramCore, **[Mac]** by the macOS app, **[int]** used only inside
MtProtoKit, **[dead]** declared but never called by anyone.

### 1.1 Module shape

- One ObjC module `MtProtoKit`. Umbrella `h/MtProtoKit.h:1-63` imports 61 headers. The only external dependency
  is `EncryptionProvider` (bignum and RSA protocol, implemented by `OpenSSLEncryptionProvider`). SwiftPM
  manifest `Package.swift` (macOS 10.13, excludes `BUILD` and `Tests`); Bazel `BUILD` also defines the
  `MtProtoKitTests` ios_unit_test and a testonly `MtProtoKitPrivateHeaders` target.
- Private but test-visible seams live in `Sources/MTInternalInterfaces.h:18-66`: `MTContext.authActionFactory`,
  `.transferAuthActionFactory`, `-makeAuthActionWithSelector:...`, `MTDatacenterTransferAuthAction -complete/-fail`,
  `+applyRetryPolicyToRequest:`, `MTDatacenterAuthAction.bindError` and `-complete/-fail`,
  `+bindErrorMeansPermanentKeyIsUnknown:`, `MTBackupAddressSignals +applyAddressList:toContext:`. The Rust
  engine needs equivalent injection points so the ObjC regression tests (§9) can be ported.
- Dead headers and classes: `h/MTFileBasedKeychain.h` is empty (1 byte). `MTProtoEngine`, `MTProtoInstance` and
  `MTProtoPersistenceInterface` (`MTProtoEngine.m:1-52`, `MTProtoInstance.m:1-48`) are empty scaffolding: each
  holds an impl on a private unnamed queue and does nothing else. **[dead]**
- Consumers. TelegramCore uses MtProtoKit from `Network/Network.swift`, `Network/Download.swift`,
  `State/Serialization.swift`, `State/UpdateMessageService.swift`, `State/UnauthorizedAccountStateManager.swift`,
  `Account/Account.swift`, `Network/NetworkFrameworkTcpConnectionInterface.swift`,
  `Network/ProxyServersStatuses.swift`, `Network/FetchHttpResource.swift`, `Settings/{ProxySettings,NetworkSettings}.swift`,
  `State/ManagedConfigurationUpdates.swift`, and from the secret-chat, call, SRP and CDN crypto code.
  `MTRpcError` alone appears 199 times. The macOS app touches only `MTLogSetEnabled` (`AppDelegate.swift:450`,
  `DeveloperViewController.swift:196`, `InAppLinks.swift:1468`), `MTProxySecret` (parse and serialize in
  `ProxyUI`, `TelegramLinks`), `MTSocksProxySettings` and `MTProxyConnectivity.pingProxy` (`ProxyAlert.swift:122-134`).
  `WebProxyTransport` (a separate submodule) implements `MTTcpConnectionInterface` with `isWebProxyCarrier`.

### 1.2 Queue model

Every MtProtoKit queue is an `MTQueue` that wraps a serial GCD queue created with attr `0`. No QoS is set
explicitly, so blocks inherit the submitter's QoS.

| Queue | Created | Scope | Runs |
|---|---|---|---|
| `com.mtproto.MTContextQueue` | `MTContext.m:318-327` | **process-global**, shared by every MTContext (all accounts, temp contexts) | all MTContext state, change-listener callbacks, auth/transfer/discovery actions, retry timers |
| `org.mtproto.managerQueue` | `MTProto.m:140-149` | **process-global**, shared by every MTProto (main connection, every Download worker, auth/bind/transfer/backup protos of every account) | all MTProto state, every `MTMessageService` callback, `MTProtoDelegate` callbacks, `MTRequest` callbacks; `-messageServiceQueue` returns it (`MTProto.m:572-575`) |
| `org.mtproto.tcpTransportQueue` | `MTTcpTransport.m:74-83` | global | MTTcpTransport state and `MTTransportDelegate` calls out of it |
| `org.mtproto.tcpQueue` | `MTTcpConnection.m:876-885` | global | MTTcpConnection, GCDAsyncSocket delegate queue, and the `delegateQueue` handed to `makeTcpConnectionInterface` |
| `org.mtproto.MTNetwotkAvailability` (sic) | `MTNetworkAvailability.m:110-119` | global | reachability callback and its 5 s poll timer |
| unnamed | `MTDNS.m:78-85`, `MTNetworkUsageManager.m:174` (one per manager), `MTProxyConnectivity.m:59` (one per ping), `MTBackupAddressSignals.m:179,335` (delay queues), `MTProtoEngine/Instance` | per object | as named |

`MTQueue` semantics (`MTQueue.m`) that the code relies on:
- `-dispatchOnQueue:` (`:104-130`) runs the block **inline** when the caller is already on that queue. This is
  detected with `dispatch_queue_set_specific(name)` (`:32`, `:122`). Otherwise it calls `dispatch_async`, or
  `dispatch_sync` when `synchronous:true`. Re-entrant calls therefore run immediately and nested, not after the
  current block. For example, `-[MTProto requestTransportTransaction]` issued on managerQueue runs its body at once.
- Unnamed queues (`-init`, `:15-22`) have `_name == NULL`, so `isCurrentQueue` is always false (`:86-87`) and
  dispatch is always async. `synchronous:true` from that same queue would deadlock.
- `+mainQueue` runs inline when called on the main thread (`:111-114`). `+concurrentDefaultQueue` and
  `+concurrentLowQueue` are the global DEFAULT and LOW queues, so dispatch to them is always async.

Cross-queue rules (checked by grepping every `synchronous:true` and `dispatch_sync`):
- **Synchronous reads go into contextQueue only.** All MTContext getters `dispatch_sync` onto contextQueue:
  `globalTimeDifference` and therefore `globalTime` (`MTContext.m:614-623`), `knownDatacenterIds` (`:950-971`),
  `enumerateAddressSetsForDatacenters:` (`:973-994`), `addressSetForDatacenterWithId:` (`:996-1010`),
  `chooseTransportScheme...` (`:1012-1054`), `transportSchemesForDatacenterWithId:...` (`:1056-1125`),
  `authInfoForDatacenterWithId:selector:` (`:1127-1135`), `publicKeysForDatacenterWithId:` (`:1137-1144`),
  `authTokenForDatacenterWithId:` (`:1233-1242`), `performExternal*Verification` (`:583-607`), and the setters
  `setDiscoverBackupAddressListSignal:`, `setExternal*Verification:` (`:565-581`) and `removeChangeListener:`
  (`:549-563`). Callers include managerQueue, tcpTransportQueue and arbitrary Swift threads (main thread via
  `Network.globalTime`).
- The one synchronous dispatch into managerQueue is `-[MTProto takeConnectionForReusing]` (`MTProto.m:692-699`).
  Its only caller runs on managerQueue (`MTDatacenterAuthAction.m:141`), so it executes inline.
- Lock order invariant: contextQueue must never `dispatch_sync` to another MtProtoKit queue. Breaking this
  deadlocks against every MTProto that is reading the context.
- `isPasswordInputRequiredForDatacenterWithId:` and `updatePasswordInputRequired...` use an `os_unfair_lock`
  (`MTContext.m:825-859`) rather than the queue.
- Not synchronized at all (plain nonatomic ivars written on one queue and read on others): `MTContext.apiEnvironment`,
  `.keychain` and `.makeTcpConnectionInterface`. See §10 M21.

### 1.3 MTContext (`h/MTContext.h:88-177`)

Construction **[TC]**: `-initWithSerialization:encryptionProvider:apiEnvironment:isTestingEnvironment:useTempAuthKeys:`
(`MTContext.m:252-311`). It asserts all three objects are non-nil. `_uniqueId` is random. `tempKeyExpiration`
defaults to `24*60*60` s (`:272`). `-init` asserts. TC always passes `useTempAuthKeys = true` (`Network.swift:507`).
After `init` the caller must set `keychain` (`Network.swift:563`). `setKeychain:` is async on contextQueue and loads
persisted state (`MTContext.m:444-527`; details in §2).

| Member | Exec | Used by |
|---|---|---|
| `keychain` (strong, nonatomic) | set async; get unsynchronized | [TC] set once; read by `passwordKDF`, `MTCheckMod`, `MTCheckIsSafePrime` callers |
| `serialization`, `encryptionProvider`, `isTestingEnvironment`, `useTempAuthKeys` (readonly) | plain reads | [TC] `useTempAuthKeys` (`Network.swift:634`, `Download.swift:70`) |
| `apiEnvironment` (readonly) | unsynchronized read; written in `updateApiEnvironment:` on contextQueue | [TC] `Network.swift:890` |
| `tempKeyExpiration` | plain | [int] (`MTBindKeyMessageService.m:56`, `MTDatacenterAuthMessageService.m:494,713`) |
| `makeTcpConnectionInterface` (copy block) | plain get/set; captured by each MTTcpConnection at init (`MTTcpConnection.m:907`) | [TC] Network.framework factory (`Network.swift:523-540`), WEB-proxy carrier (`:1017-1021`) |
| `+contextQueue` | | [TC] `Network.getAuthKeyId` (`Network.swift:1142`) |
| `+performWithObjCTry:` | `@try{}@finally{}` with **no `@catch`**, so exceptions still propagate (`MTContext.m:329-333`) | [TC] `Keychain.setObject` |
| `+fixedTimeDifference`/`+setFixedTimeDifference:` | process-global static int32, unsynchronized; set from the DoH `Date` header (`MTBackupAddressSignals.m:129`), read for the fake-TLS ClientHello timestamp (`MTTcpConnection.m:1147`) | [int] |
| `+copyAuthInfoFrom:toTempKeychain:` | copies `temp:globalTimeDifference`, `persistent:datacenterAddressSetById`, `persistent:datacenterAuthInfoById`, `ephemeral:datacenterPublicKeysById` (`:350-356`) | [dead] on macOS |
| `-performBatchUpdates:` | dispatch on contextQueue (inline if already there) (`:438-442`) | [TC] used as "run on context queue" |
| `-add/removeChangeListener:` | add async, remove **sync**; listeners are held **weakly** (`MTWeakContextChangeListener`, `:146-162`); add prunes dead boxes and dedupes (`:529-547`) | [TC] `NetworkHelper` (`Network.swift:956`) |
| `-setDiscoverBackupAddressListSignal:` | sync | [TC] `MTBackupAddressSignals.fetchBackupIps(...)` (`Network.swift:591`) |
| `-setExternalRequestVerification:` / `-setExternalRecaptchaRequestVerification:` | sync | [TC] (`Network.swift:593-627`); TC times out after 15 s with `"APNS_PUSH_TIMEOUT"` / `"RECAPTCHA_TIMEOUT"` |
| `-performExternalRequestVerificationWithNonce:` / `...RecaptchaRequestVerificationWithMethod:siteKey:` | sync read, then call; returns `[MTSignal single:nil]` when unset | [int] MTRequestMessageService |
| `-globalTime` = `now1970 + globalTimeDifference` (`:609-612`); `-globalTimeOffsetFromUTC` adds `secondsFromGMT` | sync | [TC] heavily (message timestamps) |
| `-setGlobalTimeDifference:` | async; persists `temp:globalTimeDifference` (`:630-642`) | [int] |
| `-setSeedAddressSetForDatacenterWithId:seedAddressSet:` | async | [TC] seed IPs, all port 443 (`Network.swift:541-561`) |
| `-updateAddressSetForDatacenterWithId:addressSet:forceUpdateSchemes:` | async | [TC] `ManagedConfigurationUpdates.swift:36` |
| `-addAddressForDatacenterWithId:address:` | async | [TC] `Network.mergeBackupDatacenterAddress` |
| `-updateTransportSchemeForDatacenterWithId:transportScheme:media:isProxy:` | async; persists `datacenterManuallySelectedSchemeById_v1` | [TC] same |
| `-transportSchemesForDatacenterWithId:media:enforceMedia:isProxy:` | sync | [TC] same, [int] MTProto |
| `-updateAuthInfoForDatacenterWithId:authInfo:selector:` | async; persists `persistent:datacenterAuthInfoById` | [int] |
| `-authInfoForDatacenterWithId:selector:` | sync | [TC] `Account.swift:206`, `Network.getAuthKeyId` |
| `-authInfoForDatacenterWithIdRequired:isCdn:selector:allowUnboundEphemeralKeys:` | async | [TC] `Account.swift:207` (pre-warms EphemeralMain keys for DCs 1,2,4, or 3 on test) |
| `-authTokenForDatacenterWithIdRequired:authToken:masterDatacenterId:`, `-updateAuthTokenForDatacenterWithId:authToken:` | async | [TC] `Download.requestMessageServiceAuthorizationRequired` (`Download.swift:101-104`) |
| `-beginExplicitBackupAddressDiscovery` | async | [TC] `Account.swift:210` |
| `-updateApiEnvironment:` (block returns new env or nil = no change) | async; notifies `contextApiEnvironmentUpdated:` on contextQueue (`:1750-1768`) | [TC] proxy, lang pack, systemCode, network settings |
| `-checkIfLoggedOut:` | async | [int] MTProto |
| `-isPasswordInputRequired...`, `-updatePasswordInputRequired...` | lock | [int] |
| `-scheduleSessionCleanupForAuthKeyId:sessionInfo:` | **no-op**: `dispatchOnQueue:^{ return; }` (`:891-895`) | [int] |
| `-collectSessionIdsForCleanupWithAuthKeyId:completion:`, `-sessionIdsDeletedForAuthKeyId:sessionIds:` | async | [int] |
| `-reportProblemsWithDatacenterAddressForId:address:` | empty body (`:1745-1748`) | [dead] |
| `-reportTransportSchemeFailure/Success...`, `-invalidateTransportScheme(s)...`, `-revalidateTransportScheme...`, `-chooseTransportScheme...`, `-transportSchemeForDatacenterWithIdRequired:media:`, `-publicKeys...`, `-removeAllAuthTokens`, `-removeTokenForDatacenterWithId:`, `-addressSetForDatacenterWithIdRequired:`, `-knownDatacenterIds`, `-enumerateAddressSetsForDatacenters:` | see above | [int] |
| `-cancelPendingActions` (not in the public header; used by MTBackupAddressSignals) | async `cleanup` (`:431-436`) | [int] |

### 1.4 Listener and connection-interface protocols

**`MTContextChangeListener`** (`h/MTContext.h:56-78`, all optional). Every callback runs **on contextQueue**,
on a snapshot of the weak-listener array. Dead targets are skipped.

| Callback | Implemented by |
|---|---|
| `contextDatacenterAddressSetUpdated:datacenterId:addressSet:` | — |
| `contextDatacenterAuthInfoUpdated:datacenterId:authInfo:selector:` | MTProto (`MTProto.m:2599`) |
| `contextDatacenterAuthTokenUpdated:datacenterId:authToken:` | MTProto (`:2697`) |
| `contextDatacenterAuthInfoRequestFailed:datacenterId:selector:` (new 2026-09) | MTProto (`:2676`) |
| `contextDatacenterAuthTokenTransferFailed:datacenterId:` (new 2026-09) | MTProto (`:2688`) |
| `contextDatacenterTransportSchemesUpdated:datacenterId:shouldReset:` | MTProto (`:2579`) |
| `contextIsPasswordRequiredUpdated:datacenterId:` | MTRequestMessageService via an `MTContextBlockChangeListener` that only a local variable holds, so the weak box dies at once and the callback **never fires** (see the commit 028f835528 note) |
| `contextDatacenterPublicKeysUpdated:datacenterId:publicKeys:` | MTProto (`:2775`) |
| `fetchContextDatacenterPublicKeys:datacenterId:` → `MTSignal` of `NSArray<{key, fingerprint}>` | [TC] `NetworkHelper`: `help.getCdnConfig`, filters by dc, `fingerprint = MTRsaFingerprint(key)` (`Network.swift:910-942`) |
| `contextApiEnvironmentUpdated:apiEnvironment:` | MTProto (`:2785`); [TC] `NetworkHelper` (proxy id) |
| `isContextNetworkAccessAllowed:` → `MTSignal` of `NSNumber(bool)` | [TC] `NetworkHelper` (= `shouldKeepConnection`) |
| `contextLoggedOut:` | [TC] `NetworkHelper` → `Network.loggedOut` |

`MTContextBlockChangeListener` (`h/MTContext.h:80-86`) forwards only 3 of these callbacks to blocks.

**`MTTcpConnectionInterface`** (`h/MTContext.h:30-53`), the pluggable socket. Required: `setGetLogPrefix:`,
`setUsageCalculationInfo:`, `connectToHost:onPort:viaInterface:withTimeout:error:` (returns bool),
`writeData:` (no timeout), `readDataToLength:withTimeout:tag:` (exact-length read), `disconnect`, `resetDelegate`.
Optional: `isWebProxyCarrier`. A carrier ignores host and port. MTTcpConnection must never pair a carrier with a
real address, and must never let a WEB-proxy connection fall back to a socket (`MTTcpConnection.m:1009-1014`).
Delegate **`MTTcpConnectionInterfaceDelegate`** (`:21-28`): `connectionInterfaceDidReadPartialDataOfLength:tag:`,
`connectionInterfaceDidReadData:withTag:networkType:` (`networkType` 0 = Wi-Fi or other, 1 = WWAN;
`GCDAsyncSocket.m:5116`), `connectionInterfaceDidConnect`, `connectionInterfaceDidDisconnectWithError:`.
These callbacks run on the `delegateQueue` passed to the factory, which is always tcpQueue. Implementations:
`MTGcdAsyncSocketTcpConnectionInterface` (default; `MTTcpConnection.m:710-787`; read-timeout extension always
−1), TC `NetworkFrameworkTcpConnectionInterface` (behind a networkSettings flag or beta, macOS 14+), and
`WebProxyTransport`.

### 1.5 MTProto (`h/MTProto.h:33-117`)

`-initWithContext:datacenterId:usageCalculationInfo:requiredAuthToken:authTokenMasterDatacenterId:` **[TC]**
(`MTProto.m:151-182`) registers itself as a context listener, creates a random-session `MTSessionInfo`, and
**starts Paused** (`_mtState |= MTProtoStatePaused`, `:177-179`). Nothing happens until `-resume`. State bits
(`MTProto.m:61-67`): AwaitingDatacenterScheme=1, AwaitingDatacenterAuthorization=2, AwaitingDatacenterAuthToken=8,
AwaitingTimeFixAndSalts=16, AwaitingLostMessages=32, Stopped=64, Paused=128.

| Member | Semantics | Used |
|---|---|---|
| `delegate` (weak `MTProtoDelegate`) | | [TC] |
| `context`, `apiEnvironment` (readonly), `datacenterId` (settable) | | [TC] reads `datacenterId`, `context` |
| `useTempAuthKeys`, `media`, `cdn`, `checkForProxyConnectionIssues` | plain flags; set them **before** `resume` | [TC] |
| `useUnauthorizedMode`, `enforceMedia`, `allowUnboundEphemeralKeys`, `canResetAuthData`, `useExplicitAuthKey`, `tempConnectionForReuse` | used by auth, bind, backup and transfer protos | [int] |
| `requiredAuthToken`, `authTokenMasterDatacenterId` | readable and settable; TC reads them in `Download` | [TC] |
| `getLogPrefix` | | [TC] Download |
| `shouldStayConnected` | set true in init (`:175`), never read | [dead] |
| `tempAuthKeyBindingResultUpdated` | never invoked | [dead] |
| `-pause` / `-resume` | async on managerQueue. pause drops the transport. resume clears Paused, `resetTransport`, requests a transaction, then re-asks for an awaited key (`_requestAwaitedAuthInfo`) or token (`_requestAwaitedAuthToken`) (`:205-246`) | [TC] driven by `shouldKeepConnection` |
| `-stop` | sets Stopped, removes the context listener, stops the transport. **Irreversible** (`:248-264`) | [TC] `Download.deinit` |
| `-finalizeSession` | **empty** (`:395-396`) | [TC] (no-op) |
| `-add/removeMessageService:` | `mtProtoWillAddService:` runs **synchronously on the caller's thread** before the hop (`:467-468`). Add/remove and `DidAdd`/`DidRemove` run on managerQueue. Services are deduplicated by identity. Adding the first `MTResendMessageService` flips "service tasks" on (`:465-570`) | [TC] |
| `-messageServiceQueue` | managerQueue | [int] |
| `-requestTransportTransaction` | coalesced: at most one pending `dispatch_async` per managerQueue pass (`_willRequestTransactionOnNextQueuePass`). Skipped if Stopped, Paused or throttled. Creates a transport if none exists, then `setDelegateNeedsTransaction` (`:646-669`) | [int] |
| `-requestSecureTransportReset` | `[_transport reset]` unless stopped (`:671-681`) | [int] |
| `-resetSessionInfo:(ifActive)` | new random session and `mtProtoDidChangeSession:` to every service (iterated in reverse), then reset the transport. With `ifActive`, skipped unless `canAskForTransactions` (`:363-393`) | [int] |
| `-requestTimeResync` | adds an `MTTimeSyncMessageService` unless one is present (`:398-428`) | [int] |
| `-simulateDisconnection`, `-takeConnectionForReusing` (sync) | | [int] |
| `-_messageResendRequestFailed:`, `+_manuallyEncryptedMessage:...` (V1 encryption for the bind inner message) | | [int] |
| `+_paddedPlaintextWithSalt:...`, `+_encryptedTransportDataForPaddedPlaintext:...`, `+_decryptedPayloadForIncomingTransportData:...`, `+_readIncomingPayload:...` | exposed for tests (§3, §7) | [test] |

**`MTProtoDelegate`** (`h/MTProto.h:22-31`). All callbacks run on managerQueue and are all implemented by TC
`MTProtoConnectionStatusDelegate` (`Network.swift:95-157`), which folds them into flags:
- `mtProtoNetworkAvailabilityChanged:isNetworkAvailable:` comes from the transport (`MTProto.m:726-747`).
  `updateConnectionState` with no transport also sends `false` (`:266-283`).
- `mtProtoConnectionStateChanged:state:` receives `MTProtoConnectionState{isConnected, proxyAddress = proxySettings.ip, proxyHasConnectionIssues = _probingStatus}`
  (`:761-786`). It is re-emitted with `isConnected` unchanged when probing flips `proxyHasConnectionIssues` (`:869-872`).
  `state:nil` is sent when there is no transport (`:277-278`). TC ignores `proxyHasConnectionIssues` while connected.
- `mtProtoConnectionContextUpdateStateChanged:isUpdatingConnectionContext:` comes from the transport.
- `mtProtoServiceTasksStateChanged:isPerformingServiceTasks:` is `AwaitingTimeFixAndSalts || anyResendServicePresent`
  and is emitted only on change (`:427-463`, `:500-512`, `:552-566`).

TC derives `ConnectionStatus` from these flags: `waitingForNetwork` / `connecting(proxy, issues)` /
`updating` / `online` (`Network.swift:641-659`).

### 1.6 MTMessageService (`h/MTMessageService.h:13-45`, all optional)

Every callback except `mtProtoWillAddService:` runs on managerQueue. Call sites in `MTProto.m`:
`WillAdd` 467, `DidAdd` 493, `DidRemove` 528, `PublicKeysUpdated` 2778, `MessageTransaction:authInfoSelector:sessionInfo:scheme:` 1017
(pull model: each service returns an `MTMessageTransaction` or nil when asked), `DidChangeSession` 386,
`ServerDidChangeSession:firstValidMessageId:otherValidMessageIds:` 2554 (on `new_session_created`),
`receivedMessage:authInfoSelector:networkType:` 2564 (every body MTProto does not consume itself, services in
reverse order), `receivedQuickAck:` 1725, `transactionsMayHaveFailed:` 1680, `AllTransactionsMayHaveFailed` 1706,
`messageDeliveryFailed:` 2475-2482, `messageDeliveryConfirmed:` 2498, `messageResendRequestFailed:` 2767,
`protocolErrorReceived:` 1970, `shouldRequestMessageWithId:inResponseToMessageId:currentTransactionId:` 2519,
`updateReceiveProgressForToken:progress:packetLength:` 1887, `TransportActivityUpdated` 1901,
`NetworkAvailabilityChanged` 739, `ConnectionStateChanged:isConnected:` 774, `ConnectionContextUpdateStateChanged` 801,
`ServiceTasksStateChanged` 455/506/559, `AuthTokenUpdated` 2715, `ApiEnvironmentUpdated` 2803.

Implementers: `MTRequestMessageService`, `MTTimeSyncMessageService`, `MTResendMessageService`,
`MTBindKeyMessageService`, `MTDatacenterAuthMessageService`, `MTTransport`/`MTTcpTransport` (the transport is
itself a service), and TC `UpdateMessageService` / `UnauthorizedUpdateMessageService`. The TC services implement
`WillAdd`, `DidChangeSession` and `ServerDidChangeSession` (each pushes `.reset`), and `receivedMessage`, which
forwards `BoxedMessage` bodies of type `Api.Updates`. **Selector traps:** `MTTimeSyncMessageService.m:118` and
`MTBindKeyMessageService.m:134` implement `...firstValidMessageId:messageIdsInFirstValidContainer:`, which MTProto
never calls. `MTTimeSyncMessageService.m:206` calls a 3-argument `timeSyncServiceCompleted:` that MTProto does not
implement (§10 H2).

### 1.7 Requests: MTRequestMessageService, MTRequest, contexts

**`MTRequestMessageService`** (`h/MTRequestMessageService.h:20-37`) **[TC]**. `-initWithContext:` registers a
block listener that is dead on arrival (see above). The service's `_queue` stays nil until
`mtProtoWillAddService:` sets it to managerQueue (`MTRequestMessageService.m:393-396`).
- `-addRequest:` (`:121-139`) is async on `_queue`. It is **silently dropped** (completion never called) if the
  service has not been added to an MTProto (nil queue, so `[nil dispatchOnQueue:]` is a no-op) or `_mtProto` is nil.
  Requests are deduplicated by identity, then `requestTransportTransaction`.
- `-removeRequestByInternalId:[askForReconnectionOnDrop:]` (`:146-205`) removes by `internalId isEqual:`. If the
  request was already sent (`requestContext != nil`) it marks a drop. If `expectedResponseSize >= 512*1024`
  (`:169`) it also forces `resetSessionInfo:true`, so that a cancelled large download does not keep streaming.
  Then it requests a transaction. If the list became empty it calls `requestMessageServiceDidCompleteAllRequests:`.
  Note that the `MTDropResponseContext` append is commented out (`:163`), so cancellation sends **no**
  `rpc_drop_answer` (§4).
- `-requestCount:` returns 0 synchronously when not attached.
- `apiEnvironment` and `forceBackgroundRequests` ([TC] Download sets it true). `didReceiveSoftAuthResetError`
  ([TC] forwarded to `Network.didReceiveSoftAuthResetError`).
- When `apiInitializationHash` changes, `mtProtoApiEnvironmentUpdated:` enqueues a `help.test` noop request so that
  initConnection is re-sent (`:405-420`).
- **`MTRequestMessageServiceDelegate`** (`:11-18`), called on managerQueue: `requestMessageServiceAuthorizationRequired:`.
  [TC] `Network` implements it as logout. `Download` implements it as "drop the token for this DC, then
  `authTokenForDatacenterWithIdRequired`". `requestMessageServiceDidCompleteAllRequests:` is not implemented by TC.

**`MTRequest`** (`h/MTRequest.h:19-47`). `internalId` is an `MTRequestInternalId` (process-wide
`OSAtomicIncrement32` counter; `copy` allocates a new id then overwrites its value; `MTRequest.m:22-63`).
`dependsOnPasswordEntry` **defaults to true** (`MTRequest.m:73`). TC always sets it false. Properties TC uses:
`setPayload:metadata:shortMetadata:responseParser:` (the parser returns nil on TL failure; TC then reports
`500 TL_VERIFICATION_ERROR` itself), `completed(result, MTRequestResponseInfo{networkType, timestamp, duration}, MTRpcError)`,
`progressUpdated(progress, packetLength)`, `acknowledgementReceived` (non-nil requests a quick-ack;
`MTRequestMessageService.m:638`), `shouldContinueExecutionWithErrorContext` (TC returns false when
`floodWaitSeconds > 0 && !automaticFloodWait`, or `internalServerErrorCount > 0 && failOnServerErrors`),
`shouldDependOnRequest` (dependency tags), `needsTimeoutTimer` (= `useRequestTimeoutTimers`),
`expectedResponseSize`, `metadata`. Not used by TC: `hasHighPriority`, `passthroughPasswordEntryError`,
`decorators`, `transactionResetStateVersion`, `shortMetadata` (TC passes it but never reads it back). Every request
callback runs on managerQueue. `completed` is copied out and called after the request is removed (`:1053-1062`).
**`MTRequestErrorContext`** (`h/MTRequestErrorContext.h:27-41`): `minimalExecuteTime`, `internalServerErrorCount`,
`floodWaitSeconds`, `floodWaitErrorText`, `waitingForTokenExport`, `waitingForRequestToComplete`, and the
pending APNS-nonce or recaptcha verification data. **`MTRequestContext`** (`h/MTRequestContext.h`): messageId, seqNo,
waitingForMessageId, transactionId, quickAckId, delivered, responseMessageId, willInitializeApi, sentTimestamp.
**`MTRpcError`**: `{int32 errorCode, NSString errorDescription}`, with description `"%d: %@"`.

### 1.8 Transport-level public types

- **`MTTransport`** (`h/MTTransport.h:39-69`) is the abstract base and itself an `MTMessageService`.
  `MTTcpTransport` is the only subclass. `MTTransportDelegate` (`:18-37`) callbacks are issued from
  tcpTransportQueue. MTProto's implementations hop to managerQueue and ignore any transport other than the current
  `_transport` (`MTProto.m:726-811`). Exported constants are `MTMaxTransportPayloadLength = 16 MiB` and
  `MTMaxUnpackedMessageLength = 32 MiB` (`MTTransport.m:3-4`).
- **`MTTransportScheme`** `{transportClass, address, media}`. `isOptimal` is true iff the class is
  `MTTcpTransport`. `compareToScheme:` puts TCP first.
- **`MTMessageTransaction`** `{internalId, messagePayload: [MTOutgoingMessage], prepared, failed, completion(msgInternalId→transactionId, →MTPreparedMessage, →quickAckId), allowServiceMode, requiresEncryption}`.
  `completion` may fire multiple times when one message transaction spans several transport transactions
  (`h/MTMessageTransaction.h:9-12`). It fires with `(nil,nil,nil)` when the transaction is abandoned
  (`MTProto.m:1150`).
- **`MTOutgoingMessage`** `{internalId, data, metadata, shortMetadata, messageId/seqNo (0 = assign), requiresConfirmation, needsQuickAck, hasHighPriority, inResponseToMessageId, dynamicDecorator}`.
  **`MTPreparedMessage`** is `{internalId, messageId, seqNo, salt, data, requiresConfirmation, hasHighPriority, inResponseToMessageId}`.
  **`MTIncomingMessage`** is `{messageId, seqNo, authKeyId, sessionId, salt, timestamp, size, body}`, where
  `body` is either an internal MT*Message object or whatever `MTSerialization.parseMessage` returned.
- **`MTTransportTransaction`** `{payload, completion(success, transactionId), needsQuickAck, expectsDataInResponse}`.
- Quick-ack helpers (`h/MTQuickAck.h`, `MTQuickAck.m`): the token is the LE first 4 bytes of `msg_key_large`
  with bit 31 cleared. In intermediate framing the echoed word is masked as-is. In abridged framing the 4 wire
  bytes are byte-swapped, then masked.
- `MTSessionInfo` (`h/MTSessionInfo.h`), `MTTimeFixContext` and `MTDropResponseContext` are public but internal to
  the session engine (§3). `MTNetworkAvailability` (delegate on its global queue; flags are polled every 5.0 s and
  on reachability callbacks; it notifies only when the `"%s_%s_%s"` state string changes, and reports
  `isReachable` alone; `MTNetworkAvailability.m:51-166`) is created **once per `MTTransport`** (`MTTransport.m:33`).

### 1.9 Value classes and their persisted (NSCoding) format

These objects are archived with `NSKeyedArchiver` into the app keychain. **TC reads them directly**:
`accountBackupData` unarchives `persistent:datacenterAuthInfoById` and casts entries to `MTDatacenterAuthInfo`
(`Account.swift:1120-1160`). Backup restore writes a dictionary keyed by `NSNumber(dcId)` holding
`MTDatacenterAuthInfo(validUntil = Int32.max, saltSet = [], attrs = [:])` (`Account.swift:302-322`). The archives
embed the **ObjC class names**, so these classes must exist at runtime for the archives to decode.

| Class | Coder keys | Notes |
|---|---|---|
| `MTDatacenterAddress` | `ip`(obj) `host`(obj) `port`(int) `preferForMedia` `restrictToTcp` `cdn` `preferForProxy`(bool) `secret`(obj) (`MTDatacenterAddress.m:24-51`) | `isEqual` compares all fields except `host`. `hash = ip.hash*31+port`. `copy` returns self. `isIpv6` uses `inet_pton(AF_INET6)` |
| `MTDatacenterAddressSet` | `addressList` | `isEqual` is ordered element-wise; **no `hash` override** |
| `MTDatacenterAuthInfo` | `authKey` `authKeyId`(i64) `validUntilTimestamp`(i32) `saltSet` `authKeyAttributes` (`MTDatacenterAuthInfo.m:51-75`) | a missing `validUntilTimestamp` decodes as **0** here, but as INT32_MAX in `MTDatacenterAuthKey`. Only non-persistent keys are expiry-checked at load (`MTContext.m:484-490`) |
| `MTDatacenterAuthKey` | `key` `keyId` `validUntilTimestamp` (0→INT32_MAX) `notBound` | |
| `MTDatacenterSaltInfo` | `salt` `firstValidMessageId` `lastValidMessageId` (i64) | `validMessageCountAfterId` = 0 if `id < first`, else `max(0, last-id)`. `isValidFutureSaltForMessageId` = `last > id` |
| `MTTransportScheme` | `transportClass` (string via `NSStringFromClass`) `address` `media` | decoding fails to a nil class if the class name is unknown |
| `MTTransportSchemeKey` (private, `MTContext.m:62-117`) | `datacenterId` `isProxy` `isMedia` | used as the dictionary key of `datacenterManuallySelectedSchemeById_v1` |

The auth-info dictionary key is `NSNumber(longlong)` = `(selector << 32) | dcId` (`MTContext.m:126-144`), with
selector Persistent=0, EphemeralMain=1, EphemeralMedia=2. Persistent entries are therefore keyed by plain `dcId`.
TC's backup code relies on this: it skips keys that do not fit an Int32 and only accepts ids 1...10.

Salt selection, `-[MTDatacenterAuthInfo authSaltForMessageId:]` (`:77-90`): `bestValidMessageCount` is never
updated, so the result is the **last** salt in array order with a non-zero remaining window, or 0. `mergeSaltSet:forTimestamp:`
keeps old salts with `last > ts*2^32`, then appends new ones that are not already present (deduplicated by
`firstValidMessageId`) and still valid.

### 1.10 App-implemented protocols

- **`MTSerialization`** (`h/MTSerialization.h:14-25`). [TC] `Serialization` (`State/Serialization.swift:261`):
  `currentLayer` = **230**. `parseMessage:` returns `BoxedMessage(Api.parse)` or nil and is called once per
  non-internal incoming body (`MTProto.m:2296`). `exportAuthorization:data:` encodes `auth.exportAuthorization(dcId)`
  and returns a parser to `MTExportedAuthorizationData{bytes,id}`. `importAuthorization:bytes:` encodes
  `auth.importAuthorization`. `requestDatacenterAddressWithData:` encodes `help.getConfig` and returns a parser to
  `MTDatacenterAddressListData{dcId: [MTDatacenterAddress]}`, built from `dcOption` flags bit1=media, bit2=tcpo,
  bit3=cdn, bit4=static(preferForProxy). `requestNoop:` is `help.test`. Callers: `MTBackupAddressSignals.m:275`,
  `MTDiscoverDatacenterAddressAction.m:105`, `MTDatacenterTransferAuthAction.m:111,152`,
  `MTRequestMessageService.m:413,438` (`currentLayer` goes into invokeWithLayer).
- **`MTKeychain`** (`h/MTKeychain.h:5-12`): `setObject:forKey:group:`, `dictionaryForKey:group:`,
  `numberForKey:group:`, `removeObjectForKey:group:`. [TC] `Keychain` (`Network.swift:1327-1380`) stores an
  `NSKeyedArchiver` blob under the Postbox keychain key `"<group>:<key>"`. Reads use `MTDeprecated`
  (`unarchiveObjectWithData`, exceptions swallowed to nil; `MTKeychain.m:5-14`). Postbox reads are **synchronous**
  (`syncWith` on the Postbox queue), writes are async transactions, and `removeKeychainEntryForKey` is a no-op on
  macOS Postbox. Reads return nil for a keychain that is no longer the account's current one (`Account.swift:11-50`).
  Keys MtProtoKit uses: `temp:{globalTimeDifference, transportSchemeStats_v1}`,
  `persistent:{datacenterAddressSetById, datacenterManuallySelectedSchemeById_v1, datacenterAuthInfoById, authTokenById}`,
  `ephemeral:datacenterPublicKeysById`, `cleanup:cleanupSessionIdsByAuthKeyId`,
  `primes:{isPrimeSafe_<hex>, isPrimeModSafe_<hex>_<g>}` (the `MTCheckIsSafePrime`/`MTCheckMod` cache,
  `MTEncryption.m:631-796`). MtProtoKit never calls `removeObjectForKey:` on the context keychain.
- **`EncryptionProvider`** (`EncryptionProvider.h`): an `MTBignumContext` factory (create, assign, modExp, modMul,
  isPrime, ...), `rsaEncryptWithPublicKey:data:`, `rsaEncryptPKCS1OAEPWithPublicKey:data:`, `parseRSAPublicKey:`,
  `macosRSAEncrypt:data:`. The full crypto export list is in §7.

### 1.11 Other public utilities

- `MTApiEnvironment`, `MTProxySecret{Type0,1,2}`, `MTSocksProxySettings{ip,port,username,password,secret,webProxy}`
  and `MTNetworkSettings{reducedBackupDiscoveryTimeout}` (`h/MTApiEnvironment.h`) are covered in §8. [TC] uses
  `withUpdated{LangPackCode,SocksProxySettings,NetworkSettings,SystemCode}`, `apiId`, `langPack`, `layer`,
  `disableUpdates`, `accessHostOverride`. [Mac] uses `MTProxySecret parse:/parseData:/serialize/serializeToString`.
- `MTProxyConnectivity.pingProxyWithContext:datacenterId:settings:` [TC, Mac] (`MTProxyConnectivity.m:113-152`).
  For **every** address of the DC it builds a throwaway `MTContext` with the proxy env and an `MTTcpConnection`,
  and sends an unencrypted `req_pq` payload. The response is valid iff it is ≥84 bytes, `auth_key_id == 0`,
  `res_pq` constructor `0x05162463` sits at offset 20, and the nonce matches at offset 24. Results are combined, the
  first reachable status (with RTT) wins, otherwise `reachable:false`. There is **no overall timeout**; it relies on
  the connection's own timeouts.
- `MTHttpRequestOperation.dataForHttpUrl:[headers:]` [TC `FetchHttpResource`] wraps an `NSURLSession sharedSession`
  data task. A non-HTTP response errors with nil. Dispose cancels the task.
- `MTBackupAddressSignals.fetchBackupIps:...` [TC] (§2). `MTGzip` [TC]: `decompress:` = `decompress:maxOutputLength:32 MiB`
  (`MTGzip.m:6`), windowBits 15+32 (zlib or gzip auto-detect), 16 KiB chunks, nil on any error, on overflow, or if
  `Z_STREAM_END` is not reached. Input 0 or >UINT_MAX bytes gives nil. Bytes after the first member are ignored.
  `compress:` is gzip (windowBits 31), level 9, memLevel 8. An empty input is **returned as-is** (not gzip).
  `deflate` return codes are unchecked (`:76-111`).
- `MTLogging` [TC via `NetworkLogging`]: two global function pointers (full and short). `MTLogEnabled()` =
  function set && enabled flag (default **true**, `MTLogging.m:5`). `MTLog` and `MTLogWithPrefix` format and
  forward whenever a function is set, **ignoring the enabled flag** (`:11-35`). Callers normally guard with
  `MTLogEnabled()`, but some do not. `MTShortLog` is always on.
- `MTTime`: `MTAbsoluteSystemTime()` is `mach_absolute_time` in seconds, monotonic and not wall clock. Request
  timing uses `CFAbsoluteTimeGetCurrent()`, which is wall clock.
- `MTInternalId(name)` macro and `MTAtomic` (`os_unfair_lock`; `modify`/`with` run `f` **under the lock**).
  `MTBag` (not thread-safe; keys count up from 0; `addItem:nil` returns −1). `MTTimer` (see §1.12).
- `MTEncryption.h` exports (`MTSha1`, `MTSha256`, `MTRawSha256TwoParts`, AES-IGE variants, `MTAesCtr`,
  `MTRsaEncrypt`, `MTExp`, `MTModSub`, `MTModMul`, `MTMul`, `MTAdd`, `MTIsZero`, `MTFactorize`, `MTCheckIsSafe*`,
  `MTCheckMod`, `MTRsaFingerprint`, `MTRsaEncryptPKCS1OAEP`, `MTIPDataDecode`, `MTPBKDF2`, `MTMurMurHash32`) are
  specified in §7. TC uses `MTSha1`, `MTSubdataSha1`, `MTSha256`, `MTAesEncrypt`, `MTAesDecrypt`,
  `MTAes{En,De}cryptBytesInplaceAndModifyIv`, `MTAesCtrDecrypt`, `MTExp`, `MTModSub`, `MTModMul`, `MTMul`, `MTAdd`,
  `MTIsZero`, `MTCheckIsSafeG`, `MTCheckIsSafeB`, `MTCheckIsSafeGAOrB`, `MTCheckIsSafePrime`, `MTCheckMod`,
  `MTPBKDF2`, `MTRsaFingerprint`, `MTRsaEncryptPKCS1OAEP`.

### 1.12 MTSignal, subscribers, disposables, timers

The engine's async glue is a minimal Rx implementation. Discovery, backup, proxy-ping and verification behaviour
depends on these exact semantics.

- **Subscriber** (`MTSubscriber.m`). `putNext` is delivered only while not terminated. `putError` and
  `putCompletion` are terminal: they release the callback blocks, deliver once, then **dispose the upstream
  disposable** (`:103-156`). If the generator terminates before returning its disposable, `_assignDisposable:`
  disposes it immediately (`:51-65`). `startWithNext:...` returns an `MTSubscriberDisposable`, whose `dispose`
  disposes the generator's disposable and marks the subscriber terminated **without** calling any callback
  (`MTSignal.m:36-48`). `startWithNextStrict:...file:line:` additionally asserts in DEBUG if the disposable is
  freed undisposed (`:84-95`).
- **Disposables** (`MTDisposable.m`). `MTBlockDisposable` runs its block at most once. `MTMetaDisposable.setDisposable:`
  disposes the previous value. After `dispose`, any newly set value is disposed immediately (the disposed state is
  sticky). `MTDisposableSet` disposes all members once, and members added later are disposed immediately.
  **Deallocating any of these does not dispose** (`:26-37`, `:73-86`, `:147-157`); dropping one leaks the work.
- **Operators** (`MTSignal.m`): `single` 374, `fail` 384 (`fail:nil` is a legal "error"), `never` 393,
  `complete` 401. `then:` 410 starts B when A completes; errors pass through. `delay:onQueue:` 443 starts the
  source when an MTTimer fires on the queue's native queue; dispose invalidates the timer.
  **`timeout:onQueue:orSignal:` 477**: on timer fire it **starts the alternative without cancelling the source**.
  The source is torn down only when the downstream subscriber terminates. Every in-tree alternative terminates
  (`fail:nil`, `single:@false`), so in practice the source is cancelled right after the alternative's event. A
  non-terminating alternative would leave both the source and the alternative feeding the subscriber. Dispose
  disposes the source and the alternative but **does not invalidate the timer**: the timer is invalidated only by
  a source event. A disposed timeout still fires later and runs the alternative's generator into an
  already-disposed `MTMetaDisposable`.
  `catch:` 519 subscribes `f(error)` on error. `combineSignals:` 554 emits an array once every input has emitted
  at least once, errors at most once, completes when all inputs complete; an empty input emits `@[]`.
  `mergeSignals:` 656 completes when all complete (empty input completes); the first error terminates.
  `restart` 703 resubscribes on every completion, recursively and **synchronously**, so a synchronously completing
  source would recurse without bound. Every in-tree use ends in a `then:delay` (`MTDNS.m:219`,
  `MTDiscoverConnectionSignals.m:332-333`, `MTProto.m:846`, 20 s), which breaks the recursion through the timer. `take:` 748 forwards the first n values and completes on the n-th (`take:0`
  forwards nothing and never completes early). `switchToLatest`/`mapToSignal:` 781/836: a new inner disposes the
  previous one; completion waits for the current inner. `map`/`filter` 802/818. `onDispose:` 841.
  `deliverOn:` 867 hops each event via `dispatchOnQueue` (inline when already on a named queue). `startOn:` 893
  subscribes on the queue and is cancellable before it starts. `takeLast` 925. `reduceLeft:with:` 950 (emits only
  a non-nil accumulator).
- **`+[MTDiscoverConnectionSignals repeatSignal:withBackoffFrom:upTo:onQueue:]`** (`MTDiscoverConnectionSignals.m:228-257`,
  private). Each round is `signal.then(complete.delay(d))`. After a round completes, the next round starts with
  `d = min(d*2, max)`. Values pass through, an error terminates, and the recursion runs from the timer callback, so
  it does not grow the stack. Used as `[repeat(merge(probes), 1 s → 15 s) take:1]`.
- **`MTTimer`** (`MTTimer.m`): a `dispatch_source` timer on the given queue with leeway 0. Repeating timers use
  interval = timeout. `timeoutDate` is Unix seconds (initially `INT_MAX`, 0 after invalidate). `start` creates a
  new source **without cancelling an existing one**. `resetTimeout:` invalidates, then starts. The handler block
  captures `self`, so a repeating timer stays alive until it is invalidated. `remainingTime` returns `DBL_MAX` when
  not scheduled. `fireAndInvalidate` runs the completion synchronously.

### 1.13 TL primitive encoding

All integers are little-endian and native (both code paths `#error` on big-endian).
`int32` takes 4 bytes, `int64` 8, `double` 8 (raw IEEE754).
`bytes` and `string` use this layout: if `L ≤ 253`, `[L:u8] data pad`, where pad zero-fills to a multiple of 4
counted from the length byte. Otherwise `[0xFE] [L:u24 LE] data pad`, with pad to a multiple of 4. **Writers**
(`MTOutputStream.m:90-170`, `MTBuffer.m:51-88`): empty or nil data is written as an int32 0 (`00 00 00 00`), which
is a valid empty bytes. The long form applies to `L ≥ 254`. `L ≥ 2^24` is silently truncated to 24 bits (no
check). Strings are UTF-8. **Readers** come in two incompatible flavours:
- `MTBufferReader` (`MTBufferReader.m`) is bounds-checked and used by `MTInternalMessageParser`,
  `MTEncryption`, the handshake parsers and the containers. `readTLBytes:` (`:78-114`) assembles the 24-bit length
  **unsigned**, checks the remaining length before allocating (`readData:`, `:43-51`), and requires the padding
  bytes to be present (their value is not checked). Marker `255` is accepted as a short length of 255.
  `readTLString:` returns true even for invalid UTF-8 (nil string).
- `MTInputStream` (`MTInputStream.m`, an `NSInputStream` wrapper) is still used for the 16-byte msg_key and the
  encrypted body read in the MTProto legacy path (`MTProto.m:1762-1771`). `readString:` and `readBytes:` ignore the
  result of the length-byte reads and build the 24-bit length with a **signed** `>>8` (`:155-156`, `:209-210`), so
  `L ≥ 8 MiB` becomes negative, then `malloc(huge)` returns NULL and `read` writes into NULL. Padding reads are
  unchecked. `readData:(int)` takes a signed length. Use the MTBufferReader rules.

### 1.14 What the Rust shim must preserve for consumers

1. ObjC surface parity for the symbols marked [TC]/[Mac] above, including `mtProtoWillAddService:` running
   synchronously, the weak listener and delegate semantics, and TC's pattern of creating an `MTProto` paused and
   then calling `resume`.
2. Callback queue guarantees: TC code assumes `MTProtoDelegate`, `MTMessageService` and request callbacks run
   serially on **one** queue for all protos (it mutates `Atomic` and `ValuePipe` without further hops), and that
   context listeners run serially.
3. `globalTime` and `authInfoForDatacenterWithId` are synchronous, with no stale cache that could differ from
   what MTProto uses.
4. Keychain key names, archive classes and the dictionary-key encoding (§1.9, §1.10). TC's backup and restore code
   reads `persistent:datacenterAuthInfoById` itself, and the ObjC engine must still read keys written while the
   Rust engine was active.
5. The `MTSerialization` round-trip points: the engine never parses API TL itself, except for the handful of
   service constructors in §3/§5.

### 1.z Constants

| Name | Value | File:line | Meaning |
|---|---|---|---|
| context queue label | `com.mtproto.MTContextQueue` | `MTContext.m:324` | global serial queue for all contexts |
| manager queue label | `org.mtproto.managerQueue` | `MTProto.m:146` | global serial queue for all MTProtos and services |
| tcp transport queue | `org.mtproto.tcpTransportQueue` | `MTTcpTransport.m:80` | transport state |
| tcp queue | `org.mtproto.tcpQueue` | `MTTcpConnection.m:882` | sockets and interface delegate queue |
| availability queue | `org.mtproto.MTNetwotkAvailability` | `MTNetworkAvailability.m:116` | reachability |
| reachability poll | 5.0 s, repeating | `MTNetworkAvailability.m:76` | flag re-read |
| `tempKeyExpiration` default | 86400 s | `MTContext.m:272` | temp key `expires_in` |
| auth/transfer retry backoff | 1,2,4,…,32 s then 60 s | `MTContext.m:225-230` | `MTRetryDelayForFailureCount` |
| drop-triggers-session-reset | `expectedResponseSize >= 524288` | `MTRequestMessageService.m:169` | cancel of a big download resets the session |
| `MTMaxTransportPayloadLength` | 16 MiB | `MTTransport.m:3` | max frame / container child |
| `MTMaxUnpackedMessageLength` | 32 MiB | `MTTransport.m:4` | gzip_packed ceiling |
| `MTGzipDefaultMaxDecompressedLength` | 32 MiB | `MTGzip.m:6` | default inflate ceiling |
| gzip chunk | 16 KiB | `MTGzip.m:10` | inflate/deflate step |
| gzip compress level | 9, windowBits 31, memLevel 8 | `MTGzip.m:92-93` | outgoing gzip |
| TL long-form threshold | 254 (`0xFE`) | `MTOutputStream.m:104`, `MTBufferReader.m:86` | bytes/string |
| `MTRequest.dependsOnPasswordEntry` default | true | `MTRequest.m:73` | TC overrides to false |
| `currentLayer` (TC) | 230 | `State/Serialization.swift:263` | invokeWithLayer value |
| auth-info key | `(selector<<32)\|dcId` | `MTContext.m:126-133` | keychain dict key |
| selectors | Persistent 0, EphemeralMain 1, EphemeralMedia 2 | `h/MTDatacenterAuthInfo.h:14-18` | |
| MTProto state bits | 1,2,8,16,32,64,128 | `MTProto.m:61-67` | Scheme, Auth, Token, TimeFix, LostMsgs, Stopped, Paused |
| verification timeouts (TC) | 15 s | `Network.swift:601,617` | APNS / recaptcha |
| backoff probe repeat (discovery) | 1 s → ×2 → 15 s cap | `MTDiscoverConnectionSignals.m:228-257,328-330` | see §2 |
| proxy-ping valid response | ≥84 B, `res_pq` 0x05162463 @20, nonce @24 | `MTProxyConnectivity.m:42-55` | |
| networkType | 0 = other/Wi-Fi, 1 = WWAN | `GCDAsyncSocket.m:5116` | `MTRequestResponseInfo.networkType` |

## 2. MTContext, persistent state and context-level actions

`MTContext` is the per-account (per-"environment") shared state object. Every `MTProto` instance of an account
(main connection, every Download/Upload worker, every temp auth/bind/transfer/discovery connection) points at the
same `MTContext`. It owns: the auth keys per DC and selector, address sets, transport-scheme preferences and stats,
auth tokens for non-master DCs, the global server-time offset, CDN public keys, the api environment (incl. proxy
settings), and it runs the context-level "actions" that produce missing keys, tokens and addresses.

File refs: `MTContext.m` etc. = `Sources/`, `h/X.h` = `PublicHeaders/MtProtoKit/X.h`, TelegramCore paths are
relative to `submodules/TelegramCore/Sources/`.

### 2.1 Queue and threading model

- **One process-wide serial queue** for *all* contexts: `+[MTContext contextQueue]`, an `MTQueue` named
  `"com.mtproto.MTContextQueue"` (`MTContext.m:318-327`). Every context mutation and every listener notification
  runs on it.
- `MTQueue dispatchOnQueue:` runs the block **inline when already on the queue**, otherwise `dispatch_async`
  (default) or `dispatch_sync` (`synchronous:true`) (`MTQueue.m:104-130`). Consequences a port must reproduce or
  consciously replace:
  - Setters are fire-and-forget async from foreign queues, but synchronous and re-entrant when called from the
    context queue (e.g. from inside a listener callback or an action completion).
  - Getters (`authInfoForDatacenterWithId:`, `addressSetForDatacenterWithId:`, `authTokenForDatacenterWithId:`,
    `globalTimeDifference`, `transportSchemesForDatacenterWithId:...`, `chooseTransportScheme...`,
    `knownDatacenterIds`, `enumerateAddressSetsForDatacenters:`, `publicKeysForDatacenterWithId:`) are
    `dispatch_sync`; since the queue is serial, a getter issued after an async setter from the same thread
    observes that setter (FIFO).
  - Listener callbacks are invoked synchronously on the context queue while the context is mid-mutation;
    `MTProto` immediately hops to its own `managerQueue` in every callback (`MTProto.m:2579-2815`).
- `performBatchUpdates:` is only `dispatchOnQueue:` (async) of the block (`MTContext.m:438-442`). No coalescing, no
  deferred notifications: "batch" just means "run these calls back-to-back on the context queue".
- The password-required map is the one piece of state guarded by an `os_unfair_lock` instead of the queue
  (`MTContext.m:825-859`).
- `+performWithObjCTry:` is `@try { block(); } @finally {}` with **no `@catch`** (`MTContext.m:329-334`) — it does
  not swallow exceptions (TelegramCore's `Keychain.setObject` relies on it, `Network.swift:1337-1344`).
- `MTContext` must be created with `initWithSerialization:encryptionProvider:apiEnvironment:isTestingEnvironment:useTempAuthKeys:`
  (`MTContext.m:252-311`); plain `init` asserts. Init draws a random `_uniqueId` (unused), sets
  `tempKeyExpiration = 86400` s (`:269`), allocates empty maps, and calls the no-op `updatePeriodicTasks`.

### 2.2 State inventory

| State (ivar) | Shape | Persisted as (group / key) | Notes |
|---|---|---|---|
| `_globalTimeDifference` | `double` seconds | `temp` / `globalTimeDifference` (NSNumber) | server − local time (§2.12) |
| `_datacenterSeedAddressSetById` | dcId → `MTDatacenterAddressSet` | not persisted | set by app every launch |
| `_datacenterAddressSetById` | dcId → `MTDatacenterAddressSet` | `persistent` / `datacenterAddressSetById` | learned addresses |
| `_datacenterManuallySelectedSchemeById` | `MTTransportSchemeKey(dc,isProxy,isMedia)` → `MTTransportScheme` | `persistent` / `datacenterManuallySelectedSchemeById_v1` | discovered/forced scheme |
| `_transportSchemeStats` | dcId → (`MTDatacenterAddress` → `MTTransportSchemeStats`) | `temp` / `transportSchemeStats_v1` (debounced 5 s) | failure/response stamps |
| `_datacenterAuthInfoById` | int64 key (§2.4) → `MTDatacenterAuthInfo` | `persistent` / `datacenterAuthInfoById` | all selectors in one dict |
| `_datacenterPublicKeysById` | dcId → `[ {key: PEM string, fingerprint: uint64} ]` | `ephemeral` / `datacenterPublicKeysById` | CDN RSA keys |
| `_authTokenById` | dcId → opaque token | `persistent` / `authTokenById` | non-master DC authorization |
| `_cleanupSessionIdsByAuthKeyId` | authKeyId → [sessionId] | `cleanup` / `cleanupSessionIdsByAuthKeyId` (read; written only by dead code) | §2.17 |
| `_passwordRequiredByDatacenterId` | dcId → bool | memory only | §2.15 |
| `_apiEnvironment` | `MTApiEnvironment` | memory only | replaced via `updateApiEnvironment:` |
| `_changeListeners` | `[MTWeakContextChangeListener]` | — | weak boxes |
| action maps | `_discoverDatacenterAddressActions` (dc), `_datacenterAuthActions` (auth key), `_datacenterTransferAuthActions` (dc), `_transportSchemeDisposableByDatacenterId` (dc), `_fetchPublicKeysActions` (dc), `_datacenterCheckKeyRemovedActions` (dc) | — | de-duplication of in-flight work |
| retry state | `_datacenterAuthFailureCounts`, `_datacenterAuthRetryTimers` (auth key), `_datacenterTransferAuthFailureCounts`, `_datacenterTransferAuthRetryTimers` (dc) | — | backoff (§2.5, §2.6) |
| `_datacenterCheckKeyRemovedActionTimestamps` | dc → CFAbsoluteTime int | — | logout-check throttle |
| `_backupAddressListDisposable`, `_discoverBackupAddressListSignal` | — | — | §2.10 |
| `_externalRequestVerification`, `_externalRecaptchaRequestVerification` | blocks | — | §2.16 |
| `makeTcpConnectionInterface` | factory block | — | §2.14 |
| `+fixedTimeDifference` | **process-global static int32** | — | §2.12 |

`ivars: MTContext.m:164-218`.

### 2.3 Keychain and persisted format

- Protocol `MTKeychain` (`h/MTKeychain.h:5-12`): `setObject:forKey:group:`, `dictionaryForKey:group:`,
  `numberForKey:group:`, `removeObjectForKey:group:`. `MTFileBasedKeychain.h/.m` are empty files.
- TelegramCore implementation `Keychain` (`Network/Network.swift:1327-1382`): storage key is
  `"<group>:<key>"`; value is `NSKeyedArchiver.archivedData(withRootObject:requiringSecureCoding:false)`; reads use
  `+[MTDeprecated unarchiveDeprecatedWithData:]` = `NSKeyedUnarchiver unarchiveObjectWithData:` with exceptions
  swallowed to nil (`MTKeychain.m:5-14`). A wrong type asserts in debug and returns nil. Bytes go to the account's
  Postbox keychain table (`Account/Account.swift:24-52`), guarded by a per-account "keychainId" generation so a
  stale `Keychain` instance silently stops reading/writing after a newer one is created for the same account.
- **Every write rewrites the whole dictionary** for that key (e.g. one salt merge on one DC re-archives all auth
  infos of all DCs and selectors). Writes happen synchronously on the context queue.
- NSCoding keys (needed for NSKeyedArchiver compatibility or a one-time migration):

| Class | Coder keys |
|---|---|
| `MTDatacenterAddressSet` | `addressList` (NSArray<MTDatacenterAddress>) (`MTDatacenterAddressSet.m:17-30`) |
| `MTDatacenterAddress` | `ip` (string), `host` (string, never set), `port` (int), `preferForMedia`, `restrictToTcp`, `cdn`, `preferForProxy` (bool), `secret` (NSData) (`MTDatacenterAddress.m:24-51`) |
| `MTDatacenterAuthInfo` | `authKey` (NSData), `authKeyId` (int64), `validUntilTimestamp` (int32), `saltSet` (NSArray<MTDatacenterSaltInfo>), `authKeyAttributes` (NSDictionary) (`MTDatacenterAuthInfo.m:51-75`) |
| `MTDatacenterSaltInfo` | `salt`, `firstValidMessageId`, `lastValidMessageId` (int64) (`MTDatacenterSaltInfo.m:17-34`) |
| `MTDatacenterAuthKey` | `key`, `keyId`, `validUntilTimestamp` (0 decodes to INT32_MAX), `notBound` (`MTDatacenterAuthInfo.m:17-31`) — not stored by the context |
| `MTTransportSchemeKey` (private, `MTContext.m:62-117`) | `datacenterId` (NSInteger), `isProxy`, `isMedia`; hash `dc*961 + isProxy*31 + isMedia` |
| `MTTransportScheme` | `transportClass` (class-name string, always `"MTTcpTransport"`), `address`, `media` (`MTTransportScheme.m:29-46`) |
| `MTTransportSchemeStats` | `lastFailureTimestamp`, `lastResponseTimestamp` (int32, **CFAbsoluteTime epoch = seconds since 2001-01-01**) (`MTTransportSchemeStats.m:16-23`) |

- `authKeyAttributes` holds `apiInitializationHash` (written by `MTRequestMessageService` when initConnection was
  accepted — see §4); it is persisted with the key.
- **Load (`setKeychain:`, `MTContext.m:444-527`)** — async on the context queue; in order:
  1. `globalTimeDifference` ← `temp/globalTimeDifference` if present.
  2. `_datacenterAddressSetById` ← `persistent/datacenterAddressSetById` (replaces the map).
  3. `_datacenterManuallySelectedSchemeById` ← `persistent/datacenterManuallySelectedSchemeById_v1`.
  4. For each `apiEnvironment.datacenterAddressOverrides[dc]`: `_datacenterAddressSetById[dc] = {override}`
     (in-memory; persisted by the next address-set write).
  5. `_datacenterAuthInfoById` ← `persistent/datacenterAuthInfoById`, then **drop every non-persistent selector
     entry whose `validUntilTimestamp != INT32_MAX` and `now(unix) > validUntilTimestamp`** (`:480-491`). This is the
     only place temp-key expiry is enforced; at runtime an expired temp key is used until the server rejects it.
  6. `_datacenterPublicKeysById` ← `ephemeral/datacenterPublicKeysById`.
  7. `_transportSchemeStats` ← `temp/transportSchemeStats_v1` (deep-copied to mutable).
  8. `_authTokenById` ← `persistent/authTokenById`.
  9. `_cleanupSessionIdsByAuthKeyId` ← `cleanup/cleanupSessionIdsByAuthKeyId`.
  No listener is notified on load. Setting a nil keychain only logs.
- `+copyAuthInfoFrom:toTempKeychain:` (`MTContext.m:350-356`) copies `temp/globalTimeDifference`,
  `persistent/datacenterAddressSetById`, `persistent/datacenterAuthInfoById`, `ephemeral/datacenterPublicKeysById`
  (not tokens, schemes, stats). No caller in TelegramCore/TelegramUI/Telegram (dead API).

### 2.4 Auth infos and selectors

- `MTDatacenterAuthInfoSelector` (`h/MTDatacenterAuthInfo.h:14-18`, int64): `Persistent = 0`,
  `EphemeralMain = 1`, `EphemeralMedia = 2`.
- Map key: `key = (int64(selector) << 32) | int64(dcId)`; parse: `dc = key & 0x7fffffff`,
  `selector = (key >> 32) & 0x7fffffff` (`MTContext.m:126-144`). Persisted as `NSNumber(longLong)`.
- `MTDatacenterAuthInfo` = `{authKey (256 B), authKeyId (int64), validUntilTimestamp (int32; INT32_MAX = never),
  saltSet [MTDatacenterSaltInfo], authKeyAttributes}`. `MTDatacenterAuthKey` = `{authKey, authKeyId,
  validUntilTimestamp, notBound}` is the in-flight form used by auth/bind code.
- Which selector a connection uses (decided in `MTProto getAuthKeyForCurrentScheme:`, `MTProto.m:893-947`):
  `useExplicitAuthKey` (bind connection) → `EphemeralMedia` if `scheme.media` else `EphemeralMain`; CDN →
  `Persistent`; `useTempAuthKeys` → `EphemeralMedia` if **`scheme.address.preferForMedia`** else
  `EphemeralMain`; otherwise `Persistent`. TelegramCore sets `useTempAuthKeys = true` for the context
  (`Network.swift:507`), the main MTProto, and workers unless CDN (`Download.swift:70`).
- Initial salt set written for every newly created key (`MTDatacenterAuthAction.m:115,128,164`):
  one entry `{salt: 0, firstValidMessageId: T, lastValidMessageId: T + 29 min * 2^32}` where `T` is the msg_id of the
  server's `dh_gen_ok` message (`MTDatacenterAuthMessageService.m:803`). The real salt is learnt from the first
  `bad_server_salt` (§3). Persistent keys get `validUntilTimestamp = INT32_MAX`; temp keys
  `validUntil = local_unix_now + tempKeyExpiration` (`MTDatacenterAuthMessageService.m:713`).
- `authSaltForMessageId:` (`MTDatacenterAuthInfo.m:77-90`) is intended to pick the salt with the most remaining
  validity but never updates `bestValidMessageCount`, so it returns **the last salt in the array** whose window
  contains `messageId` (`validMessageCountAfterId` = 0 if `msgId < first`, else `max(0, last − msgId)`), or 0.
- `mergeSaltSet:forTimestamp:` (`:92-124`): reference id = `timestamp * 2^32`; keep existing salts with
  `last > ref`; append new salts whose `firstValidMessageId` is not already present and `last > ref`. Called by
  `MTProto timeSyncInfoChanged:` with `[context globalTime]` (`MTProto.m:2733-2760`), which then writes the result
  back via `updateAuthInfoForDatacenterWithId:` (full keychain rewrite + listener fan-out on every salt update).
- **`updateAuthInfoForDatacenterWithId:authInfo:selector:`** (`MTContext.m:777-823`), on the context queue:
  1. `dcId == 0` → ignored.
  2. `authInfo == nil` and nothing stored → **return silently, no notification**. Otherwise set/remove.
  3. Persist the whole dict to `persistent/datacenterAuthInfoById`.
  4. Notify every live listener `contextDatacenterAuthInfoUpdated:datacenterId:authInfo:selector:` (authInfo may be nil).
  5. If the *persistent* key went nil → non-nil, call `execute:` again on every in-flight auth action of the same
     DC with a non-persistent selector (wakes ephemeral actions parked waiting for the permanent key).

### 2.5 Auth key creation (context orchestration)

- Entry: `authInfoForDatacenterWithIdRequired:isCdn:selector:allowUnboundEphemeralKeys:` (`MTContext.m:1557-1594`).
  Rules:
  - De-dup: does nothing if an action for `(dc, selector)` exists **or a retry timer for it is pending** (so a
    request arriving during backoff is dropped; the waiter is woken by the timer's failure notification).
  - Creates `MTDatacenterAuthAction(selector, isCdn, skipBind = allowUnboundEphemeralKeys)` (via the test
    factory hook `authActionFactory`, `MTInternalInterfaces.h:26`) and stores it.
  - Ephemeral selector without a persistent key and `!allowUnboundEphemeralKeys` → do **not** execute; instead
    request the *persistent* key (recursive call, `isCdn:false`). The ephemeral action stays parked until step 5
    of §2.4 re-executes it.
  - Otherwise `execute:` immediately.
- `MTDatacenterAuthAction` (`MTDatacenterAuthAction.m`):
  - `execute:` (`:59-102`): dc 0 or nil context → `fail`. If the context already has a key for this selector →
    `complete` (success, no network). Else create `_authMtProto = MTProto(dc, requiredAuthToken nil)` with
    `cdn = isCdn`, `useUnauthorizedMode = true`; `EphemeralMain` → `media=false`, `tempAuth=true`;
    `EphemeralMedia` → `media=true, enforceMedia=true, tempAuth=true`; add
    `MTDatacenterAuthMessageService(context, tempAuth)` (§5) and `resume`.
  - On `authMessageServiceCompletedWithAuthKey:timestamp:` (`:104-185`):
    - Persistent → store `MTDatacenterAuthInfo(validUntil INT32_MAX, initial salt)`, `complete`.
    - Ephemeral + `skipBind` → store unbound temp key, `complete`.
    - Ephemeral + bind: if the persistent key exists, create `_bindMtProto` (dc, `useUnauthorizedMode=false`,
      `useTempAuthKeys=true`, `useExplicitAuthKey = new temp key`, `tempConnectionForReuse = [_authMtProto
      takeConnectionForReusing]` — the bind reuses the already-open TCP connection; media flags as above), add
      `MTBindKeyMessageService(persistentKey, ephemeralKey)` (§5). Bind success → stop bind proto, store the temp
      key under the selector, `complete`; failure → `bindError = error`, `fail`. If the persistent key vanished in
      between, **nothing happens** (action never completes; §10 H11).
  - `cancel` = `cleanup` only (stops both MTProtos) and does **not** call the completion.
  - `+bindErrorMeansPermanentKeyIsUnknown:` is true only for `400 ENCRYPTED_MESSAGE_INVALID` (`:40-42`).
- Completion handling `_authActionFinished:success:` (`MTContext.m:1680-1735`, on the context queue):
  - Remove the action. Success → clear the failure count for that key. Done.
  - Failure with `ENCRYPTED_MESSAGE_INVALID` → log, **no retry timer, no notification** (waiters re-ask only when
    their MTProto resumes).
  - Other failure → `count += 1`, `delay = MTRetryDelayForFailureCount(count)`, (re)start a one-shot timer; on fire
    remove the timer and notify listeners `contextDatacenterAuthInfoRequestFailed:datacenterId:selector:`.
    The context itself never restarts the action.
- Backoff `MTRetryDelayForFailureCount(n)` (`MTContext.m:225-230`): `n==0 → 0`, else
  `min(60, 2^min(n−1, 6))` → **1, 2, 4, 8, 16, 32, 60, 60, … s**. Shared by key creation and token transfer.
- Waiter side (`MTProto.m:2645-2686`, and resume at `:240-243`): an MTProto that is active (not paused/stopped),
  waits for authorization (`MTProtoStateAwaitingDatacenterAuthorization`) and awaits exactly that selector calls
  `authInfoForDatacenterWithIdRequired:` again (which is deduped). A paused MTProto re-asks on `resume`.
- Note: real handshake failures rarely reach `fail` — `MTDatacenterAuthMessageService` retries the DH exchange
  internally (§5); `fail` is mostly a failed **bind**.

### 2.6 Auth tokens and authorization transfer

- A token marks "this account is authorized on DC X". TelegramCore uses `requiredAuthToken = NSNumber(dcId)` for
  every non-CDN worker on a DC other than the master, with `authTokenMasterDatacenterId = master` (`Download.swift:57-64`);
  the main connection uses `nil`. Tokens are compared with `isEqual:`.
- MTProto gate (`MTProto.m:347-352`, inside `resetTransport`): if `requiredAuthToken != nil`, not unauthorized
  mode, and `context.authToken(dc) != requiredAuthToken` → set `MTProtoStateAwaitingDatacenterAuthToken` (once) and
  call `authTokenForDatacenterWithIdRequired:authToken:masterDatacenterId:`. No transport is created meanwhile.
- `authTokenForDatacenterWithIdRequired:` (`MTContext.m:1596-1611`): ignored if `authToken == nil`, if a transfer
  or a retry timer for the dc exists, or if `masterDatacenterId == datacenterId`; else creates
  `MTDatacenterTransferAuthAction` (factory hook `transferAuthActionFactory`) with the context as delegate.
- `MTDatacenterTransferAuthAction` (`MTDatacenterTransferAuthAction.m`):
  1. `execute:` (`:57-72`): bad args → `fail`; if the context already holds an equal token for the destination →
     `complete`; else `beginTransferFromDatacenterId:master`.
  2. Source MTProto on the **master** DC (`requiredAuthToken nil`, `useTempAuthKeys = context.useTempAuthKeys`),
     `MTRequestMessageService` with `forceBackgroundRequests = true`; request `auth.exportAuthorization(dc_id: dest)`
     built by `serialization exportAuthorization:data:` (TelegramCore `State/Serialization.swift:273-288`).
  3. On result `{id, bytes}`: stop the source MTProto; create destination MTProto (`canResetAuthData = true`,
     `useTempAuthKeys = context.useTempAuthKeys`) and send `auth.importAuthorization(id, bytes)`; its response
     parser accepts **any** payload as success (`return @true`).
  4. Import success → `context updateAuthTokenForDatacenterWithId:dest authToken:` then `complete`. Any error in 2/3
     → `fail`.
  - Both requests get `applyRetryPolicyToRequest:` (`:30-38`): `shouldContinueExecutionWithErrorContext = ^{ return
    true; }`, i.e. MTRequestMessageService's generic retry (5xx after a delay, FLOOD_WAIT waited out — §4) instead of
    failing on the first 500 (field bug: `500 INTERDC_2_CALL_ERROR`).
  - Internal requests keep `MTRequest.dependsOnPasswordEntry = true` (default, `MTRequest.m:73`) — see §2.15.
  - `contextDatacenterAuthTokenUpdated:` is implemented (`:74-87`) but the action never registers as a listener,
    so it is dead; `cleanup` nevertheless calls `removeChangeListener:` (synchronous on the context queue).
  - `cancel` = `cleanup` + `fail` (reports failure to the delegate, which the context nils first in every cancel path).
- Context completion: `datacenterTransferAuthActionCompleted:` removes the action and clears the dc failure count
  (`MTContext.m:1623-1632`). `datacenterTransferAuthActionFailed:` (`:1639-1666`) removes the action, increments the
  count, starts the backoff timer (same formula as §2.5) and on fire notifies
  `contextDatacenterAuthTokenTransferFailed:datacenterId:`.
- `updateAuthTokenForDatacenterWithId:authToken:` (`:1496-1518`): set (and clear failure count) or remove; persist
  `persistent/authTokenById`; notify `contextDatacenterAuthTokenUpdated:`. MTProto reaction (`MTProto.m:2697-2720`): if
  the token equals its `requiredAuthToken` → clear `AwaitingDatacenterAuthToken`, reset transport, request
  transaction, and call `mtProtoAuthTokenUpdated:` on every message service (RequestMessageService releases
  requests parked in `waitingForTokenExport`).
- `removeTokenForDatacenterWithId:` (`:1214-1231`, called by MTProto.handleMissingKey for a non-master temp key loss,
  `MTProto.m:2128-2140`): remove + persist; if a transfer was running, cancel it and notify
  `contextDatacenterAuthTokenTransferFailed:` **immediately** (no backoff) so waiters re-ask.
- `removeAllAuthTokens` (`:1197-1212`): clear + persist, cancel all transfers silently (no notification). No caller
  in TelegramCore.
- 401 path (TelegramCore): a worker's `requestMessageServiceAuthorizationRequired` sets the token to nil and calls
  `authTokenForDatacenterWithIdRequired` itself (`Download.swift:101-104`); the main `Network` instead reports
  `loggedOut` (`Network.swift:1067-1070`). Waiters for a token re-ask on failure notification or resume
  (`MTProto _requestAwaitedAuthToken`, `MTProto.m:2662-2674`: also re-asks when the flag is not set but the token
  is missing — the 401 case).

### 2.7 Address sets

- `MTDatacenterAddress` = `{ip, port (uint16), preferForMedia, restrictToTcp, cdn, preferForProxy ("static"),
  secret}`; `host` is never assigned. Equality compares **all** fields incl. secret (nil vs non-nil differ);
  `hash = ip.hash*31 + port` (`MTDatacenterAddress.m:57-104`). `isIpv6` = `inet_pton(AF_INET6)` succeeds.
- `MTDatacenterAddressSet` = ordered `addressList`; equality is element-wise in order (`MTDatacenterAddressSet.m:32-47`).
- dc_option → address mapping (TelegramCore `State/Serialization.swift:294-318`, `State/ManagedConfigurationUpdates.swift:20-37`):
  flag bit1 → `preferForMedia`, bit2 → `restrictToTcp`, bit3 → `cdn`, bit4 → `preferForProxy`, `secret` bytes kept.
  bit0 (ipv6) and bit5 (this_port_only) are ignored (IPv6 is inferred from the string).
- Seeds (not persisted, set each launch, `Network.swift:542-560`), all port 443, no flags:
  production `1: 149.154.175.50, 2001:b28:f23d:f001::a; 2: 149.154.167.50, 95.161.76.100, 2001:67c:4e8:f002::a;
  3: 149.154.175.100, 2001:b28:f23d:f003::a; 4: 149.154.167.91, 2001:67c:4e8:f004::a; 5: 149.154.171.5,
  2001:b28:f23f:f005::a`; test `1: 149.154.175.10; 2: 149.154.167.40; 3: 149.154.175.117`.
- `addressSetForDatacenterWithId:` (`MTContext.m:996-1010`): the learned set if it is non-empty, else the seed set,
  else nil.
- `updateAddressSetForDatacenterWithId:addressSet:forceUpdateSchemes:` (`:652-728`): ignored for nil set or dc 0.
  Stores the set (no equality check — a no-op update still writes and notifies), persists the whole map, notifies
  `contextDatacenterAddressSetUpdated:` to all listeners, then `contextDatacenterTransportSchemesUpdated:shouldReset:`
  with `shouldReset = previousLearnedSetWasEmpty || forceUpdateSchemes` (MTProto resets its transport when
  `shouldReset`, or when it was waiting for a scheme). If `forceUpdateSchemes` and a scheme discovery for that dc
  is in flight, it is disposed and restarted with `media:false` (`:717-725`).
  Callers: periodic `help.getConfig` (`forceUpdateSchemes:false`), the address-discovery action (`false`), backup
  discovery (`true`, only for DCs whose set differs, `MTBackupAddressSignals.m:213-227`).
- `addAddressForDatacenterWithId:address:` (`:730-775`): if the effective set lacks the address, **prepend** it,
  persist, and notify only `contextDatacenterAddressSetUpdated:` (no scheme notification, so live connections do
  not reset). Used by `Network.mergeBackupDatacenterAddress` (`Network.swift:1111-1140`), which also forces a
  manual scheme for `(dc, isProxy:false, isMedia:false)` if no current scheme matches.
- `knownDatacenterIds` = sorted union of seed and learned keys (`:950-971`). `enumerateAddressSetsForDatacenters:`
  visits learned sets (dictionary hash order) then seed-only dcs (`:973-994`).
- `apiEnvironment.datacenterAddressOverrides[dc]` (used by the backup config fetch) replaces the dc's scheme list
  with exactly that address (`:1061-1066`) and is also injected into the address map on keychain load.

### 2.8 Transport schemes, stats and selection

- `MTTransportScheme` = `{transportClass (always MTTcpTransport), address, media}`; `isOptimal` ⇔ TCP (always true);
  equality on all three (`MTTransportScheme.m:55-75`).
- **Scheme list for a connection** — `transportSchemesForDatacenterWithId:media:enforceMedia:isProxy:`
  (`MTContext.m:1056-1125`; `isProxy` is always `apiEnvironment.socksProxySettings != nil`):
  1. If an address override exists → `[TCP(override, media:false)]` only.
  2. Else one TCP scheme per address of the effective set (`media = address.preferForMedia`); if the dc has no set
     at all, start address discovery (§2.9) and use an empty list.
  3. If not overridden and a manual scheme exists for `(dc, isProxy, media)` **and its address is still in the
     effective set**, append it if not already present.
  4. Filter: `enforceMedia` → drop non-media addresses; `!media` → drop media addresses.
  5. If `media` and at least one media address remains → keep only media addresses.
  `preferForProxy` and `cdn` are **not** used for filtering here.
- **Choosing one** — `chooseTransportSchemeForConnectionToDatacenterId:schemes:` (`:1012-1054`), called by
  `MTTcpTransport startIfNeeded` for each new connection (`MTTcpTransport.m:186-203`):
  - IPv6 schemes are considered only if *any* IPv6 scheme in the list has `lastResponseTimestamp > now − 3600 s`.
  - Iterate the list **in reverse**; pick the minimal `lastFailureTimestamp` (strict `<`, so ties go to the
    later-listed scheme). Fresh stats are 0 → the last eligible address wins.
  - Returns nil when every scheme is IPv6 and none answered within the hour; the transport then opens nothing
    (no watchdog), §10 L4.
- **Stats** (`:1350-1408`): per `(dc, address)` `{lastFailureTimestamp, lastResponseTimestamp}` in
  `(int32)CFAbsoluteTimeGetCurrent()`. `reportTransportSchemeFailure` stamps failure (MTProto on connection problems
  and decryption failures, `MTProto.m:757,825,2054,2082`); `reportTransportSchemeSuccess` stamps response (MTProto on
  **every** incoming packet, `MTProto.m:2060`). Any change schedules a one-shot 5.0 s timer that writes the whole
  stats map to `temp/transportSchemeStats_v1` (`:1373-1392`) — i.e. while traffic flows, a keychain write every ~5 s.
- `updateTransportSchemeForDatacenterWithId:transportScheme:media:isProxy:` (`:861-889`): stores the manual scheme
  under `(dc, isProxy, media)`, persists `persistent/datacenterManuallySelectedSchemeById_v1`, stamps
  `lastResponse = now` and `lastFailure = 0` for its address (so `choose…` prefers it), and notifies
  `contextDatacenterTransportSchemesUpdated:shouldReset:false` (live connections keep their socket).
- **Scheme discovery** `transportSchemeForDatacenterWithIdRequired:moreOptimalThan:beginWithHttp:media:isProxy:`
  (`:1265-1348`), entry points `transportSchemeForDatacenterWithIdRequired:media:` (MTProto with an empty scheme
  list, `MTProto.m:340-345`), `invalidateTransportSchemeForDatacenterId:` (connection problems),
  `invalidateTransportSchemesForDatacenterIds:` / `…ForKnownDatacenterIds` (no callers in TelegramCore):
  - De-duplicated **per dc only** (not per media/proxy) via `_transportSchemeDisposableByDatacenterId`.
  - Probe list = effective address set ∪ seed addresses not already present; signal =
    `MTDiscoverConnectionSignals discoverSchemeWithContext:` (§2.9.1), built eagerly with the proxy settings of
    that moment.
  - Gate: the **last** listener implementing `isContextNetworkAccessAllowed:` supplies a Bool signal (TelegramCore:
    `shouldKeepConnection |> distinctUntilChanged`, `Network.swift:943-948`); `mapToSignal` (= switchToLatest):
    true → discovery, false → never; whole thing `take:1`. Backgrounding cancels a running discovery and
    foregrounding restarts it from scratch.
  - Each emitted scheme → `updateTransportSchemeForDatacenterWithId:` with the requested media/isProxy.
  - When the signal terminates or is disposed the dc entry is removed (only if it is still the same disposable).
- `invalidateTransportSchemeForDatacenterId:transportScheme:isProbablyHttp:media:` (`:1436-1454`): start discovery
  (as above) **and** schedule backup-address discovery after `delay = 20 s`, or `5 s` when
  `apiEnvironment.networkSettings == nil` or `networkSettings.reducedBackupDiscoveryTimeout` (server "blocked mode",
  config flag bit 8, `ManagedConfigurationUpdates.swift:40-46`), or `1 s` in DEBUG builds.
- `revalidateTransportSchemeForDatacenterId:` (`:1477-1494`, connection healthy again): if the scheme is optimal
  (always) dispose the dc's running discovery; dispose any pending/running backup discovery.
- `reportProblemsWithDatacenterAddressForId:` and `updatePeriodicTasks` are empty.

#### 2.8.1 What discovery actually changes

Because step 3 above only honours a manual scheme whose address is in the current set, a scheme discovered on an
**alternate port (80/5222)** is stored and persisted but never used for a connection, and its stats are keyed by an
address that never appears in a scheme list. The observable effect of a successful discovery is therefore: the
winning in-set address gets `lastFailure = 0`, so `choose…` picks it for the next connection.

### 2.9 Datacenter address and scheme discovery

#### 2.9.1 `MTDiscoverConnectionSignals` (TCP probing)

- Probe payload (`MTDiscoverConnectionSignals.m:22-67`): an unencrypted MTProto message `auth_key_id = 0 (8 B) |
  msg_id = (int64)(local_unix_time * 2^32) (8 B, LE) | length = 20 (4 B) | req_pq_multi 0xbe7e8ef1 (LE bytes
  f1 8e 7e be) | nonce (16 random B)`. If the effective secret (proxy secret when a proxy with secret is set, else
  the address secret) parses as `MTProxySecretType1` (dd) or `Type2` (ee, fake-TLS), append
  `arc4random_uniform(128)` (0…127) random bytes.
- Valid answer (`:69-79`): length ≥ 84, first 8 bytes zero, bytes 20..23 = `63 24 16 05` (resPQ 0x05162463), bytes
  24..39 = sent nonce. Probe = a fresh `MTTcpConnection` (inherits context proxy settings and connection-interface
  factory) on `MTTcpConnection tcpQueue`; valid answer → completes; invalid → error; closed before data → error
  (`:92-150`).
- Probe address list `probeAddressesForAddressList:media:isProxy:proxySettings:` (`:152-216`):
  1. Keep addresses with `preferForMedia == media && preferForProxy == isProxy`.
  2. If empty: keep `preferForMedia == media`.
  3. If still empty: the whole list.
  4. If a proxy with `secret` (MTProxy) or `webProxy` is configured: collapse to **one** address — the first IPv4,
     else the first entry (the proxy ignores the destination).
- Alternate ports (`:218-226`): `[80, 5222]` with no proxy, `[]` with any proxy. For each IPv4 probe address and each
  alternate port not already used by that ip, an extra probe whose success is **delayed 5 s** (so 443 wins ties).
- Each probe: `timeout 5.0 s` (time to the scheme value) → on error/timeout completes empty (`:281-317`).
- Rounds (`:319-336`): IPv4 probes merged; IPv6 probes merged; HTTP list empty. Each group is wrapped in
  `repeatSignal:withBackoffFrom:1.0 upTo:15.0` (pause before the next round 1, 2, 4, 8, 15, 15… s; resets only when
  discovery is restarted) and `take:1`; the three groups merged, `take:1`. The "optimal" path (30 s restart loop)
  is only used for non-optimal (HTTP) schemes and is dead in practice.
- Result: the first answering address (IPv4 or IPv6, whichever answers first) is emitted once; discovery then
  completes. With an empty probe list the round loop spins on its timer forever (no probes) until disposed.
- `repeatSignal:withBackoffFrom:upTo:onQueue:` (`:228-258`): runs the signal; on completion waits `delay`, doubles
  (capped); disposing during the wait stops further rounds.

#### 2.9.2 `MTDiscoverDatacenterAddressAction` (unknown DC address via getConfig)

- Trigger: `addressSetForDatacenterWithIdRequired:` (`MTContext.m:1520-1532`) from `_allTransportSchemesForDatacenterWithId`
  when the dc has neither a learned nor a seed set; one action per dc.
- Algorithm (`MTDiscoverDatacenterAddressAction.m:43-230`), all on the context queue:
  1. Enumerate address sets (learned then seed). If the target dc is now known → `complete`. Otherwise pick the
     first other dc not yet in `_processedDatacenters`, mark it, and ask it; none left → `fail`.
  2. Asking dc S: if S has a **persistent** key → MTProto(S) (`useTempAuthKeys = context.useTempAuthKeys`,
     `forceBackgroundRequests`), send `help.getConfig`; success with a non-empty list for the target → 
     `updateAddressSetForDatacenterWithId:target forceUpdateSchemes:false` + `complete`; empty list or error →
     stop the proto and re-run step 1 (next dc).
  3. No persistent key on S → register as listener, request S's persistent key, and continue when
     `contextDatacenterAuthInfoUpdated` reports it; on `contextDatacenterAuthInfoRequestFailed` for S (persistent)
     ask for the key again.
  - `complete`/`fail` both unregister and call `discoverDatacenterAddressActionCompleted:`, which removes the action;
    no retry timer — the next MTProto `resetTransport` that still lacks schemes triggers a new action.
  - getConfig requests keep `dependsOnPasswordEntry = true` (§2.15).

#### 2.9.3 Auth-key-removed probe

`checkIfAuthKeyRemovedWithContext:datacenterId:authKey:` (`MTDiscoverConnectionSignals.m:353-375`) builds an
`EphemeralMain` auth action **with bind** (not registered in `_datacenterAuthActions`) and emits
`!success && bindError == 400 ENCRYPTED_MESSAGE_INVALID`. The `authKey` argument is unused, and `execute:`
short-circuits to success when an `EphemeralMain` key already exists for the dc (then "not removed" is reported
without any network check). A successful bind stores the new temp key in the context as a side effect.

### 2.10 Backup address discovery (`MTBackupAddressSignals`)

- Installed by TelegramCore for non-supplementary networks: `setDiscoverBackupAddressListSignal(fetchBackupIps(
  testing, currentContext, additionalSource: iCloud CloudData (iOS only), phoneNumber, mainDatacenterId))`
  (`Network.swift:591`).
- Started by `_beginBackupAddressDiscoveryWithDelay:` (`MTContext.m:1456-1467`) only if none is running and a
  signal is installed: `[signal delay:delay onQueue:mainQueue]`, result values ignored; `onDispose` clears the
  field. Starters: `invalidateTransportScheme…` (20/5/1 s, §2.8) and `beginExplicitBackupAddressDiscovery`
  (`:1469-1475`: dispose current, start with delay 0) — TelegramCore calls the latter when an
  `UnauthorizedAccount` is created (`Account.swift:198-211`, together with pre-requesting `EphemeralMain` keys for
  DCs 1, 2, 4 (test: 3) that lack a persistent key). Stopped by `revalidateTransportScheme…`.
- `fetchBackupIps` (`MTBackupAddressSignals.m:309-344`): merge of (a) DNS-over-HTTPS source and (b) optional
  additional source (validated with the same time check), `take:1`; then for each backup address
  `fetchConfigFromAddress` with staggered delays **0, 5, 10, … s**, merged, `take:1`.
- DNS-over-HTTPS (`:99-185`): `GET https://dns.google.com/resolve?name=<N>&type=16&random_padding=<P>` via
  `NSURLSession.sharedSession` (no Host override; HTTP status not checked, `MTHttpRequestOperation.m:25-56`), where
  `N = "tapv3.stel.com"` in the test environment, else `apiEnvironment.accessHostOverride ?? "apv3.stel.com"`, and
  `P` = 13…127 random `[A-Za-z0-9]` characters (`:187-202`). Processing:
  - The `Date` response header (format `EEE',' dd' 'MMM' 'yyyy HH':'mm':'ss zzz`, `en_US`) sets the process-global
    `+[MTContext setFixedTimeDifference:(int32)(date − now)]` (used for fake-TLS timestamps, §6).
  - Collect `Answer[].data` strings, sort by length **descending**, strip `=` from each, concatenate, re-pad with `=`
    to a multiple of 4, base64-decode (ignoring unknown characters), force length to exactly 256 bytes, decode with
    `MTIPDataDecode`.
- `MTIPDataDecode` / `decrypt_TL_data` (`MTEncryption.m:850-1108`): input 256 bytes.
  1. RSA "decrypt" with a hard-coded 2048-bit public key (`:851-858`): `y = x^e mod n`; `y` big-endian copied
     right-aligned into the 256-byte buffer (leading bytes are **not** zeroed when `y` is shorter).
  2. `key = buf[0..32]`, `iv = buf[16..32]`, AES-256-CBC-decrypt `buf[32..256]` (224 B).
  3. Check `SHA256(plain[0..208])[0..16] == plain[208..224]`.
  4. `len = LE uint32 plain[0..4]`; require `0 < len ≤ 208` and `len % 4 == 0`; TL payload = `plain[4..4+len]`.
  5. TL: `0xd997c3c5` → `{date:int, expires:int, dc_id:int, vector(0x1cb5c415) of {ip:int(BE dotted), port:int}}`;
     `0x5a592a6c` → `{date, expires, count, rules: [0x4679b65f {phone_prefix_rules:string, dc_id:int,
     ips: count × (0xd433ad73 {ip, port} | 0x37982646 {ip, port, secret:bytes})}]}`. Phone rules are a
     comma-separated list evaluated left to right with the **last rule deciding** (`""` → include, `+P` → include iff
     phone has prefix P, `-P` → exclude iff prefix P, any non-match → exclude, `:1084-1095`).
- Validity (`checkIpData`, `:88-97`): reject if `date ≥ now + 1200 s` or `expires ≤ now − 1200 s`, with
  `now = currentContext.globalTime`.
- `fetchConfigFromAddress` (`:229-307`) — built eagerly per address (even for delayed ones):
  - Derived `MTApiEnvironment`: copy of the app's with **proxy removed** (`withUpdatedSocksProxySettings:nil`),
    `datacenterAddressOverrides = {dc: address(ip, port, secret)}`, same apiId/layer/langPack/langPackCode,
    `disableUpdates = true`.
  - New `MTContext(useTempAuthKeys:false)` with the app's serialization/encryption provider and
    `makeTcpConnectionInterface` (MTTcpConnection refuses to use a WEB carrier for a non-WEB context).
  - Keychain = process-global `MTTemporaryKeychain` cached per `"<dc>:<ip>:<port>"` (never evicted), so a key
    negotiated for a backup address is reused for the process lifetime.
  - `MTProto(dc)` with `useTempAuthKeys = true`, `allowUnboundEphemeralKeys = true` (unbound temp key, no permanent
    key needed), plain `MTRequestMessageService`, `help.getConfig`.
  - Success → `applyAddressList:toContext:` against the **app** context (only changed DCs updated, with
    `forceUpdateSchemes:true`), emit `@(updated)`, complete; error → complete. Dispose → remove request,
    `[mtProto stop]`, `[tempContext cancelPendingActions]`.
  - `mainDatacenterId` is unused.

### 2.11 Logout detection

- `checkIfLoggedOut:` (`MTContext.m:1774-1809`): only if the dc has a persistent key; throttled to one check per dc
  per **60 s** (CFAbsoluteTime); disposes a previous check for the dc; runs the auth-key-removed probe (§2.9.3); a
  `true` result notifies `contextLoggedOut:` on all listeners (TelegramCore → `Network.loggedOut`,
  `Network.swift:951-954`).
- Only caller: `MTProto handleMissingKey:` in the branch "persistent selector, not CDN, no explicit key, no required
  token, `!canResetAuthData`" (`MTProto.m:2158-2163`), reached on transport error `-404` or
  `401 AUTH_KEY_PERM_EMPTY` (`MTProto.m:1975, 2034-2039`). Connections using temp keys instead drop and recreate the
  temp key (and, on a non-master dc with a required token, also drop the token).

### 2.12 Time

- `globalTime = [NSDate now].timeIntervalSince1970 + globalTimeDifference`; `globalTimeOffsetFromUTC =
  globalTimeDifference + localTimeZone.secondsFromGMT` (`MTContext.m:609-628`).
- `setGlobalTimeDifference:` (`:630-642`) stores and persists (`temp/globalTimeDifference`), no listener
  notification. Callers: `MTProto timeSyncInfoChanged:` (time-sync service result, and corrections computed from
  the server msg_id of a `bad_server_salt` or `bad_msg_notification` 16/17 that answers the time-fix probe: `diff = msg_id / 2^32 − now`, `MTProto.m:2418-2447`).
- `+fixedTimeDifference` is a separate **process-global** int32 set only from the DoH `Date` header (§2.10) and read
  by MTTcpConnection for the fake-TLS ClientHello timestamp (`MTTcpConnection.m:1147`).

### 2.13 Api environment and proxy settings at context level

- `updateApiEnvironment:(f)` (`MTContext.m:1750-1768`): `f(current)`; nil result = no change; otherwise replace and
  notify `contextApiEnvironmentUpdated:apiEnvironment:`. MTProto (`MTProto.m:2785-2813`) adopts the new environment,
  forwards it to its message services (RequestMessageService re-sends initConnection when the hash changes, §4),
  and resets its transport if proxy presence/equality changed or `langPackCode` changed.
- TelegramCore (`Network.swift:1012-1037`): `updateProxySettings` first swaps `context.makeTcpConnectionInterface`
  (WEB carrier factory vs base factory), then updates the environment only if
  `MTSocksProxySettings` equality changed (ip, port, username, password, secret, webProxy — `MTApiEnvironment.m:310-334`),
  dropping the connection status to `.waitingForNetwork`. App-data changes update `systemCode` the same way.
- Everything that needs "isProxy" uses `apiEnvironment.socksProxySettings != nil` at call time.
- `MTProxyConnectivity pingProxyWithContext:datacenterId:settings:` (`MTProxyConnectivity.m:113-151`, used by the
  proxy list UI): for **every** address of the dc's effective set (IPv4 and IPv6 alike, no collapse), a throwaway
  context with the candidate proxy and the app's interface factory sends the same req_pq_multi probe; emits
  `{reachable, roundTripTime}` for the first reachable address, or unreachable when all have answered/closed or the
  set is empty. No own timeout (relies on MTTcpConnection's).
- Hostname proxies are resolved by `MTDNS resolveHostnameUniversal:port:` (`MTDNS.m:237-252`): coalesced native
  `getaddrinfo` per `"host:port"` (first IPv4 preferred, else first IPv6), retried every 2.0 s on failure, bounded by
  **10.0 s** after which the bare hostname is handed to the socket; `take:1`. There is no HTTP DNS fallback anymore.

### 2.14 `makeTcpConnectionInterface` hook

- `@property (copy) id<MTTcpConnectionInterface> (^makeTcpConnectionInterface)(delegate, delegateQueue)`
  (`h/MTContext.h:99`). Read by each `MTTcpConnection` at init and invoked at every connect
  (`MTTcpConnection.m:907, 1009-1036`) with the connection as delegate and `MTTcpConnection.tcpQueue` as queue.
- The interface (`h/MTContext.h:21-53`): `connectToHost:onPort:viaInterface:withTimeout:error:`, `writeData:`,
  `readDataToLength:withTimeout:tag:`, `disconnect`, `resetDelegate`, `setGetLogPrefix:`, `setUsageCalculationInfo:`,
  optional `isWebProxyCarrier`; delegate callbacks `connectionInterfaceDidConnect`,
  `…DidReadData:withTag:networkType:`, `…DidReadPartialDataOfLength:tag:`, `…DidDisconnectWithError:`.
- Pairing rule: a WEB-proxy context must get a carrier (else the connection fails closed); a non-WEB context discards
  a carrier and falls back to `MTGcdAsyncSocketTcpConnectionInterface`. TelegramCore installs
  `NetworkFrameworkTcpConnectionInterface` when `networkSettings.useNetworkFramework` (or beta) and the OS allows
  (`Network.swift:512-528`). Derived contexts (backup fetch, proxy ping) copy the factory.

### 2.15 Password-required flag

- `isPasswordInputRequiredForDatacenterWithId:` / `updatePasswordInputRequiredForDatacenterWithId:required:`
  (`MTContext.m:825-859`), lock-protected, memory only; on change notifies `contextIsPasswordRequiredUpdated:` and
  returns the *previous* value.
- Set to `true` by MTRequestMessageService on `401 …SESSION_PASSWORD_NEEDED…` unless the request has
  `passthroughPasswordEntryError` (`MTRequestMessageService.m:850-855`). Nothing in MtProtoKit or TelegramCore ever
  sets it back to false. While true, every request with `dependsOnPasswordEntry == true` (the `MTRequest` default)
  to that dc is skipped when building transactions (`MTRequestMessageService.m:565-566`). TelegramCore's own
  requests set `dependsOnPasswordEntry = false`; MtProtoKit's internal getConfig/export/import requests do not.
- The `MTContextBlockChangeListener` that MTRequestMessageService registers for `contextIsPasswordRequiredUpdated`
  (`MTRequestMessageService.m:92-100`) is only held weakly by the context and dies at the end of `init`, so this
  callback never reaches a request service.

### 2.16 External verification hooks and CDN public keys

- `setExternalRequestVerification:` / `setExternalRecaptchaRequestVerification:` store blocks (sync);
  `performExternalRequestVerificationWithNonce:` / `…RecaptchaRequestVerificationWithMethod:siteKey:` return the
  block's signal, or `[MTSignal single:nil]` if none (`MTContext.m:571-607`). TelegramCore wires APNS-nonce and
  reCAPTCHA streams with a 15 s timeout yielding `"APNS_PUSH_TIMEOUT"` / `"RECAPTCHA_TIMEOUT"` (`Network.swift:592-627`);
  consumed by MTRequestMessageService (§4).
- `publicKeysForDatacenterWithIdRequired:` (`MTContext.m:1164-1195`, called by the auth service for CDN dcs): if no
  fetch is in flight, ask the **first** listener whose `fetchContextDatacenterPublicKeys:` returns a signal
  (TelegramCore: `help.getCdnConfig`, keys filtered to the dc, `{key, fingerprint: MTRsaFingerprint}`,
  `Network.swift:911-935`); the first value is stored via `updatePublicKeysForDatacenterWithId:` → persisted
  (`ephemeral/datacenterPublicKeysById`) and `contextDatacenterPublicKeysUpdated:` notified. A nil/empty array is
  stored as-is; errors leave the in-flight entry in place.

### 2.17 Change-listener protocol

- `addChangeListener:` (`MTContext.m:529-547`, async): scans the boxes from the end, **drops boxes whose target died**,
  and appends a new weak box unless the same object is present. `removeChangeListener:` (`:549-563`) is
  **synchronous** and removes the first box with that target.
- Notification: iterate a snapshot copy of the box array in registration order, skip dead targets, call only
  implemented optional selectors, synchronously on the context queue. (`updatePublicKeysForDatacenterWithId:` and
  `publicKeysForDatacenterWithIdRequired:` iterate the live array without a snapshot.)
- Callbacks and their triggers:

| Callback | Fired by |
|---|---|
| `contextDatacenterAddressSetUpdated:datacenterId:addressSet:` | `updateAddressSet…`, `addAddress…` |
| `contextDatacenterTransportSchemesUpdated:datacenterId:shouldReset:` | `updateAddressSet…` (reset = prev empty or force), `updateTransportScheme…` (false) |
| `contextDatacenterAuthInfoUpdated:datacenterId:authInfo:selector:` | `updateAuthInfo…` (incl. removal) |
| `contextDatacenterAuthInfoRequestFailed:datacenterId:selector:` | key-creation backoff timer fired |
| `contextDatacenterAuthTokenUpdated:datacenterId:authToken:` | `updateAuthToken…` |
| `contextDatacenterAuthTokenTransferFailed:datacenterId:` | transfer backoff fired; `removeTokenForDatacenterWithId:` cancelling a transfer |
| `contextIsPasswordRequiredUpdated:datacenterId:` | password flag changed |
| `contextDatacenterPublicKeysUpdated:datacenterId:publicKeys:` | public keys stored |
| `contextApiEnvironmentUpdated:apiEnvironment:` | `updateApiEnvironment:` |
| `contextLoggedOut:` | logout probe positive |
| `fetchContextDatacenterPublicKeys:datacenterId:` (pull) | CDN keys needed — first responder wins |
| `isContextNetworkAccessAllowed:` (pull) | scheme discovery gate — last responder wins |

- Registered listeners in practice: every `MTProto` (registered in `init`, removed in `stop`, `MTProto.m:169, 255`),
  `MTDiscoverDatacenterAddressAction` while waiting, TelegramCore `NetworkHelper` (`Network.swift:956`); the
  request service's block listener is dead (§2.15).

### 2.18 Cleanup, cancellation and dead session-cleanup code

- `cleanup` (`MTContext.m:358-429`, also run from `dealloc`): snapshot and nil the auth, discovery, transfer,
  key-removed-check and public-key action maps and both retry-timer maps; then, async on the context queue,
  cancel discovery actions (delegate nil first), cancel auth actions, cancel transfers (delegate nil), invalidate
  retry timers, dispose public-key fetches, key-removed checks, session-cleanup disposables and scheme-discovery
  disposables (the scheme map itself is not niled). Running it twice is safe.
- `cancelPendingActions` (private, used by the backup fetch dispose) = `cleanup` on the context queue
  (`:431-436`).
- Session cleanup is dead: `scheduleSessionCleanupForAuthKeyId:sessionInfo:` returns immediately (`:891-895`),
  `_currentSessionInfos` is never appended to, and nothing calls `collectSessionIdsForCleanup…` /
  `sessionIdsDeletedForAuthKeyId:`; `MTProto finalizeSession` is empty (`MTProto.m:395-396`). No `destroy_session`
  is ever sent from this path.

### 2.19 How TelegramCore drives the context (summary)

1. `initializedNetwork` (`Network.swift:467-660`): build `MTApiEnvironment` (apiId, langPack, layer, disableUpdates
   for supplementary, langPackCode, proxy, network settings, `accessHostOverride`, `systemCode` from app data);
   `MTContext(useTempAuthKeys: true)`; optional Network.framework / WEB-carrier factory; seeds; `context.keychain`;
   backup signal + verification hooks (non-supplementary only); main `MTProto(dc, requiredAuthToken nil)` with
   `useTempAuthKeys`, `checkForProxyConnectionIssues = true`, request service, connection-status delegate.
2. `Network.init`: `NetworkHelper` listener (CDN keys, network-access gate = `shouldKeepConnection`, proxy id,
   logout); `shouldKeepConnection` → `mtProto.resume/pause`.
3. Workers (`Download`): MTProto per (dc, media, cdn) with required token for non-master DCs; paused/resumed by
   `shouldKeepConnection || explicit || background-downloads`; on 401 drop + re-transfer the token.
4. Config refresh → `updateAddressSetForDatacenterWithId(…, forceUpdateSchemes:false)` per dc; `blockedMode` →
   `reducedBackupDiscoveryTimeout`.
5. Proxy change → `updateProxySettings` (§2.13). Unauthorized account → pre-create keys + explicit backup discovery.

### 2.z Constants

| Name | Value | file:line | Meaning |
|---|---|---|---|
| context queue name | `"com.mtproto.MTContextQueue"` | `MTContext.m:324` | process-wide serial queue |
| `tempKeyExpiration` | 86400 s | `MTContext.m:269` | temp key lifetime (bind `expires_at`, local validUntil) |
| `MTRetryDelayForFailureCount` | 1, 2, 4, 8, 16, 32, then 60 s | `MTContext.m:225-230` | key-creation and token-transfer backoff |
| initial salt window | salt 0, `[T, T + 29 min·2^32]` | `MTDatacenterAuthAction.m:115,128,164` | salt for a fresh key |
| auth info map key | `(selector << 32) \| dc` | `MTContext.m:126-140` | persisted dict key |
| logout check throttle | 60 s per dc | `MTContext.m:1783` | `checkIfLoggedOut:` |
| stats sync debounce | 5.0 s one-shot | `MTContext.m:1377` | keychain write of scheme stats |
| IPv6 eligibility | response within 3600 s | `MTContext.m:1024` | `chooseTransportScheme…` |
| backup discovery delay | 20 s / 5 s (blocked or no settings) / 1 s DEBUG | `MTContext.m:1445-1451` | after connection problems |
| backup stagger | 0, 5, 10 … s per backup address | `MTBackupAddressSignals.m:331-339` | fetchConfigFromAddress |
| backup validity slack | ±1200 s | `MTBackupAddressSignals.m:89` | DNS/iCloud blob date window |
| DoH name | `apv3.stel.com` / `tapv3.stel.com` (test) / `accessHostOverride` | `MTBackupAddressSignals.m:115-119` | TXT record holder |
| DoH padding | 13…127 chars `[A-Za-z0-9]` | `MTBackupAddressSignals.m:191-193` | `random_padding` |
| backup blob | 256 B, payload ≤ 208 B, len % 4 == 0 | `MTEncryption.m:957, 910` | `MTIPDataDecode` |
| backup TL ids | `0xd997c3c5`, `0x5a592a6c`, `0x4679b65f`, `0xd433ad73`, `0x37982646`, vector `0x1cb5c415` | `MTEncryption.m:970-1065` | blob layouts |
| probe timeout | 5.0 s | `MTDiscoverConnectionSignals.m:286,294,306` | per-address probe |
| alternate ports | 80, 5222 (none under a proxy) | `MTDiscoverConnectionSignals.m:218-226` | extra probes |
| alternate-port result delay | 5.0 s | `MTDiscoverConnectionSignals.m:307-309` | 443 preference |
| probe round backoff | 1 s doubling to 15 s | `MTDiscoverConnectionSignals.m:324-325` | between rounds |
| optimal re-probe | 30 s (dead path) | `MTDiscoverConnectionSignals.m:326` | non-optimal schemes only |
| probe extra padding | 0…127 B for dd/ee secrets | `MTDiscoverConnectionSignals.m:58-65` | req_pq_multi probe |
| probe valid answer | ≥ 84 B, resPQ `0x05162463` at 20, nonce at 24 | `MTDiscoverConnectionSignals.m:69-79` | |
| DNS bound | 10.0 s, retry every 2.0 s | `MTDNS.m:251, 218` | hostname proxies |
| seed port | 443 | `Network.swift:558` | all seed addresses |
| external verification timeout | 15 s | `Network.swift:601, 617` | APNS / reCAPTCHA (TelegramCore) |

## 3. MTProto session state machine

Scope: `MTProto` (one encrypted MTProto session to one datacenter over one logical transport), its session bookkeeping (`MTSessionInfo`), the incoming parser (`MTInternalMessageParser`), the built-in message services that live inside the session (`MTTimeSyncMessageService`, `MTResendMessageService`, and the transport itself, which is also a message service), and the transaction value types. The request layer (`MTRequestMessageService`), key exchange (`MTDatacenterAuthMessageService`), bind (`MTBindKeyMessageService`) and TCP framing are specified in their own sections; they appear here only where `MTProto` drives them.

File references: `MTProto.m:123` = `Sources/MTProto.m`; `h/MTProto.h:45` = `PublicHeaders/MtProtoKit/MTProto.h`.

### 3.1 Object model and threading

- **One global serial queue for every MTProto in the process**: `+[MTProto managerQueue]`, label `"org.mtproto.managerQueue"` (`MTProto.m:140-149`). All state of every MTProto instance, every `MTMessageService` callback and every `MTProtoDelegate` callback runs on it. `-messageServiceQueue` returns the same queue (`MTProto.m:572-575`).
- `MTQueue -dispatchOnQueue:` runs the block **inline** when already on the queue, otherwise `dispatch_async` (`MTQueue.m`, `dispatchOnQueue:synchronous:`). Every public MTProto method is therefore "async unless already on the manager queue". Consequence: callbacks re-entering MTProto from a service run synchronously and may mutate `_messageServices` while it is being iterated (§10 M35).
- Exceptions: `-addMessageService:` calls `mtProtoWillAddService:` synchronously on the caller's thread before hopping (`MTProto.m:467-468`); `-takeConnectionForReusing` is `dispatchOnQueue:synchronous:true` (`MTProto.m:692-699`); `requestMessageWithId:` and `timeSyncServiceCompleted:...` assume they are already on the queue.
- The TCP transport has its own serial queue (`MTTcpTransport tcpTransportQueue`) and the connection another (`MTTcpConnection tcpQueue`); every transport→MTProto delegate call hops back to the manager queue and is **dropped if `transport != _transport`** (stale-transport guard in every `transport*` delegate method, e.g. `MTProto.m:730`, `751`, `765`, `958`, `1947`).
- `_messageServices` is an ordered `NSMutableArray`, insertion order, no duplicates (`MTProto.m:489-495`). The current transport is itself a message service: `setTransport:` removes the old transport and appends the new one (`MTProto.m:303-312`). Typical order on the main connection: `[MTRequestMessageService, MTTcpTransport, (MTResendMessageService…)]`.
- Iteration direction differs per callback (relevant for ordering-sensitive ports): **forward** for `mtProtoMessageTransaction`, `mtProtoServiceTasksStateChanged`, `mtProtoNetworkAvailabilityChanged`, `mtProtoConnectionStateChanged`, `mtProtoConnectionContextUpdateStateChanged`, `shouldRequestMessageWithId` (stops at first `true`), `updateReceiveProgressForToken`, `mtProtoTransportActivityUpdated`, `messageResendRequestFailed`, `mtProtoPublicKeysUpdated`, `mtProtoApiEnvironmentUpdated`; **reverse index loop** for `mtProtoDidChangeSession`, `transactionsMayHaveFailed`, `mtProtoAllTransactionsMayHaveFailed`, `receivedQuickAck`, `protocolErrorReceived`, `messageDeliveryFailed`, `messageDeliveryConfirmed`, `mtProtoServerDidChangeSession`, `receivedMessage`, `mtProtoAuthTokenUpdated`.

Lifetime: MTProto registers itself as a context change listener in `init` (`MTProto.m:169`) and unregisters only in `stop` (`MTProto.m:255`). `dealloc` nils the transport delegate and asynchronously stops the transport and disposes the proxy probe (`MTProto.m:184-196`).

### 3.2 Configuration properties (set before `resume`)

| Property (`h/MTProto.h`) | Default | Effect in MTProto.m |
|---|---|---|
| `datacenterId` (39) | ctor | DC for schemes, keys, tokens. |
| `delegate` (35) | nil | `MTProtoDelegate`, weak. |
| `useUnauthorizedMode` (47) | false | Plain (auth_key_id = 0) messages; no salts, acks, time sync, key handling (3.10). Used by the DH handshake MTProto (`MTDatacenterAuthAction.m:77`). |
| `useTempAuthKeys` (48) | false | Selects ephemeral key selectors (3.7). TelegramCore: main = `context.useTempAuthKeys` (always true, `Network.swift:507,634`); download = `useTempAuthKeys && !isCdn` (`Download.swift:70`). |
| `media` (49), `enforceMedia` (50) | false | Passed to `transportSchemesForDatacenterWithId:media:enforceMedia:isProxy:` (`MTProto.m:338`) and scheme invalidation. |
| `cdn` (51) | false | Always `Persistent` selector; `handleMissingKey` drops and recreates the key with `isCdn:true`. |
| `allowUnboundEphemeralKeys` (52) | false | Forwarded to `authInfoForDatacenterWithIdRequired:...allowUnboundEphemeralKeys:`. |
| `checkForProxyConnectionIssues` (53) | false | Enables proxy probing (3.20). Main connection sets true (`Network.swift:635`). |
| `canResetAuthData` (54) | false | On -404 for a persistent key: drop and recreate instead of `checkIfLoggedOut`. Never set by TelegramCore. |
| `requiredAuthToken` (55), `authTokenMasterDatacenterId` (56) | ctor | Non-master DC connections must carry an imported authorization (3.7.3). TelegramCore passes `NSNumber(datacenterId)` as the token for every non-master, non-CDN download connection (`Download.swift:59-63`). |
| `useExplicitAuthKey` (40) | nil | Bind-only MTProto: use this key, never the context's (3.7.1). |
| `tempConnectionForReuse` (42) | nil | A live transport to adopt on next `resetTransport` (`MTProto.m:332-336`). |
| `shouldStayConnected` (46) | true | **Unused.** |
| `tempAuthKeyBindingResultUpdated` (44) | nil | **Unused.** |
| `getLogPrefix` (58) | nil | Logging only. |

### 3.3 State bitmask

`_mtState` is an `int` bitmask (`MTProto.m:60-68`):

| Flag | Value | Meaning |
|---|---|---|
| `AwaitingDatacenterScheme` | 1 | No transport scheme known; context asked. |
| `AwaitingDatacenterAuthorization` | 2 | No usable auth key for `_awaitingAuthInfoForSelector`; context asked. |
| (none) | 4 | unused gap |
| `AwaitingDatacenterAuthToken` | 8 | Required auth token not present; context asked to transfer. |
| `AwaitingTimeFixAndSalts` | 16 | Time/salt fix in progress; only the time-fix ping may be sent. |
| `AwaitingLostMessages` | 32 | **Declared, never set.** |
| `Stopped` | 64 | Terminal. |
| `Paused` | 128 | Initial state. |

Predicates (`MTProto.m:701-724`):
- `canAskForTransactions` = none of {Scheme, Authorization, AuthToken, TimeFixAndSalts, Stopped}. **Paused is not included** (pausing removes the transport instead).
- `canAskForServiceTransactions` = none of {Scheme, Authorization, AuthToken, Stopped} (i.e. time-fix allowed).
- `timeFixOrSaltsMissing` = TimeFixAndSalts set.

`setMtState:` (`MTProto.m:427-463`) only emits notifications when the TimeFixAndSalts bit flips: it computes `isPerformingServiceTasks = TimeFixAndSalts || anyMTResendMessageServicePresent` and calls `mtProtoServiceTasksStateChanged:` on all services (forward) then the delegate. Several code paths set `AwaitingDatacenterAuthorization` by raw `_mtState |=` (`MTProto.m:942`, `2124`, `2138`, `2147`, `2159`, `2621`) — no notification, which is fine because that bit is not reported.

### 3.4 State transitions

| Trigger | Precondition | State change | Side effects |
|---|---|---|---|
| `init` (`MTProto.m:151-182`) | — | `= Paused` | random session (3.6), add as context listener. |
| `resume` (`224-246`) | Paused | clear Paused | `resetTransport`; `requestTransportTransaction`; `_requestAwaitedAuthInfo`; `_requestAwaitedAuthToken` (re-ask for a key/token that may have failed while paused). |
| `pause` (`205-222`) | !Paused | set Paused | `setTransport:nil keepTransportActive:false` (stops transport, fails all transactions, see 3.5). Session id, seqno, processed/sent sets and **pending acks survive** a pause. |
| `stop` (`248-264`) | !Stopped | set Stopped | unregister context listener; transport.delegate=nil; `[transport stop]`; `setTransport:nil`. Irreversible (`resume` only clears Paused). Proxy probe is **not** disposed until dealloc. |
| `resetTransport`, schemes empty (`340-346`) | !Stopped, flag not yet set | set Scheme | `[context transportSchemeForDatacenterWithIdRequired:dc media:]`. Transport stays nil. |
| `resetTransport`, token mismatch (`347-352`) | `requiredAuthToken != nil && !unauthorized && ![token isEqual:context.authTokenForDC]`, flag not yet set | set AuthToken | `[context authTokenForDatacenterWithIdRequired:dc authToken:masterDatacenterId:]`. Transport stays nil. |
| `resetTransport`, otherwise (`353-358`) | — | — | new `MTTcpTransport(schemes, apiEnvironment.socksProxySettings)`. Note: created even while `AwaitingDatacenterAuthorization` (the transport connects and sits idle; 3.9 step 1 returns nil). |
| `contextDatacenterTransportSchemesUpdated` (`2579-2597`) | same ctx+dc, !Stopped | clear Scheme (and force `shouldReset=true` if it was set) | if !Authorization && !Paused && shouldReset: `resetTransport` + `requestTransportTransaction`. |
| key missing in `getAuthKeyForCurrentScheme` (`937-946`) | createIfNeeded, context has no key for selector | set Authorization, `_awaitingAuthInfoForSelector = selector` | in one `performBatchUpdates`: `updateAuthInfo(nil)` + `authInfoForDatacenterWithIdRequired`. |
| `handleMissingKey` (3.7.2) | -404 or AUTH_KEY_PERM_EMPTY | may set Authorization | see table. |
| `contextDatacenterAuthInfoUpdated(nil)` (`2619-2623`,`2638-2640`) | selector matches awaited/valid | set Authorization, `_validAuthInfo=nil` | `resetTransport`. |
| `contextDatacenterAuthInfoUpdated(info)` (`2627-2637`) | selector matches awaited | clear Authorization, `_awaitingAuthInfoForSelector=nil` | if it was set: `resetTransport` + `requestTransportTransaction`. |
| `contextDatacenterAuthTokenUpdated(token)` (`2697-2720`) | `[requiredAuthToken isEqual:token]` | clear AuthToken (if set) | if it was set: `resetTransport` + `requestTransportTransaction`; always: `mtProtoAuthTokenUpdated:` to services (reverse). |
| `contextDatacenterAuthInfoRequestFailed` / `...AuthTokenTransferFailed` (`2676-2695`) | same ctx+dc, !Paused, !Stopped (and matching awaited selector for key) | — | ask the context again (`_requestAwaitedAuthInfo` / `_requestAwaitedAuthToken`); the context owns backoff and dedupe. |
| `initiateTimeSync` (`577-588`) | TimeFix not set | set TimeFixAndSalts (notifies) | `requestTimeResync` (adds an `MTTimeSyncMessageService` unless one exists, `398-425`). |
| `completeTimeSync` (`590-610`) | TimeFix set | clear TimeFixAndSalts (notifies) | nil the delegate of and remove every `MTTimeSyncMessageService`. |

`_requestAwaitedAuthToken` (`2662-2674`) also fires when the flag is clear but the context's token differs from the required one (covers the 401 path where `Download` dropped the token itself and parked requests with `waitingForTokenExport`).

### 3.5 Lifecycle helpers

`setTransport:keepTransportActive:` (`MTProto.m:285-316`), in order:
1. `allTransactionsMayHaveFailed` (`1689-1712`): if not Stopped, drop `_timeFixContext` (remember to re-request if it had a transactionId), call `mtProtoAllTransactionsMayHaveFailed:` on all services (reverse) — `MTRequestMessageService` clears every request's `requestContext`, so **every in-flight RPC is re-sent with a new msg_id after any transport change** — then `requestTransportTransaction` if a time fix was in flight and not Paused.
2. Ask the old transport for `activeTransactionIds` (= its current connection id) and run `transportTransactionsMayHaveFailed:` for them (asynchronously, via the TCP queue).
3. `_timeFixContext = nil`; remove old transport from services; assign; stop old transport unless `keepTransportActive`; add new transport as a service.
4. `updateConnectionState` (`266-283`): with a transport → transport re-emits availability/connected/context-update; without → delegate gets `networkAvailable=false`, `connectionState=nil`, `isUpdatingConnectionContext=false`.

`resetTransport` (`318-361`): no-op when Stopped; stops and nils the current transport; then either adopts `tempConnectionForReuse` (sets its delegate to self, `keepTransportActive:false`) or applies the three-way decision in 3.4.

`resetSessionInfo:(bool)ifActive` (`363-393`): if `ifActive && !canAskForTransactions` → no-op. Else: new random `MTSessionInfo` (new session_id, seqno 0, empty sets and **acks discarded**), `_timeFixContext = nil`, `mtProtoDidChangeSession:` on all services (reverse), `resetTransport`, `requestTransportTransaction`. Triggers: msg_id monotonicity violation (`1163`), bad_msg 32/33 (`2455`), incoming parse error (`2058`), `MTRequestMessageService` cancelling a request with `expectedResponseSize >= 512 KiB` or `askForReconnectionOnDrop` (`MTRequestMessageService.m:165-190`, `resetSessionInfo:true`).

`requestSecureTransportReset` (`671-681`): if not Stopped, `[transport reset]` = close the TCP connection; the transport's connection behaviour reconnects; session unchanged.

`takeConnectionForReusing` (`692-699`): synchronously detaches the transport (`setTransport:nil keepTransportActive:true`) and returns it. Used to hand the DH MTProto's socket to the bind MTProto (`MTDatacenterAuthAction.m:141`).

`finalizeSession` (`395-396`): empty. `simulateDisconnection` (`683-690`): fires the transport's watchdog path.

### 3.6 Session info: ids, msg_id, seqno

`MTSessionInfo` (`MTSessionInfo.m`):
- **session_id**: 64 random bits from `arc4random_buf` (`62-67`). A new `MTSessionInfo` is created only in `init` and `resetSessionInfo` (3.5). No `destroy_session` is ever sent for the old one.
- **Client msg_id** (`generateClientMessageId:`, `91-109`): `id = (int64)(context.globalTime * 2^32)` where `globalTime = NSDate.now (wall clock, seconds since 1970) + globalTimeDifference` (`MTContext.m:609-612`). If `id < last` → set `*monotonityViolated = true` (if the out-pointer is non-NULL) **and still return the smaller id and store it as `last`**. If `id == last` → `last + 1`. Then increment until `id % 4 == 0`. Store as `_lastClientMessageId`.
  - Check: two calls in the same clock tick yield `t`, `t+4`. A wall clock stepping back yields a smaller id plus the flag once; the next call compares against the smaller value.
  - Callers passing NULL (violation ignored): container ids (`1473`), time-fix ping (`1389`), bind (`MTBindKeyMessageService.m:52`).
- `actualClientMessagId` (`111-119`): same formula, rounded up to `%4==0`, no state; used only to pick the salt for the whole transaction (`MTProto.m:1075`).
- `generateServerMessageId` (`121-131`): `%4==1` variant; **unused**.
- **seqno** (`takeSeqNo:`, `278-291`): content-related → `seq = _seqNo + 1; _seqNo += 2` (odd); otherwise `seq = _seqNo` (even, not advanced). `content-related` == `MTOutgoingMessage.requiresConfirmation` (default true, `MTOutgoingMessage.m:68`). Non-content in this codebase: msgs_ack, containers, actualization ping, time-fix ping, `msg_resend_req`, `rpc_drop_answer`. Messages that already carry `messageId != 0` keep their stored seqno (`MTProto.m:1094-1098`).
- Sets (all unbounded, cleared only by a new `MTSessionInfo`): `_processedMessageIdsSet` (incoming ids seen), `_sentMessageIdsSet` (outgoing ids sent standalone once), `_containerMessagesMappingDict` (container id → child ids requiring confirmation), `_scheduledMessageConfirmations` (pending acks, array with O(n) dedupe).
- `messageIdsInContainersAfterMessageId:first` (`259-276`): every child id whose container id `>= first` **or** whose own id `>= first`.
- `scheduledForCleanup`, `canBeDeleted` properties: only read by an `MTContext` cleanup path whose scheduler is a no-op (`MTContext.m:890-894`).

### 3.7 Auth keys, tokens and the "missing key" path

#### 3.7.1 Key selection — `getAuthKeyForCurrentScheme:createIfNeeded:authInfoSelector:` (`MTProto.m:892-952`)

| Mode | Selector |
|---|---|
| `useExplicitAuthKey != nil` | `scheme.media ? EphemeralMedia : EphemeralMain`; synthesises `MTDatacenterAuthInfo(explicitKey, saltSet=[salt 0, valid [0,0)])` once and caches it in `_validAuthInfo` (`903-906`). That salt set is always empty-valid, so the first transaction triggers a time/salt fix (3.8). |
| `cdn` | `Persistent` |
| `useTempAuthKeys` | `scheme.address.preferForMedia ? EphemeralMedia : EphemeralMain` (note: address flag, not `scheme.media`) |
| else | `Persistent` |

Then: if `_validAuthInfo.selector == selector` return the cached key. Else clear the cache; if `createIfNeeded`, read `[context authInfoForDatacenterWithId:selector:]`; present → cache and return; absent → (batch) `updateAuthInfo(nil)` + `authInfoForDatacenterWithIdRequired:isCdn:selector:allowUnboundEphemeralKeys:`, set `AwaitingDatacenterAuthorization`, remember the selector, return nil.
- Outgoing uses `createIfNeeded:true` (`975`); incoming decrypt and progress decoding use `false` (`2011`, `1743`).
- **The cached key is never revalidated**: a key replaced in the context while this MTProto is not awaiting it keeps being used (`contextDatacenterAuthInfoUpdated` does not refresh `_validAuthInfo` for a non-awaited update, `2611-2614`, `2627-2637`). `validUntilTimestamp` is never checked; temp-key expiry (`tempKeyExpiration = 24*60*60`, `MTContext.m:269`) is discovered only when the server answers -404.

#### 3.7.2 `handleMissingKey:` (`MTProto.m:2090-2169`)

Called on transport error -404 (`1974-1976`) and on an `rpc_error 401 AUTH_KEY_PERM_EMPTY` inside any decrypted packet (`2034-2042`). No-op in unauthorized mode. Recomputes the selector for the scheme, then:

| Condition (first match) | Action |
|---|---|
| `useExplicitAuthKey != nil` | if `scheme.media`: call `complete` on every service that responds to it (the bind service then reports **success**). Otherwise nothing. |
| `cdn` | drop cached key; batch `updateAuthInfo(nil)` + require (`isCdn:true`); set Authorization; await selector. |
| `requiredAuthToken != nil && authTokenMasterDatacenterId != datacenterId` (non-master DC) | drop cached key; `[context removeTokenForDatacenterWithId:dc]`; batch drop+require key; set Authorization. (The next `resetTransport` will then also wait for a token.) |
| `canResetAuthData` | drop+require key; set Authorization. |
| selector is `EphemeralMain`/`EphemeralMedia` | drop+require key; set Authorization. |
| else (persistent key on master/ordinary DC) | `[context checkIfLoggedOut:dc]` — the context decides whether the account is logged out. |

`AUTH_KEY_PERM_EMPTY` additionally triggers `requestSecureTransportReset` and **returns before processing anything else in that packet** (no acks scheduled, no messages dispatched, no `transportTransactionsSucceeded`) (`2027-2046`). The probe unwraps a gzip_packed result first (`2030`).

#### 3.7.3 Auth tokens

Only `resetTransport` checks the token (`347-352`). The token is compared with `-isEqual:` against `[context authTokenForDatacenterWithId:]`. While waiting there is no transport at all (no socket). Tokens dropped later (401 handling in TelegramCore's `Download`) do not set the flag; requests stay parked in `MTRequestMessageService` with `errorContext.waitingForTokenExport` until `mtProtoAuthTokenUpdated:` (`MTRequestMessageService.m:1279-1293`).

### 3.8 Salts and time synchronisation

**Salt storage**: per auth info, `saltSet: [MTDatacenterSaltInfo{salt, firstValidMessageId, lastValidMessageId}]` persisted with the key (`MTDatacenterSaltInfo.m:17-34`).
- A freshly created key gets `[salt 0 valid [t, t + 29 min)]` where `t` is the handshake timestamp as a msg_id (`MTDatacenterAuthAction.m:115`, `128`, `164`). So the first encrypted message on a new key is always rejected with `bad_server_salt`.
- **Selection** `authSaltForMessageId:` (`MTDatacenterAuthInfo.m:77-90`): a salt is eligible when `first <= msgId < last` (`validMessageCountAfterId` > 0, `MTDatacenterSaltInfo.m:36-42`). Because `bestValidMessageCount` is never updated, the **last eligible entry in array order wins**, not the longest-lived. Returns 0 when none is eligible.
- MTProto picks one salt per transaction for `actualClientMessagId` (`MTProto.m:1075`); every message and the container use it. Salt 0 ⇒ `saltSetEmpty` ⇒ the whole transaction is abandoned and `initiateTimeSync` runs (`1145-1167`).
- **Merge** `mergeSaltSet:forTimestamp:` (`MTDatacenterAuthInfo.m:92-124`): keep existing salts with `last > now`; append each new salt with `last > now` unless an existing one has the same `firstValidMessageId` (existing wins, even if the salt value differs).

**Time-fix flow** (the only mechanism that actually runs):
1. `initiateTimeSync` sets `AwaitingTimeFixAndSalts` (normal traffic stops: `canAskForTransactions` is false).
2. Next `transportReadyForTransaction` takes the time-fix branch (`MTProto.m:1387-1437`) when `timeFixOrSaltsMissing && canAskForServiceTransactions && (_timeFixContext == nil || _timeFixContext.transactionId == nil)`: build `ping#7abe77ec ping_id:random64`, msg_id from `generateClientMessageId:NULL`, **even** seqno (`takeSeqNo:false`), salt = `authSaltForMessageId(msgId)` (usually 0), padding per 3.9, encrypt with `quickAckId:NULL`. Sent alone (no acks, no other messages; the transport's actualization ping, if pending, is silently dropped). Transport transaction flags: `needsQuickAck:false expectsDataInResponse:true`.
3. Transport completion: success with a transaction id → `_timeFixContext = {msgId, seqNo, transactionId, MTAbsoluteSystemTime()}`; failure → `requestTransportTransaction` (`1415-1432`).
4. Resolution in `_processIncomingMessage` (3.11.3):
   - `bad_server_salt` whose `bad_msg_id == timeFix.msgId` → `completeTimeSync`; `timeDifference = serverMsgId/2^32 − NSDate.now` where `serverMsgId` is the **notification's own** msg_id; salt list `[new_server_salt valid [serverMsgId, serverMsgId + 30*60*2^32)]` (`2420-2428`).
   - bad_msg 16/17 for the time-fix msg → `completeTimeSync` + time difference only (no salt) (`2439-2446`). If the salt is still missing, the next transaction restarts the cycle.
   - `pong` with `msg_id == timeFix.msgId` → `completeTimeSync`, **no time-difference update** (`2568-2575`).
   - Any of those for a different msg id → `initiateTimeSync` (no-op if already syncing).
5. `timeSyncInfoChanged:` (`2733-2759`): `[context setGlobalTimeDifference:]` (persisted, shared by every MTProto of the context); if salts given and not unauthorized: explicit-key mode merges into `_validAuthInfo` only; otherwise merge into the context's auth info for the selector (`updateAuthInfoForDatacenterWithId`, which notifies every listener) and refresh `_validAuthInfo` if selectors match. Then `requestTransportTransaction` if allowed.
6. `_timeFixContext` is dropped (and the ping re-sent) when its transport transaction fails, on any transport change, and on session reset (`1670-1674`, `1696-1700`, `381`).

**Steady state cost**: every salt is synthetic with a 30-minute window, so roughly every 30 minutes the salt set becomes empty, traffic for that MTProto stalls for one extra round trip (time-fix ping → bad_server_salt). `new_session_created.server_salt` is ignored (3.11.3).

**`MTTimeSyncMessageService` (`MTTimeSyncMessageService.m`) is effectively dead code**: it is only added by `requestTimeResync`, which is only called from `initiateTimeSync` after `AwaitingTimeFixAndSalts` is set, so `canAskForTransactions` is false and its `mtProtoMessageTransaction:` is never polled before `completeTimeSync` removes it. If it ever ran: it would send `get_future_salts#b921bd04 num:32` (then `num:1`) (`56-58`), take one sample, or 6 when the first round trip exceeded 1.0 s (`151-158`), drop min and max |difference|, average, and call `timeSyncServiceCompleted:timeDifference:saltList:` — a 3-argument selector that **MTProto does not implement** (it implements a 4-argument one, `MTProto.m:2722`), so completion would never be delivered. Its `mtProtoServerDidChangeSession:...messageIdsInFirstValidContainer:` is also a selector MTProto never calls. A Rust port should implement `get_future_salts` properly rather than mirror this.

### 3.9 Outgoing pipeline

#### 3.9.1 Triggering

`requestTransportTransaction` (`MTProto.m:646-669`) coalesces: if no pass is pending, set `_willRequestTransactionOnNextQueuePass` and `dispatch_async` to the manager queue; on that pass: return if Stopped, Paused or `_isConnectionThrottled`; `resetTransport` if there is no transport; `[transport setDelegateNeedsTransaction]`. The TCP transport coalesces again on its queue (`MTTcpTransport.m:164-184`): no connection → `connectionBehaviour requestConnection`; connected → `_requestTransactionFromDelegate`.

`_requestTransactionFromDelegate` (`MTTcpTransport.m:581-703`) holds a one-at-a-time lock (`isWaitingForTransactionToBecomeReady`): a request arriving while locked sets `requestAnotherTransactionWhenReady`, unless the lock is older than **1.0 s** or the actualization ping has not been sent, in which case the lock is broken (`584-611`). The first transaction after each TCP open carries the **actualization ping** as `transportSpecificTransaction` (`ping#7abe77ec random`, `requiresConfirmation=false`, `requiresEncryption=true`) and passes `forceConfirmations = (transportSpecificTransaction != nil)` (`621-659`).

#### 3.9.2 `transportReadyForTransaction:...` algorithm (`MTProto.m:954-1446`)

1. Stale transport → `transactionReady(nil)`. If neither `canAskForServiceTransactions` nor `canAskForTransactions` → `transactionReady(nil)` (`958-970`).
2. Unless unauthorized: obtain the key (3.7.1, `createIfNeeded:true`); nil → `transactionReady(nil)` (`972-983`).
3. **Extended padding** = the transport's proxy secret, or else the scheme address secret, parses as `MTProxySecretType1` (dd) or `MTProxySecretType2` (ee/fake-TLS) (`985-996`). Parsed on every transaction.
4. If `canAskForTransactions` (normal branch):
   1. Start the list with `transportSpecificTransaction` unless (`requiresEncryption && unauthorized`) or (`requiresEncryption && key == nil`) (`1004-1010`).
   2. Poll every service (forward) for `mtProtoMessageTransaction:authInfoSelector:sessionInfo:scheme:`; note whether any payload message `hasHighPriority` (`1014-1034`).
   3. **Acks**: if `forceConfirmations || !anyHighPriority || pendingAcks exceed (size > 1 MiB or count > 64)`, and there are pending acks, build one `msgs_ack#62d6b459` + `vector#1cb5c415` + count + all pending ids (`requiresConfirmation=false`). Its completion assigns the transport transaction id to those acks (`1036-1061`). Acks are inserted **before** service transactions, after the transport-specific one.
   4. Salt = `authSaltForMessageId(actualClientMessagId)` (`1072-1078`).
   5. For each transaction, for each message: if `messageId == 0` → fresh msg_id (with violation detection) + `takeSeqNo(requiresConfirmation)`; else reuse `messageId`/`messageSeqNo`. Apply `dynamicDecorator(msgId, data, messageInternalIdToPreparedMessage)` if set (used to prepend `invokeAfterMsg#cb9f372d` once the dependency's msg_id is known, `MTRequestMessageService.m:644-664`). If no violation so far (or unauthorized) create `MTPreparedMessage{data, msgId, seqNo, salt, requiresConfirmation, hasHighPriority, inResponseToMessageId}` and record it (`1083-1131`). After each transaction: `if transport.needsParityCorrection (TCP: always true) && !expectsDataInResponseSoFar → needsQuickAck = true` (`1134-1135`) — the flag latches, so a transaction list that starts with a non-content transaction (actualization ping, msgs_ack) always requests a quick ack.
   6. Call every transaction's `prepared(messageInternalIdToPreparedMessage)` (`1138-1143`).
   7. If monotonicity was violated or the salt is 0: call every `completion(nil, nil, nil)`, `transactionReady(nil)`, then `resetSessionInfo:false` (violation) or `initiateTimeSync` (salt) (`1145-1167`). The consumed msg_ids/seqnos are not reused unless the service kept them (see `MTRequestMessageService`, which keeps `requestContext.messageId` from `prepared`).
   8. Ordering (`1172-1202`): if more than one message, sort ascending by msg_id; unless `forceConfirmations`, move all high-priority messages to the front (stable).
   9. Packing (`1209-1293`), authorized mode: greedily fill a container while `size + data.length <= MTMaxContainerSize (3072)` (body bytes only; the 16-byte per-message headers are not counted); a message that alone exceeds 3072 bytes forms its own group; unless `forceConfirmations`, a transition from high-priority to normal priority closes the group. No limit on message count per container.
      - Group of exactly one message whose msg_id is **not** in `_sentMessageIdsSet` → mark it sent and send it **standalone** (`1251-1262`).
      - Otherwise (several messages, or a single message already sent once standalone) → `msg_container#73f1f8dc` with a fresh container msg_id (`generateClientMessageId:NULL`), even seqno (`takeSeqNo:false`), salt of the last child; record `container → [children with requiresConfirmation]` (`1448-1492`). A re-sent message therefore always travels inside a new container.
   10. Each payload becomes one `MTTransportTransaction{payload, needsQuickAck, expectsDataInResponse}`; the flags are the same for all payloads of the pass. `expectsDataInResponse` = any message `requiresConfirmation`. On transport completion (`1301-1352`), success → every `MTMessageTransaction.completion(internalId→transactionId, internalId→prepared, internalId→quickAckId)` is called **once per payload**, with maps restricted to that payload's messages; failure → every transaction's `completion(nil,nil,nil)` (also those whose messages were in other payloads).
   11. Empty payload list → `completion(nil…)` for all + `transactionReady(nil)`.
5. Else if time-fix is needed → time-fix branch (3.8). Else → `transactionReady(nil)`.

**Transaction id = connection id.** The TCP transport completes each payload with `transactionId = connection.internalId` (`MTTcpTransport.m:677-681`). All bookkeeping keyed by "transaction id" (request contexts, acks, time fix, resend, bind) is therefore per TCP connection: closing the connection fails everything sent on it; any decrypted packet received on it "succeeds" all acks sent on it.

#### 3.9.3 Encrypted frame (MTProto 2.0)

`_paddedPlaintextWithSalt:sessionId:messageId:seqNo:body:extendedPadding:` (`MTProto.m:1529-1561`): `salt(8) ‖ session_id(8) ‖ msg_id(8) ‖ seq_no(4) ‖ len(4) ‖ body ‖ padding`, all little-endian. Padding: start at 12 bytes, grow to the next multiple of 16 (`take` ∈ 12..27), then add `r − r%16` with `r = arc4random_uniform(E + 1 − take)`, `E = 72` (or `256` with extended padding). Total padding ∈ [12, E].

`_encryptedTransportDataForPaddedPlaintext:authKey:quickAckId:` (`1563-1608`): reject key < 120 bytes, empty or non-16-multiple plaintext (returns nil, message dropped). `msg_key_large = SHA256(auth_key[88..120] ‖ plaintext)`; `msg_key = msg_key_large[8..24]`; AES key/iv from `messageEncryptionKeyV2ForAuthKey(x=0)` (`MTMessageEncryptionKey.m:70-101`); frame = `auth_key_id(8) ‖ msg_key(16) ‖ AES-256-IGE(plaintext)`. Quick-ack token = `MTQuickAckTokenFromMsgKeyLarge` = LE uint32 of `msg_key_large[0..4]` with bit 31 cleared (`MTQuickAck.m:7-11`). Encryption failure → nil → the message is silently dropped from the payload list (its transaction gets no per-payload completion).

`_manuallyEncryptedMessage:messageId:authKey:` (`1610-1649`): MTProto 1.0 (SHA1 msg_key, random 16-byte salt+session, padding to 16 via `paddedDataV1` ≤ 15 bytes) — used only for `bind_auth_key_inner` (`MTBindKeyMessageService.m:71`).

### 3.10 Unauthorized (plain) mode

Outgoing (`_dataForPlainMessage:`, `MTProto.m:1494-1517`): `auth_key_id = 0 (8) ‖ msg_id (8) ‖ len (4) ‖ body ‖ extra`, where `extra` = `arc4random_uniform(60) * 4` random bytes (0..236) only with extended padding, else none. One message per payload; no containers, acks, salts or time sync. Monotonicity violation is not a per-message filter here, but the pass is still abandoned and the session reset (`1118`, `1145`).

Incoming (`_readIncomingPayload:unauthorized:YES`, `2244-2264`): require ≥ 20 bytes, `auth_key_id == 0`, `message_data_length >= 4`; body = everything after the 20-byte header (the declared length is reported as `size` but the body is **not** truncated to it). No session-id check. seqno is 0 so no acks.

### 3.11 Incoming pipeline

#### 3.11.1 `transportHasIncomingData:...` (`MTProto.m:1933-2088`)

Dropped if stale transport or Stopped. Sets `transport.simultaneousTransactionsEnabled = true` (property is unused).

**Transport error** — payload length 4..19 bytes (`4 <= len <= 4+15`): read int32 LE code, then:
- `decodeResult(transactionId, false)` → TCP transport `connectionIsInvalid` → `transportConnectionProblemsStatusChanged(hasProblems:true, isProbablyHttp:true)` → scheme failure/invalidation in the context and possibly backup-address discovery and proxy probing (3.20) — **even for a routine -404 caused by temp-key expiry**.
- `mtProto:protocolErrorReceived:` to all services (reverse).
- `-404` → `handleMissingKey:` (3.7.2).
- `-429` → `_isConnectionThrottled = true`; an `MTTimer(5.0 s)` is created to clear it **but never started** (`1978-1992`), so this MTProto stops requesting transactions for good (§10 H1). No reset, no transaction failure.
- any other code (including -404) → if transport unchanged, `requestSecureTransportReset` (drop the TCP connection); `transportTransactionsMayHaveFailed:@[transactionId]`.

**Decrypt** (authorized; `_decryptedPayloadForIncomingTransportData:authKey:`, `2179-2237`), all must hold else nil:
- key ≥ 128 bytes; frame ≥ 60 bytes (24 header + 36);
- `auth_key_id` equals the cached key's id (the key is looked up with `createIfNeeded:false`; with no cached key the frame is "undecryptable");
- AES-IGE decrypt `floor((len−24)/16)*16` bytes (trailing bytes ignored), key/iv from `msg_key` with x = 8;
- constant-time compare `SHA256(auth_key[96..128] ‖ plaintext)[8..24] == msg_key`;
- `0 <= message_data_length <= plaintextLen − 32` and padding `plaintextLen − 32 − message_data_length ∈ [12, 1024]`.

Undecryptable → `decodeResult(false)` (connection-problem path as above), `transportTransactionsMayHaveFailed`, scheme failure report, `requestSecureTransportReset` (`2071-2086`).

**Decrypted** → `decodeResult(true)` (TCP: `connectionIsValid` — stops the 20 s connection watchdog, marks the behaviour healthy) → `_parseIncomingMessages:` → AUTH_KEY_PERM_EMPTY probe (3.7.2) → on parse error: scheme failure report, `transportTransactionsMayHaveFailed`, **`resetSessionInfo:false`** (`2047-2058`); on success: `reportTransportSchemeSuccess` (every packet), `transportTransactionsSucceeded:@[transactionId]` (removes acks sent on this connection), `_processIncomingMessage` for each message in order, then `requestTransportTransaction` if the transport asked (`requestTransactionAfterProcessing`; TCP passes false).

#### 3.11.2 Parse (`_parseIncomingMessages:`, `2299-2379`; `parseMessage:`, `2284-2297`)

- Header at fixed offsets (`_readIncomingPayload`, `2265-2278`): salt, session_id, msg_id, seq_no; the body slice **includes the trailing padding** (TL parsers ignore trailing bytes).
- Authorized: `session_id != current` → parse error → session reset. **Not checked**: incoming salt, server msg_id parity (`%4 ∈ {1,3}`), msg_id time window, seqno, msg_id monotonicity. Replay protection is only the processed-id set.
- `parseMessage:`: `unwrapMessage` (gzip, 3.17) → `MTInternalMessageParser parseMessage:` → fallback `context.serialization parseMessage:` (TelegramCore `Api.parse`, `Serialization.swift:266-271`). nil at any level ⇒ parse error for the **whole packet** (all siblings lost, session reset).
- Top object `msg_container` → one `MTIncomingMessage` per child (child id/seqno/length, child body parsed recursively once — a nested container becomes an opaque body); `msg_copy#e06046b2` (`MTMessage`) → its inner message; otherwise the top-level message itself with `size = topMessageSize` (0 in authorized mode). All children share `timestamp = top msg_id / 2^32`, the top salt and session.

`MTInternalMessageParser` constructors (`MTInternalMessageParser.m:41-657`): resPQ `05162463`, server_DH_params_fail `79cb045d`/ok `d0e8075c`, server_DH_inner_data `b5890dba`, dh_gen_ok/retry/fail `3bcbf734`/`46dc1fb9`/`a69dae02`, rpc_result `f35c6d01` (req_msg_id + raw rest), rpc_error `2144ca19`, rpc_answer_unknown `5e2ad36e`, rpc_answer_dropped_running `cd78e586`, rpc_answer_dropped `a43ad8b7`, msgs_state_req `da69fb52`, msgs_state_info `04deb57d`, msg_detailed_info `276d3ec6`, msg_new_detailed_info `809db6df`, msgs_all_info `8cc0d131`, msg_copy `e06046b2` (inner must be `message#5bb8e511`, exact length), msg_resend_req `7d861a08` (**reads the count without skipping the `vector#1cb5c415` constructor** → always fails, §10 H3), bad_msg_notification `a7eff811`, bad_server_salt `edab447b`, msgs_ack `62d6b459` (vector constructor checked), ping `7abe77ec`, pong `347773c5`, new_session_created `9ec20908`, destroy_session_ok `e22045fc` / none `62d350c9`, destroy_sessions_res `fb95abcd` (raw), msg_container `73f1f8dc` (child length must be `0..MTMaxTransportPayloadLength` and present), future_salts `ae500895` (bare vector). Vector constructors of msgs_state_req and msgs_all_info are skipped unchecked.

#### 3.11.3 Per-message processing (`_processIncomingMessage:`, `2381-2577`)

1. **Duplicate** (`messageProcessed`): schedule an ack again (size = message size), flush if over the ack limits, return — not dispatched (`2383-2395`).
2. Mark processed. If authorized and seqno is odd: schedule ack; `requestTransportTransaction` only if pending acks exceed **size > 1 MiB or count > 64** (`2401-2408`).
3. Dispatch:

| Incoming body | Handling in MTProto | Who else sees it |
|---|---|---|
| `bad_server_salt` (authorized) | time-fix match → complete + time diff + salt (3.8); else `initiateTimeSync` | `messageDeliveryFailed(bad_msg_id)` and, if `bad_msg_id` is a known container, for each of its confirmable children (reverse over services); then `requestTransportTransaction` if allowed |
| `bad_msg_notification` (authorized) | per code, table 3.12 | same delivery-failed fan-out |
| `msgs_ack` | — | `messageDeliveryConfirmed(ids)` (request service marks `delivered`) |
| `msg_detailed_info` (has req_msg_id) | ask services `shouldRequestMessageWithId:answer inResponseTo:req currentTransactionId:` (forward, first true wins); `MTRequestMessageService` answers true whenever a request with that msg_id exists | true → `requestMessageWithId(answer_msg_id)` (3.15); false → schedule ack for `answer_msg_id` with `size = bytes` and `requestTransportTransaction` |
| `msg_new_detailed_info` | always `requestMessageWithId(answer_msg_id)` | — |
| `new_session_created` | `server_salt` and `unique_id` **ignored** | `mtProtoServerDidChangeSession(first_msg_id, messageIdsInContainersAfterMessageId(first_msg_id))` (reverse). Request service drops contexts of requests with `msg_id < first` not in that list → re-send with new msg_id. Transport clears a pending actualization ping that is older. |
| anything else (rpc_result, pong, future_salts, msgs_state_info, msgs_all_info, msgs_state_req, msg_resend_req, destroy_session_*, server ping, API updates, …) | none, except: pong for the time-fix msg → `completeTimeSync` + `requestTransportTransaction` | `receivedMessage:authInfoSelector:networkType:` to all services (reverse) |

Not handled by anyone: incoming `msgs_state_req` (no `msgs_state_info` reply), `msgs_all_info`, server `msg_resend_req` (also unparseable), `destroy_session_*`, server `ping`. `rpc_result` routing is the request/bind/auth services' job.

### 3.12 `bad_msg_notification` reactions (`MTProto.m:2410-2489`)

| Code | Meaning (spec) | MtProtoKit reaction | Then |
|---|---|---|---|
| 16 | msg_id too low | if it is the time-fix ping: complete sync, `timeDiff = notif.msg_id/2^32 − now`; else `initiateTimeSync` | delivery-failed fan-out → request service re-sends with a new msg_id |
| 17 | msg_id too high | same as 16 | same |
| 18 | msg_id low bits wrong | nothing | fan-out |
| 19 | container msg_id equals a previous one | nothing | fan-out |
| 20 | message too old | nothing | fan-out (re-send, new msg_id) |
| 32 | seqno too low | `resetSessionInfo:false` + `initiateTimeSync` | fan-out runs after the reset (services already cleared) |
| 33 | seqno too high | same as 32 | same |
| 34 | even seqno expected | nothing | fan-out |
| 35 | odd seqno expected | nothing | fan-out |
| 48 | bad server salt (non-salt variant) | `initiateTimeSync` | fan-out |
| 64 | invalid container | nothing | fan-out (children via the container map) |
| `bad_server_salt` (`edab447b`, code 48) | | see 3.8 | fan-out |

Unauthorized mode skips this branch entirely; the notification is passed to services as an ordinary message.

### 3.13 Acknowledgements

- Scheduled for every processed authorized message with odd seqno and for every duplicate; `size` is the child length (container children, msg_copy) or 0 for a standalone top-level message (`2357`, `2373`, `2375`), so the 1 MiB size trigger only ever counts container children.
- No timer: acks ride on the next outgoing transaction (3.9.2 step 3) or are flushed proactively only when `count > 64` or `size > 1 MiB` (`MTSessionInfo.m:182-200`), or after a "not requested" `msg_detailed_info`.
- Suppressed in a transaction that carries a high-priority message unless forced or over limits.
- Each msgs_ack contains **all** pending ids (no 8192 cap). An ack stays pending until a packet is successfully decrypted and parsed on the connection it was sent on (`transportTransactionsSucceeded`, `1907-1913`); until then it is repeated in every transaction on that connection and re-sent on the next connection. Session reset discards pending acks.

### 3.14 Retransmission of outgoing messages (summary of the contract MTProto offers)

MTProto never re-sends anything itself. It signals; services rebuild:
- `transactionsMayHaveFailed(connIds)` — connection closed, protocol error, undecryptable or unparseable packet, transport stop.
- `mtProtoAllTransactionsMayHaveFailed` — any `setTransport:` (pause, reset, scheme change).
- `messageDeliveryFailed(msgId)` — bad_msg / bad_server_salt (+ container children).
- `mtProtoDidChangeSession` — local session reset.
- `mtProtoServerDidChangeSession(first, others)` — new_session_created.
- `messageResendRequestFailed(msgId)` — msgs_state_info answered our msg_resend_req.

`MTRequestMessageService` reacts by clearing `requestContext`, which re-sends the RPC **with a new msg_id** (not the same msg_id in a new container), i.e. at-least-once execution on the server. Only messages a service explicitly re-emits with `messageId != 0` (request contexts that were prepared but never reached the wire; dropped-answer contexts) keep their msg_id and are then wrapped in a container (3.9.2 step 9).

### 3.15 Resend requests (`MTResendMessageService`)

- `requestMessageWithId:` (`MTProto.m:612-635`): if no `MTResendMessageService` for that id exists and the id is not processed, add one (delegate = MTProto). Adding the first one flips `isPerformingServiceTasks` to true (`474-513`); removing the last one flips it back unless time sync is running (`531-567`).
- The service (`MTResendMessageService.m:44-76`) emits `msg_resend_req#7d861a08 vector#1cb5c415 [1] msg_id` as a non-content message (even seqno), records its msg_id/transaction id; re-emits when its transaction fails or the message is reported failed.
- Completes (removes itself) when a message with `msg_id == requested id` arrives (any body), when `msgs_state_info` answers its request (then calls `MTProto _messageResendRequestFailed:` → services' `messageResendRequestFailed` → request service drops the context of requests whose `responseMessageId` matches → full re-send), on local session reset, or when new_session_created invalidates its request id.
- No timeout: if the server never answers, the service stays forever and `isPerformingServiceTasks` stays true (UI shows "Updating").

### 3.16 new_session_created

See the dispatch table. Additionally (3.11.3 step 2) it is acked like any content message. The server-provided salt is not stored; the next transaction normally hits `bad_server_salt` if the salt changed.

### 3.17 gzip

- Incoming: `unwrapMessage:` (`MTInternalMessageParser.m:669-686`): if the first int32 is `gzip_packed#3072cfa1`, read TL bytes with bounds checks (truncated → nil → parse error) and inflate with `windowBits = 15+32` (gzip or zlib auto-detect), 16 KiB chunks, output capped at `MTMaxUnpackedMessageLength = 32 MiB` (nil when exceeded or stream not at `Z_STREAM_END`) (`MTGzip.m:18-74`). Applied to every top-level and child body and, separately, inside `rpc_result` by the request service and the AUTH_KEY_PERM_EMPTY probe.
- Outgoing: MTProto never compresses. TelegramCore wraps some method bodies itself (`gzip_packed` + `MTGzip compress` at `Z_BEST_COMPRESSION`, used only if smaller) (`Download.swift:25-37`).

### 3.18 Ping, keepalive and liveness

- **Actualization ping** (transport-specific, `MTTcpTransport.m:621-656`): one `ping` per TCP connection in its first transaction. When its message is prepared, the transport records `currentActualizationPingMessageId` and reports `isUpdatingConnectionContext = true` to MTProto → delegate. Cleared (→ false) on the matching `pong` (`763-782`), on `messageDeliveryFailed` for it (`784-799`), on local session change (`731-743`), or on new_session_created when it is older than `first_msg_id` (`745-761`). Re-send: when **incoming data arrives** while it is pending and no timer runs, a 3 s timer starts; on expiry the ping is re-sent (`463-464`, `349-395`). No data at all → no re-send.
- **Time-fix ping**: 3.8.
- **No periodic ping, no `ping_delay_disconnect`, no idle keepalive** anywhere in MtProtoKit. Liveness comes from the transport: a 20 s connection watchdog until the first decryptable packet (`MTTcpTransport.m:304-347`), and an `MTTcpConnection` response timer armed when a payload expecting a response is written: `12 s + payloadLen/12288 s`, reset to 12 s on every partial read, closing the connection with error on expiry (`MTTcpConnection.m:677`, `1413-1421`, `1459-1475`).

### 3.19 Quick acknowledgements

- Requested per transport transaction (`needsQuickAck`): any message with `needsQuickAck` (request service sets it when the request has an `acknowledgementReceived` block, `MTRequestMessageService.m:638`) or the parity latch in 3.9.2 step 5.
- Token recorded per message internal id (3.9.3); the time-fix ping records none.
- `transportReceivedQuickAck:` (`MTProto.m:1714-1729`) forwards to services (reverse) unless stale or Stopped; the request service fires `acknowledgementReceived` for requests whose context has a transaction id and matching token (`MTRequestMessageService.m:1092-1104`). Wire decoding per framing is the transport's job (`MTQuickAck.m:13-21`).

### 3.20 Proxy connection-issue detection (`checkForProxyConnectionIssues`)

`transportConnectionProblemsStatusChanged:scheme:hasConnectionProblems:isProbablyHttp:` (`MTProto.m:811-865`), ignored in unauthorized mode (release builds):
- `hasProblems` → `reportTransportSchemeFailure` + `invalidateTransportScheme(isProbablyHttp, media)` (context then looks for a better scheme and starts backup-address discovery after 5 s, or 20 s when `networkSettings.reducedBackupDiscoveryTimeout` is false; `MTContext.m:1436-1454`). Else → `revalidateTransportScheme`.
- If `!hasProblems || transport.proxySettings == nil || !checkForProxyConnectionIssues` → stop probing and, if a status was set, report `proxyHasConnectionIssues=false`.
- Else, if not already probing: start `[probeProxy delay:5.0] then [complete delay:20.0]` **restarted forever** (`845-846`). `probeProxyWithContext:` (`MTConnectionProbing.m:126-141`) = `MTProxyConnectivity pingProxy` (10 s timeout → false) combined with an ICMP echo to a random one of `google.com` / `8.8.8.8` (10 s timeout → false); result `true` ("proxy has issues") iff proxy unreachable **and** ICMP reachable. Each result updates `_connectionState.proxyHasConnectionIssues` and re-emits `mtProtoConnectionStateChanged` (`867-875`) if a state exists.
- The TCP transport only ever reports `hasConnectionProblems:true` (watchdog: `isProbablyHttp:false`, `MTTcpTransport.m:344`; failed decode: `true`, `506`). Nothing reports `false`, so once started, probing never stops for the life of the MTProto, and `revalidateTransportScheme` is never called from here.

Also `transportConnectionFailed:scheme:` (`749-759`; TCP close with error, watchdog) → `reportTransportSchemeFailure` unless unauthorized.

### 3.21 Transaction value types and the service contract

- `MTOutgoingMessage` (`h/MTOutgoingMessage.h`): `internalId` (process-wide atomic counter, `MTOutgoingMessage.m:13-27`), `data`, `metadata`/`shortMetadata` (logging), `messageId`/`messageSeqNo` (0 = assign), `requiresConfirmation` (default **true**), `needsQuickAck`, `hasHighPriority`, `inResponseToMessageId` (carried into the prepared message, unused by MTProto), `dynamicDecorator`.
- `MTMessageTransaction` (`h/MTMessageTransaction.h`): `messagePayload: [MTOutgoingMessage]`, `prepared(map)` once per pass, `completion(transactionIdMap, preparedMap, quickAckMap)` once per successful payload or once with all-nil on failure/abandon, `failed` (**never invoked by MTProto**), `allowServiceMode` (**unused**), `requiresEncryption` (honoured only for the transport-specific transaction).
- `MTPreparedMessage`: immutable `{internalId, messageId, seqNo, salt, data, requiresConfirmation, hasHighPriority, inResponseToMessageId}`.
- `MTTransportTransaction`: `{payload, completion(success, transactionId), needsQuickAck, expectsDataInResponse}`.
- `MTIncomingMessage`: `{messageId, seqNo, authKeyId, sessionId, salt, timestamp, size, body}` where `body` is an internal message object or TelegramCore's boxed API object.
- `MTTimeFixContext`: `{messageId, messageSeqNo, transactionId, timeFixAbsoluteStartTime}` (start time unused).

`MTMessageService` callbacks (`h/MTMessageService.h:13-45`) and their emitters:

| Callback | Emitted from |
|---|---|
| `mtProtoWillAddService` / `DidAddService` / `DidRemoveService` | add/remove (`465-570`) |
| `mtProtoMessageTransaction:authInfoSelector:sessionInfo:scheme:` | 3.9.2 step 4.2 |
| `mtProtoDidChangeSession` | `resetSessionInfo` |
| `mtProtoServerDidChangeSession:firstValidMessageId:otherValidMessageIds:` | new_session_created |
| `mtProto:receivedMessage:authInfoSelector:networkType:` | 3.11.3 else-branch |
| `mtProto:receivedQuickAck:` | 3.19 |
| `mtProto:transactionsMayHaveFailed:` / `mtProtoAllTransactionsMayHaveFailed` | 3.14 |
| `mtProto:messageDeliveryFailed:` / `messageDeliveryConfirmed:` | bad_msg / msgs_ack |
| `mtProto:messageResendRequestFailed:` | 3.15 |
| `mtProto:protocolErrorReceived:` | 3.11.1 |
| `mtProto:shouldRequestMessageWithId:inResponseToMessageId:currentTransactionId:` | msg_detailed_info |
| `mtProto:updateReceiveProgressForToken:progress:packetLength:` / `mtProtoTransportActivityUpdated` | transport progress (3.23) |
| `mtProtoNetworkAvailabilityChanged` / `ConnectionStateChanged` / `ConnectionContextUpdateStateChanged` / `ServiceTasksStateChanged` | 3.22 |
| `mtProtoAuthTokenUpdated` | token updated |
| `mtProtoPublicKeysUpdated:datacenterId:publicKeys:` / `mtProtoApiEnvironmentUpdated:` | context listener (3.24) |

### 3.22 Delegate callbacks and connection-state semantics

All on the manager queue, only for the current transport (`MTProto.m:726-809`, `266-283`):

| `MTProtoDelegate` method | Meaning | Source |
|---|---|---|
| `mtProtoNetworkAvailabilityChanged:isNetworkAvailable:` | SCNetworkReachability for `0.0.0.0` says reachable (flag `kSCNetworkReachabilityFlagsReachable` only), polled every 5.0 s plus callback, emitted on change (`MTNetworkAvailability.m:51-166`). `false` when no transport. On change the TCP transport also drops its current connection and, if available, clears reconnect backoff (`MTTcpTransport.m:715-729`). | transport |
| `mtProtoConnectionStateChanged:state:` | `state.isConnected` = TCP connect completed (`MTTcpConnection.m:2085-2094`; for SOCKS5 only after the CONNECT reply, `1660-1665`; for fake-TLS **before** the ServerHello HMAC is checked) — not "has decrypted data"; `proxyAddress = proxySettings.ip`; `proxyHasConnectionIssues` = last probe result. `state == nil` when no transport. Re-emitted with only the issues flag changed by the prober. | transport open/close/stop |
| `mtProtoConnectionContextUpdateStateChanged:isUpdatingConnectionContext:` | actualization ping outstanding (3.18). | transport |
| `mtProtoServiceTasksStateChanged:isPerformingServiceTasks:` | time-fix running or any resend service present. | MTProto |

TelegramCore maps these (`Network.swift:94-155`, `639-650`): Connected && (UpdatingConnectionContext || PerformingServiceTasks) → `updating`; Connected → `online`; !NetworkAvailable → `waitingForNetwork`; otherwise `connecting` (with `proxyHasConnectionIssues` only while not connected). The same four booleans must be reproduced bit-exactly for UI parity.

### 3.23 Progress tokens

`transportDecodeProgressToken:` (`MTProto.m:1731-1817`): for a large packet the transport hands its first 128 bytes (`MTTcpConnection.m:1885-1916`, `1998-2004`); MTProto (authorized, cached key, `auth_key_id` matches) decrypts them **without msg_key verification**, skips the 32-byte header and walks `findReqMsgId` (`1819-1876`): container → recurse into each child's first constructor; `rpc_result` → `req_msg_id`; `msgs_ack` (reads ids as int32, §10 L23); `pong`. The resulting `@(req_msg_id)` lets `MTRequestMessageService` report download progress per request (`MTRequestMessageService.m:1235-1247`).

### 3.24 Context listener callbacks

- `contextDatacenterTransportSchemesUpdated:datacenterId:shouldReset:` — 3.4.
- `contextDatacenterAuthInfoUpdated:datacenterId:authInfo:selector:` — 3.4; ignored in unauthorized mode, for other DCs, and for selectors other than the awaited/cached one.
- `contextDatacenterAuthInfoRequestFailed:` / `contextDatacenterAuthTokenTransferFailed:` — re-ask (3.4).
- `contextDatacenterAuthTokenUpdated:` — 3.4.
- `contextDatacenterPublicKeysUpdated:` — forwarded to services (forward), not filtered by DC (`2775-2783`).
- `contextApiEnvironmentUpdated:` (`2785-2813`) — store the new environment, forward `mtProtoApiEnvironmentUpdated:` to services, and `resetTransport` + `requestTransportTransaction` when the SOCKS/MTProxy settings presence or value changed, or `langPackCode` changed (the request service re-sends `initConnection` because the init hash changes).

### 3.25 Scheme feedback to `MTContext`

| Event | Context call |
|---|---|
| packet decrypted and parsed | `reportTransportSchemeSuccessForDatacenterId` (every packet) |
| parse error, undecryptable, TCP close with error, watchdog | `reportTransportSchemeFailureForDatacenterId` (not in unauthorized mode) |
| connection problems true | failure + `invalidateTransportSchemeForDatacenterId:transportScheme:isProbablyHttp:media:` |
| connection problems false | `revalidateTransportSchemeForDatacenterId` (never happens with TCP) |
| `resetTransport` with no schemes | `transportSchemeForDatacenterWithIdRequired:media:` |

### 3.z Constants

| Name | Value | file:line | Meaning |
|---|---|---|---|
| `MTProtoState*` | 1, 2, 8, 16, 32, 64, 128 | `MTProto.m:60-68` | state bits (3.3) |
| `MTMaxContainerSize` | 3072 B | `MTProto.m:70` | max summed body bytes per container group |
| `MTMaxUnacknowledgedMessageSize` | 1 MiB | `MTProto.m:71` | pending-ack size flush threshold (strictly greater) |
| `MTMaxUnacknowledgedMessageCount` | 64 | `MTProto.m:72` | pending-ack count flush threshold (count > 64) |
| padding min | 12 B | `MTProto.m:1536` | MTProto 2.0 outgoing padding floor |
| padding max | 72 B / 256 B (dd/ee secret) | `MTProto.m:1533` | outgoing padding ceiling |
| plain-mode extra | `arc4random_uniform(60)*4` = 0..236 B | `MTProto.m:1505` | only with extended padding |
| min auth key (send) | 120 B | `MTProto.m:1565` | `88+32` bytes needed for msg_key |
| min auth key (receive) | 128 B | `MTProto.m:2183` | `88+8+32` |
| min encrypted frame | 60 B | `MTProto.m:2187` | 24 header + 36 |
| incoming padding | 12..1024 B | `MTProto.m:2232` | after the 32-byte header and body |
| transport error frame | 4..19 B | `MTProto.m:1952` | int32 LE code + optional slack |
| -429 unthrottle | 5.0 s (timer never started) | `MTProto.m:1982` | |
| proxy probe start delay | 5.0 s | `MTProto.m:845` | |
| proxy probe repeat delay | 20.0 s | `MTProto.m:846` | after each probe |
| proxy / ICMP probe timeout | 10.0 s each | `MTConnectionProbing.m:129-130` | |
| ICMP probe hosts | `google.com`, `8.8.8.8` | `MTConnectionProbing.m:62-65` | random pick |
| bad_server_salt validity | 30 min (`30*60*2^32` msg_id units) | `MTProto.m:2427` | synthetic window |
| new-key salt | 0, valid 29 min | `MTDatacenterAuthAction.m:115` | forces first bad_server_salt |
| msg_id scale | `globalTime * 2^32`, `%4 == 0` | `MTSessionInfo.m:93-105` | client ids |
| `get_future_salts` num | 32 first, then 1 | `MTTimeSyncMessageService.m:58` | dead path |
| time-sync samples | 1, or 6 if first RTT > 1.0 s | `MTTimeSyncMessageService.m:151-158` | dead path |
| actualization ping re-send | 3 s | `MTTcpTransport.m:358` | armed on incoming data |
| connection watchdog | 20.0 s | `MTTcpTransport.m:312` | until first decryptable packet |
| transaction lock timeout | 1.0 s | `MTTcpTransport.m:594` | |
| TCP response timeout | 12.0 s + len/12288 s, reset to 12 s on partial read | `MTTcpConnection.m:677`, `1416`, `1475` | |
| `MTMaxTransportPayloadLength` | 16 MiB | `MTTransport.m:3` | frame cap, container child cap |
| `MTMaxUnpackedMessageLength` | 32 MiB | `MTTransport.m:4` | gzip inflate cap |
| gzip chunk | 16 KiB | `MTGzip.m:10` | |
| network reachability poll | 5.0 s | `MTNetworkAvailability.m:76` | |
| `tempKeyExpiration` | 86400 s | `MTContext.m:269` | not checked by MTProto |
| large-response drop threshold | 512 KiB | `MTRequestMessageService.m:165` | cancel ⇒ session reset |
| TL ids sent by MTProto | `msgs_ack 62d6b459`, `vector 1cb5c415`, `msg_container 73f1f8dc`, `ping 7abe77ec` | `MTProto.m:1042-1043`, `1455`, `1396` | |

## 4. MTRequestMessageService and the request lifecycle

`MTRequestMessageService` (RMS) is the only `MTMessageService` that carries API calls. It owns a list of
`MTRequest` objects, hands them to `MTProto` as `MTOutgoingMessage`s on every transport transaction,
matches `rpc_result`s back to requests, and implements all client-side retry policy (flood wait,
500 retry, auth-token waits, connection (re)initialisation, APNS/reCAPTCHA verification). MTProto
itself knows nothing about API semantics except one interception (`AUTH_KEY_PERM_EMPTY`, 4.9).

### 4.1 Ownership and threading

- One RMS per `MTProto`. TelegramCore creates one for the main connection (`TC/Network/Network.swift:639`)
  and one per `Download` worker (`TC/Network/Download.swift:72`). Internal actions create throwaway RMS
  instances: transfer auth export/import (`MTDatacenterTransferAuthAction.m:102,144`), getConfig discovery
  (`MTDiscoverDatacenterAddressAction.m:96`), backup-address config fetch (`MTBackupAddressSignals.m:267`).
- RMS holds `_context` strongly and `_mtProto` weakly (`MTRequestMessageService.m:68-70`).
- **Queue.** `_queue` is set in `mtProtoWillAddService:` to `[mtProto messageServiceQueue]`
  (`MTRequestMessageService.m:393-396`), which is the single process-wide serial queue
  `org.mtproto.managerQueue` shared by every `MTProto` instance (`MTProto.m:140-149, 572-575`). All RMS
  state is mutated only on that queue. `MTQueue.dispatchOnQueue:` runs the block inline when already on
  the queue, otherwise `dispatch_async` (`MTQueue.m`), so public methods called from the manager queue are
  synchronous and re-entrant.
- Consequence for the port: every request completion, ack, progress and error callback is invoked on the
  manager queue, synchronously from inside incoming-message processing; callbacks may re-enter RMS
  (`removeRequestByInternalId:` from the completion is the normal TelegramCore path, because disposing a
  completed Swift signal removes the request). The response loop survives this only because it `break`s
  right after calling `completed` (`MTRequestMessageService.m:1066`).
- `addRequest:` before the service is added to an MTProto is a **silent no-op**: `_queue` is nil and
  `[nil dispatchOnQueue:]` does nothing (`:123`). `addRequest:` when `_mtProto` has been deallocated also
  silently drops the request without calling `completed` (`:125-127`).
- `requestCount:` returns 0 synchronously when `_queue == nil`, otherwise asynchronously on the queue
  (`:207-221`). Not used by TelegramCore.
- Registered context listener: `initWithContext:` builds an `MTContextBlockChangeListener` for
  `contextIsPasswordRequiredUpdated` and adds it (`:92-100`). The context stores listeners weakly
  (`MTWeakContextChangeListener`, `MTContext.m:529-547`) and nothing else retains this block listener, so it
  dies when `init` returns: **the password-required-cleared callback never fires** (documented and kept
  deliberately in commit 028f835528). `addChangeListener:` prunes dead boxes on each call.

### 4.2 Data model

`MTRequest` (`h/MTRequest.h:19-47`, `MTRequest.m`):

| Field | Default | Meaning |
|---|---|---|
| `internalId` | `MTRequestInternalId`, process-wide `OSAtomicIncrement32` counter starting at 2 (`MTRequest.m:36-39`) | identity used by `removeRequestByInternalId:`; compared with `isEqual:` there but with pointer `==` in dependency checks (`:256, 337, 589, 991, 1029`) |
| `payload`, `metadata`, `shortMetadata`, `responseParser` | set via `setPayload:...` | raw TL function body; `responseParser(NSData) -> id` returns nil on parse failure |
| `decorators` | nil | **unused** anywhere |
| `transactionResetStateVersion` | 0 | bumped when a transport transaction carrying the request is declared failed; stale `prepared`/`completion` callbacks compare against it (4.7) |
| `requestContext` | nil | in-flight state (below); nil means "must be (re)sent" |
| `errorContext` | nil | retry state (below), created lazily on the first handled error |
| `hasHighPriority` | false | copied to `MTOutgoingMessage.hasHighPriority`; never set by TelegramCore |
| `dependsOnPasswordEntry` | **true** (`MTRequest.m:73`) | skip while `context.isPasswordInputRequiredForDatacenterWithId` is true. TelegramCore sets false on every request; internal requests keep true |
| `passthroughPasswordEntryError` | false | if true, `401 SESSION_PASSWORD_NEEDED` does not flip the context's password-required flag. Never set by TelegramCore |
| `needsTimeoutTimer` | false | participates in the 5 s stall detector (4.11) |
| `expectedResponseSize` | 0 | if `>= 512 KiB`, cancelling an in-flight request resets the session (4.13) |
| `completed(result, info, error)` | nil | exactly one terminal callback; `info` is `MTRequestResponseInfo{networkType, timestamp, duration}` |
| `progressUpdated(progress, packetLength)` | nil | receive progress of the response packet (4.14) |
| `acknowledgementReceived()` | nil | non-nil ⇒ the message requests a transport quick-ack (`:638`) |
| `shouldContinueExecutionWithErrorContext(errorContext) -> bool` | nil | retry gate for 500/-500 and flood waits (4.10) |
| `shouldDependOnRequest(other) -> bool` | nil | dependency predicate for `invokeAfterMsg` (4.6) |

`MTRequestContext` (`h/MTRequestContext.h`): `messageId`, `messageSeqNo` (readonly), `waitingForMessageId`,
`transactionId` (the `MTTcpConnection.internalId` the bytes were written to, `MTTcpTransport.m:676`),
`quickAckId`, `delivered` (msgs_ack seen), `responseMessageId` (from msg_detailed_info), `willInitializeApi`,
`sentTimestamp` (`CFAbsoluteTimeGetCurrent`, wall clock).

`MTRequestErrorContext` (`h/MTRequestErrorContext.h:27-41`): `minimalExecuteTime` (seconds on
`MTAbsoluteSystemTime()` = `mach_absolute_time`, which does **not** advance while the device sleeps,
`MTTime.m`), `internalServerErrorCount`, `floodWaitSeconds`, `floodWaitErrorText` (both never reset once
set), `waitingForTokenExport`, `waitingForRequestToComplete` (another request's `internalId`),
`pendingVerificationData {nonce, secret, isResolved, disposable}`,
`pendingRecaptchaVerificationData {siteKey, token, isResolved, disposable}`.

### 4.3 Enqueue and eligibility

`addRequest:` (`:121-139`): on the queue, appends if not already contained, then
`[mtProto requestTransportTransaction]`. Insertion order is the send order.

On each transport transaction MTProto calls `mtProtoMessageTransaction:authInfoSelector:sessionInfo:scheme:`
(`:554-765`, called from `MTProto.m:1015-1033`). For each request in `_requests` order:

1. Skip if `dependsOnPasswordEntry && context.isPasswordInputRequiredForDatacenterWithId(dc)` (`:565-566`).
2. If `errorContext != nil`, skip when any of: `minimalExecuteTime > now`; `waitingForTokenExport`;
   `pendingVerificationData` present and unresolved; `pendingRecaptchaVerificationData` present and
   unresolved; `waitingForRequestToComplete` equals the `internalId` of a request still in `_requests`
   (`:568-597`).
3. Send iff `requestContext == nil` **or** (`!waitingForMessageId && !delivered && transactionId == nil`)
   (`:599`). The second clause re-sends a request that was prepared but whose transport transaction never
   completed, **reusing its old `messageId`/`seqNo`** (`:609-615`, `MTProto.m:1088-1096` keeps a non-zero
   preset id).
4. Build `MTOutgoingMessage(data: decorated payload, messageId, seqNo)`, `needsQuickAck =
   acknowledgementReceived != nil`, `hasHighPriority` (`:637-639`), optional `dynamicDecorator` (4.6).

`requestsWillInitializeApi` is computed once per transaction (`:559`) and applied to **every** request in
it (4.5). Requests are never batched by size here; container packing and limits are MTProto's (section 3).

### 4.4 Payload decoration (wire layout)

`decorateRequestData:` (`:423-552`) wraps the stored payload, innermost first. Resulting wire order,
outermost first:

```
[invokeAfterMsg (dynamic, 4.6)]
 invokeWithReCaptcha#adbb0f94 token:string            (if resolved recaptcha data)      :535-545
  invokeWithApnsSecret#0dae54f8 nonce:string secret:string (if resolved APNS data)       :522-533
   invokeAfterMsg#cb9f372d msg_id:long                (static dependency)               :485-520
    invokeWithoutUpdates#bf9459b7                     (env.disableUpdates || forceBackgroundRequests) :473-483
     invokeWithLayer#da9b0d0d layer:int               (if initializeApi && env != nil)  :437-438
      initConnection#c1cd5ea9 flags:# ...                                                :448-467
       <payload>
```

`initConnection` field mapping (`:440-467`), all strings TL-encoded (nil → empty string, `MTBuffer.m:51-88`):

| TL field | Source |
|---|---|
| `layer` (in invokeWithLayer) | `[serialization currentLayer]` (TelegramCore: 230, `TC/State/Serialization.swift:262-264`); `env.layer` is only used for the hash |
| `flags.0` + `proxy:InputClientProxy` | set iff `env.socksProxySettings.secret != nil` (MTProxy or WEB proxy, never SOCKS5); `inputClientProxy#75588b3f address:string port:int` with `socksProxySettings.ip`, `.port` |
| `flags.1` + `params:JSONValue` | set iff `env.systemCode != nil`; raw bytes appended verbatim (already a boxed TL `JSONValue`) |
| `api_id` | `env.apiId` |
| `device_model` | `env.deviceModel` |
| `system_version` | `env.systemVersion` |
| `app_version` | `env.appVersion` |
| `system_lang_code` | `env.systemLangCode` |
| `lang_pack` | `env.langPack` |
| `lang_code` | `env.langPackCode` |

The API hash is not sent (MtProtoKit never handles `api_hash`; it belongs to `auth.*` calls).
`apiInitializationHash` is logged on every decoration (`:431-433`); it embeds proxy credentials (8.2).

### 4.5 Connection initialisation state ("when is initConnection sent")

- State is **per auth key**, not per session: the string `authKeyAttributes["apiInitializationHash"]` of the
  `MTDatacenterAuthInfo` for (dc, selector) currently used to encrypt (`:559`). It is persisted with the auth
  info in the keychain (`MTDatacenterAuthInfo.m:63,74`).
- `requestsWillInitializeApi = env != nil && env.apiInitializationHash != stored` (`:559`). While true,
  **every** request of every transaction is wrapped with `invokeWithLayer(initConnection(...))`, and its
  `requestContext.willInitializeApi = true` (`:713, 746`).
- Stored on the first **successful** (non-error, parsed) response of a request with `willInitializeApi`:
  RMS writes the *current* `_apiEnvironment.apiInitializationHash` (not the one that was sent) into the auth
  info (`:837-847`). Error responses never store it, so wrapping continues until a success.
- Cleared/invalidated by:
  - `400 CONNECTION_NOT_INITED`: attribute removed inside `performBatchUpdates`, request restarted
    immediately with no delay (`:961-972`).
  - Unparseable response (`responseParser` returned nil or result unwrap failed): attribute set to `""`
    (`:812-824`), plus the 500 handling below.
  - A new auth key (temp key rotation, re-generated key, CDN key) naturally has no attribute.
- Env change: `MTProto contextApiEnvironmentUpdated:` (`MTProto.m:2785-2812`) forwards to
  `mtProtoApiEnvironmentUpdated:` (`:405-421`). If the new hash differs from RMS's previous env hash, RMS
  enqueues a no-op request (`serialization.requestNoop` = `help.test`, `TC/State/Serialization.swift:326-337`)
  with an empty completion, so the new parameters reach the server even if no API traffic follows. MTProto
  additionally resets the transport when the SOCKS/MTProxy settings or `langPackCode` changed
  (`MTProto.m:2794-2811`).
- `new_session_created` / session reset do **not** re-trigger initConnection (state is per key).
- TelegramCore detail: `systemCode` arrives through `deliverOn(queue)` onto the queue that is currently
  building the network, so the first environment always has `systemCode == nil` and the real params follow
  as an env update (`TC/Network/Network.swift:490-504, 674-700`). Expect one extra `help.test` (or the
  first real requests) carrying initConnection twice per key on cold start.

### 4.6 Dependencies (`invokeAfterMsg`)

- Static: if `request.shouldDependOnRequest` is set, scan `_requests` **in reverse** (newest first), skipping
  itself, and take the **first** `other` with `shouldDependOnRequest(other) == true` (`:485-519`):
  - `other.requestContext != nil` → wrap with `invokeAfterMsg(other.requestContext.messageId)`;
  - else → record `other.internalId` as an unresolved dependency.
- Dynamic: an unresolved dependency installs `outgoingMessage.dynamicDecorator` (`:641-665`). MTProto calls
  it while assigning message ids (`MTProto.m:1102-1106`); if the dependency was prepared earlier **in the
  same transaction** it prepends `invokeAfterMsg(prepared.messageId)` outside all other wrappers; otherwise
  the request is sent without any dependency.
- TelegramCore's only predicate (`PendingMessageRequestDependencyTag`): same peer and namespace and
  `self.id > other.id` (`TC/State/PendingMessageManager.swift:198-203`), i.e. strict send order per chat.
- `400 MSG_WAIT_TIMEOUT` (`:883-904`): set `errorContext.waitingForRequestToComplete` to the **first**
  request in forward order matching the predicate (note: forward scan here, reverse scan in 4.6 static),
  restart with no delay. The request then waits until that request leaves `_requests`; the field is never
  cleared, only re-evaluated. `500 MSG_WAIT_FAILED` is listed in the same condition but is **unreachable**:
  the preceding `500/-500` branch catches every code 500 first (`:873`).

### 4.7 Transaction callbacks and message-id lifecycle

`MTMessageTransaction` (`h/MTMessageTransaction.h`) carries three blocks; RMS uses them as follows:

- `prepared(messageInternalIdToPreparedMessage)` (`:697-718`, called at `MTProto.m:1138-1143` even when the
  transaction is about to be abandoned): for each request whose `transactionResetStateVersion` is unchanged
  since the transaction was built, set `requestContext = {messageId, seqNo, transactionId: nil,
  quickAckId: 0, waitingForMessageId: true, willInitializeApi, sentTimestamp: now}`.
- `completion(messageInternalIdToTransactionId, ..., messageInternalIdToQuickAckId)` (`:726-761`): may be
  called several times (once per transport payload, `MTProto.m:1301-1352`) and with all-nil dictionaries when
  the transaction is abandoned (monotonicity violation, empty salt set, transport refused,
  `MTProto.m:1145-1166, 1336-1384`). Every request of the transaction gets `waitingForMessageId = false`;
  requests whose message got a transaction id (and unchanged reset version) get a fresh context with
  `transactionId` and `quickAckId`.
- `failed()`: implemented (`:719-725`) but **never invoked** by MTProto (no call site in Sources).
- Abandoned transaction with salt set empty: the request keeps the prepared `messageId` and is resent with
  that same id after the time sync (4.3 rule 3). If the id is now outside the server window the server
  answers `bad_msg_notification` 16/17 → resend with a new id (4.12).
- If the transport object dies before writing, `MTTcpTransport` never calls the payload completion
  (`MTTcpTransport.m:661-664`), leaving `waitingForMessageId = true` until a session change or
  `allTransactionsMayHaveFailed` clears the context.

### 4.8 Response matching and parsing

`mtProto:receivedMessage:authInfoSelector:networkType:` (`:767-1090`) handles only `MTRpcResultMessage`
(`rpc_result#f35c6d01 req_msg_id:long result:Object`, parsed with "rest of buffer" as result,
`MTInternalMessageParser.m:201-210`):

1. `resultData = unwrapMessage(result)`: if it starts with `gzip_packed#3072cfa1`, inflate with a
   32 MiB ceiling (`MTMaxUnpackedMessageLength`), nil on truncation/failure (`MTInternalMessageParser.m:669-686`).
2. `maybeInternal = parseMessage(resultData)`; recognised kinds: `rpc_error#2144ca19 code:int text:string`
   → `MTRpcError`; `rpc_answer_unknown#5e2ad36e`, `rpc_answer_dropped_running#cd78e586`,
   `rpc_answer_dropped#a43ad8b7 msg_id seq_no bytes` → `MTDropRpcResultMessage` (`MTInternalMessageParser.m:211-245`).
3. A drop result is matched only against `_dropReponseContexts` and then ignored (`:778-790`).
4. Otherwise find the request whose `requestContext.messageId == req_msg_id` (`:796-797`). No match → log
   "didn't match any request" and drop (`:1074-1078`); the message is still acked by MTProto.
5. If not an `rpc_error`: `rpcResult = request.responseParser(resultData)`. A nil result (parser failure or
   gzip failure) becomes the synthetic error `500 TL_PARSING_ERROR`, and the stored
   `apiInitializationHash` is set to `""` (`:809-825`). Because it is code 500 it then goes through the 500
   retry path (4.10).
6. TL type verification of the boxed result against the call's return type is **not** done in MtProtoKit;
   TelegramCore surfaces `500 TL_VERIFICATION_ERROR` itself when the parsed object is not the expected type
   (`TC/Network/Network.swift:1202, 1262`).
7. `MTRequestResponseInfo`: `networkType` from the transport (0 = Wi-Fi/other, 1 = WWAN; see 8.6 for the
   GCDAsyncSocket bug that makes it always 0), `timestamp` = outer message id / 2^32 (`MTProto.m:2340`),
   `duration` = wall-clock now − `sentTimestamp` (`:1057-1061`).

### 4.9 Error classification: handled vs surfaced

Evaluated in this order (`:849-1045`); "restart" means `requestContext = nil`, request kept, resent later
with a **new** message id; otherwise the request is removed and `completed(nil, info, error)` is called.

| Condition | Action | Surfaced to caller? |
|---|---|---|
| intercepted in MTProto: `401 AUTH_KEY_PERM_EMPTY` (exact text) in any `rpc_result` of a decrypted packet | `handleMissingKey` + transport reset; **the whole packet is discarded**, including other messages in it (`MTProto.m:2027-2043`) | no; RMS never sees it, the request is resent after the reset |
| `401` and text contains `SESSION_PASSWORD_NEEDED` | unless `passthroughPasswordEntryError`, set `context.passwordInputRequired(dc) = true` (`:851-855`) | yes |
| `401` any other text | call delegate `requestMessageServiceAuthorizationRequired:` (`:857-861`); if `mtProto.requiredAuthToken != nil` and text contains `SESSION_REVOKED` or `AUTH_KEY_UNREGISTERED` → `waitingForTokenExport = true`, restart (`:863-871`) | yes, except the token-wait case |
| `500` or `-500` (any text, including `TL_PARSING_ERROR`, `INTERDC_x_CALL_ERROR`, `MSG_WAIT_FAILED`) | `internalServerErrorCount++`; if `shouldContinueExecutionWithErrorContext` is **non-nil and returns true** → restart no earlier than now + 2.0 s (`:873-881`) | yes if the gate is nil or returns false |
| `400 MSG_WAIT_TIMEOUT` | dependency wait, restart immediately (4.6) | no |
| `420` (text not containing `FROZEN_METHOD_INVALID`) **or** any code whose text contains `FLOOD_WAIT_` or `FLOOD_PREMIUM_WAIT_` | parse integer after the marker with `NSScanner scanInt`; on success set `floodWaitSeconds`/`floodWaitErrorText`; restart at now + X s if the gate is **nil** or returns true (`:905-960`) | yes if the integer does not parse (e.g. `420 SLOWMODE_WAIT_X`, `2FA_CONFIRM_WAIT_X`) or the gate returns false |
| `400` text contains `CONNECTION_NOT_INITED` | remove stored init hash, restart immediately (`:961-972`) | no |
| `403` text contains `APNS_VERIFY_CHECK_` | nonce = text after the prefix; start `context.performExternalRequestVerificationWithNonce`; on first value set `secret`, `isResolved`, request a transaction; restart (parked until resolved) (`:973-1000`) | no |
| `403` text contains `RECAPTCHA_CHECK_` with `<method>__<siteKey>` | start `performExternalRecaptchaRequestVerificationWithMethod:siteKey:`; park until token; restart (`:1001-1039`) | no if the `__` separator is found, otherwise yes |
| `406` any text | call `didReceiveSoftAuthResetError` block (`:1040-1044`) | **yes** (the block is a side notification) |
| everything else, incl. `303 *_MIGRATE_X` (`PHONE_`, `USER_`, `NETWORK_`, `FILE_`, `STATS_`), `AUTH_KEY_DUPLICATED`, `USER_DEACTIVATED`, `CONNECTION_LAYER_INVALID`, `FROZEN_METHOD_INVALID`, `400 *` | none | yes |

Notes:
- Matching uses `rangeOfString:` (substring) for most texts, `isEqualToString:` only for the MSG_WAIT pair.
- Asymmetric defaults: with `shouldContinueExecutionWithErrorContext == nil`, 500s are **not** retried but
  flood waits **are** waited out automatically.
- TelegramCore's gate returns true unless (`floodWaitSeconds > 0 && !automaticFloodWait`) or (Download
  variants) `internalServerErrorCount > 0 && failOnServerErrors`; it also calls `onFloodWaitError(text)`
  whenever `floodWaitSeconds > 0`, which stays set after the first flood wait, so a later 500 re-reports
  the old flood text (`TC/Network/Network.swift:1168-1179`, `TC/Network/Download.swift:322-334, 374-389, 430-445`).
  Hence a TelegramCore main request retries 500s forever every 2 s.
- `MTDatacenterTransferAuthAction` gives its export/import requests a gate that always returns true
  (`MTDatacenterTransferAuthAction.m:30-37`) so `500 INTERDC_*` is retried (commit 1c68bb83d2).
- Zero-or-negative flood values: `FLOOD_WAIT_0` restarts immediately; there is no cap on X.
- APNS/reCAPTCHA data stays attached after resolution, so every later retry of the same request keeps the
  `invokeWithApnsSecret`/`invokeWithReCaptcha` wrapper. A second `APNS_VERIFY_CHECK_` replaces the pending
  data without disposing the first signal (`:984`). TelegramCore's verifiers time out after 15 s with the
  literal values `"APNS_PUSH_TIMEOUT"` / `"RECAPTCHA_TIMEOUT"` (`TC/Network/Network.swift:593-622`); on macOS
  the APNS stream is `.single([:])`, so it always times out.

### 4.10 Delayed retries: the service timer

`updateRequestsTimer` (`:239-310`), run after every response and removal: for requests with an
`errorContext` and no `requestContext`, if `minimalExecuteTime > now + DBL_EPSILON` the earliest such
deadline arms one non-repeating `MTTimer` (`_requestsServiceTimer`, reset rather than recreated); otherwise
`minimalExecuteTime` is zeroed and a transaction is requested. A request whose `waitingForRequestToComplete`
target has left `_requests` also requests a transaction. The timer event invalidates itself and requests a
transaction (`:312-322`). Deadlines use `mach_absolute_time`, so a flood wait does not elapse while the
machine sleeps.

### 4.11 Request timeout timer (`needsTimeoutTimer`)

- Set by TelegramCore only on `Download` worker requests when `useRequestTimeoutTimers`
  (`TC/Network/Download.swift:216, 270, 320, 372, 428`). `useRequestTimeoutTimers` is true unless the app
  config contains `ios_killswitch_disable_request_timeout` (`TC/Account/Account.swift:331-336`); it is false
  for two other account paths (`TC/Account/Account.swift:243, 1809`).
- `updateRequestsTimeoutTimerWithReset:` (`:324-383`): needed iff some `needsTimeoutTimer` request has no
  `errorContext`, or has a vanished dependency, or is not in flight and past its `minimalExecuteTime`. Then
  ensure a single **5.0 s** non-repeating timer exists (`:370`); with `reset` the existing timer is first
  invalidated. When not needed the timer is cancelled.
- `mtProtoTransportActivityUpdated:` (any received bytes on the current connection,
  `MTTcpTransport.m:554-565` → `MTProto.m:1893-1905`) calls it with `reset: true`; responses and removals call
  it with `reset: false`.
- On fire (`:385-391`): `[mtProto requestSecureTransportReset]` (closes and reopens the transport,
  `MTProto.m:671-681`) and `requestTransportTransaction`. In-flight requests are then resent via
  `transactionsMayHaveFailed` (4.12).
- The fired timer object is not cleared, so it does not re-arm until the next `reset: true` (new activity).
  Net semantics: "5 s with no inbound bytes on this connection while a timed request is pending ⇒ reconnect
  once".

### 4.12 Resend triggers coming from MTProto

| MTProto event (service callback) | RMS reaction |
|---|---|
| `msgs_ack` (`messageDeliveryConfirmed:`) (`MTProto.m:2490-2500`) | `delivered = true` for the first matching context (`:1110-1126`); delivered requests are no longer resent by the transaction loop |
| any `bad_msg_notification`/`bad_server_salt` for msg X (`messageDeliveryFailed:` for X and for every message MTProto recorded inside container X) (`MTProto.m:2410-2488`) | matching request: `requestContext = nil`, request transaction; matching drop context: id reset (`:1128-1157`) |
| transport closed / connection id failed (`transactionsMayHaveFailed:`) (`MTTcpTransport.m:420-453, 216-226`; parse/decrypt failures `MTProto.m:1998, 2056, 2080`) | every request whose `transactionId` is in the list, **delivered or not**: `requestContext = nil`, `transactionResetStateVersion += 1`, transaction requested (`:1159-1175`) |
| transport replaced (`mtProtoAllTransactionsMayHaveFailed:` from `setTransport:`, `MTProto.m:284-299`) | every request with a context: same as above (`:1177-1193`) |
| local session reset (`mtProtoDidChangeSession:` from `resetSessionInfo:`, `MTProto.m:363-391`) | all contexts nil, drop contexts cleared, transaction requested (`:1249-1260`) |
| `new_session_created first_msg_id` (`mtProtoServerDidChangeSession:`) (`MTProto.m:2546-2557`) | requests with `messageId < first_msg_id` and not among MTProto's "message ids in containers after first_msg_id" lose their context (`:1262-1277`) |
| `msg_detailed_info` / `msg_new_detailed_info` (`shouldRequestMessageWithId:`) (`MTProto.m:2502-2545`) | if a request has `messageId == req_msg_id`: store `responseMessageId = answer_msg_id` and return true (always, even when the stored transaction id differs: "but today it will", `:1195-1216`); MTProto then sends `msg_resend_req` |
| resend request failed (`messageResendRequestFailed:`) | requests with `responseMessageId == id` lose their context (`:1218-1233`) |
| auth token arrived (`mtProtoAuthTokenUpdated:`) (`MTProto.m:2697-2721`) | clear `waitingForTokenExport`, request transaction (`:1279-1293`) |

Consequence: MtProtoKit is **at-least-once with a new msg_id on every reconnect**. A request already
received (even acked) by the server is re-executed after any connection loss; the late answer to the old
msg_id is dropped as "didn't match" (4.8 step 4). Correctness relies on server-side idempotency
(`random_id`, etc.).

### 4.13 Cancellation and `rpc_drop_answer`

`removeRequestByInternalId:askForReconnectionOnDrop:` (`:146-205`), TelegramCore's disposable path:

- Removes the first request with an equal `internalId` and clears its context.
- If it had a context (prepared or in flight): if `expectedResponseSize >= 512 * 1024` or
  `askForReconnectionOnDrop` (never passed true by TelegramCore) → `[mtProto resetSessionInfo:true]`
  (new random session id + transport reset, only if `canAskForTransactions`, `MTProto.m:363-391`). This is
  how a cancelled large `upload.getFile` stops the server from streaming it; every other in-flight request
  of that MTProto is resent in the new session.
- `rpc_drop_answer#58e4a740 req_msg_id:long` is **never sent**: the line that would create an
  `MTDropResponseContext` is commented out (`:163`), so `_dropReponseContexts` is always empty and the
  drop-answer code in the transaction builder (`:672-689`, `requiresConfirmation = false`) and response
  handler (`:778-790`) is dead.
- No `completed` call on cancellation. If `_requests` becomes empty, delegate
  `requestMessageServiceDidCompleteAllRequests:` (not implemented by TelegramCore).
- Updates both timers.

### 4.14 Quick ack, delivery and progress callbacks

- Quick ack (`mtProto:receivedQuickAck:` `:1092-1104`): fires `acknowledgementReceived` for every request
  whose context has a non-nil `transactionId` and `quickAckId` equal to the token. All requests sent in the
  same transport payload share one token (`MTProto.m:1301-1323`). The `transactionId != nil` guard exists
  because 0 is also a valid 31-bit token (commit 44a188a19f). TelegramCore's `requestWithAdditionalInfo`
  always sets the block (`TC/Network/Network.swift:1181-1185`), so those calls always request quick-ack;
  plain `request` does not.
- Progress (`mtProto:updateReceiveProgressForToken:` `:1235-1247`): the token is the `req_msg_id` that MTProto
  decrypts out of the first bytes of a large incoming packet (`MTProto.m:1731-1815`); every request whose
  `messageId` equals it gets `progressUpdated(progress, packetLength)`.

### 4.15 Auth tokens and password gating

- `requiredAuthToken` is set by TelegramCore only for non-CDN `Download` workers on a non-master DC: the
  token is `NSNumber(datacenterId)`, `authTokenMasterDatacenterId = master` (`TC/Network/Download.swift:57-62`).
  MTProto then refuses to open a transport until the context's token for that DC equals it and asks the
  context to transfer authorization (`MTProto.m:347-352`); RMS is not involved in that wait.
- A 401 on such a worker: RMS first calls the delegate, which drops the DC token and asks for a new
  transfer (`TC/Network/Download.swift:101-104`); for `SESSION_REVOKED`/`AUTH_KEY_UNREGISTERED` the request
  parks on `waitingForTokenExport` and resumes on `mtProtoAuthTokenUpdated:`; MTProto re-asks for the token
  on failures and on resume (`MTProto.m:2662-2695, 243`).
- A 401 on the main connection (`requiredAuthToken == nil`) is always surfaced, and the delegate
  `requestMessageServiceAuthorizationRequired:` triggers TelegramCore's `loggedOut` → the account is marked
  logged out (`TC/Network/Network.swift:1067-1070`, `TC/Account/Account.swift:1353-1359`). The Rust port must
  emit this callback for **every** non-`SESSION_PASSWORD_NEEDED` 401 on a main connection.
- Password gating: `SESSION_PASSWORD_NEEDED` sets a per-DC flag on the context
  (`MTContext.m:825-859`). Nothing in TelegramCore ever clears it and the RMS listener that would react to a
  clear is dead (4.1). App requests are unaffected (`dependsOnPasswordEntry = false`), but internal requests
  on that DC within the same context (transfer export/import, getConfig discovery) are blocked for the
  context's lifetime.

### 4.16 Contract with TelegramCore (what the port must expose)

| TelegramCore use | Flags it sets | Why |
|---|---|---|
| `Network.request` / `requestWithAdditionalInfo` (main connection) | `dependsOnPasswordEntry = false`; gate (flood-wait opt-out, `onFloodWaitError`); `shouldDependOnRequest` when a dependency tag is given; `acknowledgementReceived` and `progressUpdated` (additional-info variant) | normal API calls (`TC/Network/Network.swift:1154-1290`) |
| `Download.part` / `webFilePart` | `expectedResponseSize = length`, `dependsOnPasswordEntry = false`, `needsTimeoutTimer`, gate `{ true }`; limit rounded so `limit % 4096 == 0 && 1 MiB % limit == 0` | file chunks; cancellation resets the session for ≥ 512 KiB (`TC/Network/Download.swift:196-305`) |
| `Download.request`, `requestWithAdditionalData`, `rawRequest` (multiplexed media/upload workers) | as above plus `failOnServerErrors` | `TC/Network/Download.swift:307-460` |
| `Download.uploadPart` | gate always true after reporting flood text | uploads |
| every `Download` RMS | `forceBackgroundRequests = true` → `invokeWithoutUpdates` | workers must not receive updates (`TC/Network/Download.swift:73`) |
| main RMS | `didReceiveSoftAuthResetError` → `postSmallLogIfNeeded` | diagnostics only (`TC/Account/Account.swift:1360-1362`) |

Not used by TelegramCore: `hasHighPriority`, `passthroughPasswordEntryError`, `decorators`, `requestCount:`,
`askForReconnectionOnDrop:`, `requestMessageServiceDidCompleteAllRequests:`.

### 4.z Constants

| Name | Value | file:line | Meaning |
|---|---|---|---|
| 500 retry delay | 2.0 s (`MAX` with existing deadline) | `MTRequestMessageService.m:880` | earliest re-send after `500`/`-500` when the gate allows |
| flood wait | X s parsed from `FLOOD_WAIT_X` / `FLOOD_PREMIUM_WAIT_X`, uncapped | `:910-958` | earliest re-send |
| request stall timeout | 5.0 s, one-shot, reset by inbound activity | `:370` | triggers `requestSecureTransportReset` |
| large-response cancel threshold | 512 × 1024 B | `:165` | cancel of an in-flight request ≥ this resets the session |
| `invokeWithLayer` | `0xda9b0d0d` | `:437` | |
| `initConnection` | `0xc1cd5ea9` | `:448` | flags bit 0 = proxy, bit 1 = params |
| `inputClientProxy` | `0x75588b3f` | `:460` | |
| `invokeWithoutUpdates` | `0xbf9459b7` | `:477` | |
| `invokeAfterMsg` | `0xcb9f372d` | `:503, 653` | |
| `invokeWithApnsSecret` | `0x0dae54f8` | `:525` | |
| `invokeWithReCaptcha` | `0xadbb0f94` | `:538` | |
| `rpc_drop_answer` | `0x58e4a740` | `:681` | dead code |
| `rpc_result` | `0xf35c6d01` | `MTInternalMessageParser.m:201` | |
| `rpc_error` | `0x2144ca19` | `MTInternalMessageParser.m:211` | |
| `rpc_answer_unknown` / `_dropped_running` / `_dropped` | `0x5e2ad36e` / `0xcd78e586` / `0xa43ad8b7` | `MTInternalMessageParser.m:223-245` | |
| `gzip_packed` | `0x3072cfa1`, inflate cap 32 MiB | `MTInternalMessageParser.m:678-685` | |
| noop for re-init | `help.test` | `TC/State/Serialization.swift:326-337` | sent when the env hash changes |
| API layer | 230 | `TC/State/Serialization.swift:262-264` | `invokeWithLayer.layer` |
| synthetic errors | `500 TL_PARSING_ERROR` (RMS), `500 TL_VERIFICATION_ERROR` (TelegramCore) | `:814`, `TC/Network/Network.swift:1202` | |
| verification timeouts | 15 s → `"APNS_PUSH_TIMEOUT"` / `"RECAPTCHA_TIMEOUT"` | `TC/Network/Network.swift:601, 617` | |
| worker idle teardown (TelegramCore) | 20 min; ≤ 4 workers/target, ≤ 3 requests/worker | `TC/Network/MultiplexedRequestManager.swift:218-219, 345` | explains one RMS per worker and the churn |

## 5. Auth key generation and temp-key binding

Files: `MTDatacenterAuthMessageService.m` (the DH handshake state machine), `MTDatacenterAuthAction.m` (one key-creation job: owns the auth MTProto and the bind MTProto), `MTBindKeyMessageService.m` (auth.bindTempAuthKey), `MTProto.m` (crypto helpers, explicit-key mode, salt/time fix after the key exists), `MTContext.m` (bookkeeping, retry backoff; covered in §2), `MTEncryption.m` (DH checks, factorisation, RSA fingerprint), `MTInternalMessageParser.m` (handshake TL parsing), `MTDatacenterAuthInfo.m` (what is stored).

### 5.1 Who starts a handshake, and on which connection

- A key is requested per `(datacenterId, selector)` through `-[MTContext authInfoForDatacenterWithIdRequired:isCdn:selector:allowUnboundEphemeralKeys:]` (`MTContext.m:1557`). Selectors: `Persistent=0`, `EphemeralMain=1`, `EphemeralMedia=2` (`h/MTDatacenterAuthInfo.h:14-18`).
- At most one `MTDatacenterAuthAction` exists per key, and none is created while a retry timer for that key is pending (`MTContext.m:1563`).
- An ephemeral action whose persistent key is missing (and `allowUnboundEphemeralKeys == false`) is created and stored but **not executed**; the persistent key is requested instead (`MTContext.m:1577-1585`). When a persistent key for that DC first appears, every stored non-persistent action of that DC is executed (`MTContext.m:813-820`).
- `skipBind` passed to the action is the caller's `allowUnboundEphemeralKeys` (`MTContext.m:1566`). Only the backup-address config fetch sets `allowUnboundEphemeralKeys = true` (`MTBackupAddressSignals.m:251,266`); `MTDiscoverConnectionSignals.m:358` creates an `EphemeralMain` action with `skipBind:false`.
- TelegramCore always creates the context with `useTempAuthKeys = true` (`TelegramCore/Sources/Network/Network.swift:507`); main connections set `mtProto.useTempAuthKeys = context.useTempAuthKeys` (`Network.swift:634`), downloads set it to `useTempAuthKeys && !isCdn` (`Download.swift:70`). CDN connections therefore always use a persistent key; everything else uses temp keys bound to the persistent key.
- Selector choice per connection (`MTProto.m:908-922`): CDN -> Persistent; `useTempAuthKeys` -> `EphemeralMedia` if `scheme.address.preferForMedia` else `EphemeralMain`; otherwise Persistent. With `useExplicitAuthKey` set (bind connection) the selector is chosen by `scheme.media` instead (`MTProto.m:894`).
- `-[MTDatacenterAuthAction execute:datacenterId:]` (`MTDatacenterAuthAction.m:59-102`):
  - DC id 0 or nil context -> `fail` immediately.
  - Key already present in context -> `complete` immediately (no network).
  - Otherwise builds a dedicated `MTProto` (`requiredAuthToken:nil`, `usageCalculationInfo:nil`), `cdn = isCdn`, `useUnauthorizedMode = true`; for `EphemeralMain`: `tempAuth = true, media = false`; for `EphemeralMedia`: `tempAuth = true, media = true, enforceMedia = true` (so the temp media key is created over a media address); Persistent: `tempAuth = false`. Adds one `MTDatacenterAuthMessageService` and calls `resume`.
- In unauthorized mode MTProto sends each message as a plain frame `auth_key_id=0 ‖ msg_id ‖ length ‖ body` (no container, `MTProto.m:1281-1291, 1494-1517`). With a dd/ee MTProxy secret (`extendedPadding`, `MTProto.m:985-996`), `arc4random_uniform(60)*4` = 0..236 random bytes are appended after the body and are **not** counted in the length field (`MTProto.m:1503-1512`).
- Message ids for handshake messages: the service passes `_currentStageMessageId`/`_currentStageMessageSeqNo`; 0 means "MTProto generates one" (`MTProto.m:1089-1098`). After a send, the prepared id is remembered (`MTDatacenterAuthMessageService.m:239-245` etc.), so a resend after a transport failure **reuses the same msg_id and seqno**. A stage change or `reset` sets them back to 0.

### 5.2 Handshake stages (`MTDatacenterAuthMessageService`)

Stage enum (`MTDatacenterAuthMessageService.m:94-100`): `WaitingForPublicKeys=0`, `PQ=1`, `ReqDH=2`, `KeyVerification=3`, `Done=4`. State: `_nonce`(16), `_serverNonce`(16), `_newNonce`(32), `_dhP`, `_dhQ`, `_dhPublicKeyFingerprint`, `_dhEncryptedData`, `_authKey`, `_encryptedClientData`, `_publicKeys`.

`reset:` (`MTDatacenterAuthMessageService.m:154-187`) clears all of the above, selects keys (5.3), sets stage `PQ` (or `WaitingForPublicKeys` for a CDN with no known keys, then calls `publicKeysForDatacenterWithIdRequired:`), then calls `[mtProto requestSecureTransportReset]` (closes and reconnects the transport, `MTProto.m:671-681`) and `[mtProto requestTransportTransaction]`. `mtProtoDidAddService:` calls `reset:` (`:189-192`), so every handshake starts with a transport reset.

The service builds at most one transaction at a time (`_currentStageTransactionId == nil`, `:216`). Outgoing messages per stage:

| Stage | TL sent | Constructor | Body | Ref |
|---|---|---|---|---|
| PQ | `req_pq_multi nonce:int128` | `0xbe7e8ef1` | nonce (16 random bytes, generated once per `reset`) | `:224-246` |
| ReqDH | `req_DH_params nonce server_nonce p:string q:string public_key_fingerprint:long encrypted_data:string` | `0xd712e4be` | | `:248-277` |
| KeyVerification | `set_client_DH_params nonce server_nonce encrypted_data:string` | `0xf5045f1f` | | `:278-297` |
| WaitingForPublicKeys / Done | nothing | | | `:220-221, 298` |

DEBUG builds only: each time a ReqDH transaction is built, `arc4random_uniform(100) < 50` triggers `[mtProto simulateDisconnection]` (`:250-254`). Do not port.

#### 5.2.1 resPQ (`resPQ#05162463`)

Parsed at `MTInternalMessageParser.m:43-76`: nonce(16), server_nonce(16), pq (TL bytes), vector constructor word (read, **not validated**), count, `count` x int64 fingerprints (stored as signed NSNumber).

Handling (`MTDatacenterAuthMessageService.m:415-540`), only in stage `PQ`:
1. `nonce` mismatch -> message ignored silently (no reset).
2. Key selection (5.3). No key -> `reset:`.
3. `pq` bytes are folded big-endian into a `uint64_t` (`:438-443`; more than 8 bytes silently overflow).
4. `MTFactorize(pq, &p, &q)` (5.4); failure -> `reset:`.
5. `_serverNonce = resPQ.server_nonce`; p and q encoded as minimal big-endian byte strings (at least 1 byte) (`:456-472`).
6. `_dhPublicKeyFingerprint` = fingerprint of the chosen key; `_newNonce` = 32 bytes `SecRandomCopyBytes` (status ignored, `:476-478`).
7. Inner data (note: the code comment names the `_dc` variants but the **legacy constructors without `dc` are sent**):
   - temp key (`tempAuth`): `p_q_inner_data_temp#3c6a84d4 pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 expires_in:int` with `expires_in = context.tempKeyExpiration` (`:485-505`).
   - persistent / CDN: `p_q_inner_data#83c95aec pq p q nonce server_nonce new_nonce` (`:507-523`).
8. `encrypted_data = RSA_PAD(inner, key)` (5.5). If it returns nil: stage stays `PQ`, stage msg id/seqno/transaction cleared, `requestTransportTransaction` -> **req_pq_multi is re-sent with the same nonce, no transport reset, no delay** (`:525-530`). Otherwise stage `ReqDH` (`:531-537`).

#### 5.2.2 server_DH_params (`server_DH_params_ok#d0e8075c` / `server_DH_params_fail#79cb045d`)

Only in stage `ReqDH`; both nonce and server_nonce must match, otherwise the message is ignored (`:545`).
- `_fail`: logged and `reset:` (its `new_nonce_hash` is not checked) (`:743-749`).
- `_ok` (`:547-742`):
  1. `tmp_aes_key = SHA1(new_nonce‖server_nonce) ‖ SHA1(server_nonce‖new_nonce)[0..12]`; `tmp_aes_iv = SHA1(server_nonce‖new_nonce)[12..20] ‖ SHA1(new_nonce‖new_nonce) ‖ new_nonce[0..4]` (`:549-576`).
  2. `answer_with_hash = AES-256-IGE-decrypt(encrypted_answer)`; nil (length not a multiple of 16, CommonCrypto failure) or shorter than 20 bytes -> `reset:` (`:578-586`).
  3. Hash check: `answer = answer_with_hash[20..]`; up to 16 tries comparing `SHA1(answer)` with the first 20 bytes, dropping one trailing byte after each failed try (i.e. accepts 0..15 padding bytes) (`:587-611`). No match -> `reset:`.
  4. Parse as `server_DH_inner_data#b5890dba nonce server_nonce g:int dh_prime:string g_a:string server_time:int` (`MTInternalMessageParser.m:114-143`); wrong type -> `reset:`; nonce / server_nonce mismatch -> `reset:` (`:613-643`).
  5. Checks, each failure -> `reset:` (`:645-686`), in this order:
     - `g >= 0 && MTCheckIsSafeG(g)` (g in 2..7);
     - `MTCheckIsSafeGAOrB(g_a, dh_prime)`: `1 < g_a < p-1` and `2^(2048-64) < g_a < p - 2^(2048-64)`;
     - `MTCheckMod(dh_prime, g, keychain)` (residue condition per g, cached);
     - `MTCheckIsSafePrime(dh_prime, keychain)` (cached; see 7.6).
  6. `b` = 256 bytes `SecRandomCopyBytes` (status ignored, `:688-690`); `g` encoded as 4-byte big-endian; `g_b = g^b mod p`; `auth_key = g_a^b mod p` (`:692-698`). Both come from `MTExp`, which returns the **minimal** big-endian encoding (no left padding to 256 bytes; see §10 M6). `g_b` is **not** range-checked.
  7. `auth_key_id = SHA1(auth_key)[12..20]` read as little-endian int64 (`:700-703`).
  8. `server_salt = new_nonce[0..8] XOR server_nonce[0..8]` is computed (`:704-711`) but **never used** (see 5.8).
  9. `validUntilTimestamp = (int32)now_local + tempKeyExpiration` (local clock, not server time) (`:713`); `_authKey = MTDatacenterAuthKey(authKey, authKeyId, validUntil, notBound: tempAuth)` (`:714`).
  10. `client_DH_inner_data#6643b654 nonce server_nonce retry_id:long=0 g_b:string` (retry_id is always 0) (`:716-723`).
  11. `data_with_hash = SHA1(inner) ‖ inner ‖ random bytes (arc4random_buf, one at a time) up to a multiple of 16` (0..15 bytes) (`:725-733`); `encrypted_data = AES-256-IGE(data_with_hash, tmp_aes_key, tmp_aes_iv)` (`:735`; a nil result is not checked and would serialize as an empty TL string).
  12. Stage `KeyVerification` (`:737-741`).

#### 5.2.3 dh_gen_* (`dh_gen_ok#3bcbf734` / `dh_gen_retry#46dc1fb9` / `dh_gen_fail#a69dae02`)

Only in stage `KeyVerification`, both nonces must match (else ignored) (`:752-756`). `auth_key_aux_hash = SHA1(auth_key)[0..8]`; `new_nonce_hashN = SHA1(new_nonce ‖ byte(N) ‖ auth_key_aux_hash)[4..20]` (the last 16 of 20 bytes) for N = 1, 2, 3 (`:758-783`).
- `ok` with matching hash1 -> stage `Done`, delegate `authMessageServiceCompletedWithAuthKey:_authKey timestamp:message.messageId` (the **server msg_id of the dh_gen_ok frame**) (`:785-804`). Mismatch -> `reset:`.
- `retry` -> `reset:` whether or not hash2 matches (`:806-822`). The spec's "resend set_client_DH_params with retry_id = auth_key_aux_hash" is **not implemented**; a full new handshake is started instead.
- `fail` -> `reset:` whether or not hash3 matches (`:823-839`).
- any other subtype -> `reset:` (`:840-846`).

#### 5.2.4 Other inputs

- Any 4-byte transport error (frame length 4..19, e.g. -404, -429, -444) reaches `mtProto:protocolErrorReceived:` -> `reset:` (`:851-854`; dispatch in `MTProto.m:1952-1972`).
- `transactionsMayHaveFailed:` containing the current stage's transaction, or `mtProtoAllTransactionsMayHaveFailed:` -> clear only the transaction id and request a transaction: the **same stage message is re-sent with the same msg_id/seqno** (`:856-872`).
- A frame that fails to parse in unauthorized mode -> `transportTransactionsMayHaveFailed` (resend, `MTProto.m:2047-2058`).
- There is no handshake-level timer. A stalled stage is resolved only by the TCP response timeout: `MTMinTcpResponseTimeout + payloadLength / 12288` seconds (`MTTcpConnection.m:677, 1414-1420`; reset to 12 s on every partial read, `:1475`), after which the connection closes and the stage message is resent.

### 5.3 RSA key selection and fingerprints

- Built-in keys (`MTDatacenterAuthMessageService.m:46-78`), one per environment, PEM `BEGIN RSA PUBLIC KEY` (PKCS#1), 2048-bit, e = 65537:
  - production (`!context.isTestingEnvironment`): modulus starts `0xe8bb3305...`; fingerprint **`0xd09d1d85de64fd85`** (signed `-3414540481677951611`);
  - test: modulus starts `0xc8c11d63...`; fingerprint **`0xb25898df208d2603`** (signed `-5595554452916591101`).
  (Fingerprints computed from the embedded PEMs with the algorithm below.)
- CDN: keys come from `-[MTContext publicKeysForDatacenterWithId:]` as `NSArray<NSDictionary>`; only `dict[@"key"]` (PEM string) is read (`:143-152, 172-179`). TelegramCore fills them from `help.getCdnConfig` and also stores `dict["fingerprint"] = MTRsaFingerprint(...)` (`TelegramCore/Sources/Network/Network.swift:931`). The context persists them under keychain key `datacenterPublicKeysById`, group `ephemeral` (`MTContext.m:494-497, 1150`). Arrival is pushed via `mtProtoPublicKeysUpdated:` and only acted upon in stage `WaitingForPublicKeys` for the same DC (`:194-208`).
- `MTRsaFingerprint` (`MTEncryption.m:813-844`): parse PEM; `sha1 = SHA1(TLbytes(n) ‖ TLbytes(e))` with n, e minimal big-endian; fingerprint = `sha1[12..20]` interpreted little-endian (`(sha1[19] << 56) | ... | sha1[12]`). Returns 0 when the PEM does not parse.
- `selectPublicKey` (`:80-92`): for each server fingerprint in server order, for each local key in local order, return the first equality (`unsignedLongLongValue == fingerprint`). The fingerprint is recomputed (PEM parse + SHA1) per comparison.
- CDN fallback (`:423-425`): if nothing matched, `mtProto.cdn`, the server sent exactly 1 fingerprint and exactly 1 local key is known, that key is used **without a fingerprint match**.

### 5.4 PQ factorisation (`MTFactorize`, `MTEncryption.m:538-612`)

Pollard rho, Brent cycle detection, with `lrand48()` (unseeded, non-cryptographic; fine here):
- outer loop `for (i = 0; i < 3 || it < 1000; i++)`; `q = ((lrand48() & 15) + 17) % pq`; `x = lrand48() % (pq - 1) + 1`, `y = x`; inner loop `j = 1 .. (1 << (i + 18)) - 1`: `x = (x*x + q) mod pq` using a 64-step double-and-add mulmod without 128-bit arithmetic; `g = binary_gcd(|x - y|, pq)`; break when `g != 1`; when `j` is a power of two, `y = x`.
- success iff `1 < g < pq`; returns `p1 = min(g, pq/g)`, `p2 = max(...)` (p < q, as the protocol requires).
- No guard for `pq < 2`: `% (pq - 1)` and `% pq` divide by zero (traps on x86_64, yields 0 on arm64). pq >= 2^63 can overflow the mulmod (a wrong result only makes the search fail; any `g` found still divides pq).

### 5.5 RSA_PAD (`encryptRSAModernPadding`, `MTDatacenterAuthMessageService.m:314-411`)

1. `data` = serialized inner data; if `len > 144` -> nil (`:317-319`).
2. `data_with_padding` = data padded to **192 bytes** with `SecRandomCopyBytes` (failure -> nil) (`:320-328`).
3. `data_pad_reversed` = byte-reverse of the 192 bytes (`:330`).
4. Loop (unbounded; restarts only for the modulus check):
   - `temp_key` = 32 bytes `SecRandomCopyBytes` (failure -> nil);
   - `data_with_hash = data_pad_reversed ‖ SHA256(temp_key ‖ data_with_padding)` (must be 224 bytes);
   - `aes_encrypted = AES-256-IGE(data_with_hash, key = temp_key, iv = 32 zero bytes)` (nil -> nil);
   - `temp_key_xor = temp_key XOR SHA256(aes_encrypted)`;
   - `key_aes_encrypted = temp_key_xor ‖ aes_encrypted` (must be 256 bytes);
   - parse the PEM, take the modulus n; if `n <= key_aes_encrypted` (big-endian integer compare) -> `continue` with a new temp_key;
   - `encrypted = provider.rsaEncryptWithPublicKey(pem, key_aes_encrypted)` = raw `x^e mod n` (no padding scheme; `OpenSSLEncryptionProvider.m:323-338`); left-pad with zero bytes to 256 (`:398-403`).
5. Every other failure (bignum context, PEM parse, length mismatch) returns nil; see 5.2.1 step 8 for what nil causes.

### 5.6 What is stored after the handshake (`MTDatacenterAuthAction.completeWithAuthKey:timestamp:`)

`timestamp` = server msg_id of `dh_gen_ok`. Every stored key gets a single-salt set: `MTDatacenterSaltInfo(salt: 0, firstValidMessageId: timestamp, lastValidMessageId: timestamp + 29 min * 2^32)` (computed in `double`, so rounded) (`MTDatacenterAuthAction.m:115, 128, 164`).

| Selector | skipBind | Action | Ref |
|---|---|---|---|
| Persistent | n/a | `MTDatacenterAuthInfo(authKey, keyId, validUntil = INT32_MAX, salts, attributes nil)` -> `updateAuthInfoForDatacenterWithId:` -> `complete` | `:114-121` |
| Ephemeral* | true | store with `validUntil = authKey.validUntilTimestamp` (local now + 86400), no bind -> `complete` | `:127-132` |
| Ephemeral* | false, persistent key present | start bind (5.7) | `:134-175` |
| Ephemeral* | false, persistent key **absent** | nothing: the action never completes or fails (§10 H11) | `:135` |
| other | | `assert(false)` | `:181-183` |

Persistence (details in §2): the whole `_datacenterAuthInfoById` dictionary, keyed by `NSNumber((selector << 32) | dcId)` (`MTContext.m:125-128`), is written to keychain key `datacenterAuthInfoById`, group `persistent`, on every change (`MTContext.m:802`). NSCoding keys of `MTDatacenterAuthInfo`: `authKey`, `authKeyId`, `validUntilTimestamp`, `saltSet` (array of `MTDatacenterSaltInfo`: `salt`, `firstValidMessageId`, `lastValidMessageId`), `authKeyAttributes` (`MTDatacenterAuthInfo.m:51-75`; `MTDatacenterSaltInfo.m:17-34`). `MTDatacenterAuthKey` uses `key`, `keyId`, `validUntilTimestamp` (0 decodes as `INT32_MAX`), `notBound` (`MTDatacenterAuthInfo.m:17-31`). Temp keys are persisted too and are purged **only at context load** when `now_local > validUntilTimestamp` (`MTContext.m:476-492`); there is no runtime expiry or proactive rotation. An expired temp key is discovered by the server's -404 (`MTProto.m:1974-1976` -> `handleMissingKey`, §3).

### 5.7 Temp-key binding (`MTBindKeyMessageService`)

Setup (`MTDatacenterAuthAction.m:134-175`):
- A second MTProto `_bindMtProto` on the same DC: `cdn = false`, `useUnauthorizedMode = false`, `useTempAuthKeys = true`, `useExplicitAuthKey = <new temp key>`, `media/enforceMedia` as for the handshake.
- `tempConnectionForReuse = [_authMtProto takeConnectionForReusing]` (`MTProto.m:692-699`): the bind is sent over the **same TCP connection** that carried the handshake (`MTProto.m:332-336`).
- Explicit-key mode: the auth info is synthesised with salt set `{salt 0, first 0, last 0}` (`MTProto.m:903-905`), so `authSaltForMessageId` returns 0, which MTProto treats as "salts missing" (`MTProto.m:1072-1078, 1145-1166`): the first transaction is a time-fix `ping#7abe77ec` encrypted with salt 0 (`MTProto.m:1387-1437`), answered by `bad_server_salt`, whose salt and server msg_id become the salt set and the global time difference (`MTProto.m:2418-2428, 2733-2743`; in explicit mode the salt lives only in `_validAuthInfo`, it is not written to the context). Only then is the bind request sent.

Request (`MTBindKeyMessageService.m:47-100`), built once per transaction attempt:
- `msg_id = sessionInfo.generateClientMessageId(NULL)` (monotonicity result ignored), `seqno = takeSeqNo(true)` (content-related, odd).
- `expires_at = (int32)(context.globalTime + context.tempKeyExpiration)` (server-corrected clock, computed at send time) (`:56`).
- `nonce` = 8 bytes `arc4random_buf` (a separate unused `randomId` is also drawn) (`:58-62`).
- Inner: `bind_auth_key_inner#75a3f765 nonce:long temp_auth_key_id:long perm_auth_key_id:long temp_session_id:long expires_at:int` with `temp_session_id` = the bind MTProto's own session id (`:64-71`).
- `encrypted_message = MTProto._manuallyEncryptedMessage(inner, msg_id, permKey)` (MTProto 1.0, `MTProto.m:1610-1649`):
  - plaintext = `random_int64 (salt slot) ‖ random_int64 (session slot) ‖ msg_id (same as outer) ‖ seqno = 0 ‖ length ‖ inner`, then 0..15 random bytes to a multiple of 16 (`paddedDataV1`, `MTProto.m:1519-1527`);
  - `msg_key = SHA1(plaintext without padding)[4..20]`;
  - key/iv = v1 derivation with x = 0 on the **persistent** key (7.3);
  - output `perm_auth_key_id ‖ msg_key ‖ AES-256-IGE(plaintext)`; AES failure -> nil (the request then carries an empty string).
- Outer: `auth.bindTempAuthKey#cdd42a05 perm_auth_key_id:long nonce:long expires_at:int encrypted_message:bytes` (`:79-83`), sent as an ordinary encrypted message under the **temp** key with the explicit msg_id/seqno.

Response (`:143-171`): on `rpc_result` whose `req_msg_id == _currentMessageId`:
- body parsed with `MTInternalMessageParser` (no gzip unwrap); `rpc_error` -> remembered as `error`;
- success iff the first 4 bytes are `boolTrue#997275b5`; anything else (boolFalse, error, short body) -> failure.
- `_completion(success, error)` is called exactly once per matching result.

Resend rules: `messageDeliveryFailed:` for the current id, `transactionsMayHaveFailed:` containing the transaction, `mtProtoAllTransactionsMayHaveFailed:`, `mtProtoDidChangeSession:`, or `mtProtoServerDidChangeSession:` where the id predates `firstValidMessageId` and is not in the first valid container -> clear state and request a transaction; the next attempt **regenerates msg_id, nonce, expires_at and the inner encryption** (`:102-141`). (`mtProtoDidChangeSession:` is never invoked by MTProto; see §3.)

Completion (`MTDatacenterAuthAction.m:156-173`): the bind MTProto is stopped. Success -> store `MTDatacenterAuthInfo(tempKey, tempKeyId, validUntil = local DH time + 86400, salts {0, [ts, ts+29 min]}, attributes nil)` under the ephemeral selector -> `complete`. Failure -> `bindError = error` -> `fail`.

macOS-maintainer special case (`MTProto.m:2107-2116`; "attempt to fix expired key for mtproto", 92eaeb4c9a 2024-07-05, reverted by the iOS side in 75d6f07a57, re-applied in e5052038d2): on the bind connection (`useExplicitAuthKey != nil`), a transport -404 with `scheme.media` calls `-complete` on every message service that responds to it; `MTBindKeyMessageService.complete` reports **success with no error** (`MTBindKeyMessageService.m:173-175`), so the unbound media temp key is stored as if bound. For a non-media bind connection a -404 only resets the transport and resends (`MTProto.m:1993-1998`).

After binding: the context notifies listeners (`contextDatacenterAuthInfoUpdated:`), waiting MTProtos leave `AwaitingDatacenterAuthorization` (§3). Every new key starts with `authKeyAttributes == nil`, so `MTRequestMessageService` re-wraps the next request in `initConnection` (it compares `apiInitializationHash` stored in `authKeyAttributes`, `MTRequestMessageService.m:559, 840-844`; §4). Because the stored salt is 0, the first connection that uses the key again performs the time-fix ping round trip described above.

### 5.8 Server time and salt from the handshake

- `server_DH_inner_data.server_time` is parsed (`MTInternalMessageParser.m:138-142`) and **ignored**. The handshake does not update `globalTimeDifference`.
- The `dh_gen_ok` server msg_id is used only as the start of the initial salt window.
- The derived first salt (`new_nonce[0..8] XOR server_nonce[0..8]`) is discarded; salt 0 is stored and salt 0 means "missing" to MTProto.
- Consequence (parity-relevant, and a free optimisation for Rust): after every new key, MtProtoKit spends one encrypted round trip (time-fix ping -> `bad_server_salt`, or `bad_msg_notification` 16/17 if the clock is off) to learn both the salt and the time difference, with time difference = `bad_msg.server_msg_id / 2^32 - now_local` (`MTProto.m:2425, 2443`). TDLib uses `server_time` and the derived salt directly.

### 5.9 Retry policy summary

Inside the handshake service there is **no attempt counter and no delay**:

| Event | Reaction | Ref |
|---|---|---|
| resPQ / DH params / dh_gen with wrong nonce(s) | ignore message | `:419, 545, 756` |
| no matching RSA key, factorisation failure, any DH decrypt/hash/parse/nonce/g/g_a/prime check failure, `server_DH_params_fail`, any `dh_gen_*` other than a valid ok, any transport error code | `reset:` = new nonce, transport reset, restart at req_pq_multi | `:427-452, 578-686, 743-749, 785-846, 851-854` |
| RSA_PAD returns nil | re-send req_pq_multi with the same nonce, no transport reset | `:525-530` |
| transport failure / timeout | re-send current stage message with the same msg_id/seqno | `:856-872` |

The only pacing is the transport's reconnect behaviour (§6). The action reports `fail` only for DC 0 / nil context and for bind failures; a handshake that never succeeds keeps the action alive and retrying until `cancel`.

Context level (`MTContext.m:1680-1735`): on action success the failure count for the key is cleared. On failure: if `bindError` is `400 ENCRYPTED_MESSAGE_INVALID` (`MTDatacenterAuthAction.m:40-42`) nothing is scheduled (waiting connections ask again on resume); otherwise `failureCount += 1`, delay `MTRetryDelayForFailureCount = min(60, 2^min(count-1, 6))` = 1, 2, 4, 8, 16, 32, 60, 60 ... s (`MTContext.m:225-230`); when the timer fires, listeners get `contextDatacenterAuthInfoRequestFailed:datacenterId:selector:` and waiting MTProtos call `authInfoForDatacenterWithIdRequired:` again.

### 5.10 Threading

All handshake and bind work runs on the global serial `[MTProto managerQueue]`: message handling, RSA_PAD, two 2048-bit modexps, Pollard rho, and the uncached Miller-Rabin prime test (64 rounds on p and on (p-1)/2). Every MTProto instance shares this queue, so an uncached prime check stalls all connections for its duration. Context bookkeeping runs on `[MTContext contextQueue]`.

### 5.11 Constants

| Name | Value | Ref | Meaning |
|---|---|---|---|
| `req_pq_multi` | `0xbe7e8ef1` | `MTDatacenterAuthMessageService.m:232` | stage PQ request |
| `resPQ` | `0x05162463` | `MTInternalMessageParser.m:43` | |
| `p_q_inner_data` | `0x83c95aec` | `MTDatacenterAuthMessageService.m:508` | persistent/CDN inner data (no `dc`) |
| `p_q_inner_data_temp` | `0x3c6a84d4` | `:487` | temp inner data (no `dc`) |
| `req_DH_params` | `0xd712e4be` | `:257` | |
| `server_DH_params_ok` / `_fail` | `0xd0e8075c` / `0x79cb045d` | `MTInternalMessageParser.m:96, 77` | |
| `server_DH_inner_data` | `0xb5890dba` | `MTInternalMessageParser.m:114` | |
| `client_DH_inner_data` | `0x6643b654` | `:717` | retry_id always 0 |
| `set_client_DH_params` | `0xf5045f1f` | `:281` | |
| `dh_gen_ok` / `_retry` / `_fail` | `0x3bcbf734` / `0x46dc1fb9` / `0xa69dae02` | `MTInternalMessageParser.m:144, 163, 182` | |
| `bind_auth_key_inner` | `0x75a3f765` | `MTBindKeyMessageService.m:66` | |
| `auth.bindTempAuthKey` | `0xcdd42a05` | `MTBindKeyMessageService.m:79` | |
| `boolTrue` | `0x997275b5` | `MTBindKeyMessageService.m:164` | bind success |
| nonce / server_nonce / new_nonce | 16 / 16 / 32 bytes | `:226, 476` | |
| DH secret `b` | 256 bytes | `:688` | |
| RSA_PAD data_with_padding | 192 bytes, inner data max 144 | `:317-323` | |
| RSA_PAD temp_key / iv | 32 bytes random / 32 zero bytes | `:334, 351` | |
| RSA ciphertext | 256 bytes (left zero-padded) | `:400-407` | |
| Answer padding tries | 16 (0..15 bytes) | `:591` | server_DH_inner_data hash search |
| `tempKeyExpiration` | 86400 s (DEBUG override 30 s commented out) | `MTContext.m:269-273` | expires_in and bind expires_at |
| Initial salt | 0, valid 29 min from dh_gen_ok msg_id | `MTDatacenterAuthAction.m:115` | 0 = "missing" |
| Persistent `validUntilTimestamp` | `INT32_MAX` | `MTDatacenterAuthAction.m:115` | never expires |
| Context retry delay | 1, 2, 4, 8, 16, 32 s, then 60 s | `MTContext.m:225-230` | failed key creation / bind |
| Bind error not retried | `400 ENCRYPTED_MESSAGE_INVALID` | `MTDatacenterAuthAction.m:40-42` | |
| Production RSA fingerprint | `0xd09d1d85de64fd85` | `MTDatacenterAuthMessageService.m:62-71` | |
| Test RSA fingerprint | `0xb25898df208d2603` | `:51-60` | |
| TCP response timeout | 12 s + bytes/12288 | `MTTcpConnection.m:677, 1416` | effective per-stage timeout |
| DEBUG simulated disconnect | 50 % per ReqDH send | `:250-254` | debug builds only |

## 6. Transport layer

Scope: `MTTransport` (abstract), `MTTcpTransport`, `MTTcpConnection`, `MTTcpConnectionBehaviour`, `MTTransportScheme`/`MTTransportSchemeStats` (+ the scheme choice in `MTContext`), `MTQuickAck`, `MTTransportTransaction`, `MTNetworkAvailability`, `MTProxySecret`/`MTSocksProxySettings`, `MTDNS`, `MTConnectionProbing`/`MTProxyConnectivity`, the `MTTcpConnectionInterface` hook, and the parts of `GCDAsyncSocket` whose behaviour leaks out. Scheme *discovery* (`MTDiscoverConnectionSignals`, backup addresses) is §2; message encryption is §3/§7; this section only touches them where the transport hands data across.

Conventions: `MTTcpConnection.m:123` = `Sources/`, `h/X.h:45` = `PublicHeaders/MtProtoKit/`.

### 6.1 Object graph, ownership, queues

```
MTProto ──owns──> MTTcpTransport (one per MTProto "transport generation"; recreated by -[MTProto resetTransport])
                   ├─ MTTcpTransportContext (all mutable state, touched only on tcpTransportQueue)
                   │    ├─ MTTcpConnection *connection   (0 or 1 at a time; a new object per dial)
                   │    ├─ MTTcpConnectionBehaviour       (reconnect backoff)
                   │    └─ timers: connectionWatchdog (20 s), actualizationPingResend (3 s), sleepWatchdog (disabled)
                   └─ MTNetworkAvailability (from MTTransport base init; one per transport)
MTTcpConnection ──owns──> id<MTTcpConnectionInterface> _socket
                   (MTGcdAsyncSocketTcpConnectionInterface → GCDAsyncSocket, or an injected
                    interface: Network.framework or the WEB-proxy carrier)
```

| Queue | Name | Who runs there |
|---|---|---|
| `[MTTcpTransport tcpTransportQueue]` | `org.mtproto.tcpTransportQueue` (serial, process-global) `MTTcpTransport.m:74-83` | every `MTTcpTransport` method body, behaviour timers, watchdog/ping timers |
| `[MTTcpConnection tcpQueue]` | `org.mtproto.tcpQueue` (serial, process-global) `MTTcpConnection.m:876-885` | all connection state, socket delegate callbacks (GCDAsyncSocket `delegateQueue`), response-timeout timer |
| `[MTNetworkAvailability networkAvailabilityQueue]` | `org.mtproto.MTNetwotkAvailability` `MTNetworkAvailability.m:110-119` | SCNetworkReachability callback + 5 s poll |
| `[MTProto managerQueue]` | §3 | every `MTTransportDelegate` callback re-dispatches here |
| `MTDNSContext sharedQueue` | unnamed serial `MTDNS.m:78-85` | DNS coalescing; `getaddrinfo` itself runs on the global default queue |
| `[MTContext contextQueue]` | §2 | scheme choice/stats; called **synchronously** from tcpTransportQueue (`MTTcpTransport.m:194` → `MTContext.m:1015-1051`, `synchronous:true`) |

`-[MTQueue dispatchOnQueue:]` runs the block inline when already on that queue (checked via `dispatch_queue_set_specific`), otherwise `dispatch_async` (`MTQueue.m`, `dispatchOnQueue:synchronous:`). Unnamed queues (`MTDNSContext`, `MTProxyConnectivity`'s per-ping queue) never report "current", so they always hop.

All cross-object references are guarded by identity: every `MTTcpConnectionDelegate` callback in the transport first checks `transportContext.connection == connection` and drops stale callbacks (`MTTcpTransport.m:402,425,460,517,531,545,558`); every `MTTransportDelegate` callback in MTProto checks `transport == _transport` (`MTProto.m:730,751,765,792,814,958,1947`). The Rust port must keep this "generation check" on every hop.

### 6.2 `MTTransportDelegate` contract (transport → MTProto)

Declared `h/MTTransport.h:18-37`, all optional. Exact emission points in `MTTcpTransport`:

| Callback | Emitted when | MTProto reaction (for context) |
|---|---|---|
| `transportNetworkAvailabilityChanged:isNetworkAvailable:` | reachability state string changed (§6.16), and on every `updateConnectionState` (`MTTcpTransport.m:149-162`) | forwards to services + `MTProtoDelegate` (`MTProto.m:726-747`) |
| `transportConnectionStateChanged:isConnected:proxySettings:` | `true` in `tcpConnectionOpened` (`:410-411`); `false` in `tcpConnectionClosed` (`:441-442`) and `stop` (`:232-234`); current value in `updateConnectionState` | builds `MTProtoConnectionState{isConnected, proxyAddress=proxySettings.ip, proxyHasConnectionIssues=_probingStatus}` (`MTProto.m:761-786`) |
| `transportConnectionFailed:scheme:` | connection closed **with error** (`:444-448`); 20 s watchdog fired (`:340-342`) | `reportTransportSchemeFailure` unless unauthorized mode (`MTProto.m:749-759`) |
| `transportConnectionContextUpdateStateChanged:isUpdatingConnectionContext:` | `true` when the actualization ping got a msg_id (`:645-650`); `false` on matching pong (`:770-779`), `mtProtoDidChangeSession` (`:731-743`), server new-session that invalidates the ping (`:745-761`), ping delivery failed (`:784-799`); `updateConnectionState` reports `currentActualizationPingMessageId != 0` | "Updating…" UI state |
| `transportConnectionProblemsStatusChanged:scheme:hasConnectionProblems:isProbablyHttp:` | `(true,false)` on the 20 s watchdog (`:343-345`); `(true,true)` every time MTProto reports a decode failure (`connectionIsInvalid`, `:498-510`) — this includes **every** 4..19-byte protocol error (-404, -444, -429) and every decrypt/parse failure. Never emitted with `false` by MTTcpTransport. | failure stat + `invalidateTransportSchemeForDatacenterId` (= start discovery + backup-address discovery after 5 s, or 20 s if `networkSettings.reducedBackupDiscoveryTimeout==false`, 1 s in DEBUG) (`MTProto.m:824-826`, `MTContext.m:1436-1454`); starts proxy probing if a proxy is set and `checkForProxyConnectionIssues` (§6.18) |
| `transportReadyForTransaction:scheme:transportSpecificTransaction:forceConfirmations:transactionReady:` | §6.3 transaction pump | MTProto builds `MTTransportTransaction`s and calls `transactionReady` **exactly once** (possibly with nil) on every path |
| `transportHasIncomingData:scheme:networkType:data:transactionId:requestTransactionAfterProcessing:decodeResult:` | each complete frame body (§6.8) not swallowed as quick-ack/nop; `requestTransactionAfterProcessing` is always `false` from TCP; `transactionId` = `connection.internalId` | protocol error if `4 <= len <= 19` (`MTProto.m:1952`); else decrypt/parse; calls `decodeResult(transactionId, success)` |
| `transportTransactionsMayHaveFailed:transactionIds:` | `@[connection.internalId]` on every connection close (`:450-451`); active ids on `stop` (`:221-226`) | services drop request contexts whose `transactionId` matches → resend |
| `transportReceivedQuickAck:quickAckId:` | quick-ack token decoded (§6.19) | services (`MTProto.m:1714-1729`) |
| `transportDecodeProgressToken:…` / `transportUpdatedDataReceiveProgress:…` | large-frame progress (§6.8) | maps first 128 bytes → `req_msg_id` |
| `transportActivityUpdated:` | every completed or partial socket read (`MTTcpConnection.m:1490-1491,1545-1546` → `MTTcpTransport.m:554-565`) | §3 |

`decodeResult(transactionId, success)` from MTProto back into the transport: `success` → `connectionIsValid:` → if `transactionId` equals the live connection's id, set `connectionIsValid=true` and `behaviour.connectionValidDataReceived` (backoff reset); **always** stop the 20 s watchdog (even if the id is stale) (`MTTcpTransport.m:483-496`). `!success` → `connectionIsInvalid` (`:498-510`), see table.

MTProto→transport (as an `MTMessageService`, added via `addMessageService:`): `mtProtoDidChangeSession`, `mtProtoServerDidChangeSession:firstValidMessageId:otherValidMessageIds:`, `mtProto:receivedMessage:` (pong match), `mtProto:messageDeliveryFailed:` (`MTTcpTransport.m:731-799`). Plus direct calls: `setDelegateNeedsTransaction`, `reset`, `stop`, `updateConnectionState`, `simulateDisconnection`, `activeTransactionIds:`, `setUsageCalculationInfo:`, `needsParityCorrection` (TCP: `true`, `MTTcpTransport.m:144-147`).

Dead surface (no-ops for parity): `simultaneousTransactionsEnabled` (set by MTProto `MTProto.m:1950`, never read), `reportTransportConnectionContextUpdateStates` (set `true` in base init, never read), `-updateSchemes:` (implemented `MTTcpTransport.m:801-818`, **no callers** anywhere in submodules/), sleep watchdog (`MTTcpTransport.m:250-282` body commented out; constant 60 s at `:25`).

### 6.3 `MTTcpTransport` lifecycle and transaction pump

Construction (`MTTcpTransport.m:85-115`): async on tcpTransportQueue: store the scheme list (**frozen for the life of the transport**, §10 H9), create behaviour (`needsReconnection=true`), `isNetworkAvailable=true`, `proxySettings = context.apiEnvironment.socksProxySettings`. MTProto always creates `MTTcpTransport` with `transportSchemesForDatacenterWithId:media:enforceMedia:isProxy:` (`MTProto.m:338,355`). No connection is opened until someone asks for a transaction.

**Connect on demand.** `setDelegateNeedsTransaction` (`:164-184`) coalesces to one pass per queue turn (`willRequestTransactionOnNextQueuePass`, then `dispatch_async` to itself): if `connection == nil` → `behaviour.requestConnection`; else if `connectionConnected` → `_requestTransactionFromDelegate`; else (dialing) do nothing — the open event will ask.

`startIfNeeded` (`:186-205`), reached only through the behaviour delegate (`:567-579`, ignored when `stopped`): if `connection == nil`, `scheme = [context chooseTransportSchemeForConnectionToDatacenterId:schemes:]` (§6.17); if nil, nothing happens and nothing is retried. Otherwise start the 20 s watchdog (only if not already running), create `MTTcpConnection(context, dcId, scheme, interface:nil, usageInfo)`, set delegate, `start`.

**Open** (`tcpConnectionOpened`, `:397-418`): `connectionConnected=true`, `connectionIsValid=false`, `behaviour.connectionOpened` (no-op — backoff is NOT reset on open, `MTTcpConnectionBehaviour.m:42-47`), report connected, reset ping state, `_requestTransactionFromDelegate`.

**Close** (`tcpConnectionClosed:error:`, `:420-453`): clear connection (delegate=nil), `behaviour.connectionClosed` (schedules reconnect, §6.4), reset ping state, report disconnected, `transportConnectionFailed` if `error`, then `transportTransactionsMayHaveFailed(@[connection.internalId])`. Note: `isUpdatingConnectionContext=false` is **not** reported here.

**reset** (`:207-214`): `[connection stop]` only — the transport survives and reconnects through the behaviour (a clean close still increments the backoff counter). This is what `-[MTProto requestSecureTransportReset]` does (`MTProto.m:671-681`).

**stop** (`:216-248`): report `transactionsMayHaveFailed(activeIds)`, `stopped=true`, `connectionConnected=false`, `connectionIsValid=false`, report disconnected, `behaviour.needsReconnection=false`, detach+stop connection, stop watchdog/sleep/ping timers. Irreversible.

**simulateDisconnection** (`:820-832`): fires the watchdog-timeout path for the current scheme (reports failure/problems; does not close).

**Network availability change** (`:715-729`): super forwards to MTProto first; then `isNetworkAvailable = value`; if available → `behaviour.clearBackoff`; **always** `[connection stop]` (any reachability-state change, including "became available" and WWAN/on-demand flag flips, kills the live connection). `isNetworkAvailable` is never used to gate dialing.

**Transaction pump** (`_requestTransactionFromDelegate`, `:581-703`), always on tcpTransportQueue:
1. Lock: if `isWaitingForTransactionToBecomeReady`:
   - if `!didSendActualizationPingAfterConnection` (connection just (re)opened) → unlock;
   - else if `now > transactionLockTime + 1.0 s` → unlock (`:594`);
   - else set `requestAnotherTransactionWhenReady=true` and return.
2. If the connection has a scheme and the delegate implements the selector: lock (`transactionLockTime=now`). If this is the first request since open (`didSendActualizationPingAfterConnection==false`), build the **actualization ping**: `ping#7abe77ec ping_id:long` with `ping_id` from `arc4random_buf`, `requiresConfirmation=false`, wrapped in an `MTMessageTransaction` with `requiresEncryption=true`, passed as `transportSpecificTransaction` with `forceConfirmations=true` (`:621-659`). Its `completion` records the prepared msg_id in `currentActualizationPingMessageId` and reports `isUpdatingConnectionContext=true`.
3. `transactionReady(list)` (hops back to tcpTransportQueue): for each `MTTransportTransaction` with non-empty `payload`: if a connection exists → `[connection sendDatas:@[payload] completion:^(ok){ transaction.completion(ok, connectionIdAtSendTime) } requestQuickAck:needsQuickAck expectDataInResponse:expectsDataInResponse]`; else `completion(false, nil)` immediately. Empty payloads are silently skipped (their completion never fires). Then unlock and, if `requestAnotherTransactionWhenReady`, run the pump again (`:689-698`).

`completion(true)` means "accepted into the socket write queue" (`MTTcpConnection.m:1423-1425`), not "on the wire". Each `MTTransportTransaction` becomes its own `sendDatas` call → its own write (and its own TLS record group, §6.11).

**Actualization ping resend** (`:349-395,455-465`): when any frame is received while `currentActualizationPingMessageId != 0` and no resend timer exists, start a one-shot **3 s** timer; on fire: `didSendActualizationPingAfterConnection=false`, `currentActualizationPingMessageId=0`, pump again (a fresh ping is attached). Nothing starts this timer if no data at all arrives after the ping. Cleared by: matching `MTPongMessage.messageId` (`:763-782`), session change (`:731-743`), server new_session_created when `pingId < firstValidMessageId` and not in `otherValidMessageIds` (`:745-761`), delivery failure (`:784-799`), close/stop (silently).

**Parity correction**: because `needsParityCorrection` is true for TCP, MTProto sets `needsQuickAck=true` on any transaction that contains no message requiring confirmation (`MTProto.m:1134-1135`); `expectsDataInResponse` = any message `requiresConfirmation` (`MTProto.m:1122-1125`).

**Connection watchdog** (`:304-347`): one-shot **20.0 s** timer, started in `startIfNeeded` only when none is running, so it measures time from the first dial attempt (across reconnects) to the first successfully decoded frame. Stopped by `connectionIsValid:` or `stop`. On fire it only *reports* (`transportConnectionFailed` + problems `(true, isProbablyHttp=false)`); it never closes the connection. The next `startIfNeeded` after it fired arms a new one.

### 6.4 `MTTcpConnectionBehaviour` (reconnect backoff)

State: `_backoffCount` (starts 0), `_backoffTimer`, `needsReconnection` (init `true`) (`MTTcpConnectionBehaviour.m:8-28`).

| Event | Rule |
|---|---|
| `requestConnection` | if no backoff timer pending → `timerEvent(error:false)` → delegate → `startIfNeeded` (`:35-40`). A pending timer suppresses on-demand dials. |
| `connectionOpened` | no-op (reset commented out) (`:42-47`) |
| `connectionValidDataReceived` | `_backoffCount = 0`, cancel timer (`:49-54`) |
| `connectionClosed` | if `needsReconnection`: `_backoffCount += 1`; count 1 → reconnect immediately; 2..5 → after **1.0 s**; 6..20 → **4.0 s**; ≥21 → **8.0 s** (`:56-78`) |
| `clearBackoff` | `_backoffCount = 0` (timer untouched) (`:80-83`) |

Testable: a server that accepts and closes repeatedly without ever producing a decodable frame yields dial times t=0, 0+, +1, +1, +1, +1, +4 ×15, then +8 forever (plus connect latency). The count is reset only by a *decoded* frame (MTProto `decodeResult(success)`) or a reachability change to "available".

### 6.5 `MTTcpConnection` setup and proxy-mode resolution

Init (`MTTcpConnection.m:887-959`) derives the mode from the scheme and the **context's current** `apiEnvironment` (not the transport's copy):

1. `scheme.address.secret != nil` → `_mtpIp/_mtpPort = address.ip/port`, `_mtpSecret = [MTProxySecret parseData:address.secret]` (DC-level obfuscation secret).
2. If `apiEnvironment.socksProxySettings != nil`: `_isWebProxy = settings.webProxy`; if `settings.secret != nil` → MTProxy: `_mtpIp/_mtpPort/_mtpSecret` from settings (overrides step 1); else SOCKS5: `_socksIp/_socksPort/_socksUsername/_socksPassword`.
3. `_useIntermediateFormat = (_mtpSecret is Type1 (dd) or Type2 (ee))` (`:933-937`). Otherwise abridged.
4. DC tag (`:941-953`): `tag = dcId`, or `10000 + dcId` when `context.isTestingEnvironment`; negated when `scheme.address.preferForMedia`. Written as int16 LE (§6.7).
5. `apiEnvironment.tcpPayloadPrefix` is copied into `_firstPacketControlByte` when `datacenterAddressOverrides[dcId]` exists (`:909-911`) but **never used** — dead.

`start` (`:996-1185`), on tcpQueue, once (`_socket == nil` guard):
- **Interface choice** (`:1008-1037`): `injected = context.makeTcpConnectionInterface(self, tcpQueue)` if set. `isCarrier = injected responds to and returns true for -isWebProxyCarrier`. If `_isWebProxy`: require a carrier, else `resetDelegate` + `closeAndNotifyWithError:true` (fail closed, no socket fallback). If not web proxy: use `injected` unless it is a carrier; fall back to `MTGcdAsyncSocketTcpConnectionInterface` (GCDAsyncSocket on tcpQueue).
- **Address resolution** (`:1042-1092`): default target = `scheme.address.ip:port`. WEB proxy → no resolution (carrier ignores the address). SOCKS with a hostname (not parseable by `inet_aton` or `inet_pton(AF_INET6)`) → `MTDNS resolveHostnameUniversal` (§6.13), result replaces `_socksIp`. MTProxy hostname → same, connects to the resolved IP (keeps `_mtpIp` as hostname). Numeric → used directly. Direct, no proxy → DC IP.
- **Dial** (`:1126-1180`): `connectToHost:ip onPort:port viaInterface:nil withTimeout:12` — sync failure → `closeAndNotifyWithError:true`. Then, without waiting for TCP connect:
  - no SOCKS, `_mtpSecret` is ee → build and write the fake-TLS ClientHello, read 5 bytes (§6.11);
  - no SOCKS otherwise → `_readyToSendData = true`, flush queue, arm the first frame read (4 bytes for intermediate, 1 byte for abridged);
  - SOCKS → write the SOCKS5 greeting (§6.12).
- `connectionInterfaceDidConnect` (`:2084-2095`): if not SOCKS → `connectionOpened` block + `tcpConnectionOpened` delegate. So for direct/MTProxy the transport sees "open" at TCP connect (for ee: **before** the TLS handshake); for SOCKS "open" fires only after the SOCKS CONNECT reply (`:1660-1668`).
- `connectionInterfaceDidDisconnectWithError:` → `closeAndNotifyWithError:(error != nil)` (`:2097-2111`).

`stop` → `closeAndNotifyWithError:false` if not closed. `closeAndNotifyWithError:` (`:1196-1215`) is idempotent: `_closed=true`, `disconnect`, `resetDelegate`, `_socket=nil`, fire `connectionClosed` block, `tcpConnectionClosed:error:`. It does **not** drain `_pendingDataQueue` (§10 H4) and does not dispose `_resolveDisposable` (only `dealloc` does).

`sendDatas:completion:requestQuickAck:expectDataInResponse:` (`:1443-1457`): empty `datas` → `completion(false)` synchronously; else enqueue an `MTTcpSendData` and flush if `_readyToSendData`. Flush (`sendDataIfNeeded`, `:1217-1441`) pops FIFO; closed → `completion(false)`; no socket → `completion(false)`; else frame (§6.6), obfuscate (§6.7), optionally TLS-wrap (§6.11), `writeData`, maybe arm the response timer (§6.9), `completion(true)`.

### 6.6 Outgoing framing

MtProtoKit always uses the **obfuscated** transport (there is no plain abridged/intermediate mode) and only two tags:

| Mode | Chosen when | Tag at header[56..60] | Per-frame encoding |
|---|---|---|---|
| Abridged | no secret, or plain 16-byte secret (Type0) | `ef ef ef ef` (`:1284`) | `q = len/4`; if `q <= 0x7e`: 1 byte `q` (\|0x80 if quick-ack); else `0x7f` (\|0x80 if quick-ack) + 3 bytes `q` little-endian (`:1248-1263`). Body length is assumed to be a multiple of 4. |
| Padded intermediate | dd (Type1) or ee (Type2) secret | `dd dd dd dd` (`:1282`) | `pad = arc4random_uniform(16)` (0..15) random bytes; int32 LE `len(body)+pad`, bit 31 set if quick-ack; then body, then pad (`:1234-1270`) |

Plain intermediate (`ee ee ee ee`) and full transport are never sent. TDLib uses intermediate (`0xeeeeeeee`) for non-dd secrets; MtProtoKit uses abridged — both are legal, but a Rust port that wants byte parity must use abridged for Type0/direct.

All frames of one `sendDatas` call are concatenated and obfuscated with the connection's outgoing AES-CTR stream (`:1378-1383`), then written in one `writeData` (or split into TLS records).

MTProto-level padding is separate: when the transport secret is dd/ee MTProto uses `extendedPadding` (§3; `MTProto.m:985-996`), and the unencrypted req_pq probes append 0..127 random bytes (`MTDiscoverConnectionSignals.m:50-65`).

### 6.7 Obfuscation init header (first 64 bytes on the stream)

Generated lazily with the first frame ever sent on the connection (`_addedControlHeader`, `MTTcpConnection.m:1274-1377`):

| Bytes | Content (pre-encryption buffer `H`) |
|---|---|
| 0..7 | random (`arc4random_buf`) |
| 8..39 | random → outgoing key material |
| 40..55 | random → outgoing IV |
| 56..59 | protocol tag `efefefef` / `dddddddd` |
| 60..61 | DC tag, int16 little-endian (§6.5 step 4) |
| 62..63 | random |

Key derivation:
- outgoing: `key = H[8..40]`, `iv = H[40..56]`; incoming: `R = reverse(H[0..64])`, `key = R[8..40]`, `iv = R[40..56]` (`:1291-1300`).
- with a proxy secret (`_mtpSecret.secret`, always exactly 16 bytes after parsing; the 17-byte branch at `:1315-1316,1325-1326` is dead): `key = SHA256(key ‖ secret16)` for both directions (`:1310-1330`). Without a secret, raw keys.
- Both directions are AES-256-CTR (`MTAesCtr`, `decrypt:false`), 16-byte big-endian counter in `iv` (`:680-684`). Cipher creation failure → close with error and `completion(false)` (`:1336-1345`).

Wire bytes: `H[0..56]` **plaintext**, then `E[56..64]` where `E = CTR_out(H)` (the whole 64 bytes are run through the outgoing stream, so the payload continues at keystream offset 64) (`:1366-1370`). The incoming stream starts at offset 0 of its own keystream.

Forbidden-pattern retry (`:1347-1364`): up to 10 attempts, but only when a secret is present, and it tests `E[0..4]` (the encrypted bytes, which are never sent) against `0x44414548 'HEAD'`, `0x54534f50 'POST'`, `0x20544547 'GET '`, `0x4954504f 'OPTI'`, `0xdddddddd`, `0xeeeeeeee`, `0x02010316`; attempt index 9 hits `assert(false)` (no-op in release). There is no `0xef` first-byte check and no "second word != 0" check, and nothing at all for direct connections. Spec/TDLib apply all three rules to the plaintext `H` for every connection (§10 M1). A Rust port should implement the spec rules (which yields byte-identical behaviour in all cases where MtProtoKit's output is valid).

### 6.8 Incoming frame state machine

Reads are explicit, tag-driven (`MTTcpReadTags`, `:653-675`); one outstanding logical read at a time (`_pendingReceiveData`, asserted `:1846`). Non-TLS: each logical read issues `readDataToLength:len withTimeout:-1 tag:MTTcpSocksReceivePassthrough` and the delivered chunk (exactly `len`) is processed. TLS: the logical read is satisfied from `_receivedDataBuffer` fed by TLS records (§6.11). Every chunk is decrypted with the incoming CTR stream before interpretation (`:1879-1897`).

| Tag | Input | Rule |
|---|---|---|
| `PacketShortLength` (abridged) | 1 byte `m` | `m & 0x80` → quick-ack: keep `m`, read 3 more (`QuickAck`). `1 <= m <= 0x7e` → body `4*m`. `m == 0x7f` → read 3 (`LongLength`). `m == 0` → close(error) (`:1899-1928`) |
| `PacketLongLength` | 3 bytes LE `q` | `q == 0` or `q > 1_048_576` (body > **4 MiB**) → close(error); else body `4*q` (`:1929-1951`) |
| `PacketFullLength` (intermediate) | int32 LE `L` | bit 31 set → quick-ack token `L & 0x7fffffff` (§6.19), read next length; `L < 4` or `L > MTMaxTransportPayloadLength` (**16 MiB**) → close(error); else body `L` (`:1952-1989`) |
| body dispatch | — | `len >= 4096` (`MTTcpProgressCalculationThreshold`, `:678`) → read 128-byte `PacketHead` first, then `len-128` as `PacketBody`; else read whole `PacketBody` |
| `PacketHead` | 128 bytes | stored; process-global counter `nextToken` (static, `:1993-1995`) → `tcpConnectionDecodePacketProgressToken`; the delegate's async answer is accepted only if the token still matches. Progress callbacks fire on each 1 % step of partial reads (`:1477-1488`) |
| `PacketBody` | body (head prepended, decrypted in place) | stop the response timer; clear progress token; **truncate to a multiple of 4** (drops 1..3 padded-intermediate tail bytes; 4/8/12 padding bytes remain and are tolerated by MTProto which rounds the ciphertext down to 16, `MTProto.m:2207`). If first word `== 0xffffffff` and `len >= 8` → quick-ack token from word 2 (decoded as intermediate) and swallow. If first word `== 0` and `len < 16` → "nop", swallow. Else deliver to `connectionReceivedData` block and `tcpConnectionReceivedData` delegate. Then read next length (`:2010-2061`) |
| `QuickAck` (abridged) | 3 bytes | token = `bswap32([m, b0, b1, b2]) & 0x7fffffff` (§6.19), read next length (`:2062-2081`) |

Transport error codes (-404 auth key missing, -429 flood, -444 invalid DC) arrive as ordinary 4-byte bodies (4..16 bytes after the multiple-of-4 truncation) and are classified by MTProto (`4 <= len <= 19` → protocol error, `MTProto.m:1952-2002`; -404 → `handleMissingKey`; -429 → throttle (§10 H1); others → `requestSecureTransportReset` + `transactionsMayHaveFailed`). Each one also reports `decodeResult(false)` → problems `(true, isProbablyHttp=true)` → discovery + backup discovery.

Network type: delivered per read by the socket interface (`networkType` 0 = "Other/WiFi", 1 = WWAN) and passed through untouched; see §10 M29 for how GCDAsyncSocket computes it.

### 6.9 Timeouts

| Timer | Value | Arms | Resets / cancels | Fires |
|---|---|---|---|---|
| TCP connect | **12 s** (`MTTcpConnection.m:1127`) incl. GCDAsyncSocket's own DNS for hostnames | `connectToHost` | connect | GCDAsyncSocket `didNotConnect` → `socketDidDisconnect:withError:` → close(error) |
| Socket reads/writes | **none** (`-1`, `:745,1158,1179,1593,1620…`; `shouldTimeoutReadWithTag` returns -1, `:789-791`) | — | — | — |
| Response timeout | **12 s + bytes/12288 s** (`MTMinTcpResponseTimeout=12.0`, `:677,1416`) where bytes = framed (pre-obfuscation) length of that `sendDatas` call | after a write whose `expectDataInResponse` is true, only if no response timer exists (`:1414-1421`) | reset to a flat **12 s** on every *partial* socket read (`:1475`; GCDAsyncSocket emits partial callbacks only while a read is incomplete); cancelled by any complete `PacketBody` (`:2011-2012`); untouched by quick-ack frames | close(error) (`:1459-1468`) |
| Connection watchdog | **20 s** (`MTTcpTransport.m:312`) | first dial with no watchdog running | first decoded frame; `stop` | reports failure + problems, no close |
| Actualization ping resend | **3 s** (`MTTcpTransport.m:358`) | first frame received after the ping | pong/session change/delivery failure/close | new ping |
| Transaction lock | **1.0 s** (`MTTcpTransport.m:594`) | pump asks MTProto | `transactionReady` | next pump bypasses the lock |
| DNS | **10 s** cap, 2 s retry (§6.13) | | | bare hostname handed to the socket |
| Behaviour backoff | 0/1/4/8 s (§6.4) | | | redial |

Consequences to reproduce or consciously change: (a) the "response timeout" is really "first complete frame after a send": any unrelated incoming frame (an update) cancels it, and a later send cannot re-arm it while one is running; (b) a request whose reply takes >12 s with no other traffic kills the connection even if a quick-ack arrived; (c) a handshake that stalls after TCP connect (SOCKS reply, fake-TLS ServerHello) has no transport-level timeout — writes are still queued, so the response timer is never armed, and the 20 s watchdog only reports. Recovery depends on upper layers (`MTRequestMessageService` 5 s request timer → `requestSecureTransportReset`, `MTRequestMessageService.m:370-389`, when `useRequestTimeoutTimers`).

### 6.10 MTProxy secrets and proxy settings

`MTProxySecret parseData:` (`MTApiEnvironment.m:105-130`):

| Input bytes | Result | `.secret` | Framing |
|---|---|---|---|
| exactly 16 | `MTProxySecretType0` | the 16 bytes | abridged |
| 17 with first byte `0xdd` | `MTProxySecretType1` | bytes 1..17 | padded intermediate |
| 17 otherwise | nil | | |
| ≥18 with first byte `0xee` | `MTProxySecretType2`, `domain` = UTF-8 of bytes 17.. (nil if invalid UTF-8 → nil) | bytes 1..17 | padded intermediate + fake TLS |
| anything else (<16, ≥18 not `ee`, incl. `dd`+domain) | nil | | |

`MTProxySecret parse:` (string, `:85-103`): first try hex (`parseHexString`, `:13-33`: even length, pairs through `strtol(…,16)` with "consumed exactly 2 chars" check — so pairs like `-1`, `+a`, ` a` are accepted); else base64url: trim `=` from both ends, `-`→`+`, `_`→`/`, re-pad to a multiple of 4, decode with `NSDataBase64DecodingIgnoreUnknownCharacters`. Serialisation: Type0/Type1 → lowercase hex (`dd` prefix for Type1); Type2 → `ee‖secret‖domain` base64url without padding (`:257-273`).

`MTSocksProxySettings` (`h/MTApiEnvironment.h:34-46`, `MTApiEnvironment.m:291-343`): `ip` (may be a hostname), `port`, `username`, `password`, `secret`, `webProxy`. `secret != nil` ⇒ MTProxy; `secret == nil` ⇒ SOCKS5; `webProxy` ⇒ WEB relay (TelegramCore always supplies the secret for WEB, `TelegramCore/Sources/Settings/ProxySettings.swift:22-31`). Equality compares all six fields.

### 6.11 Fake-TLS (ee secrets)

**ClientHello** is produced by a tiny template interpreter (`MTTcpConnection.m:179-483`, template `:486-531`). Commands: `S "\xNN…"` literal, `Z n` zeros, `R n` random, `D` SNI domain bytes, `G i` two copies of `grease[i]`, `K` 32-byte X25519-looking key, `M` 1184-byte ML-KEM-768-looking key, `[`/`]` push/pop a 2-byte big-endian length of everything in between, `< (…) (…) >` choose one alternative uniformly (`arc4random_uniform`).

GREASE (`:143-156`): 8 random bytes, each `(b & 0xf0) | 0x0a`; for even `i`, if `g[i] == g[i+1]` then `g[i+1] ^= 0x10`. Indices used: 0 cipher, 2 first extension, 4 supported_groups and key_share (same value), 6 supported_versions, 3 last extension.

Field sequence (domain length `L`, 1..65535 bytes, else nil → close; `:569-576`):

| # | Bytes | Meaning |
|---|---|---|
| 1 | `16 03 01` + u16 | TLS record, length = total − 5 |
| 2 | `01 00` + u16 | ClientHello, 3-byte length (high byte literal 0) = total − 9 |
| 3 | `03 03` | legacy_version |
| 4 | 32 × `00` | random (offset **11..43**), replaced after HMAC |
| 5 | `20` + 32 random | session_id |
| 6 | choice A: `00 1c` G0 `1302 1301 1303 c02c c030 c02b cca9 c02f cca8 c00a c009 c014 c013`; choice B: `00 2a` G0 `1302 1303 1301 c02c c02b cca9 c030 c02f cca8 c00a c009 c014 c013 009d 009c 0035 002f c008 c012 000a` | cipher_suites |
| 7 | `01 00` | compression: null |
| 8 | u16 | extensions length |
| 8a | G2 `00 00` | GREASE extension, empty |
| 8b | `00 00` u16 u16 `00` u16 + domain | server_name |
| 8c | `00 17 00 00` | extended_master_secret |
| 8d | `ff 01 00 01 00` | renegotiation_info |
| 8e | `00 0a 00 0e 00 0c` G4 `11ec 001d 0017 0018 0019` | supported_groups (X25519MLKEM768, x25519, P-256/384/521) |
| 8f | `00 0b 00 02 01 00` | ec_point_formats |
| 8g | choice A: `00 10 00 0b 00 09 08 "http/1.1"`; B: `00 10 00 0e 00 0c 02 "h2" 08 "http/1.1"` | ALPN |
| 8h | `00 05 00 05 01 00 00 00 00` | status_request |
| 8i | `00 0d 00 16 00 14 0403 0804 0401 0503 0805 0805 0501 0806 0601 0201` | signature_algorithms (0805 duplicated, as Safari) |
| 8j | `00 12 00 00` | signed_certificate_timestamp |
| 8k | `00 33 04 ef 04 ed` · G4 `00 01 00` · `11 ec 04 c0` + M(1184) + K(32) · `00 1d 00 20` + K(32) | key_share; the two K values are independent |
| 8l | `00 2d 00 02 01 01` | psk_key_exchange_modes |
| 8m | `00 2b 00 07 06` G6 `03 04 03 03` | supported_versions |
| 8n | `00 1b 00 03 02 00 01` | compress_certificate (zlib) |
| 8o | G3 `00 01 00` | GREASE extension, 1 byte |

Total length = **1506 + L** (+14 for cipher choice B, +3 for ALPN choice B), verified by re-running the template. The "pad to 513 with extension `0x0015`" step (`:551-564`) therefore never executes (and would append after the closed lengths , §10 L26). The caller also rejects a hello shorter than 513 (`:1133`).

Key generators: `K` (`:33-115`): random 32 bytes, clear bit 255, `x = r² mod p` (p = 2²⁵⁵−19), repeat until `y² = x³+486662x²+x` is a square (Euler: `y²^((p−1)/2) == 1`), then point-double three times (x-only formula `(x²−1)²/(4y²)`), output 32 bytes little-endian. `SecRandomCopyBytes` failure falls back to `arc4random_buf`. `M` (`:121-141`): 384 × (two 32-bit randoms mod 3329 packed into 3 bytes as 12-bit pairs) = 1152 bytes, + 32 random bytes; any `SecRandomCopyBytes` failure → nil → close.

**HMAC/timestamp** (`:1138-1155`): `d = HMAC-SHA256(key = secret16, msg = hello with zero random)`; `d[28..32] ^= LE32(uint32(now_unix + [MTContext fixedTimeDifference]))`; `hello[11..43] = d`; remember `d` as `_helloRandom`; write hello; read 5. `fixedTimeDifference` is a process-global int32 set only from the HTTP `Date` header of the DNS-over-HTTPS backup-address fetch (`MTBackupAddressSignals.m:119-130`, `MTContext.m:222-240`) — not the MTProto server time.

**Server response** (`:1693-1800`):
1. 5 bytes: must be `16 03 03` + BE int16 `n1` with `0 <= n1 <= 10240`.
2. `n1 + 11` bytes: the last 11 must be `14 03 03 00 01 01 17 03 03` + BE int16 `n2` with `0 <= n2 <= 10240`.
3. `n2` bytes.
4. `resp = all bytes (5+n1+11+n2)`; must be ≥ 43; `srv = resp[11..43]`; zero `resp[11..43]`; require `HMAC-SHA256(secret16, _helloRandom ‖ resp) == srv` (non-constant-time `isEqualToData`). Any failure → close(error).
5. `_readyToSendData = true`, flush the queue, set the first logical frame read, and start the record loop.

**Record loop (receive)** (`:1801-1838`): read 5 bytes, require `17 03 03`, BE int16 length `>= 0` (so ≤ 32767; no other bound), read that many bytes, append to the frame reassembler (`addReadData`, `:1860-1877`), repeat. Zero-length records stall (§10 M23).

**Record wrapping (send)** (`:1385-1408`): the obfuscated bytes of one `sendDatas` call are split into chunks of at most **16408** bytes, each prefixed `17 03 03` + BE u16 length; the very first write on the connection is prefixed once by `14 03 03 00 01 01` (ChangeCipherSpec). Nothing is TLS-encrypted; the payload is the AES-CTR obfuscated stream including the 64-byte init header.

The ClientHello is sent only when there is no SOCKS proxy (`:1129-1158`). Order on the wire: ClientHello → (wait for verified server response) → CCS + record(s) containing `[64-byte header][frames…]`. Because "opened" fires at TCP connect, MTProto's first transaction is generated before the handshake and sits in `_pendingDataQueue` until step 5.

### 6.12 SOCKS5

(`MTTcpConnection.m:1168-1180, 1494-1692`)
1. Greeting: `05 01 00`, or `05 02 00 02` when `username != nil` (even if empty). Read 2.
2. Reply must be exactly 2 bytes, version 5; method `0xFF` → close(error). Method `0x02` → RFC 1929: `01, ulen, user, plen, pass` (UTF-8, each truncated to 255 by the length byte only — the full data is still appended), read 2, require `01 00`. Any other method (incl. unsupported ones) → proceed as "no auth".
3. CONNECT: `05 01 00 01` + IPv4 from `inet_aton(scheme.address.ip)` + BE port. ATYP is hard-coded to 1 (IPv4); the IPv6/domain branches are unreachable (§10 M24). Read 4.
4. Reply: exactly 4 bytes, `REP == 0` else close(error); ATYP 1 → read 4, ATYP 4 → read 16, ATYP 3 → read 1 then that many; then read 2 (port). Bound address/port are ignored. Unknown ATYP → close(error).
5. After the port bytes: `connectionOpened` block, `tcpConnectionOpened`, `_readyToSendData = true`, flush, first frame read.

SOCKS + a DC address that carries an `ee` secret never sends a ClientHello yet uses the TLS read path → hang (§10 M24). All SOCKS reads use timeout -1.

### 6.13 Proxy hostname DNS (`MTDNS`)

`resolveHostnameUniversal:port:` (`MTDNS.m:237-252`) = `resolveHostnameNative` with `timeout:10.0 orSignal:[MTSignal single:hostname]` then `take:1`. Native (`:108-220`): coalesced per `"host:port"` key across all callers in the process (`MTDNSContext`); `getaddrinfo(PF_UNSPEC, SOCK_STREAM, IPPROTO_TCP)` on the global queue; first IPv4 result wins, else first IPv6; failure → wait **2 s** and retry forever (`catch` → `complete.delay(2)` → `restart`, `take:1`). When all subscribers dispose, the shared lookup is dropped. The old DoH-over-`google.com/resolve` path was removed (commit c716a36b8e); the comment at `MTTcpConnection.m:1050` still mentions it and is stale.

### 6.14 Connection-interface hook

`MTContext.makeTcpConnectionInterface` (`h/MTContext.h:99`) is a factory `(delegate, delegateQueue) -> id<MTTcpConnectionInterface>` (`h/MTContext.h:21-53`):
- methods: `setGetLogPrefix:`, `setUsageCalculationInfo:`, `connectToHost:onPort:viaInterface:withTimeout:error:` (returns NO on synchronous failure), `writeData:`, `readDataToLength:withTimeout:tag:` (exact-length reads, FIFO), `disconnect`, `resetDelegate`; optional `isWebProxyCarrier`.
- delegate (must be invoked on `delegateQueue` = tcpQueue): `connectionInterfaceDidConnect`, `connectionInterfaceDidReadData:withTag:networkType:`, `connectionInterfaceDidReadPartialDataOfLength:tag:`, `connectionInterfaceDidDisconnectWithError:` (nil error = clean close).

Providers in this tree: `MTGcdAsyncSocketTcpConnectionInterface` (default, `MTTcpConnection.m:710-793`); `NetworkFrameworkTcpConnectionInterface` (TelegramCore, installed when `networkSettings.useNetworkFramework` or beta builds, iOS 12+/macOS 14+, `TelegramCore/Sources/Network/Network.swift:511-527`; options `noDelay`, keepalive idle 5 s / count 2 / interval 5 s, TCP Fast Open, own connect timer; `NetworkFrameworkTcpConnectionInterface.swift:132-140,194-201`); `WebProxyConnectionInterface` (`WebProxyTransport`, multiplexes streams over a hidden WebView, `isWebProxyCarrier == true`, swapped in by `Network.updateProxySettings`, `Network.swift:1012-1022`). Derived contexts (backup-address fetch, `MTProxyConnectivity`) copy the factory but carry different proxy settings; the `isWebProxyCarrier`/`webProxy` pairing in §6.5 keeps them off the carrier. A Rust engine needs the same pluggable byte-stream interface with this pairing rule.

### 6.15 GCDAsyncSocket behaviour that leaks out

- Socket options (`GCDAsyncSocket.m:2401-2413`): `SO_NOSIGPIPE`; `TCP_NODELAY` at `IPPROTO_TCP` (fixed 96dbe82f03; previously wrongly `SOL_SOCKET`, i.e. Nagle on); **no** `SO_RCVBUF/SO_SNDBUF` (kernel autotuning, dfb9537cf5); **no** `SO_KEEPALIVE`.
- Address family: for hostnames, `kPreferIPv6` is unset so IPv4 wins when both resolve (`:2334-2336`).
- Connect runs `connect()` on the global queue; connect timeout = the 12 s passed in (`:2008,2122`).
- `readDataToLength:0` is silently ignored (`:3896-3899`) — relevant to zero-length TLS records.
- Usage accounting: after connect a `MTNetworkUsageManager` is created if `usageCalculationInfo` is set; incoming/outgoing bytes are added per interface. The interface is decided by `bool isWifi = true` that is only ever set to `true` (`:2425,2451`), so all bytes are booked as "Other", and `networkType` delivered with reads is `0` when usage info is set and `1` (WWAN, the enum's zero value) when not (`:5116`). Network.framework's interface does this correctly (`NetworkFrameworkTcpConnectionInterface.swift:263,304,354`).

### 6.16 Network availability

`MTNetworkAvailability` (`MTNetworkAvailability.m:51-166`), one per `MTTransport`: SCNetworkReachability for `0.0.0.0`; initial state seeded from `kSCNetworkReachabilityFlagsReachable` without notifying, then an immediate real read with notification, then a **5 s repeating** poll plus the reachability callback. State string `"%s_%s_%s"` = `M|L` (WWAN, iOS only) `_` `+U|-U` (can connect on demand/traffic without user intervention) `_` `+|-` (reachable). Any change of the string notifies `networkIsAvailable = reachable`. Effects: §6.3 (clear backoff when available, always stop the live connection) and MTProto/services forwarding.

### 6.17 Transport scheme list, choice and stats

`MTTransportScheme` (`h/MTTransportScheme.h`, `MTTransportScheme.m`): `{transportClass (always MTTcpTransport now), address, media}`; equality = class + `isEqualToAddress` + media; `isOptimal` = TCP. NSCoding keys `transportClass` (class name), `address`, `media`. `isEqual:` is overridden without `hash` (do not use as a hash key).

**List** (`MTContext.m:1056-1125`): `datacenterAddressOverrides[dc]` → exactly one scheme `(override, media:false)`, nothing else. Otherwise one scheme per address of the DC's address set (`_allTransportSchemesForDatacenterWithId`, `:1244-1255`; no address set → triggers `addressSetForDatacenterWithIdRequired` and returns empty), plus the persisted manually-selected scheme for `(dc, isProxy, media)` appended if its address is still in the set and not already present. Filter: `enforceMedia` keeps only `preferForMedia`; non-media drops `preferForMedia`; media keeps only media addresses if any exist. `isProxy` (= `socksProxySettings != nil`) only selects which manual scheme is used — `preferForProxy` addresses are not filtered here.

**Choice per dial** (`MTContext.m:1012-1054`, synchronous on contextQueue): IPv6 schemes are eligible only if some IPv6 scheme in the list has `lastResponseTimestamp > now − 3600 s`. Iterate the list **in reverse**; pick the minimum `lastFailureTimestamp`, replacing only on strictly smaller — so ties go to the last element of the list (with clean stats: the appended manual scheme, else the last eligible address). There is no rotation other than via failure timestamps.

**Stats** (`MTTransportSchemeStats`, `MTTransportSchemeStats.m`): per `(dcId, MTDatacenterAddress)` → `{lastFailureTimestamp, lastResponseTimestamp}`, int32 seconds of `CFAbsoluteTimeGetCurrent()` (2001 epoch). Updated on contextQueue (`MTContext.m:1350-1408`): failure ← `transportConnectionFailed`, problems, decrypt failure, parse error; response ← every successfully decoded+parsed incoming packet (`MTProto.m:2060`) and discovery success (which also zeroes the failure, `MTContext.m:867-872`). A change schedules a one-shot **5 s** timer that writes the whole dictionary to keychain key `transportSchemeStats_v1`, group `temp` (`:1373-1392`); loaded at context init (`:499-507`). Manually selected schemes persist under `datacenterManuallySelectedSchemeById_v1`, group `persistent` (`:861-866`).

Scheme lists are captured when the transport is created; newly discovered schemes reach an `MTProto` only when it recreates its transport (resume, session reset, auth changes, api-environment change, address-set update with `shouldReset`) — discovery itself notifies `shouldReset:false` (`MTContext.m:880-889`, `MTProto.m:2579-2595`). See §10 H9.

### 6.18 Proxy connection-issue probing

Triggered from MTProto when the transport reports problems, a proxy is configured on the transport, and `checkForProxyConnectionIssues` is set (`MTProto.m:831-863`): `probe = [MTConnectionProbing probeProxy…].delay(5 s)` then `complete.delay(20 s)`, `restart` — i.e. one probe every ~25 s until a `hasConnectionProblems:false` arrives (never from MTTcpTransport) or the problems path clears it. Each result updates `MTProtoConnectionState.proxyHasConnectionIssues`.

`probeProxyWithContext` (`MTConnectionProbing.m:126-141`) = `combineLatest(proxyReachable (≤10 s, default false), icmpReachable (≤10 s, default false))` → `issues = !proxyReachable && icmpReachable`. ICMP reference: `PingFoundation` echo to `google.com` or `8.8.8.8` (random), first reply wins, on a dedicated run-loop thread (`:21-101`).

`MTProxyConnectivity pingProxyWithContext` (`MTProxyConnectivity.m:113-151`): for **every** address of the DC (IPv4 and IPv6), a throwaway `MTContext` with the proxy settings (and the copied interface factory) and an `MTTcpConnection` that, on open, sends an unencrypted `req_pq_multi#be7e8ef1` (`MTDiscoverConnectionSignals.m:22-67`, `msg_id = unix·2³²` from wall time) with `expectDataInResponse:true`; valid reply = ≥84 bytes, `auth_key_id == 0`, constructor at offset 20 = `resPQ#05162463`, nonce echo at 24..40 (`:42-55`). Reachable if any address answers validly; RTT measured from open. The same probe/validation is used by scheme discovery (§2).

### 6.19 Quick-ack end to end

- Token on send: first 4 bytes of `msg_key_large = SHA256(auth_key[88..120] ‖ plaintext)` read little-endian, bit 31 cleared (`MTQuickAck.m:7-11`; computed in `MTProto.m:1563-1586`). Recorded per payload; `MTRequestMessageService` ignores request contexts with no transaction id when matching (0 is a valid token).
- Request: abridged length byte `|0x80`, intermediate length word `|0x80000000` (§6.6). Requested when any message `needsQuickAck`, or for TCP when nothing in the transaction expects a response.
- Receive: intermediate/padded — the 4-byte LE word as sent, `& 0x7fffffff` (`MTQuickAck.m:13-15`); abridged — 4 bytes in wire order (first byte has 0x80), byte-swapped then `& 0x7fffffff` (`:17-21`); in-body form `ffffffff` + intermediate word (§6.8). Regression tests: `Tests/MTQuickAckTests.m` (fix 616783c0a7: intermediate was byte-swapped before, so quick-acks never matched through MTProxy).

### 6.20 Parity checklist (checkable rules for the Rust engine)

1. Exactly one connection per transport; a stale connection's events are ignored by identity.
2. Dial only on demand (`setDelegateNeedsTransaction`) or via the backoff timer; never while `stopped`.
3. Backoff: immediate, then 1 s ×4, 4 s ×15, then 8 s; reset only by a decoded frame or reachability→available.
4. First transaction after every open carries one `ping#7abe77ec` (random id, no ack requested, encrypted, `forceConfirmations`); "updating" state is true from its msg_id until its pong.
5. Transaction pump lock: at most one outstanding `transportReadyForTransaction`, auto-unlocked after 1.0 s or on reopen; coalesced re-asks.
6. Abridged for direct/plain secret (`efefefef`), padded intermediate with 0..15 random pad bytes for dd/ee (`dddddddd`); quick-ack bit as specified.
7. Obfuscation header per §6.7 (implement the spec's forbidden-pattern rules on the plaintext header).
8. Receive limits: abridged ≤ 4 MiB, intermediate 4..16 MiB; length word bit 31 = quick-ack; truncate bodies to a multiple of 4; swallow `ffffffff`-prefixed (≥8 bytes) and `00000000`-prefixed (<16 bytes) bodies.
9. Timeouts per §6.9 (12 s connect; 12 s + 1 s/12 KiB response; 20 s report-only watchdog; 3 s ping resend).
10. Fake-TLS: byte-exact template (§6.11) including GREASE rules and both choices; HMAC with timestamp XOR into the last 4 bytes; server verification; 16408-byte records; CCS once.
11. SOCKS5 per §6.12 (decide consciously whether to keep IPv4-only CONNECT).
12. Scheme choice per §6.17 (reverse iteration, min failure timestamp, 1 h IPv6 gate); stats persisted ≤5 s after change.
13. Every reachability change drops the live connection.

### 6.z Constants

| Name | Value | File:line | Meaning |
|---|---|---|---|
| `MTMaxTransportPayloadLength` | 16 MiB | `MTTransport.m:3` | max intermediate frame; also msg_container child bound (§3) |
| `MTMaxUnpackedMessageLength` | 32 MiB | `MTTransport.m:4` | gzip_packed inflate cap (§3) |
| abridged long-length cap | 1,048,576 quarters = 4 MiB | `MTTcpConnection.m:1937` | larger → close |
| `MTMinTcpResponseTimeout` | 12.0 s | `MTTcpConnection.m:677` | response watchdog base |
| response size allowance | +1 s per 12 KiB sent | `MTTcpConnection.m:1416` | |
| `MTTcpProgressCalculationThreshold` | 4096 B | `MTTcpConnection.m:678` | frames ≥ this are read as 128-byte head + rest |
| progress head | 128 B | `MTTcpConnection.m:1916,1947,1984` | |
| connect timeout | 12 s | `MTTcpConnection.m:1127` | passed to the interface |
| connection watchdog | 20.0 s | `MTTcpTransport.m:312` | report-only |
| actualization ping resend | 3 s | `MTTcpTransport.m:358` | |
| transaction lock timeout | 1.0 s | `MTTcpTransport.m:594` | |
| sleep watchdog | 60.0 s (disabled) | `MTTcpTransport.m:25` | dead |
| actualization ping | `ping#0x7abe77ec` | `MTTcpTransport.m:629` | |
| backoff | 0 / 1.0 / 4.0 / 8.0 s at counts 1 / 2-5 / 6-20 / ≥21 | `MTTcpConnectionBehaviour.m:62-75` | |
| abridged tag | `0xefefefef` | `MTTcpConnection.m:1284` | |
| padded-intermediate tag | `0xdddddddd` | `MTTcpConnection.m:1282` | |
| header retries | 10 (proxy only, wrong bytes) | `MTTcpConnection.m:1276,1351` | |
| test DC offset | +10000 | `MTTcpConnection.m:943,945` | negative for media |
| intermediate random pad | 0..15 B | `MTTcpConnection.m:1237` | |
| TLS record max chunk | 16408 B | `MTTcpConnection.m:1393` | outgoing |
| TLS CCS prefix | `14 03 03 00 01 01` | `MTTcpConnection.m:1389` | first write only |
| server hello length caps | 10240 B each | `MTTcpConnection.m:1716,1743` | |
| ClientHello min / pad target | 513 B (never reached; real ≥ 1507 B) | `MTTcpConnection.m:552,1133` | |
| ML-KEM key / X25519 key | 1184 B / 32 B | `MTTcpConnection.m:412,406` | |
| DNS cap / retry | 10.0 s / 2.0 s | `MTDNS.m:251,218` | |
| reachability poll | 5.0 s | `MTNetworkAvailability.m:76` | per transport |
| IPv6 eligibility window | 3600 s | `MTContext.m:1024` | since last response |
| stats sync delay | 5.0 s | `MTContext.m:1377` | keychain write |
| backup discovery delay after problems | 5.0 s (20.0 s if `reducedBackupDiscoveryTimeout==false`; 1.0 s DEBUG) | `MTContext.m:1445-1451` | |
| proxy probe delay / period | 5.0 s / +20.0 s | `MTProto.m:845-846` | |
| probe sub-timeouts | 10.0 s each | `MTConnectionProbing.m:129-130` | |
| probe valid resPQ | ≥84 B, ctor `0x05162463` at 20, nonce at 24 | `MTProxyConnectivity.m:44-48` | |
| protocol-error size window | 4..19 B | `MTProto.m:1952` | MTProto side |
| -429 unthrottle timer | 5.0 s (never started) | `MTProto.m:1982` | §10 H1 |

## 7. MTEncryption and crypto primitives

Files: `h/MTEncryption.h`, `MTEncryption.m`, `MTAes.h/.m` (internal), `h/MTMessageEncryptionKey.h` + `MTMessageEncryptionKey.m`, `h/MTGzip.h` + `MTGzip.m`, `h/MTQuickAck.h` + `MTQuickAck.m`, the class methods on `MTProto` (`h/MTProto.h:79-111`), and the external `EncryptionProvider` protocol (`submodules/EncryptionProvider/PublicHeaders/EncryptionProvider/EncryptionProvider.h`, implemented by `submodules/OpenSSLEncryptionProvider/Sources/OpenSSLEncryptionProvider.m`).

### 7.1 Exported API (`h/MTEncryption.h`) and who uses it

All functions are C functions; byte strings are `NSData`; big integers are big-endian byte strings. "TC" = `submodules/telegram-ios/submodules/TelegramCore/Sources`. No function is used directly by `Telegram-Mac/` or `packages/` (those import MtProtoKit only for proxy types).

| Function (header line) | Semantics / failure | External users |
|---|---|---|
| `MTSha1(data)` (`:12`) | CommonCrypto SHA-1, 20 bytes | TC SecretChats/*, CallSessionManager |
| `MTSubdataSha1(data, offset, length)` (`:13`) | SHA-1 of a slice, **no bounds check** | TC SecretChatEncryption.swift:168 |
| `MTSha256(data)` (`:15`) | SHA-256, 32 bytes | TC FetchV2.swift:510, MultipartFetch.swift:456 (CDN hash check), SecretChatEncryption, CallSessionManager |
| `MTRawSha256TwoParts(p1,l1,p2,l2,out)` (`:17`) | SHA-256(p1‖p2) streamed, out 32 bytes | internal (msg_key) |
| `MTRawSha1`, `MTRawSha256` (`:19-20`) | raw-pointer hashes | unused externally |
| `MTMurMurHash32(bytes, len)` (`:22`) | MurmurHash3 x86_32, seed `-137723950` (`MTEncryption.m:169-175`) | unused |
| `MTAesEncryptInplace(data,key,iv)` (`:28`) | AES-IGE in place; false + data zeroed on failure | internal (bind V1 frame), tests |
| `MTAesEncryptInplaceAndModifyIv` / `MTAesDecryptInplaceAndModifyIv` (`:29, 35`) | same; on success writes the chaining IV back (7.4) | unused externally |
| `MTAesEncryptBytesInplaceAndModifyIv(ptr,len,key,iv)` (`:30`) | void; on failure buffer zeroed + log, iv untouched | TC MultipartUpload.swift:66 (encrypted upload parts) |
| `MTAesDecryptBytesInplaceAndModifyIv(ptr,len,key,iv)` (`:36`) | void; same | TC MultipartFetch.swift:39, FetchV2.swift:190 (encrypted file parts) |
| `MTAesEncryptRaw` / `MTAesDecryptRaw(in,out,len,key32,iv32)` (`:33-34`) | bool; key forced to 32 bytes; in/out must not overlap; either may be unaligned (bounced through a temp); iv not modified | internal (MTProto frames) |
| `MTAesEncrypt` / `MTAesDecrypt(data,key,iv)` (`:37-38`) | nil if key or iv is nil or on any failure; key length = `key.length` (16/24/32 all accepted by CommonCrypto) | TC SecretChatEncryption (encrypt+decrypt), Account.swift:1086 (decrypt) |
| `MTRsaEncrypt(provider, pem, data)` (`:39`) | raw RSA (iOS: `rsaEncryptWithPublicKey`; macOS: `macosRSAEncrypt`), minimal-length output | unused |
| `MTExp(p, base, exp, mod)` (`:40`) | `base^exp mod mod`, constant-time flags set; minimal big-endian (leading zeros stripped) | TC Account.swift (SRP), CallSessionManager, secret chats |
| `MTModSub`, `MTModMul`, `MTMul`, `MTAdd` (`:41-44`) | bignum ops, minimal output; return values of the provider calls are ignored | TC Account.swift:828-834 (SRP) |
| `MTFactorize(pq,&p,&q)` (`:45`) | 5.4 | internal |
| `MTIsZero(p, value)` (`:46`) | | TC Account.swift:812 |
| `MTAesCtrDecrypt(data, key, iv)` (`:48`) | one-shot AES-256-CTR, key read as 32 bytes, iv 16 bytes (full 128-bit big-endian counter); nil on cipher failure | TC MultipartFetch.swift:441, FetchV2.swift:827 (CDN parts) |
| `MTCheckIsSafeG(g)` (`:51`) | `2 <= g <= 7` | TC Account.swift:667, SecretChatEncryptionConfig.swift:15 |
| `MTCheckIsSafeB(p, b, prime)` (`:52`) | `0 < b < prime` | TC Account.swift:804 (SRP B) |
| `MTCheckIsSafePrime(p, prime, keychain)` (`:53`) | 7.6, cached | TC Account.swift:675, SecretChatEncryptionConfig.swift:25 |
| `MTCheckIsSafeGAOrB(p, x, prime)` (`:54`) | `1 < x < prime-1` and `2^1984 < x < prime - 2^1984` | TC Account.swift:830 (SRP), CallSessionManager.swift (4 sites), ManagedSecretChatOutgoingOperations.swift (5), CreateSecretChat.swift:30, SecretChatRekeySession.swift:48 |
| `MTCheckMod(p, prime, g, keychain)` (`:55`) | 7.6, cached | TC Account.swift:671, SecretChatEncryptionConfig.swift:20 |
| `MTAesCtr` class (`:57-70`) | streaming AES-CTR with resumable state | internal (TCP obfuscation, `MTTcpConnection.m:842-843, 1332-1333`) |
| `MTRsaFingerprint(p, pem)` (`:72`) | 5.3; 0 on parse failure | TC Network.swift:931 (CDN keys) |
| `MTRsaEncryptPKCS1OAEP(p, pem, data)` (`:74`) | OpenSSL `RSA_PKCS1_OAEP_PADDING` (SHA-1/MGF1); nil on failure | TC GrantSecureIdAccess.swift:326 (Passport) |
| `MTBackupDatacenterAddress`, `MTBackupDatacenterData`, `MTIPDataDecode(p, data, phone)` (`:76-93`) | 7.8 | `CloudData/Sources/CloudData.swift:148` |
| `MTPBKDF2(data, salt, rounds)` (`:95`) | PBKDF2-HMAC-SHA512, 64-byte output; nil if `rounds < 2` or CommonCrypto fails (`MTEncryption.m:1110-1121`) | TC Account.swift:720, 818, 879, 901 (2FA) |
| `MTGzip` (`h/MTGzip.h`) | 7.7 | TC Download.swift:27, RateCall.swift:50 (compress); AccountStateManager.swift:1876, 2321, ImageRepresentationsUtils.swift:107 (decompress) |

Also exported but internal-only: `MTMessageEncryptionKey` (`h/MTMessageEncryptionKey.h`), the quick-ack helpers (`h/MTQuickAck.h:16-23`), and the MTProto class methods `_manuallyEncryptedMessage:`, `_paddedPlaintextWithSalt:...`, `_encryptedTransportDataForPaddedPlaintext:...`, `_decryptedPayloadForIncomingTransportData:...`, `_readIncomingPayload:...` (`h/MTProto.h:79-111`, used by tests). `MTAesDecryptRawInplaceAndModifyIv` is defined (`MTEncryption.m:323`) but not declared or used. `MTRsa` (`MTRsa.h/.m`, iOS-only SecKey wrapper with `kSecPaddingNone`) is dead code; its only use is commented out (`MTEncryption.m:385-390`).

A Rust replacement must keep at least the TC column. `MTExp` and friends return **unpadded** results; TelegramCore pads where needed (`paddedToLength`, `Account.swift:809`).

### 7.2 MTProto 2.0 message encryption (as implemented)

Outgoing, `+[MTProto _paddedPlaintextWithSalt:sessionId:messageId:seqNo:body:extendedPadding:]` (`MTProto.m:1529-1561`):
- plaintext = `salt(8) ‖ session_id(8) ‖ msg_id(8) ‖ seq_no(4) ‖ length(4) ‖ body ‖ padding`, all little-endian;
- padding: `take = 12`, increment until `(32 + len + take) % 16 == 0` (12..27); `r = arc4random_uniform(limit + 1 - take)`, `r -= r % 16`; `take += r`; `limit = 72`, or **256 when `extendedPadding`** (MTProxy secret of type dd or ee, `MTProto.m:985-996`). Total padding is 12..72 (or 12..256) and always 16-aligned; bytes from `arc4random_buf`.

`+[MTProto _encryptedTransportDataForPaddedPlaintext:authKey:quickAckId:]` (`MTProto.m:1563-1608`):
- rejects `authKey.length < 120` and plaintext that is empty or not a multiple of 16 (returns nil = message dropped, logged);
- `msg_key_large = SHA256(auth_key[88..120] ‖ plaintext)` (x = 0); `msg_key = msg_key_large[8..24]`;
- quick-ack token = `LE32(msg_key_large[0..4]) & 0x7fffffff` (`MTQuickAck.m:7-11`);
- key/iv = v2 derivation (7.3) with x = 0;
- frame = `auth_key_id(8, LE) ‖ msg_key(16) ‖ AES-256-IGE(plaintext)`; AES failure -> nil.
- Used for single messages, containers (`msg_container#73f1f8dc`, outer msg_id fresh, seqno `takeSeqNo(false)`, salt = salt of the last child) and the time-fix ping (`MTProto.m:1406-1408, 1448-1492, 1651-1659`).

Incoming, `+[MTProto _decryptedPayloadForIncomingTransportData:authKey:]` (`MTProto.m:2179-2237`):
- requires `authKey.length >= 128` and frame length `>= 24 + 36`;
- frame `auth_key_id` must equal the key's id;
- `encryptedLength = (frame.length - 24) & ~15`: a trailing partial block is **ignored**, not rejected;
- decrypt with v2 key/iv, x = 8; `msg_key_large' = SHA256(auth_key[96..128] ‖ decrypted)`; compare `msg_key_large'[8..24]` with the frame's msg_key **in constant time** (`isBytesEqualConstTime`, `MTProto.m:2171-2177`); mismatch -> nil;
- `message_data_length` (offset 28) must satisfy `0 <= len <= decrypted.length - 32`, and padding `decrypted.length - 32 - len` must be in **12..1024**; otherwise nil;
- `message_data_length % 4` is not checked; the body handed on still includes the padding (`_readIncomingPayload`, `MTProto.m:2239-2282`); the session id check is done by the caller (`MTProto.m:2322-2328`).
- `transportDecodeProgressToken` (`MTProto.m:1731-1817`) decrypts the first part of a large frame **without** verifying msg_key, only to find `req_msg_id` for download progress. Its output must never be trusted for anything else.

### 7.3 Key derivation (`MTMessageEncryptionKey.m`)

v2 (`messageEncryptionKeyV2ForAuthKey:messageKey:toClient:`, `:70-108`), x = 0 client->server, 8 server->client:
- `a = SHA256(msg_key ‖ auth_key[x .. x+36])`, `b = SHA256(auth_key[40+x .. 40+x+36] ‖ msg_key)`;
- `aes_key = a[0..8] ‖ b[8..24] ‖ a[24..32]`; `aes_iv = b[0..8] ‖ a[8..24] ‖ b[24..32]`.

v1 (`messageEncryptionKeyForAuthKey:messageKey:toClient:`, `:7-68`), used only for the bind inner message:
- `sha1_a = SHA1(msg_key ‖ auth_key[x..x+32])`, `sha1_b = SHA1(auth_key[32+x..+16] ‖ msg_key ‖ auth_key[48+x..+16])`, `sha1_c = SHA1(auth_key[64+x..+32] ‖ msg_key)`, `sha1_d = SHA1(msg_key ‖ auth_key[96+x..+32])`;
- `aes_key = a[0..8] ‖ b[8..20] ‖ c[4..16]`; `aes_iv = a[8..20] ‖ b[0..8] ‖ c[16..20] ‖ d[0..8]`.

Both return nil only for a nil/empty key or msg_key; neither checks that the key is long enough (v2 reads up to byte 84, v1 up to byte 136).

### 7.4 AES implementations (`MTAes.m`)

- AES-256-IGE encrypt (`MyAesIgeEncrypt`, `:48-144`): emulated with one CommonCrypto **CBC** call. IV layout: `iv[0..16]` = previous ciphertext block (y0), `iv[16..32]` = previous plaintext block (x0) (OpenSSL `AES_ige_encrypt` convention). Pre-pass `t1 = x1`, `t2 = x2 ^ x0`, `ti = xi ^ x(i-2)`; CBC(t, iv = y0); post-pass `yi ^= x(i-1)`. Verified algebraically to equal `yi = E(xi ^ y(i-1)) ^ x(i-1)`. On return the `iv` buffer holds `y_last ‖ x_last` (used by the `...AndModifyIv` chunked variants).
- AES-256-IGE decrypt (`MyAesIgeDecrypt`, `:146-214`): ECB cryptor, per block `xi = D(yi ^ x(i-1)) ^ y(i-1)`; same IV layout and write-back. Not alias-safe (in-place helpers use a malloc scratch buffer).
- Both reject `length < 0` or `length % 16 != 0` (output zeroed, false); `length == 0` is a successful no-op. Every CommonCrypto failure zeroes the whole output and returns false (`MTAesZeroOutput`). Alignment asserts compile out in release.
- `MyAesCbcDecrypt` (`:216-228`): plain AES-CBC decrypt, used only by `MTIPDataDecode`.
- `MTAesCtr` (`:269-422`): port of OpenSSL `CRYPTO_ctr128_encrypt`. State: 16-byte counter `_ivec` (incremented as a 128-bit big-endian integer after each keystream block), `_ecount` (current keystream block), `_num` (offset 0..15 in it). `initWithKey:keyLength:iv:decrypt:` starts at `num = 0` (the `decrypt` flag is ignored; CTR is symmetric); `initWithKey:keyLength:iv:ecount:num:` resumes. Both return nil when the ECB cryptor cannot be created. `encryptIn:out:len:` returns false and zeroes the unprocessed output on a keystream failure. `num`, `ecount`, `getIv:` expose the state.
- In-place wrappers (`MTEncryption.m:180-334`) allocate a scratch buffer, and on failure wipe the caller's buffer ("fail closed"). The IV is copied with `memcpy(aesIv, iv.bytes, iv.length)` into a 32-byte stack array without checking `iv.length`.

### 7.5 Constant-time and comparison behaviour

- Only the incoming msg_key comparison is constant-time (`MTProto.m:2217`).
- Handshake values (nonces, SHA1 answer hash, new_nonce_hashN) use `-[NSData isEqualToData:]`. These are unauthenticated-phase values, so timing does not matter.
- `MTExp` marks base, exponent, modulus and result `BN_FLG_CONSTTIME` (`MTEncryption.m:396-420`); the other bignum helpers do not.

### 7.6 DH group validation

- `MTCheckIsSafeG` (`MTEncryption.m:614-617`): 2..7.
- `MTCheckMod(prime, g, keychain)` (`:741-799`), cache key `isPrimeModSafe_<lowercase hex of prime>_<g>` in keychain group `primes` (value `NSNumber` bool, both outcomes cached):
  g=2: `p mod 8 == 7`; g=3: `p mod 3 == 2`; g=4: always true; g=5: `p mod 5 in {1,4}`; g=6: `p mod 24 in {19,23}`; g=7: `p mod 7 in {3,5,6}`; other g: false.
- `MTCheckIsSafePrime(prime, keychain)` (`:629-698`): cache key `isPrimeSafe_<hex>` in group `primes` is checked **first**; then `length == 256` and top bit set (else false, not cached); a byte-equal match with the well-known Telegram 2048-bit prime (`goodPrime0`, starts `c7 1c ae b9`, `:646-673`) returns true without caching; otherwise `BN_is_prime_ex(p, 64)` and `BN_is_prime_ex((p-1)/2, 64)`; the result is cached.
- `MTCheckIsSafeGAOrB` (`:700-739`): see the table in 7.1. Not cached.
- `MTCheckIsSafeB` (`:501-514`): `0 < B < p` (SRP only).

### 7.7 gzip (`MTGzip.m`)

- `+decompress:` = `+decompress:maxOutputLength: MTGzipDefaultMaxDecompressedLength` (**32 MiB**, `:6`).
- `+decompress:maxOutputLength:` (`:18-74`): nil for empty or >4 GiB input; `inflateInit2` with windowBits `15 + 32` (auto-detect gzip or zlib header); inflates in **16 KiB** chunks; returns nil as soon as the output would exceed the ceiling, on any zlib error, or if the stream did not reach `Z_STREAM_END` (truncated input). Trailing bytes after the end of the stream are ignored. The pre-reservation is `min(4 * input, ceiling)`.
- `+compress:` (`:76-111`): empty input is returned **unchanged** (not a gzip stream); `deflateInit2(level 9, Z_DEFLATED, windowBits 31 = gzip wrapper, memLevel 8, default strategy)`; output grows in 16 KiB steps; nil only if `deflateInit2` fails (the `deflate` return value is not checked).
- `gzip_packed#3072cfa1 packed_data:bytes` unwrapping (`MTInternalMessageParser.m:669-686`): inputs shorter than 4 bytes or with another constructor pass through unchanged; a truncated TL length returns nil; the payload is inflated with ceiling `MTMaxUnpackedMessageLength` = **32 MiB** (`MTTransport.m:4`). One level only (no recursive unwrap). TL bytes decoding (`MTBufferReader.m:78-112`) accepts prefix 0..253 as a short length (254 = 3-byte LE length; 255 is accepted as a short length of 255), checks the length against the remaining data before allocating, and requires the padding bytes to be present (their values are not checked).

### 7.8 Simple-config decryption (`MTIPDataDecode`, `MTEncryption.m:850-1108`)

Used by `CloudData` for backup DC address lists fetched out of band.
1. Input must be >= 256 bytes; only the first 256 are used.
2. `y = x^e mod n` with the embedded "simple config" RSA key (`:851-858`; fingerprint `0x6f3a701151477715`), left-padded to 256 bytes.
3. `key = y[0..32]`, `iv = y[16..32]` (overlapping, as specified), `AES-256-CBC-decrypt(y[32..256])` (224 bytes).
4. Require `SHA256(dec[0..208])[0..16] == dec[208..224]`.
5. `data_len = LE32(dec[0..4])`; require `0 < data_len <= 208` and `data_len % 4 == 0`; payload = `dec[4 .. 4 + data_len]` (up to 4 bytes past the hashed region when `data_len > 204`).
6. TL: legacy `0xd997c3c5 date expires dc_id vector<ipPort>` (boxed vector `0x1cb5c415`, ipPort = ipv4:int port:int); or `help.configSimple#5a592a6c date expires rules:vector<accessPointRule>` (bare vectors) with `accessPointRule#4679b65f phone_prefix_rules:string dc_id:int ips:vector<IpPort>`, `ipPort#d433ad73 ipv4 port`, `ipPortSecret#37982646 ipv4 port secret:bytes`. IPv4 is printed big-endian as dotted quad.
7. Phone rules: comma-separated; walking the list, empty -> include, `+prefix` matching -> include, `-prefix` matching -> exclude, **anything else (including a non-matching `+prefix`) -> exclude**; the last rule decides (`:1084-1098`).

### 7.9 Randomness sources

| Use | Source | Failure handling | Ref |
|---|---|---|---|
| handshake nonce (16), new_nonce (32), DH `b` (256) | `SecRandomCopyBytes` | **status ignored** | `MTDatacenterAuthMessageService.m:227, 477, 689` |
| RSA_PAD padding, temp_key | `SecRandomCopyBytes` | nil -> retry path | `:324, 335` |
| client_DH_inner_data padding | `arc4random_buf` (1 byte at a time) | n/a | `:731` |
| message padding, plain-message padding | `arc4random_uniform` + `arc4random_buf` | n/a | `MTProto.m:1505-1511, 1540-1556` |
| bind nonce, bind inner random salt/session, V1 padding | `arc4random_buf` | n/a | `MTBindKeyMessageService.m:58-62`; `MTProto.m:1613-1616, 1521-1522` |
| session id, time-fix ping id | `arc4random_buf` | n/a | `MTSessionInfo.m:65`; `MTProto.m:1393` |
| PQ factorisation | `lrand48` (unseeded, not crypto) | n/a | `MTEncryption.m:544-545` |
| obfuscation / fake-TLS keys | `SecRandomCopyBytes`, falls back to `arc4random_buf` | §6 | `MTTcpConnection.m:78-137` |

`arc4random*` on Apple platforms is a kernel-seeded CSPRNG, so these are cryptographically adequate; a Rust port should use one CSPRNG (e.g. `getrandom`/`OsRng`) throughout and must not use a non-crypto PRNG for anything except PQ factorisation.

### 7.10 Constants

| Name | Value | Ref | Meaning |
|---|---|---|---|
| msg_key slice (v2) | `SHA256(auth_key[88+x..+32] ‖ plaintext)[8..24]`, x = 0 out / 8 in | `MTProto.m:1580-1582, 2216` | |
| Min auth key length for encrypt / decrypt | 120 / 128 bytes | `MTProto.m:1565, 2183` | shorter -> frame dropped |
| Header | 32 bytes (salt, session, msg_id, seqno, length) | `MTProto.m:1534-1551` | |
| Outgoing padding | 12..72 bytes, 12..256 with dd/ee proxy | `MTProto.m:1533` | 16-aligned |
| Incoming padding accepted | 12..1024 bytes | `MTProto.m:2232` | after the 32-byte header |
| Min incoming frame | 60 bytes (24 + 36) | `MTProto.m:2187` | |
| Plain-message extra padding | 0..236 bytes, step 4 (proxy dd/ee only) | `MTProto.m:1505` | not in length field |
| Quick-ack mask | `0x7fffffff` (flag bit `0x80000000`) | `MTQuickAck.m:5-11` | |
| V1 padding | 0..15 bytes | `MTProto.m:1519-1527` | bind inner only |
| AES block / IGE IV | 16 / 32 bytes | `MTAes.m:8`, `h/MTEncryption.h:31-32` | |
| CTR key / iv (one-shot) | 32 / 16 bytes | `MTEncryption.m:801-811` | |
| PBKDF2 | HMAC-SHA512, 64-byte output, rounds >= 2 | `MTEncryption.m:1110-1121` | |
| Gzip default ceiling | 32 MiB | `MTGzip.m:6` | |
| `MTMaxUnpackedMessageLength` | 32 MiB | `MTTransport.m:4` | gzip_packed ceiling |
| `MTMaxTransportPayloadLength` | 16 MiB | `MTTransport.m:3` | container child / TCP frame bound |
| Gzip chunk | 16 KiB | `MTGzip.m:10` | |
| Prime cache keys | `isPrimeSafe_<hex>`, `isPrimeModSafe_<hex>_<g>`, group `primes` | `MTEncryption.m:631, 743` | |
| Miller-Rabin rounds | 64 | `MTEncryption.m:680, 692` | |
| DH range bound | 2^(2048-64) | `MTEncryption.m:722-733` | |
| MurmurHash seed | -137723950 | `MTEncryption.m:172` | unused |
| Simple-config RSA fingerprint | `0x6f3a701151477715` | `MTEncryption.m:851-858` | |
| Simple-config payload max | 208 bytes, 4-aligned | `MTEncryption.m:910` | |

## 8. MTApiEnvironment, network usage accounting, keychain

### 8.1 MTApiEnvironment fields (`h/MTApiEnvironment.h:56-90`, `MTApiEnvironment.m:368-935`)

| Field | Default / computation | In hash | Consumer |
|---|---|---|---|
| `apiId` | 0; plain synthesized setter (does **not** refresh the hash) | yes | initConnection `api_id` |
| `deviceModel` | `deviceModelName` if given, else iOS: `hw.machine` mapped through a lookup table (`platformString`, `:449-781`; unknown → "Unknown iPhone/iPod/iPad", simulator → "iPhone Simulator"); macOS: `hw.model` (`:783-794`) | yes | `device_model` |
| `deviceModelName` | init argument (TelegramCore: `arguments.deviceModelName`; macOS app: `deviceModelPretty()`) | no (via `deviceModel`) | kept across copies |
| `systemVersion` | iOS `UIDevice.systemVersion`; macOS 2nd space-separated token of `operatingSystemVersionString` ("Version 14.5 (Build …)" → "14.5") (`:389-394`) | yes | `system_version` |
| `appVersion` | `"<CFBundleShortVersionString> (<CFBundleVersion>) <suffix>"`, suffix = Info.plist `SOURCE` on macOS, `""` on iOS (trailing space) (`:396-406`); setter refreshes hash | yes | `app_version` |
| `systemLangCode` | `NSLocale.preferredLanguages[0]` at construction (e.g. `en-US`) (`:408`); re-read on every copy | yes | `system_lang_code` |
| `layer` | nil; setter refreshes hash | yes | hash only (wire uses `serialization.currentLayer`) |
| `langPack` | `"macos"` / `"ios"` (`:409-413`); setter refreshes hash | yes | `lang_pack` |
| `langPackCode` | `""` (`:414`); readonly, changed via `withUpdatedLangPackCode:` | yes | `lang_code`; a change also resets the transport (`MTProto.m:2798-2800`) |
| `systemCode` | nil; `withUpdatedSystemCode:` | yes (as `NSData.description`) | `params` (flags.1), raw boxed TL `JSONValue` |
| `socksProxySettings` | nil; `withUpdatedSocksProxySettings:` | yes (as `description`) | transport, `proxy` (flags.0) when `secret != nil`, transport-scheme selection |
| `networkSettings` | nil; `withUpdatedNetworkSettings:` | no | backup discovery delay (8.5) |
| `disableUpdates` | false | no | `invokeWithoutUpdates` on every request |
| `tcpPayloadPrefix` | nil | no | stored into `MTTcpConnection._firstPacketControlByte` for override DCs (`MTTcpConnection.m:909-911`) but **never sent**; nothing sets it: dead |
| `datacenterAddressOverrides` | nil; `NSDictionary<NSNumber dc, MTDatacenterAddress>` | no | replaces the DC's address set at context load (`MTContext.m:472-474`) and its transport schemes (`MTContext.m:1061-1066`); set only by the backup-config fetch context (`MTBackupAddressSignals.m:234-237`) |
| `accessHostOverride` | nil | no | DNS-over-HTTPS host for backup discovery (`MTBackupAddressSignals.m:312`); TelegramCore: `NetworkSettings.backupHostOverride` (debug) |
| `passwordInputHandler` | nil | no | **unused**; also dropped by every copy method |

`apiInitializationHash` (`:421-423`) is the only equality notion; `MTApiEnvironment` has no `isEqual:`/`hash`.

### 8.2 `apiInitializationHash`

Format (exact):

```
apiId=%d&deviceModel=%@&systemVersion=%@&appVersion=%@&langCode=%@&layer=%@&langPack=%@&langPackCode=%@&proxy=%@&systemCode=%@
```

with `langCode` = `systemLangCode`, `proxy` = `MTSocksProxySettings.description`
(`"ip:port+username+password+<secret NSData description>"`, or `"ip:port+web"` for a WEB proxy,
`:336-341`), `systemCode` = `NSData.description`.

- Recomputed by `init`, the `layer`/`appVersion`/`langPack`/`langPackCode` setters and every copy method;
  **not** by `apiId` or the other plain properties. TelegramCore sets `apiId` first and then `langPack`
  (`TC/Network/Network.swift:477-479`), so the hash happens to include it.
- Compared against the per-key stored attribute (4.5) and between old and new env (4.5).
- `NSData.description` on current OSes abbreviates data longer than ~24 bytes
  (`{length = N, bytes = 0x… … …}`), so a `systemCode` change that keeps the length and the shown head/tail
  bytes does not change the hash (§10 M13).
- The hash contains SOCKS username/password and the raw MTProxy secret; it is logged (`MTRequestMessageService.m:432`)
  and persisted in the auth info in the keychain.

### 8.3 Copy semantics

`copyWithZone:` and `withUpdated{LangPackCode,SocksProxySettings,NetworkSettings,SystemCode}:`
(`:815-933`) all re-run `initWithDeviceModelName:` (re-reading device model, OS version, preferred
language, bundle version), then copy `apiId, appVersion, layer, langPack, langPackCode, socksProxySettings,
networkSettings, systemCode, disableUpdates, tcpPayloadPrefix, datacenterAddressOverrides,
accessHostOverride`, replace the one field, and recompute the hash. `passwordInputHandler` is not copied.
The class does not declare `NSCopying` but implements `copyWithZone:` (used by
`MTBackupAddressSignals.m:229`).

Propagation: `MTContext.updateApiEnvironment:(f)` runs `f` on the context queue; a nil result means "no
change"; otherwise every live listener gets `contextApiEnvironmentUpdated:` on the context queue
(`MTContext.m:1750-1767`). MTProto hops to the manager queue (`MTProto.m:2785`).

### 8.4 How TelegramCore builds it

`initializedNetwork` (`TC/Network/Network.swift:467-510`):
`MTApiEnvironment(deviceModelName:)`; `apiId`; `langPack = arguments.languagesCategory` ("macos" in the
macOS app); `layer = currentLayer`; `disableUpdates = supplementary`; `withUpdatedLangPackCode(languageCode ?? "en")`;
`withUpdatedSocksProxySettings(activeServer.mtProxySettings)` if a proxy is active;
`withUpdatedNetworkSettings((networkSettings ?? .default).mtNetworkSettings)` (default
`reducedBackupDiscoveryTimeout = false`); `accessHostOverride = networkSettings?.backupHostOverride`;
`systemCode` = TL-serialized boxed `JSONValue` built from the app's `appData` JSON
(`apiJson(JSON(data:)).serialize(buffer, true)`).
- iOS `appData`: `{bundleId, device_token?, device_token_type?, device_token_environment?, tz_offset:int
  seconds from GMT, …signature fields}` (`submodules/BuildConfig/Sources/BuildConfig.m:148-168`).
- macOS `appData`: `{"bundleId": <id>, "data": <evaluateApiData()>}` (`packages/ApiCredentials/Sources/ApiCredentials/Config.swift:56-60`); no `tz_offset`.
- Later updates: `appDataUpdatedImpl` replaces `systemCode` when the bytes differ
  (`TC/Network/Network.swift:674-700`); proxy changes via `updateProxySettings` compare with
  `MTSocksProxySettings.isEqual` (`TC/Network/Network.swift:1012-1040`); language preview via `withUpdatedLangPackCode`
  (`TC/TelegramEngine/Localization/Localizations.swift:153`); network settings via
  `TC/Settings/NetworkSettings.swift:37`.
- The same context also gets seed addresses for DC 1-5 (production) / 1-3 (test) on port 443
  (`TC/Network/Network.swift:541-561`) — owned by section 2.

### 8.5 Proxy and network settings classes

`MTSocksProxySettings` (`:291-343`): `ip` (hostname or IP; for WEB proxies the public host, the dial
target is substituted with `127.0.0.1:443` inside `MTTcpConnection`), `port: uint16`, `username?`,
`password?`, `secret?` (raw secret bytes, parseable by `MTProxySecret parseData:`), `webProxy: bool`.
`secret != nil` means MTProxy (or WEB carrier over MTProxy); `secret == nil` means SOCKS5.
`isEqual:` compares all six fields; there is no `hash` override.

`MTProxySecret` (`:63-289`):
- `parse(string)`: try hex first (`parseHexString`, even length; each pair decoded with `strtol(…, 16)`
  and accepted iff exactly two characters were consumed, so `"+a"`, `"-1"`, `" f"` are accepted as bytes
  0x0a, 0xff, 0x0f) (`:13-33`); otherwise base64url: trim `=` from both ends, `-`→`+`, `_`→`/`, pad with `=`
  to a multiple of 4, decode ignoring unknown characters (`:85-103`). A string that is valid even-length
  hex is always taken as hex.
- `parseData(bytes)` (`:105-130`): `< 16` → nil; `== 16` → `Type0` (plain obfuscated); `== 17` and first
  byte `0xdd` → `Type1` (padded intermediate), other first byte → nil; `>= 18` and first byte `0xee` →
  `Type2` with `secret = bytes[1..17]`, `domain = UTF-8(bytes[17..])` (nil on invalid UTF-8); everything
  else → nil (e.g. `0xdd` with length > 17, `0xee` with length 17).
- `serialize` / `serializeToString`: Type0 → 16 bytes / lowercase hex; Type1 → `dd`+16 bytes / hex;
  Type2 → `ee`+16 bytes+domain / unpadded base64url (`:168-273`). Base `serialize` asserts.
- `NSCoding` keys: `secret`, `domain`. `isEqual:` per subclass, no `hash` override.
- The fake-TLS wire construction lives in the transport (section 6).

`MTNetworkSettings` (`:345-366`): one field, `reducedBackupDiscoveryTimeout`. Backup address discovery
after a transport-scheme failure is delayed **5 s** when `networkSettings == nil || reduced`, else
**20 s**, and **1 s** in DEBUG builds (`MTContext.m:1445-1451`). TelegramCore always passes a value, so the
production default is 20 s.

### 8.6 MTNetworkUsageManager and MTNetworkUsageCalculationInfo

- `MTNetworkUsageCalculationInfo` (`h/MTNetworkUsageCalculationInfo.h`): `filePath` and four int32 slot
  indices `incomingWWANKey, outgoingWWANKey, incomingOtherKey, outgoingOtherKey`.
- File format: a flat array of native-endian (little-endian) `int64` counters; slot `k` lives at byte
  offset `k * 8` (`MTNetworkUsageManager.m:12-27, 115, 137`). Unwritten slots read as 0 (short read leaves
  the zero-initialised value; holes read as zeros). No header, no versioning, no locking.
- TelegramCore layout (`TC/Network/Network.swift:165-215`): file `<basePath>/network-stats`;
  `key = category*4 + connection*2 + direction` with category `generic 0, image 1, video 2, audio 3, file 4,
  call 5, stickers 6, voiceMessages 7`, connection `cellular 0, wifi 1`, direction `incoming 0, outgoing 1`;
  slots 80 and 81 hold the reset timestamps for Wi-Fi and cellular. Interface mapping:
  `MTNetworkUsageManagerInterfaceWWAN = 0` ↔ cellular, `…Other = 1` ↔ Wi-Fi.
- Accounting points: `GCDAsyncSocket` adds every successful `read()`/`write()` byte count
  (`GCDAsyncSocket.m:4691, 5648`), so the counts are TCP payload bytes including MTProto framing and
  obfuscation but excluding TCP/IP headers; `NetworkFrameworkTcpConnectionInterface` does the same per
  send/receive (`TC/Network/NetworkFrameworkTcpConnectionInterface.swift:263, 354`); TelegramCore adds call
  traffic directly (`TC/Network/Network.swift:278-287`).
- A new `MTNetworkUsageManager` is created per socket connection (`GCDAsyncSocket.m:2315, 2466`) and per
  stats query, each with its **own** private serial queue (`:174`, unnamed `MTQueue`, always async).
- Flush cadence: `add*Bytes` accumulates into in-memory per-interface dictionaries and arms a **1.0 s**
  one-shot timer (`:58-67`); `sync` opens the file `O_RDWR|O_CREAT, 0600`, and for each pending interface
  does `lseek; read 8; += pending (truncated through intValue); lseek; write 8`, closes, clears pending
  (`:69-98`). `sync` also runs on dealloc, before `resetKeys`, and before `currentStatsForKeys`.
- `resetKeys:setKeys:completion:` zeroes listed slots and writes explicit values (`:110-129`);
  `currentStatsForKeys:` returns `{key: int64}` via an `MTSignal` (`:131-147, 234-243`).
- Wi-Fi/WWAN classification on the GCDAsyncSocket path: after `connect`, the local address is matched
  against `getifaddrs`; `isWifi` starts as `true` and the loop only ever assigns `true`
  (`GCDAsyncSocket.m:2425-2469`), so every connection counts as "Other" (Wi-Fi) and
  `MTRequestResponseInfo.networkType` is always 0 (`GCDAsyncSocket.m:5116`). Only the Network.framework
  interface distinguishes cellular.

### 8.7 MTKeychain

Protocol (`h/MTKeychain.h:5-12`):

```
setObject:(id)object forKey:(NSString*)key group:(NSString*)group
dictionaryForKey:group: -> NSDictionary?
numberForKey:group:     -> NSNumber?
removeObjectForKey:group:
```

- Synchronous, called from `MTContext.contextQueue` (section 2 lists the keys and groups, e.g.
  `"persistent"` / `"datacenterAuthInfoById"`, `"datacenterManuallySelectedSchemeById_v1"`).
- `MTDeprecated.unarchiveDeprecatedWithData:` (`MTKeychain.m:3-16`): `NSKeyedUnarchiver
  unarchiveObjectWithData:` (non-secure coding) wrapped in `@try`, nil on exception.
- TelegramCore implementation `Keychain` (`TC/Network/Network.swift:1327-1381`): storage key
  `"<group>:<key>"`; value = `NSKeyedArchiver.archivedData(withRootObject:requiringSecureCoding: false)` of
  the object (inside `MTContext.perform(objCTry:)`); getters unarchive with `MTDeprecated` and
  `assertionFailure` on a type mismatch. Backing store: the account's Postbox keychain table
  (`TC/Account/Account.swift:11-55`). Each `makeExclusiveKeychain` call bumps a per-account generation and
  older `Keychain` instances become inert (reads return nil, writes are dropped and logged), so only the
  newest context for an account persists anything.
- `MTFileBasedKeychain.h`/`.m` are empty files.
- Port implication: persisted MtProtoKit state is a set of `NSKeyedArchiver` graphs of ObjC classes
  (`MTDatacenterAuthInfo`, `MTDatacenterAddressSet`, `MTTransportScheme`, `MTTransportSchemeStats`, …).
  A Rust engine that must be switchable against MtProtoKit on the same account either reads and writes these
  archives or the Swift glue converts them; otherwise a switch loses auth keys (logout) or forces new keys.

### 8.z Constants

| Name | Value | file:line | Meaning |
|---|---|---|---|
| default `langPack` | `"macos"` / `"ios"` | `MTApiEnvironment.m:409-413` | overridden by TelegramCore with `languagesCategory` |
| default `langPackCode` | `""` | `:414` | TelegramCore uses `languageCode ?? "en"` |
| MTProxy secret length rules | 16 / 17 (`0xdd`) / ≥ 18 (`0xee` + domain) | `:105-130` | |
| backup discovery delay | 5 s (nil or reduced) / 20 s / 1 s DEBUG | `MTContext.m:1445-1451` | |
| usage flush delay | 1.0 s one-shot | `MTNetworkUsageManager.m:61` | |
| usage slot size | 8 bytes (`int64`), offset `key*8` | `:12-27` | |
| usage reset slots | 80 (Wi-Fi), 81 (cellular) | `TC/Network/Network.swift:202-205` | |
| usage file | `<basePath>/network-stats`, mode 0600 | `TC/Network/Network.swift:214`, `MTNetworkUsageManager.m:73` | |
| keychain storage key | `"<group>:<key>"`, NSKeyedArchiver value | `TC/Network/Network.swift:1338-1381` | |

## 9. Existing ObjC tests as regression cases

All 75 test methods in `Tests/` were added in September 2026, by seven commits. Each one encodes a bug that was found in the field or in an audit. Every test below should become a protocol-level test in the Rust engine. This section lists the tests, the fakes they rely on, and the behaviour that has no test yet.

### 9.1 Inventory

| Test file | # | Area | Fix commit(s) | Bug it pins |
|---|---|---|---|---|
| `Tests/MTAesFailureTests.m` | 9 | AES-IGE / CBC / CTR error handling | ebf1f9e538 | Release builds compiled out `assert(status)`. A failed IGE encrypt then put plaintext, shifted one block, on the wire under a valid msg_key. A failed CTR init gave an all-zero keystream. |
| `Tests/MTProtoMessageEncryptionTests.m` | 6 | MTProto 2.0 outgoing frame, padding | f8fbad6e16 | Byte-for-byte equality with the old encrypt path. The quick-ack id was 0 for non-container sends. Short key or unaligned plaintext was undefined behaviour. |
| `Tests/MTProtoIncomingDecryptTests.m` | 9 | MTProto 2.0 incoming frame, header parse | 44a188a19f | The padding bound was off by 32 bytes: frames with 993..1024 bytes of padding were dropped, and frames with fewer than 12 bytes were accepted. Also: tamper rejection and unaligned buffers. |
| `Tests/MTQuickAckTests.m` | 5 | Quick-ack token per framing | 616783c0a7 (+ f8fbad6e16) | The token was byte-swapped on intermediate framing too, so a quick-ack through an MTProxy never matched. |
| `Tests/MTGzipUnwrapTests.m` | 10 | gzip_packed, TL `bytes` decoding | 978e38e693 | A truncated wrapper raised before auth. Inflation had no ceiling. The 3-byte TL length was decoded through a signed shift, so 8 MiB and above went negative. |
| `Tests/MTDiscoverConnectionSignalsTests.m` | 13 | Scheme discovery under a proxy, retry backoff | c716a36b8e, dbb7a4ace1 | A connection storm through an unreachable proxy (bugs.telegram.org/c/64534). An empty probe list when there was no `static` address kept discovery spinning forever. |
| `Tests/MTTransferAuthRecoveryTests.m` | 9 | Auth-token transfer recovery | 1c68bb83d2 | A 10-hour DC 2 media stall: one 500 INTERDC_2_CALL_ERROR failed the transfer and nobody retried it. |
| `Tests/MTAuthKeyRecoveryTests.m` | 4 | Temp-key recreation recovery | 1c68bb83d2 | A failed key creation or bind was dropped silently, so waiting connections stayed stuck. |
| `Tests/MTLoggedOutCheckTests.m` | 4 | `checkIfLoggedOut` | 1c68bb83d2 | The 60 s throttle stored nil, so it never engaged. Any failed bind was reported as a logout. |
| `Tests/MTBackupAddressApplyTests.m` | 3 | Backup getConfig address apply | 1c68bb83d2 | The fetch compared against its throwaway context, so every fetch force-reset every datacenter. |
| `Tests/MTDiscoverDatacenterAddressActionTests.m` | 3 | Unknown-DC address discovery | 1c68bb83d2 | The action never registered as a listener, gave up after the first failed getConfig, and ran on two queues. |
| **Total** | **75** | | | Matches "MtProtoKitTests 75/75" in the 1c68bb83d2 commit body. |

`git log` on each test file confirms that every file has exactly the commit(s) listed. `MTTestSupport.{h,m}` came with 1c68bb83d2.

### 9.2 How the tests are built and run

- `BUILD:43-55` defines `MtProtoKitPrivateHeaders`, a testonly target that exposes `Sources/**/*.h`, so tests can import `MTInternalMessageParser.h`, `MTAes.h`, `MTBufferReader.h`, `MTDiscoverConnectionSignals.h` and others.
- `BUILD:57-71` defines `MtProtoKitTestsLib`, which compiles `Tests/**`.
- `BUILD:73-89` defines `ios_test_runner` (device "iPhone 17", OS 26.5) and `ios_unit_test MtProtoKitTests` (minimum OS 15.0). The tests run only through Bazel: `bazel test //submodules/MtProtoKit:MtProtoKitTests` on an iOS simulator.
- `Package.swift:27` excludes `Tests`, so the SwiftPM build that the macOS app uses never compiles or runs them. **No macOS run of these tests exists.**
- **The "macOS XCTest harness" with 108 tests and leak tests (commit 028f835528) is not in the repository.** I checked:
  - `git ls-files` in this worktree and in `submodules/telegram-ios`;
  - a grep of `*.pbxproj`, `*.swift`, `*.sh`, `*.py` and `*.json` for `MtProtoKitTests`, `MTTestSupport` and `xctest`;
  - the main checkout, the scratch dirs, and the leak-audit memory note.

  None of them contain it. The harness was a scratch setup that was never committed. Its 33 extra characterization and leak tests are therefore lost. They are listed in 9.5 so the Rust suite can rebuild them.
- An adjacent test lives outside MtProtoKit: `submodules/TelegramCore/Tests/ProxySettingsTests.swift` (12 cases, partly from 44a188a19f). It pins `tg://webproxy` link parsing and secret decoding:
  - a `0x70` marker followed by a 16-byte secret;
  - `dd`+16 bytes is kept as 17 bytes;
  - `ee` secrets are rejected for the WEB relay;
  - unknown query items are ignored.

  This is TelegramCore code, but it is part of the proxy contract that the Rust engine receives.

### 9.3 Test-support fakes and their seams

**Seams** (`Sources/MTInternalInterfaces.h`, all module-private):

- `MTContext.transferAuthActionFactory` (`MTInternalInterfaces.h:22`) and `MTContext.authActionFactory` (`:26`) replace the network half of token transfer and key creation. They are consumed in `MTContext.m:1550-1556` (`makeAuthActionWithSelector:`) and `MTContext.m:1605`. `checkIfAuthKeyRemovedWithContext` (`MTDiscoverConnectionSignals.m:358`) goes through the same factory.
- `-[MTDatacenterTransferAuthAction complete/fail]`, `+applyRetryPolicyToRequest:` (`MTDatacenterTransferAuthAction.m:30-38`).
- `MTDatacenterAuthAction.bindError` and `+bindErrorMeansPermanentKeyIsUnknown:` (`MTDatacenterAuthAction.m:40-42`). This returns true only for `code == 400 && desc == "ENCRYPTED_MESSAGE_INVALID"`.
- `+[MTBackupAddressSignals applyAddressList:toContext:]` (`MTBackupAddressSignals.m:213`).
- Private MTProto methods, declared in a test category (`Tests/MTTestSupport.h:30-38`):
  - `+managerQueue` (`MTProto.m:140`);
  - `-handleMissingKey:` (`MTProto.m:2090`), which is what a -404 or AUTH_KEY_PERM_EMPTY triggers;
  - `-canAskForServiceTransactions` (`MTProto.m:706`). It is false while any of AwaitingDatacenterScheme, AwaitingDatacenterAuthorization, AwaitingDatacenterAuthToken or Stopped is set.

**Fixtures** (`Tests/MTTestSupport.m`):

- `MTTestMakeContext(useTempAuthKeys)` (`:53-58`) builds a real `MTContext` with `isTestingEnvironment:true` and a default `MTApiEnvironment`. It has two stand-ins:
  - `MTTestSerialization`: layer 0, and every parser builder returns nil;
  - `EncryptionProvider`: a bare `NSObject`. Any crypto call through it would crash. The tests rely on no connection ever getting that far.
- `MTTestMakeAuthInfo()` (`:60-66`) returns a 256-byte random key with a random id, `validUntil = INT32_MAX`, and one salt `{salt 0, valid [0, INT64_MAX]}`.
- `MTTestMakeAddress()` (`:68-70`) returns `127.0.0.1:1`. Connects are refused, so an MTProto with a transport keeps reconnecting through `MTTcpConnectionBehaviour` for the whole test and never exchanges a message.
- `MTTestTransferAuthAction` (`:88-118`) overrides `execute:masterDatacenterId:destinationDatacenterId:authToken:` to record the call.
  - `succeed` calls `[context updateAuthTokenForDatacenterWithId:dest authToken:token]` and then `complete`.
  - `failWithError` calls `fail`.
- `MTTestAuthAction` (`:120-150`) overrides `execute:datacenterId:`.
  - `succeed` stores a fresh `MTTestMakeAuthInfo()` under the action's selector and then calls `complete`.
  - `failWithBindError:` sets `bindError` and calls `fail`.
- `MTTestActionRecorder` (`:152-232`) installs both factories and records every action under an `os_unfair_lock`, with `waitFor...Count:timeout:`.
- `MTTestProtoObserver` (`:234-260`) is an `MTProtoDelegate`. It sets `hasTransport = (state != nil)` from `mtProtoConnectionStateChanged:`. A nil state means that MTProto has no transport.
- `MTTestIsWaiting(proto)` (`:80-86`) evaluates `!canAskForServiceTransactions` synchronously on the manager queue.
- `MTTestWaitUntil` (`:11-20`) spins the run loop in 10 ms steps up to a wall-clock deadline.

**Reproducing these fakes in Rust:**

1. Make key creation and token transfer injectable traits on the context, for example `KeyCreator::create(dc, selector) -> Result<(), BindError>` and `TokenTransfer::run(master, dest, token) -> Result<()>`. A test double then completes or fails each call on command. Keep the dedup, backoff and notify logic in production code.
2. Expose a read-only snapshot of each session's wait flags (scheme / key / token / time-fix / paused / stopped) and of "has transport".
3. Drive time from a mockable clock (for example `tokio::time::pause` with `advance`). The ObjC tests use 0.5-10 s wall-clock windows. A virtual clock makes "retried after 1 s" and "not retried within 4 s" exact, and removes the flakiness.
4. Provide server-side helpers:
   - an MTProto 2.0 frame encoder (x = 8, `auth_key[96..128]`, server-to-client KDF);
   - quick-ack wire encoders (intermediate: raw LE word with bit 31 set; abridged: the same 4 bytes reversed);
   - a `gzip_packed#3072cfa1` builder;
   - a local TCP listener that accepts and immediately closes (needed for the lost leak and storm tests);
   - an unroutable or refused address, like `127.0.0.1:1`.

### 9.4 Per-test details

Each entry gives the scenario, what is asserted, and **R:** the Rust regression case.

#### 9.4.1 `MTAesFailureTests` (ebf1f9e538)

- `testIgeRoundTripStillWorks` (`:35`): 160 bytes, 32-byte key, 32-byte IV. Encrypt has the same length and differs from the input; decrypt returns the original.
  **R:** IGE round trip.
- `testIgeEncryptRejectsUnsupportedKeyLengthAndZeroesOutput` (`:47`): `MyAesIgeEncrypt` with a 7-byte key returns false, and the 64-byte output is all zeros.
  **R:** a cipher-init failure returns `Err` and leaves no plaintext-derived bytes in the output buffer.
- `testIgeEncryptRejectsNonBlockMultipleLength` (`:58`): `MTAesEncrypt` on 50 bytes returns nil. The raw call returns false with a zeroed output.
  **R:** a non-multiple-of-16 IGE input is an error, never a partial encrypt.
- `testIgeDecryptRejectsBadInputsAndZeroesOutput` (`:70`): `MTAesDecrypt(50 bytes)` returns nil. A 5-byte key returns false with a zeroed output.
  **R:** the same rules for decrypt.
- `testIgeZeroLengthIsANoOp` (`:83`): length 0 returns true for both directions, and the IV is unchanged.
  **R:** an empty IGE call is Ok and does not touch the IV. The old code read the IV out of bounds.
- `testRawHelpersReportFailure` (`:94`): `MTAesEncryptRaw` / `MTAesDecryptRaw` round-trip 48 bytes. Length 40 returns false and the output is zeroed.
  **R:** raw (slice) API with the same rules.
- `testInplaceHelpersWipeOnFailure` (`:110`):
  - `MTAesEncryptInplace` on 32 bytes returns true and changes the data;
  - on 30 bytes it returns false and the buffer is all zeros;
  - `MTAesEncryptBytesInplaceAndModifyIv` (returns void) on 30 bytes zeroes the data and leaves the IV untouched.

  **R:** an in-place encrypt failure wipes the buffer and does not advance the IV. The Rust API should also return `Err`.
- `testCbcDecryptReportsFailure` (`:131`): `MyAesCbcDecrypt` with a 3-byte key returns false and the output is zeroed. With a 32-byte key it returns true.
  **R:** CBC decrypt has the same rules. CBC is used by the fake-TLS / secret paths.
- `testCtrInitFailsClosed` (`:142`): `MTAesCtr` with a 9-byte key returns nil. With a 32-byte key, `encryptIn:out:len:100` returns true, and `MTAesCtrDecrypt` inverts it.
  **R:** constructing a CTR cipher with a bad key fails. An all-zero keystream is never produced. Obfuscated transport setup must close the connection on this error.

#### 9.4.2 `MTProtoMessageEncryptionTests` (f8fbad6e16)

The reference encrypt (`:12-39`):

- `msg_key_large = SHA256(auth_key[88..120] ‖ plaintext)`;
- `msg_key = msg_key_large[8..24]`;
- KDF V2 with `toClient:false`;
- `quickAck = LE32(msg_key_large[0..4]) & 0x7fffffff`;
- frame = `auth_key_id(8) ‖ msg_key(16) ‖ AES-IGE(plaintext)`.

Tests:

- `testEncryptedFrameMatchesReferenceImplementation` (`:61`): plaintext lengths {48, 64, 160, 1024, 4096, 524352}, 8 random keys each. The frame equals the reference byte for byte, its length is `24 + len`, the quick-ack equals the reference, and the quick-ack is ≥ 0.
  **R:** a known-answer vector set for client-to-server frames (generate from the ObjC code with fixed keys and plaintexts).
- `testEncryptedFrameDecryptsBackToPlaintext` (`:82`): 2048 bytes. Bytes 0..8 are the auth_key_id. Decrypting with msg_key from bytes 8..24 recovers the plaintext. msg_key equals `SHA256(key[88..120] ‖ pt)[8..24]`.
  **R:** client frame round trip.
- `testEncryptReturnsNilForShortAuthKey` (`:107`): a 64-byte auth key returns nil. The guard is `< 120` bytes (`MTProto.m:1565`).
  **R:** encrypting with a key shorter than 120 bytes is an error and the message is dropped.
- `testEncryptReturnsNilForUnalignedOrEmptyPlaintext` (`:112`): lengths 0, 63 and 65 return nil; 64 is accepted.
  **R:** plaintext must be a non-empty multiple of 16.
- `testPaddedPlaintextLayoutAndPaddingBounds` (`:120`): body lengths 0..200, 4 runs each, extended padding on and off. Asserts:
  - the length is a multiple of 16;
  - the header is `salt ‖ session_id ‖ msg_id ‖ seq_no ‖ len` (LE), followed by the body;
  - padding is between 12 and 72 (normal) or 12 and 256 (extended);
  - at least once over the runs, padding exceeds 27, which shows that the extra random padding is applied.

  The algorithm is in `MTProto.m:1529-1561`: take 12, round up to 16, then add `arc4random_uniform(max+1-take)` rounded down to 16.
  **R:** the padding generator always yields 12 ≤ pad ≤ 72 (or 256), with 16-byte alignment and a random extra.
- `testPaddingBytesAreRandom` (`:167`): over 16 builds of the same message, the 12 bytes at offset 72 are not all equal.
  **R:** padding comes from a CSPRNG and is not constant.

#### 9.4.3 `MTProtoIncomingDecryptTests` (44a188a19f)

The server-side frame helper (`:24-39`) uses x = 8 (`auth_key[96..128]`) and `toClient:true`.

- `testDecryptMatchesReferenceImplementation` (`:88`): body lengths {0, 4, 100, 1024, 4096, 524288}, with extended padding on and off. The new decrypt equals the reference and returns the exact padded plaintext.
  **R:** server-to-client known-answer vectors.
- `testTrailingPartialBlockIsIgnoredLikeBefore` (`:106`): 5 random bytes appended after the frame. The result is still the plaintext, because `encryptedLength = (len-24) & ~15` (`MTProto.m:2207`).
  **R:** up to 15 bytes of trailing junk (the padded-intermediate tail) are ignored, not rejected.
- `testTamperedFramesAreRejected` (`:116`): each of these returns nil:
  - one flipped ciphertext bit at offset 64;
  - one flipped msg_key bit;
  - one flipped auth_key_id bit;
  - a frame truncated to 59 bytes (minimum is `24 + 36 = 60`);
  - the wrong key;
  - a 64-byte key (needs ≥ 128 bytes).

  The msg_key compare is constant-time (`MTProto.m:2171-2177`).
  **R:** each kind of tampering yields `Err`. The minimum frame is 60 bytes, and the msg_key compare must be constant-time.
- `testInconsistentLengthFieldsAreRejected` (`:148`): body 16 with 1040 bytes of padding returns nil. A declared body of 2^20 bytes inside a 64-byte payload returns nil.
  **R:** reject `msg_len < 0`, `msg_len > len-32`, or padding outside 12..1024.
- `testPaddingBoundsAreAppliedAfterTheHeader` (`:193`):

  | Body | Padding | Result | Old code |
  |---|---|---|---|
  | 24 | 1000 | OK | rejected |
  | 16 | 1024 | OK | |
  | 16 | 1040 | nil | |
  | 24 | 8 | nil | accepted |
  | 20 | 12 | OK | |
  | 64 | 0 | nil | |

  The rule is in `MTProto.m:2224-2234`.
  **R:** padding is `len - 32 - msg_len` and must be in [12, 1024].
- `testUnalignedInputIsHandledByTheRawAesHelpers` (`:221`): frames and plaintexts at odd addresses (+3 / +1) give results identical to aligned ones.
  **R:** the crypto must not assume alignment, which matters for zero-copy slices in Rust.
- `testReadIncomingPayloadAuthorizedLayout` (`:244`): fields are read from fixed offsets 0/8/16/24. `topMessageSize = 0`. The body is everything after byte 32, padding included. A 31-byte input returns false.
  **R:** the encrypted-header parser. The body slice keeps its padding, so the TL parser must tolerate trailing bytes.
- `testReadIncomingPayloadUnauthorizedLayout` (`:264`): the layout is `auth_key_id(0) ‖ msg_id ‖ len(i32) ‖ body`, and salt, session and seq come out as 0. Each of these returns false:
  - a non-zero auth_key_id;
  - a declared length below 4;
  - a header shorter than 20 bytes.

  **R:** plaintext (handshake) message parser rules.
- `testServerFrameRoundTripsToBody` (`:301`): a 3000-byte body with extended padding goes through decrypt and parse, and all header fields and the body prefix match.
  **R:** the end-to-end incoming path.

#### 9.4.4 `MTQuickAckTests` (616783c0a7)

- `testClientTokenIsFirstWordWithoutFlagBit` (`:37`):
  - bytes `12 34 56 F8` give 0x78563412;
  - bytes `AA BB CC 0D` give 0x0DCCBBAA.

  The implementation (`MTQuickAck.m:7-11`) uses a native-endian `memcpy`, so it is correct on little-endian machines only.
  **R:** `token = u32::from_le_bytes(msg_key_large[0..4]) & 0x7fff_ffff`.
- `testIntermediateWireDecodesToClientToken` (`:45`): 256 random keys. Intermediate wire = LE word with bit 31 set; decoding it with `& 0x7fffffff` matches the token (`MTQuickAck.m:13-15`). Applies to intermediate and padded-intermediate, which covers every MTProxy connection.
  **R:** a length word with the top bit set on intermediate framing is a quick-ack. It is not byte-swapped.
- `testAbridgedWireDecodesToClientToken` (`:60`): abridged wire = the 4 bytes reversed, with the flag in the first byte (`0x80`). Decoding uses `OSSwapInt32` (`MTQuickAck.m:17-21`). The receive path reads the first byte, sees the 0x80 flag, and reads 3 more bytes (`MTTcpConnection.m:2061-2075`).
  **R:** abridged quick-ack decode.
- `testDecodedTokenNeverHasFlagBit` (`:73`): all three decoders return values ≥ 0.
  **R:** decoded tokens are always in `0..2^31`.
- `testEncryptedFrameReportsTokenMatchingItsMsgKeyLarge` (`:87`): end to end, the token returned by `_encryptedTransportDataForPaddedPlaintext` equals what both wire encodings decode to.
  **R:** the token recorded at send time matches the server's echo on both framings. Together with f8fbad6e16, this means single (non-container) messages carry a real quick-ack id.

#### 9.4.5 `MTGzipUnwrapTests` (978e38e693)

- `testNonGzipDataPassesThroughUnchanged` (`:36`): 40 bytes, 3 bytes and 0 bytes come back unchanged. Input shorter than 4 bytes returns the input (`MTInternalMessageParser.m:669-672`).
  **R:** a non-`0x3072cfa1` input passes through.
- `testGzipPackedWrapperRoundTripsForBothLengthForms` (`:44`): payloads of 16, 400 and 10000 random bytes cover both the short (<254) and `0xfe` TL length forms. 500 kB of zeros also round-trips.
  **R:** gzip_packed unwraps with both length encodings.
- `testTruncatedGzipPackedWrappersReturnNilWithoutRaising` (`:60`): five truncations return nil without raising:
  - the signature only;
  - `0xfe` with 1 length byte;
  - short-form length 10 with 3 bytes present;
  - `0xfe ff ff ff` with 4 bytes present;
  - a valid wrapper minus 8 bytes.

  **R:** truncated gzip_packed is `Err`. It must never panic, because this runs before auth on the handshake path.
- `testTruncatedGzipMemberIsRejectedByTheInflater` (`:89`): a gzip member cut by 10 bytes returns nil. Success requires `Z_STREAM_END` (`MTGzip.m:73`).
  **R:** inflate must reach end of stream, or the result is an error.
- `testMalformedGzipPayloadReturnsNil` (`:99`): random bytes inside the wrapper return nil. `decompress(random 64)` and `decompress(empty)` return nil.
  **R:** malformed deflate is `Err`.
- `testDecompressRefusesOutputAboveTheCeiling` (`:106`): 2 MiB of zeros compress to under 16 KiB. With `max` = 1 MiB or 2 MiB−1 the result is nil. With 2 MiB or 4 MiB it succeeds. The check is `result + chunk > max` (`MTGzip.m:61`), so an output of exactly `max` is allowed.
  **R:** an output-size ceiling that includes `max` itself. Decompression works in 16 KiB chunks.
- `testUnwrapAppliesTheUnpackedMessageCeiling` (`:118`):
  - `MTMaxUnpackedMessageLength == 2 × MTMaxTransportPayloadLength` (32 MiB and 16 MiB, `MTTransport.m:3-4`);
  - 32 MiB + 16 bytes is rejected;
  - exactly 32 MiB is accepted.

  **R:** the unpacked ceiling is 32 MiB inclusive and the transport ceiling is 16 MiB.
- `testBufferReaderDecodesLongTLLengthsUnsigned` (`:131`): a 0x800010-byte TL bytes value is read successfully.
  **R:** the 3-byte TL length is unsigned, up to 0xFFFFFF.
- `testBufferReaderRejectsOversizedTLBytesBeforeAllocating` (`:143`):
  - `fe ff ff ff 01 02` is false, and nothing is allocated (the length is checked first, `MTBufferReader.m:43-51`);
  - `02 'a' 'b'` without its padding byte is false;
  - `03 'a' 'b' 'c'` is "abc";
  - `02 'a' 'b' 00 …` consumes exactly 1 padding byte.

  The padding bytes are not checked to be zero.
  **R:** TL bytes parser rules: the declared length is checked against the remaining bytes, and padding to 4 bytes is mandatory.
- `testBufferReaderReadDataChecksBeforeAllocating` (`:171`): on a 10-byte buffer, `readData:11` is nil, then 4 and 6 succeed, then 1 is nil, and 0 gives empty.
  **R:** bounded slice reads.

#### 9.4.6 `MTDiscoverConnectionSignalsTests` (c716a36b8e, dbb7a4ace1)

The function under test is `probeAddressesForAddressList` (`MTDiscoverConnectionSignals.m:152-216`):

1. Filter to addresses where `media == preferForMedia && isProxy == preferForProxy`.
2. If that is empty, filter on the media match only.
3. If that is still empty, use the whole list.
4. Under an MTProxy (`secret != nil`) or a WEB relay, collapse to one address: the first IPv4, otherwise the first entry.

Alternate ports are `[80, 5222]` with no proxy and `[]` with any proxy (`:218-226`).

- `testWithoutProxyEveryAddressAndAlternatePortIsProbed` (`:47`): 3 addresses (one IPv6) give 3 probes, and the ports are `[80, 5222]`.
  **R:** no proxy means every address plus the alternate ports.
- `testSocksProxyKeepsAddressesButSkipsAlternatePorts` (`:61`): under SOCKS5, 2 of 3 addresses are proxy-preferred, so 2 probes and no alternate ports.
  **R:** the SOCKS5 probe list.
- `testMtProxyCollapsesToOneIpv4Address` (`:79`): [IPv6, v4 .50, v4 .50@167] gives one probe, `149.154.175.50`.
  **R:** MTProxy collapses to the first IPv4.
- `testMtProxyFallsBackToIpv6WhenThatIsAllThereIs` (`:96`): with only an IPv6 address, that address is used.
  **R:** the collapse falls back to the first entry.
- `testWebProxyCollapsesToOneAddress` (`:106`): a WEB relay (`webProxy:true`) gives 1 probe.
  **R:** WEB relay collapse.
- `testProxyWithNoProxyPreferredAddressesFallsBackToWholeList` (`:116`): no `static` address gives 2 probes under SOCKS and 1 under MTProxy, never 0.
  **R:** stage-2 relaxation under a proxy.
- `testFallbackWithoutProxyPreferenceStillExcludesMediaAddresses` (`:131`): with [media .51, .50, .50@167], MTProxy picks `.50`, not the media-only `.51`. SOCKS gives 2 probes, both non-media.
  **R:** stage 2 keeps the media match.
- `testFallbackReachesWholeListOnlyWhenMediaMatchIsEmptyToo` (`:153`): with only a media address and a non-media probe under SOCKS, there is 1 probe.
  **R:** stage 3 is used.
- `testEmptyAddressListYieldsNoProbes` (`:164`): an empty list gives `[]`.
  **R:** empty in, empty out.
- `testMediaFallbackStillAppliesUnderProxy` (`:169`): media discovery with no media address under MTProxy gives 1 probe.
  **R:** the media fallback runs before the collapse.

The retry function is `repeatSignal:withBackoffFrom:upTo:onQueue:` (`:228-258`). The next round starts only after the previous round *completes* plus a delay. The delay doubles up to the cap. Production uses 1 s → 15 s (`:324-325`) and a separate 30 s "optimal scheme" delay (`:326`).

- `testBackoffGrowsBetweenRoundsAndCaps` (`:197`): from 0.05 s up to 0.2 s, over 1.3 s.
  - There are 6-9 rounds; the expected starts are 0, .05, .15, .35, .55, … s.
  - gap[0] < 0.1 s, and gap[1] ≥ gap[0] and < 0.2 s.
  - Every later gap is between 0.15 and 0.4 s.

  **R:** under virtual time, the retry delays are exactly 1, 2, 4, 8, 15, 15, … s.
- `testBackoffStopsAtFirstValueWhenTakenOnce` (`:234`): the round emits on its 3rd start. `take:1` then delivers "scheme", completes, and runs exactly 3 rounds.
  **R:** the first emitted scheme stops the retry loop.
- `testDisposingDuringTheDelayStopsFurtherRounds` (`:259`): delay 0.1 s, disposed at 0.03 s, and there is exactly 1 round in 0.4 s.
  **R:** cancelling during a backoff delay stops all further probes. This prevents the storm.

#### 9.4.7 `MTTransferAuthRecoveryTests` (1c68bb83d2)

Setup: DC 2 has an address (media), a persistent key and no token. Each "download connection" is created with `requiredAuthToken:@2 authTokenMasterDatacenterId:1` and `media = true`. Its retry window is 10 s. The context backoff is `MTRetryDelayForFailureCount`: 1, 2, 4, 8, 16, 32 s, then 60 s (`MTContext.m:225-230`).

- `testSuccessfulTransferReleasesTheWaitingConnection` (`:87`): `resume` starts one transfer to DC 2 and there is no transport. After `succeed` there is a transport, and the transfer count is still 1.
  **R:** a missing token causes exactly one transfer. Getting the token releases the connection.
- `testConnectionCreatedAfterAFailedTransferAsksAgain` (`:104`): the first transfer fails, and a new connection starts transfer #2. Its success gives *both* connections a transport.
  **R:** a token update wakes every session waiting on that DC.
- `testTransferRequestsRetryInternalServerErrors` (`:131`): after `applyRetryPolicyToRequest`, `shouldContinueExecutionWithErrorContext` is set and returns true with `internalServerErrorCount = 25`. The request service retries a 500 after `+2.0 s` (`MTRequestMessageService.m:876-880`).
  **R:** the export and import requests retry a 500 after 2 s, with no cap. See §10 M37 for why "no cap" is questionable.
- `testFailedTransferIsRetriedWhileConnectionsWait` (`:147`): 4 connections cause exactly 1 transfer, with no second one within 0.5 s. After a failure, transfer #2 starts within 10 s, still with no third within 0.5 s. Its success gives all 4 connections a transport.
  **R:** one transfer per DC at a time. After a failure, the waiters re-ask after the backoff (`MTContext.m:1639-1666` notifies `contextDatacenterAuthTokenTransferFailed:`, and `MTProto.m:2688-2695` re-requests).
- `testConnectionPausedAcrossAFailedTransferAsksAgainOnResume` (`:177`): fail, then pause and resume, then transfer #2 starts within 10 s. Follows the field timeline 01:40:32 → 01:41:07 → 12:07:06.
  **R:** `resume` re-requests an awaited token (`MTProto.m:224-243`).
- `testConnectionPausedWhenTheRetryIsDueAsksOnResume` (`:198`): pause, then fail, then no transfer #2 within 3 s. Resume starts #2.
  **R:** a paused session does not drive retries, and resuming asks again.
- `testCancelledTransferLetsWaitingConnectionsAskAgain` (`:223`): `removeTokenForDatacenterWithId:2` while a transfer is in flight starts transfer #2. The cancel notifies the failure right away (`MTContext.m:1214-1231`).
  **R:** dropping a token mid-transfer re-triggers a transfer for the waiters.
- `testTokenDroppedAfterA401IsRetriedAfterAFailedTransfer` (`:245`): the connection starts with a token and has a transport. TelegramCore's 401 path is simulated: the token is set to nil and `authTokenForDatacenterWithIdRequired` is called, which starts transfer #1. After it fails, transfer #2 starts within 10 s, even though the awaiting flag was never set (`MTProto.m:2662-2673`).
  **R:** after a 401 (AUTH_KEY_UNREGISTERED) a parked request still gets its token, even if the first transfer fails.
- `testTempKeyLossWithAFailedTokenTransferRecovers` (`:269`): the full field sequence with temp keys.
  1. DC 2 starts with a persistent key, an EphemeralMedia key and a token, and has a transport.
  2. `handleMissingKey` (the -404) starts one EphemeralMedia auth action and one transfer, and the transport goes away.
  3. The key succeeds, the transfer fails, and transfer #2 starts within 10 s.
  4. It succeeds: the connection has a transport and is not waiting.

  **R:** after a -404 on a non-master DC with temp keys, both the key and the token are recreated, and a single transfer failure heals.

#### 9.4.8 `MTAuthKeyRecoveryTests` (1c68bb83d2)

Setup: DC 1 is the master and has persistent and EphemeralMain keys. The main connection uses temp keys and is resumed.

- `testRecreatedKeyReleasesTheWaitingConnection` (`:60`): not waiting at first. `handleMissingKey` starts one auth action (EphemeralMain) and the connection waits. After `succeed` it is no longer waiting.
  **R:** a -404 on a temp key recreates that selector's key and the session resumes.
- `testFailedKeyCreationIsRetriedWhileAConnectionWaits` (`:78`): the bind fails with 500 INTERNAL_SERVER_ERROR. Auth action #2 (EphemeralMain) starts within 10 s; the first backoff is 1 s (`MTContext.m:1712-1734`). Its success releases the connection.
  **R:** a failed key creation is retried with backoff while a session waits.
- `testBindRejectingThePermanentKeyIsNotRetriedOnATimer` (`:100`): the bind fails with 400 ENCRYPTED_MESSAGE_INVALID, and there is no auth action #2 within 4 s (`MTContext.m:1700-1708`).
  **R:** ENCRYPTED_MESSAGE_INVALID is never retried on a timer. See §10 H5: the session then stays stuck.
- `testConnectionPausedAcrossAFailedKeyCreationAsksAgainOnResume` (`:114`): pause, then the bind fails with 500, then no retry within 3 s. Resume starts #2 within 10 s, and its success releases the connection.
  **R:** the same pause and resume semantics apply to keys.

#### 9.4.9 `MTLoggedOutCheckTests` (1c68bb83d2)

- `testCheckIsThrottled` (`:64`): `checkIfLoggedOut(1)` starts one auth action. Two more calls start no second action within 1 s. The throttle is per DC, with a 60 s window (`MTContext.m:1774-1784`).
  **R:** the logout check runs at most once per DC per 60 s, and later calls do not restart the one in flight.
- `testTransientBindFailureIsNotALogout` (`:74`): a 500 bind failure produces no `contextLoggedOut` within 1 s.
  **R:** only ENCRYPTED_MESSAGE_INVALID counts as a logout.
- `testRejectedPermanentKeyIsALogout` (`:86`): a 400 ENCRYPTED_MESSAGE_INVALID produces exactly one `contextLoggedOut` within 5 s (`MTDiscoverConnectionSignals.m:358-364`).
  **R:** a bind rejection with ENCRYPTED_MESSAGE_INVALID signals a logout.
- `testBindErrorClassification` (`:98`): 400 ENCRYPTED_MESSAGE_INVALID is true. 500 INTERNAL_SERVER_ERROR, 400 TEMP_AUTH_KEY_EMPTY and nil (a bind answered with `boolFalse`) are false.
  **R:** the bind-error classifier truth table.

#### 9.4.10 `MTBackupAddressApplyTests` (1c68bb83d2)

Setup:

- DC 1 = [149.154.175.50:443];
- DC 2 = [149.154.167.41:443, 149.154.167.222:443 media];
- a listener counts `contextDatacenterTransportSchemesUpdated:shouldReset:true`.

Tests:

- `testUnchangedAddressListsResetNothing` (`:95`): applying identical lists returns false, with no reset within 1 s.
  **R:** applying an identical getConfig address list is a no-op.
- `testOnlyTheChangedDatacenterIsReset` (`:102`): a new DC 2 list returns true. DC 2 is reset and DC 1 is not, and the stored DC 2 list equals the new one. The change is applied with `forceUpdateSchemes:true` (`MTBackupAddressSignals.m:213-227`).
  **R:** only the changed DC's connections are reset.
- `testUnknownDatacenterIsAdded` (`:113`): an unknown DC 5 returns true and is stored.
  **R:** new DCs are added.

#### 9.4.11 `MTDiscoverDatacenterAddressActionTests` (1c68bb83d2)

The target DC 7 is unknown. `MTTestDiscoverAction` (`:28-83`) records `askForAnAddressDatacenterWithId:` and passes it to the real code only while `passThrough` is set.

- `testDiscoveryContinuesOnceTheSourceDatacenterHasAKey` (`:118`):
  1. Only DC 1 is known and it has no key, so DC 1 is asked.
  2. That starts one Persistent auth action, and the action now listens for the key (`MTDiscoverDatacenterAddressAction.m:122-128`).
  3. After `succeed`, DC 1 is asked a second time, and the action has not finished.

  **R:** discovery waits for the source DC's permanent key and then continues.
- `testFailedAttemptAsksTheNextKnownDatacenter` (`:140`): DCs 1 and 3 are known.
  - The first ask goes to one of them; dictionary order means it is not fixed which.
  - After `getConfigFailed`, a different DC is asked.
  - After a second `getConfigFailed`, the action is finished with exactly 2 asks (`:172-192`).

  **R:** try each known DC once, then finish.
- `testFailedKeyRequestForTheSourceDatacenterIsRetried` (`:166`): the source DC's key creation fails (nil bind error), and auth action #2 (Persistent) starts within 10 s through `contextDatacenterAuthInfoRequestFailed:` (`:148-155`). Its success leads to the second ask.
  **R:** a failed source-key creation is retried.

### 9.5 Lost tests from 028f835528 (rebuild them in Rust)

The commit body describes four leak and storm tests from the uncommitted macOS harness:

1. **Context release:** a context whose `discoverBackupAddressListSignal` captures the context must be deallocated once it is released. Before the fix it was never released.
   **R:** dropping the last handle to a context with a backup-discovery source frees it (`Arc` cycle check).
2. **Listener boxes:** 300 request services plus 100 block listeners leave ≤ 4 dead listener boxes; before the fix there were 400. Dead boxes are pruned in `addChangeListener:` (`MTContext.m:529`).
   **R:** listener registries never grow with dead entries.
3. **Cancelled backup fetch:** a fetch against a local server that accepts and then closes must open 0 new connections within 4.5 s of dispose, and its temp context must be freed about 0.01 s after dispose. Before the fix it opened 5 more connections. The fix is `mtProto stop` plus `cancelPendingActions` (`MTBackupAddressSignals.m:303-304`, `MTContext.m:431`).
   **R:** cancelling a backup config fetch stops its handshake reconnect loop at once.
4. **Invalid proxy secrets:** 64 invalid 256 KB proxy secrets leak 0 bytes; before the fix they leaked 8.4 MB (`parseHexString`, `MTApiEnvironment.m:13`). This is not relevant in Rust beyond the fuzzing case "invalid hex secret returns `Err`".

### 9.6 Coverage gaps (todo list for the Rust test suite)

None of the following behaviours has any MtProtoKit test.

- **Session/protocol:**
  - msg_id generation and monotonicity across a time-difference change;
  - seqno content/non-content rules;
  - container packing limits (`MTMaxUnacknowledgedMessageSize = 1 MiB`, `MTProto.m:71`) and the container→children mapping;
  - acks: batching and their piggyback on outgoing transactions;
  - `msg_resend_req`, `msgs_state_req/info`, `msgs_all_info`, `msg_detailed_info` / `msg_new_detailed_info` (`MTProto.m:2502`);
  - `new_session_created` (`MTProto.m:2546`), `destroy_session`, `ping_delay_disconnect` cadence;
  - outgoing gzip.
- **bad_msg_notification:**
  - codes 16/17 trigger a time sync, 32/33 reset the session, 48 triggers a time sync (`MTProto.m:2436-2465`);
  - 18/19/20/34/35/64 fall through to `default: break`, and only `messageDeliveryFailed` is sent;
  - the `bad_server_salt` path (salt valid for 30 min from the incoming msg_id, `MTProto.m:2418-2428`);
  - future_salts and salt rotation.
- **Time sync:** `MTTimeSyncMessageService` and the time-fix ping path (`MTProto.m:1387-1410`).
- **Requests:**
  - initConnection/invokeWithLayer wrapping and re-wrap after an api-environment change;
  - FLOOD_WAIT_X / FLOOD_PREMIUM_WAIT_X / 420 parsing (`MTRequestMessageService.m:905-956`);
  - the 500 retry delay;
  - `*_MIGRATE_*` errors, the 401 AUTH_KEY_UNREGISTERED surfacing, `rpc_drop_answer`;
  - request timeouts, cancellation, dependency ordering;
  - quick-ack → `applyAcknowledgedMessage` end to end;
  - AUTH_KEY_PERM_EMPTY → `handleMissingKey` (`MTProto.m:2034-2040`).
- **Handshake:**
  - req_pq / req_DH_params / set_client_DH_params steps;
  - RSA_PAD and the fingerprint choice;
  - DH safety checks (`MTCheckIsSafeG`, `GAOrB`, prime);
  - `expires_in` for temp keys;
  - the server-time fix from the handshake;
  - the bindTempAuthKey inner message (V1 encryption) and its frame.
- **Transport:**
  - abridged, intermediate and padded-intermediate framing;
  - frame length bounds: abridged is ≤ 4 MiB (`MTTcpConnection.m:1937`), intermediate is ≤ 16 MiB (`:1973`), and neither has a test;
  - the obfuscation header: forbidden first words `0x44414548/0x54534f50/0x20544547/0x4954504f/0xdddddddd/0xeeeeeeee` (`MTTcpConnection.m:1354-1359`), the protocol tags `0xefefefef/0xdddddddd` (`:1282-1284`), and the DC id field;
  - MTProxy secret parsing (plain / `dd` / `ee`+domain);
  - the fake-TLS ClientHello (template, GREASE, X25519 key, HMAC digest) and the server-hello check;
  - SOCKS5 with and without auth;
  - the WEB relay transport;
  - `MTTcpConnectionBehaviour` reconnect backoff;
  - the 20 s connect watchdog;
  - transport scheme selection, IPv6 preference and `MTTransportSchemeStats`.
- **Context:**
  - keychain persistence format (auth infos, tokens, salts, address sets, `authTokenById`);
  - the address-set equality rule, which is order-sensitive (`MTDatacenterAddressSet.m:32-47`);
  - transport-scheme reset propagation;
  - `cancelPendingActions`;
  - the `MTBackupAddressSignals` fan-out with the +5 s staggering (`MTBackupAddressSignals.m:338`);
  - the success path of `checkIfLoggedOut`.
- **Accounting:** `MTNetworkUsageManager` file format and counters, and `MTApiEnvironment` serialization (device/system/lang/proxy JSON params).
- **Memory bounds:** the growth of `MTSessionInfo` processed and sent id sets (028f835528 reports about 69 KB/h).

## 10. Suspected bugs and fragile spots

Every item below was found while reading the current sources and re-checked against them; the ones marked
**(verified)** were additionally re-read line by line while assembling this document. Nothing here was
reproduced at runtime unless stated. Severity: **H** = can wedge connectivity, lose data or grow without bound
under realistic conditions; **M** = wrong behaviour in plausible edge cases, or a measurable cost; **L** =
latent, cosmetic, or parity notes.

"Rust" gives the recommended stance: **Fix** (do better from day one; parity tests must not pin the bug),
**Copy** (reproduce for parity, the behaviour is observable or relied upon), **Decide** (needs an explicit
owner decision; write a test either way).

### 10.1 High severity

**H1. A single `-429` mutes the MTProto for good. (verified)**
`MTProto.m:1978-1992` sets `_isConnectionThrottled = true` and allocates `_unthrottleConnectionTimer`
(5.0 s) but never calls `-start` (`MTTimer.m:63-80` only arms in `start`). `requestTransportTransaction`
returns early while throttled (`MTProto.m:658`); the flag is cleared only inside the never-fired block
(`:1988`). The only sends left are transport-initiated (pump on reconnect `MTTcpTransport.m:416`, ping
resend). Listed as "not changed" in 028f835528. Rust: **Fix**: treat -429 as close + back off (5 s, growing)
+ reconnect.

**H2. Salts: future salts are never fetched; every salt is a synthetic 30-minute window. (verified)**
- `MTTimeSyncMessageService` is added only from `initiateTimeSync` after `AwaitingTimeFixAndSalts` is set
  (`MTProto.m:398-425, 577-588`); while that bit is set `canAskForTransactions` is false (`:700-703`), so the
  service is never polled (`:998`) and `get_future_salts` is never sent. Its completion uses a 3-argument
  selector MTProto does not implement (`MTTimeSyncMessageService.m:206-207` vs `MTProto.m:2722`).
- Salts therefore come only from `bad_server_salt`, stored as valid for 30 min from the notification's msg_id
  (`MTProto.m:2418-2428`). `new_session_created.server_salt` is ignored (`:2546-2557`). The salt derived in the
  DH handshake is computed and discarded; new keys start with salt 0 = "missing"
  (`MTDatacenterAuthMessageService.m:704-711`, `MTDatacenterAuthAction.m:115,128,164`).
- Impact: every new key, every bind and every ~30 min per MTProto, all traffic of that MTProto stops for one
  round trip (time-fix ping → `bad_server_salt`) and the UI shows "Updating".
- Rust: **Fix** the mechanism (use the handshake salt and `server_time`, `get_future_salts`, store the
  `new_session_created` salt); **Copy** only the observable rule that `isPerformingServiceTasks` is true while
  salts or time are genuinely missing.

**H3. One unparseable message drops the whole packet and resets the session; server `msg_resend_req` is always
unparseable. (verified)**
`_parseIncomingMessages:` returns nil for the whole container if any child fails (`MTProto.m:2340-2352`); the
caller reports a scheme failure, fails the connection's transactions and calls `resetSessionInfo:false`
(`:2047-2058`). Any constructor unknown to both `MTInternalMessageParser` and TelegramCore's `Api.parse`
triggers it. `msg_resend_req` is parsed without skipping the `vector#1cb5c415` constructor, so the count is
read as 0x1cb5c415 and parsing fails (`MTInternalMessageParser.m:362-377`); TelegramApi does not know the
constructor either. Impact: sibling `rpc_result`s and updates are lost, a new session id is generated, every
in-flight RPC is re-sent; a server that keeps re-sending the same unknown object causes a reset loop. Rust:
**Fix**: parse per message, ack and skip unknown bodies, reserve session resets for header-level corruption;
answer `msg_resend_req`.

**H4. Writes queued before a connection is ready are never completed when it closes. (verified)**
`sendDatas:` queues while `_readyToSendData == false` (`MTTcpConnection.m:1451-1456`); `closeAndNotifyWithError:`
does not drain `_pendingDataQueue` (`:1196-1215`). For fake-TLS the transport sees "opened" at TCP connect and
pumps a transaction whose bytes wait for the ServerHello; SOCKS5 is similar. If the handshake fails, the
`MTTransportTransaction` completion never fires, the request keeps `requestContext{waitingForMessageId=true,
transactionId=nil}` (`MTRequestMessageService.m:711-715`), is skipped by the scheduler (`:599`) and is not
matched by `transactionsMayHaveFailed` (needs a transaction id, `:1159-1175`). Only a transport replacement
(`MTProto setTransport:` → `allTransactionsMayHaveFailed`) frees it. Impact: RPCs over a flaky fake-TLS or
SOCKS proxy hang while reconnects inside the same transport succeed. Related: `MTMessageTransaction.failed`
is never invoked anywhere, and `MTTcpTransport` skips the completion for empty payloads and deallocated
transports (`MTTcpTransport.m:661-667`). Rust: **Fix**: every queued write completes (`false`) on close; a
"prepared but not written" request has a guaranteed terminal transition.

**H5. Logout is never detected on temp-key connections; a revoked permanent key loops one DH + bind per resume.**
`checkIfLoggedOut:` is reached only from the persistent-selector, no-token, `!canResetAuthData` branch of
`handleMissingKey:` (`MTProto.m:2158-2165`). With temp keys (every TelegramCore connection except CDN) a
-404/`AUTH_KEY_PERM_EMPTY` recreates the temp key; if the server no longer knows the permanent key the bind
fails with `400 ENCRYPTED_MESSAGE_INVALID`, and `_authActionFinished` deliberately neither retries nor notifies
(`MTContext.m:1700-1708`). The connection waits in `AwaitingDatacenterAuthorization`; each `resume` re-asks
(`MTProto.m:240-243`) and runs a full, doomed DH + bind. `contextLoggedOut:` never fires on this path. Rust:
**Fix**: a bind rejected with `ENCRYPTED_MESSAGE_INVALID` means "permanent key unknown": confirm once and emit
the logged-out event; keep backoff on resume-driven retries too.

**H6. The backup config fetch starts every per-address MTProto eagerly; the delayed ones are never disposed.**
`fetchBackupIps` calls `fetchConfigFromAddress` for every backup address inside `mapToSignal`
(`MTBackupAddressSignals.m:332-337`); that function creates the temp context and MTProto and calls `resume`
(`:245-270`) before its signal is subscribed. Signals 2..N are wrapped in `delay:5,10,...` and merged with
`take:1`; if address 1 wins first, the delayed signals are disposed before their generators run, so their
dispose blocks (stop + `cancelPendingActions`) never exist. Listed as "not changed" in 028f835528. Impact:
on DPI networks where TCP connects but the handshake never completes, every backup round leaves N−1 MTProtos
reconnecting for the process lifetime; rounds repeat every 5-20 s while problems persist (see M17). Rust:
**Fix**: create the connection lazily on subscription; tie its lifetime to the subscription.

**H7. Handshake failures retry immediately and without limit.**
Every failure inside `MTDatacenterAuthMessageService` calls `reset:` = new nonce, transport reset, restart at
`req_pq_multi`, with no counter or delay (`MTDatacenterAuthMessageService.m:154-187`, table in §5.9). A nil
RSA_PAD result re-sends `req_pq_multi` with the same nonce at network RTT without even resetting the transport
(`:525-530`). Deterministic triggers: an unparseable CDN key chosen by the single-key fallback (`:423-425`), a
DC or proxy that always answers with a transport error, a non-safe prime. The context-level 1..60 s backoff
never engages because the action only reports `fail` on bind errors. Rust: **Fix**: count consecutive
handshake failures per (dc, selector), back off (1, 2, 4 ... 32, 60 s), fail the action after N attempts.

**H8. A response the client cannot parse is retried every 2 s forever, each time with initConnection.**
A nil `responseParser` result becomes `500 TL_PARSING_ERROR` and the stored init hash is set to `""`
(`MTRequestMessageService.m:809-825`); the generic 500 branch then restarts after 2 s whenever the gate
returns true (`:873-881`), and TelegramCore's gate returns true unless a flood wait was seen
(`TC/Network/Network.swift:1168-1179`). Impact: schema drift or an unknown constructor in a result turns
into an endless re-execution loop (duplicated side effects for non-idempotent calls). Rust: **Fix**: a
local parse failure is terminal (or retried once) and surfaces a distinct error; do not wipe init state.

**H9. Scheme discovery can wedge per DC; discovered schemes rarely reach a connection.**
- Discovery is de-duplicated per DC only (`MTContext.m:1271-1273`) and captures its probe list when built
  (`:1275-1286`). Started while the DC has no addresses, it loops on an empty list with 1→15 s backoff forever
  (`MTDiscoverConnectionSignals.m:319-336`); later `updateAddressSet...forceUpdateSchemes:false` does not
  restart it and every later invalidation is a no-op because the slot is occupied.
- A winning alternate-port scheme (80/5222) is stored but never used: `transportSchemesForDatacenterWithId`
  only honours a manual scheme whose full address is in the current set (`MTContext.m:1072-1095`).
- Live transports never see new schemes: `-[MTTcpTransport updateSchemes:]` has no callers
  (`MTTcpTransport.m:801-818`); discovery notifies `shouldReset:false`, which MTProto ignores unless it was
  waiting for a scheme (`MTProto.m:2579-2597`); reconnects choose from the list frozen at transport creation.
- Rust: **Fix**: key discovery by (dc, media, proxy), rebuild the probe list per round, end a round with an
  empty list, re-read the scheme list on every dial.

**H10. Routine transport errors (the daily temp-key `-404`) are treated as "the path is broken", and proxy
probing then never stops. (verified for the probe loop)**
For every 4..19-byte transport error MTProto calls `decodeResult(false)` (`MTProto.m:1961-1962`) →
`connectionIsInvalid` → `transportConnectionProblemsStatusChanged(true, isProbablyHttp:true)`
(`MTTcpTransport.m:498-510`) → scheme failure + `invalidateTransportScheme` → scheme discovery and a backup
DoH fetch after 5-20 s (`MTContext.m:1436-1454`) and, behind a proxy, proxy probing (`MTProto.m:831-846`).
Probing (`ICMP to google.com/8.8.8.8 + proxy ping` every ~25 s) stops only on `hasConnectionProblems:false`,
which `MTTcpTransport` never emits, and it is not disposed by `pause`/`stop`, only by `dealloc`. Temp keys
expire every 24 h and expiry is only discovered through -404, so this fires daily on every account. Rust:
**Fix**: separate "server rejected us" from "bytes are not MTProto"; stop probing on the first decoded frame,
on pause/stop and on proxy change.

**H11. An ephemeral auth action can hang forever and then blocks its slot.**
After DH, the bind branch only runs `if (persistentAuthInfo != nil)` (`MTDatacenterAuthAction.m:134-135`);
otherwise the action neither completes nor fails. It stays in `_datacenterAuthActions`, so every later request
for that (dc, selector) is swallowed (`MTContext.m:1563`). Reachable when the persistent key is dropped during
the handshake (logout, -404 on a persistent connection). Related: re-executing parked actions when a
persistent key appears also re-executes running ones and overwrites their `_authMtProto` without stopping it
(`MTContext.m:813-820`, `MTDatacenterAuthAction.m:75`). Rust: **Fix**: explicit parked/running states; a
missing persistent key at bind time is a failure or an explicit re-park.

**H12. Delivery is at-least-once with a new msg_id after every connection change.**
`transactionsMayHaveFailed:` and `mtProtoAllTransactionsMayHaveFailed:` clear the context of every request
sent on the connection, including ones the server already acked (`MTRequestMessageService.m:1159-1193`); any
`setTransport:` (pause, resume, scheme or proxy change) triggers the latter. The late answer to the old msg_id
is dropped as "didn't match" (`:1074-1078`). Impact: duplicate execution of non-idempotent calls, large file
parts transferred twice under flapping networks. TelegramCore relies on `random_id` where it matters. Rust:
**Decide**: this is the parity baseline and observable; a TDLib-style design (same msg_id within a session,
`msgs_state_req` to resolve uncertainty) is safer. Pin the chosen behaviour with tests.

### 10.2 Medium severity

| ID | Finding | Evidence | Rust |
|---|---|---|---|
| M1 | **Obfuscation header check is wrong.** The forbidden-prefix test reads the *encrypted* header bytes (never sent), runs only with a proxy secret, and lacks the spec's `first byte != 0xef` and `bytes 4..8 != 0` rules. About 1/256 direct dials start with `0xef`, which the server may parse as unobfuscated abridged. (verified) | `MTTcpConnection.m:1274-1364` | Fix: apply the spec/TDLib rules to the plaintext header for every connection |
| M2 | **Unbounded per-session state.** `_processedMessageIdsSet`, `_sentMessageIdsSet`, `_containerMessagesMappingDict` are cleared only by a new session (~69 KB/h, ~11 MB/week measured in 028f835528); pending acks grow while nothing can be sent, are deduped by O(n) scan, and every `msgs_ack` carries all of them (no 8192 cap). | `MTSessionInfo.m:79-81, 151-165`; `MTProto.m:1041-1048` | Fix: replay window (~300 s + slack), split acks |
| M3 | **Stale cached key and cross-connection key churn.** `_validAuthInfo` is refreshed only when this MTProto was awaiting the selector; a key replaced by another connection keeps being used, and its -404 then deletes the *new* key everyone else uses. | `MTProto.m:2599-2640, 2155-2158` | Fix: read the current key per send; drop only the key id that failed |
| M4 | **Temp-key expiry is reactive only.** `validUntilTimestamp` is checked only at keychain load (local clock); the bind `expires_at` uses server time; nothing rotates before expiry, so every 24 h per (dc, selector) in-flight requests stall through -404 → DH → bind → time-fix (6-8 RTTs). | `MTContext.m:476-492`; `MTDatacenterAuthMessageService.m:713`; `MTBindKeyMessageService.m:56` | Fix: rotate at ~80-90 % of lifetime in server time |
| M5 | **Media bind hack (macOS maintainer, 2024-07, reverted once upstream and re-applied).** On the bind connection a -404 over a media scheme calls `complete` on all services; the bind service reports success and the unbound media temp key is stored as bound. A non-media bind -404 resets and resends with no backoff. See §5.7. | `MTProto.m:2107-2116`; `MTBindKeyMessageService.m:173-175`; `MTDatacenterAuthAction.m:163-168` | Decide: treat -404 during bind as a bind failure unless the field issue is understood |
| M6 | **DH results are not left-padded to 256 bytes.** `MTExp` returns minimal big-endian (`BN_num_bytes`); an `auth_key` with a leading zero byte fails the `new_nonce_hash1` check and the whole handshake restarts (~1/256). `g_b` is also unpadded and not range-checked. (verified) | `MTDatacenterAuthMessageService.m:696-698`; `OpenSSLEncryptionProvider.m:154-162` | Fix: fixed 256-byte encoding; check `g_b` |
| M7 | **Remote crash on a hostile resPQ.** `pq` of 0 or 1 divides by zero in `MTFactorize` (traps on x86_64); `pq` longer than 8 bytes is silently truncated; resPQ is unauthenticated (any MITM or malicious MTProxy). | `MTEncryption.m:544-545`; `MTDatacenterAuthMessageService.m:438-443` | Fix: validate `2 <= pq < 2^63`, length <= 8 |
| M8 | **Handshake resends reuse the old msg_id/seqno** after a transport failure, so a long stall can resend an id older than the server's 300 s window and be silently dropped. | `MTDatacenterAuthMessageService.m:856-872`; `MTProto.m:1089-1098` | Fix: fresh msg_id per unencrypted send |
| M9 | **Backup blob RSA output not zero-padded.** The decrypted integer is copied right-aligned into the input buffer without clearing the leading bytes, so ~1/256 valid DoH blobs fail the SHA check. (verified) | `MTEncryption.m:880-884` | Fix: left-pad with zeros |
| M10 | **Phone-prefix rules in simple config.** The last rule decides and any non-matching rule excludes (`"+7,+380"` excludes `+7…`). | `MTEncryption.m:1084-1098` | Decide: compare with tdesktop/TDLib first |
| M11 | **Password-required flag is sticky and blocks MtProtoKit's own requests.** Set on `401 SESSION_PASSWORD_NEEDED`, never cleared; internal getConfig/export/import keep `dependsOnPasswordEntry = true` and are skipped; the request-service listener meant to react is released immediately. | `MTRequestMessageService.m:92-100, 565-566, 850-855`; `MTRequest.m:73` | Fix: do not port the gate, or scope and clear it |
| M12 | **Non-atomic read-modify-write of auth info** when storing the init marker (sync read, async write of the whole record) can resurrect a replaced key or delete a fresh one. | `MTRequestMessageService.m:837-846`; `MTContext.m:777-802, 1127-1135` | Fix: compare-and-set by `auth_key_id` |
| M13 | **Init-hash problems.** The marker stores the environment at response time, not the one sent; the hash formats `systemCode` with `NSData.description` (abbreviated for long data, so some changes do not re-init); it contains SOCKS credentials and the MTProxy secret and is logged and persisted; the `apiId` setter does not refresh it. | `MTRequestMessageService.m:405-421, 432, 840-846`; `MTApiEnvironment.m:336-341, 421-447` | Fix: hash the serialized initConnection; never log or persist credentials |
| M14 | **Cancelling one ≥512 KiB request resets the whole session**; `rpc_drop_answer` is never sent (line commented out), so the other in-flight parts on that worker restart. | `MTRequestMessageService.m:146-205, 163` | Decide: `rpc_drop_answer` is the intended mechanism |
| M15 | **`CONNECTION_NOT_INITED` retries immediately without a cap**; `500 MSG_WAIT_FAILED` handling is unreachable (the generic 500 branch catches it first). | `MTRequestMessageService.m:873-904, 961-972` | Fix: bounded retry; explicit check order |
| M16 | **Sticky flood-wait fields** (`floodWaitSeconds`/`floodWaitErrorText` never reset) make TelegramCore's gate re-report an old flood text on later 500s and refuse to retry them when `automaticFloodWait` is false. | `MTRequestMessageService.m:917-943`; `TC/Network/Network.swift:1168-1179` | Fix: pass a per-error classification to the gate |
| M17 | **Backup-discovery lifecycle.** `_backupAddressListDisposable` is cleared on whatever queue completes the signal (data race); rounds restart on every connection-problem report after 5-20 s, ignore the network-access gate and bypass the user's proxy (the derived environment drops it). | `MTContext.m:1436-1467`; `MTBackupAddressSignals.m:229-237` | Fix: own the task on the context executor, rate-limit, decide proxy fallback |
| M18 | **Keychain write churn.** Every decoded packet stamps scheme stats (5 s debounced whole-dictionary write, a Postbox transaction on macOS); every salt merge rewrites all auth infos; `updateAddressSet` rewrites and notifies even when unchanged. Only the IPv6 gate reads `lastResponseTimestamp`. | `MTProto.m:2060`; `MTContext.m:652-728, 1373-1408`; `MTProto.m:2733-2760` | Fix: coarse persistence, persist only changes |
| M19 | **Address-set equality is order-sensitive**, so a reordered getConfig list force-resets that DC's connections from the backup path. | `MTDatacenterAddressSet.m:32-47`; `MTBackupAddressSignals.m:213-227` | Decide: compare as sets if order is not significant |
| M20 | **Process-global queues and synchronous keychain I/O.** All accounts share one manager queue and one context queue; `setKeychain:` reads Postbox synchronously on the context queue while TelegramCore calls `globalTime` (sync onto the context queue) inside Postbox transactions: a possible deadlock cycle (code reading only, not reproduced). Also head-of-line blocking: a 1 MiB file part is decrypted on the queue that carries every account's updates. | `MTContext.m:444-527, 614-623`; `TC/.../EnqueueMessage.swift:593,913` | Fix: per-connection actors, `globalTime` from an atomic, no sync I/O on engine state |
| M21 | **Unsynchronized `MTContext` properties.** `apiEnvironment`, `keychain`, `makeTcpConnectionInterface` are nonatomic and read on other queues; `resetTransport` builds the scheme list from MTProto's copy of the environment but gives the transport the context's proxy, so the two can disagree during a proxy change. | `h/MTContext.h:90-99`; `MTProto.m:338, 355` | Fix: immutable snapshot per connection |
| M22 | **Fake-TLS reassembly can reorder bytes** (a record whose size equals the pending read length bypasses leftover buffered bytes), desynchronising AES-CTR. | `MTTcpConnection.m:1860-1877` | Fix: always append and consume from the front |
| M23 | **Zero-length TLS records stall the stream** (`readDataToLength:0` is ignored by GCDAsyncSocket, no further read scheduled). | `MTTcpConnection.m:1756, 1821-1832`; `GCDAsyncSocket.m:3896-3899` | Fix: skip empty records |
| M24 | **SOCKS5 CONNECT is IPv4-only** (ATYP 1 hard-coded, `inet_aton` result unchecked → uninitialised address bytes for IPv6 targets); IPv6 schemes are not filtered under SOCKS. SOCKS + an `ee` DC secret never sends a ClientHello but waits on the TLS read path. | `MTTcpConnection.m:1129-1158, 1494-1523, 1848-1850` | Fix: ATYP 4/3, run fake-TLS after CONNECT |
| M25 | **No handshake-level transport timeout.** SOCKS and fake-TLS reads use timeout -1, queued writes do not arm the response timer, the 20 s watchdog only reports; no `SO_KEEPALIVE`. | `MTTcpConnection.m:1158-1837`; `MTTcpTransport.m:304-347` | Fix: per-attempt handshake deadline that closes |
| M26 | **Response timeout semantics.** It is "first complete frame after a send": any unrelated update cancels it, a running timer is not re-armed by later sends, partial reads reset it to a flat 12 s, quick-acks do not touch it. False positives for slow RPCs on idle connections, false negatives otherwise. | `MTTcpConnection.m:1414-1475, 2011-2012` | Decide: copy for parity or track outstanding sends |
| M27 | **Fake-TLS timestamp uses the process-global HTTP `Date` offset** from the DoH fetch (0 until one succeeds), not the MTProto time difference; a skewed clock can get the hello rejected, and with H4 requests then hang. | `MTTcpConnection.m:1147`; `MTBackupAddressSignals.m:119-130` | Fix: use the server time difference |
| M28 | **Reachability churn.** One `MTNetworkAvailability` with a 5 s repeating poll per transport; any reachability-string change (including "became available") stops the live connection; offline does not gate dialing. Its `dealloc` calls `CFRelease` on a possibly NULL reachability. | `MTTcpTransport.m:715-729`; `MTNetworkAvailability.m:76-107`; `MTTransport.m:33` | Fix: one shared path monitor |
| M29 | **Network usage accounting.** On the GCDAsyncSocket path `isWifi` is only ever assigned `true`, so cellular bytes are booked as Wi-Fi and `networkType` depends on whether accounting is configured; the counters file is updated with unlocked read-modify-write by one manager per socket (and by extensions), truncating pending sums through `intValue`. | `GCDAsyncSocket.m:2425-2469, 5116`; `MTNetworkUsageManager.m:69-98, 174` | Fix: classify by path; single accumulator + `flock` |
| M30 | **Logout probe is vacuous or destructive.** `checkIfAuthKeyRemovedWithContext:` ignores its key argument; if an `EphemeralMain` key exists it reports "not removed" without network I/O; otherwise it runs an unregistered auth action whose success replaces the context's temp key (resetting every connection on it) and can race a normal key creation. The 60 s throttle uses the wall clock. | `MTDiscoverConnectionSignals.m:353-375`; `MTContext.m:1774-1809` | Fix: probe with a throwaway key through the deduplicated path, monotonic clock |
| M31 | **Incoming header validation is minimal.** Only the session id is checked; not the server msg_id parity, time window, seqno or salt. Replay protection is the processed-id set alone. | `MTProto.m:2265-2328` | Fix: TDLib-style checks, same result for valid traffic |
| M32 | **msg_id from the wall clock may go backwards.** On a backward step the smaller id is returned and stored; callers passing NULL (containers, time-fix ping, bind) ignore it, so a container id can be lower than its children's; callers with a pointer abandon the pass and reset the session. | `MTSessionInfo.m:91-109`; `MTProto.m:1145-1167, 1473` | Fix: `max(now_id, last + 4)` from a monotonic base |
| M33 | **Acks have no flush timer** and standalone messages are scheduled with size 0, so the 1 MiB trigger never fires for big standalone results; acks are withheld from transactions carrying high-priority messages. Idle connections leave updates unacked. | `MTProto.m:1036-1061, 2357-2408` | Fix: short flush delay, real sizes |
| M34 | **`MTResendMessageService` has no timeout**: if the server never answers `msg_resend_req`, `isPerformingServiceTasks` stays true ("Updating") forever. | `MTResendMessageService.m:78-122`; `MTProto.m:429-462` | Fix: bound it, fall back to re-requesting the RPC |
| M35 | **Service list mutated during fan-out.** Callbacks run inline and may add or remove services (resend completion, `takeConnectionForReusing`) while `_messageServices` is being iterated, forward (`for…in`, would raise) or reverse (skips or double-visits). | `MTProto.m:285-316, 637-644, 1015, 2517` | Fix: snapshot before every fan-out |
| M36 | **Idle sockets while waiting for a key.** `resetTransport` creates and dials a transport even while `AwaitingDatacenterAuthorization`; it sits idle and is replaced when the key arrives. | `MTProto.m:353-358, 2638-2640` | Fix: do not dial without a key |
| M37 | **Token-transfer retry is unbounded.** The transfer requests' gate always returns true, so a persistent 500 retries every 2 s and a long FLOOD_WAIT stalls every connection waiting for that DC; the context backoff and failure notification never engage. | `MTDatacenterTransferAuthAction.m:30-38`; `Tests/MTTransferAuthRecoveryTests.m:131` | Fix: cap, then fail to the context backoff |
| M38 | **Dependency resolution is inconsistent.** Static `invokeAfterMsg` picks the newest matching request, `MSG_WAIT_TIMEOUT` waits for the oldest; the dynamic decorator resolves only within the same transaction, otherwise the request goes out with no dependency. | `MTRequestMessageService.m:485-520, 641-665, 883-904` | Decide: explicit dependency edges |
| M39 | **Flood-wait and retry deadlines stop during sleep** (`mach_absolute_time`, `dispatch_time`). After a laptop sleeps through `FLOOD_WAIT_3600`, the client still waits the remaining awake time. | `MTTime.m`; `MTTimer.m:63-68` | Decide: continuous/wall time matches the server |
| M40 | **`MTRsaFingerprint` writes into a function-level `static` buffer**, called from the manager queue and from TelegramCore on arbitrary queues. | `MTEncryption.m:831-832` | Fix: local buffer |
| M41 | **Uncached safe-prime check (Miller-Rabin, 64 rounds on p and (p-1)/2) runs on the shared manager queue**, stalling every connection the first time a new prime appears; the `primes` keychain cache grows without bound. | `MTEncryption.m:629-698`; `MTDatacenterAuthMessageService.m:678` | Fix: off the I/O loop, bounded cache |

### 10.3 Low severity, latent, parity notes

| ID | Finding | Evidence |
|---|---|---|
| L1 | `addRequest:` silently drops requests (no completion) before the service is attached or after its MTProto is gone. | `MTRequestMessageService.m:121-139` |
| L2 | `timeout:onQueue:orSignal:` does not invalidate its timer on dispose and does not cancel the source on timeout; retains captures for up to 10 s (028f835528 note). `MTTimer -start` is not idempotent; repeating timers retain themselves. | `MTSignal.m:477-517`; `MTTimer.m:63-80` |
| L3 | `authSaltForMessageId:` never updates `bestValidMessageCount`, so it returns the last eligible salt, not the longest-lived; `mergeSaltSet:` keeps an existing entry on `firstValidMessageId` collision even if the salt differs. (verified) | `MTDatacenterAuthInfo.m:77-124` |
| L4 | `chooseTransportScheme...` returns nil for an all-IPv6 list with no recent IPv6 response; the transport then opens nothing and arms no watchdog. | `MTContext.m:1012-1054`; `MTTcpTransport.m:194-202` |
| L5 | Scheme discovery de-dup ignores media/proxy; the restart path always uses `media:false`. | `MTContext.m:717-725, 1271` |
| L6 | DoH handling: HTTP status unchecked; any response's `Date` header sets the global fake-TLS offset; TXT parts of equal length concatenate in undefined order; single host `dns.google.com`. | `MTHttpRequestOperation.m:32-44`; `MTBackupAddressSignals.m:120-154` |
| L7 | Listener fan-outs in the public-key paths iterate the live array; `performWithObjCTry:` has no `@catch`, so archiving exceptions are not contained. | `MTContext.m:329-334, 1152, 1167` |
| L8 | Process-lifetime caches: one `MTTemporaryKeychain` per backup `dc:ip:port`; the `cleanup` session-id store is loaded but its producer is dead. | `MTBackupAddressSignals.m:204-262`; `MTContext.m:891-948` |
| L9 | `MTProxyConnectivity.pingProxy` dials every address of the DC (IPv4 and IPv6), has no overall deadline, and reports failure only after every connection closes. | `MTProxyConnectivity.m:113-152` |
| L10 | `AUTH_KEY_PERM_EMPTY` interception returns before acks, dedupe and dispatch of the rest of the packet. | `MTProto.m:2027-2046` |
| L11 | Message ids prepared in an abandoned transaction (empty salt set) are reused later, often outside the server window → bad_msg 16/17 → resend. | `MTRequestMessageService.m:599, 609-615, 697-718` |
| L12 | Stall detector: one 5 s timer, reset by any inbound bytes, not re-armed after firing; a stalled request is never detected while other traffic flows. | `MTRequestMessageService.m:324-391` |
| L13 | `completed` is called while iterating `_requests`; TelegramCore removes the request inline; safe only because of the `break`. `requestMessageServiceDidCompleteAllRequests:` can fire twice. | `MTRequestMessageService.m:1053-1084, 195-200` |
| L14 | APNS/reCAPTCHA verification: a second challenge replaces the pending data without disposing the first signal; resolved secrets stay attached to all later retries. | `MTRequestMessageService.m:973-1039` |
| L15 | Lenient MTProxy secret parsing (`strtol` accepts `-1`, `+a`, ` a`; hex tried before base64url; unknown base64 characters ignored); `isEqual:` without `hash` on several value classes. | `MTApiEnvironment.m:13-33, 85-103`; `MTDatacenterAddressSet.m`; `MTTransportScheme.m` |
| L16 | Frame size limits differ by framing: abridged ≤ 4 MiB, intermediate ≤ 16 MiB. | `MTTcpConnection.m:1937, 1973` |
| L17 | Legacy `p_q_inner_data`/`_temp` constructors without `dc` are sent although the code comment names the `_dc` variants; `dh_gen_retry` restarts the handshake instead of resending with `retry_id`. (verified) | `MTDatacenterAuthMessageService.m:480-523, 806-822` |
| L18 | RNG status ignored for nonce, new_nonce and `b`; several helpers trust buffer lengths (`memcpy` of an IV of caller-chosen length into a 32-byte stack array, unchecked `MTSubdataSha1`, key-length assumptions in KDFs, `MTAesCtrDecrypt`). | `MTDatacenterAuthMessageService.m:227, 477, 689`; `MTEncryption.m:26-32, 197-373, 802`; `MTMessageEncryptionKey.m` |
| L19 | `MTAesEncryptBytesInplaceAndModifyIv` / `...Decrypt...` return `void`; failure is signalled only by zeroing the buffer. | `h/MTEncryption.h:30, 36` |
| L20 | Simple-config payload may extend 4 bytes past the hashed region (`data_len` up to 208). | `MTEncryption.m:909-911` |
| L21 | Bad_msg 32/33 resets the session *and* starts a time sync; `msg_resend_req` and pings use even (non-content) seqno. | `MTProto.m:2452-2458`; `MTResendMessageService.m:59` |
| L22 | `langPackCode` comparison resets the transport whenever the new code is nil (`[nil isEqualToString:]` is NO). (verified) | `MTProto.m:2798` |
| L23 | Progress-token decoder reads `msgs_ack` ids as int32 and decrypts the head without msg_key verification. | `MTProto.m:1731-1876` |
| L24 | `MTBindKeyMessageService` and `MTTimeSyncMessageService` implement a `new_session_created` selector MTProto never calls (`...messageIdsInFirstValidContainer:` vs `...otherValidMessageIds:`). | `MTBindKeyMessageService.m:134`; `MTProto.m:2554` |
| L25 | The time-fix branch silently drops the transport's actualization ping (already marked sent), so that connection never reports "updating"; close/stop do not report `isUpdatingConnectionContext = false`. | `MTProto.m:1387-1437`; `MTTcpTransport.m:216-248, 435-436` |
| L26 | Fake-TLS hello padding branch (to 513 bytes) is dead (hello is always ≥ 1507 bytes) and would append outside the closed length fields. | `MTTcpConnection.m:551-564` |
| L27 | Teardown hazards: `MTTcpConnection dealloc` sends `setDelegate:` to an interface (crash if ever released unstopped; unreachable today); DNS answers after `stop` are not checked against `_closed`; `startIfNeeded` does a sync hop onto the context queue from the transport queue. | `MTTcpConnection.m:963-964, 1096-1128`; `MTTcpTransport.m:194` |
| L28 | Legacy `MTInputStream` TL reader builds the 24-bit length with a signed shift (≥ 8 MiB → negative → NULL write); still used for fixed-size reads in the progress decoder. TL writers silently truncate lengths ≥ 2^24. | `MTInputStream.m:144-241`; `MTOutputStream.m:104-117`; `MTBuffer.m:63-70` |
| L29 | DEBUG builds simulate a disconnect on 50 % of `req_DH_params` sends; ignore when diffing debug logs. | `MTDatacenterAuthMessageService.m:250-254` |
| L30 | `MTDiscoverDatacenterAddressAction` reports success and failure through the same callback, and tries source DCs in dictionary order. | `MTDiscoverDatacenterAddressAction.m:214-230` |

### 10.4 Migration hazards (not bugs, but they bite a switchable engine)

- **Persisted state is NSKeyedArchiver graphs of ObjC classes** under `"<group>:<key>"` in the Postbox keychain
  (`TC/Network/Network.swift:1327-1381`). TelegramCore's account backup/restore reads and writes
  `persistent:datacenterAuthInfoById` itself (`TC/Account/Account.swift:302-322, 1120-1160`). If the Rust engine
  writes a different format under the same keys while the switch can flip back, accounts lose their keys (logout).
  Write new formats under new keys and keep the legacy keys in sync while the ObjC engine is selectable. Decode
  quirk: a missing `validUntilTimestamp` decodes as 0 in `MTDatacenterAuthInfo` but as `INT32_MAX` in
  `MTDatacenterAuthKey` (`MTDatacenterAuthInfo.m:18-21, 59-60`).
- **Per-key init state.** `authKeyAttributes["apiInitializationHash"]` is stored inside the auth info; a Rust
  engine that shares keys with MtProtoKit must keep or ignore it consistently, or one engine will skip
  `initConnection` on a key the server has never seen initialized by it (§4.5).
- **Only the newest `Keychain` instance per account persists** (generation check in `TC/Account/Account.swift:11-55`);
  two engines alive for one account at the same time silently lose writes.
- **Callback threading.** TelegramCore mutates shared state from MtProtoKit callbacks assuming one serial queue
  for all MTProto, service and request callbacks (§1.14).

### 10.5 Dead or misleading surface (do not port; keep no-op shims where TelegramCore calls them)

`MTProtoStateAwaitingLostMessages`, `MTProto.shouldStayConnected`, `tempAuthKeyBindingResultUpdated`,
`finalizeSession` (TelegramCore calls it: keep as no-op), `MTMessageTransaction.failed`/`allowServiceMode`,
`MTTransport.simultaneousTransactionsEnabled`/`reportTransportConnectionContextUpdateStates`,
`-[MTTcpTransport updateSchemes:]`, the sleep watchdog, `MTSessionInfo.generateServerMessageId`/
`scheduledForCleanup`/`canBeDeleted`, `MTTimeFixContext.timeFixAbsoluteStartTime`, session cleanup
(`scheduleSessionCleanupForAuthKeyId:` no-op, no `destroy_session` ever sent), `reportProblemsWithDatacenterAddressForId:`,
`MTApiEnvironment.tcpPayloadPrefix` and `passwordInputHandler`, `MTRequest.decorators`, `rpc_drop_answer`
(commented out), `MTFileBasedKeychain`, `MTProtoEngine`/`MTProtoInstance`/`MTProtoPersistenceInterface`,
`MTRsa` (iOS SecKey wrapper), `MTMurMurHash32`, `copyAuthInfoFrom:toTempKeychain:`, `removeAllAuthTokens`,
`MTDatacenterTransferAuthAction contextDatacenterAuthTokenUpdated:` (never registered), the stale
`google.com/resolve` comment (`MTTcpConnection.m:1050`). `MTLog` ignores `MTLogSetEnabled(false)` whenever a
log function is registered (`MTLogging.m:11-35`).

### 10.6 Status of the 028f835528 "found but intentionally not changed" list

| Item from the commit body | Still present | Here |
|---|---|---|
| `MTSessionInfo` sets never pruned (~69 KB/h) | yes | M2 |
| `fetchBackupIps` creates every MTProto eagerly | yes | H6 |
| Stats archived ~every 5 s while traffic flows | yes | M18 |
| `timeout:onQueue:orSignal:` timer not invalidated; resolve block retains `self` via `_helloRandom` (≤ 10 s) | yes | L2 |
| `-429` unthrottle timer never started | yes | H1 |
| Proxy probing continues while paused or stopped | yes | H10 |
| Time-sync / bind services implement a new-session selector MTProto never calls | yes | L24 |
| `MTTcpConnection dealloc` `setDelegate:` on the interface | yes (unreachable) | L27 |

