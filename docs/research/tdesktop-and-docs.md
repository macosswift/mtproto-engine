# MTProto research: Telegram Desktop digest, official protocol checklist, test vectors

Status: research input for the Rust MTProto engine that will replace MtProtoKit. This file contains no engine
code. Compiled 2026-10-01.

## 0. Sources and conventions

| Source | Version | Used for |
|---|---|---|
| telegramdesktop/tdesktop `Telegram/SourceFiles/mtproto/` | `33261535a0e747f125e0ed25486f01e556330677` (2026-10-01), API LAYER 229 | Part A. Every `file:line` ref without a prefix points here. |
| desktop-app/lib_base | `5462d363717621d9de767f09cd31dcaed09a45cf` (2026-09-24) | `lib_base:` refs (msg_id generator, server time) |
| tdlib/td (`td/mtproto`, `td/telegram/net`, `ConfigManager`, `GetHostByNameActor`) | `42e6a5259551178d1dab54a22ad96d14bd906e20` (2026-09-25) | `tdlib:` refs. Used only for comparison. |
| core.telegram.org (`/mtproto*`, `/api/*`, `/cdn`, `/schema/mtproto`, `/api/errors.json`) | fetched 2026-10-01 | Part B: checklist, vectors, errors |

Map of the document:
* **Part A**: how tdesktop works.
  * A1–A12: core (sessions, messages, acks, salts, timers, connection racing, transports, key creation, PFS
    binding).
  * A-E0–A-E15: edges (fake-TLS hello, DoH, simple-config bootstrap, RSA keys, DC options, Instance error policy,
    proxies, CDN downloads).
* **Part B**: the official documentation.
  * B0: docs discrepancies D1–D14.
  * B2: the checklist, `P-001`…`P-339`. Tests should embed the id in their name, e.g.
    `p_131_reject_msg_key_mismatch`.
  * B3: test vectors, including the full verbatim auth-key sample.
  * B4: error classes and special error strings.
* **Part C**: consolidated recommendations for the Rust engine.

The rules:
* Where tdesktop and the docs disagree, the docs (`P-…`) are normative. The Part A note explains the deviation.
  Robustness recommendations are marked **[REC]**.
* Rules marked `[derived]` in Part B are implied by the docs, not stated. Tests may cite them, but they are not
  normative.

Verification already performed:
* The full auth-key sample (B3.1) was recomputed independently, and every documented value matched (B3.2).
* All self-computed vectors (B3.8) were recomputed a second time, with a different AES implementation (macOS
  CommonCrypto) following tdesktop's formulas. They matched byte for byte.
* The production RSA key fingerprint was confirmed to equal the docs sample's `0xd09d1d85de64fd85` (A-E5.3).
* The live simple-config vector was decrypted independently (A-E4.8).
* tdlib claims were checked against the pinned tdlib commit (`td/mtproto`, `td/telegram/net`, `ConfigManager`, `GetHostByNameActor`).

---

# Part A — Telegram Desktop MTProto implementation digest (core)

All paths are relative to `Telegram/SourceFiles/mtproto/` of tdesktop commit
`33261535a0e747f125e0ed25486f01e556330677` (2026-10-01), unless prefixed with
`lib_base:` (desktop-app/lib_base `5462d363717621d9de767f09cd31dcaed09a45cf`) or
`tdlib:` (tdlib/td `42e6a5259551178d1dab54a22ad96d14bd906e20`, `td/mtproto/`).
Service schema: `scheme/mtproto.tl`; API layer: `scheme/api.tl` = **LAYER 229** (`api.tl:3117`).

## A1. Architecture

```
MTP::Instance (mtp_instance.cpp, main thread)          request ids, callbacks, error policy, DC registry
  └─ details::Dcenter (details/mtproto_dcenter.cpp)     per *bare* DC: persistent key + 2 temp-key slots
  └─ details::Session (session.cpp, main thread)        per *shifted* DC: toSend/haveSent maps, send coalescing
       └─ details::SessionData (session.h:56)           shared state guarded by 3 RW locks
       └─ details::SessionPrivate (session_private.cpp) runs on a dedicated QThread: the protocol state machine
            ├─ BoundKeyCreator → DcKeyCreator (+ DcKeyBinder)  auth key creation and temp-key binding
            ├─ ReceivedIdsManager                       dedupe of incoming msg_ids (400 most recent)
            ├─ _testConnections[] (parallel probes) → _connection (the winner)
            └─ AbstractConnection = TcpConnection | HttpConnection | ResolvingConnection(child)
                   └─ AbstractSocket = TcpSocket | TlsSocket (fake-TLS, "ee" secret) | WebProxySocket
```

* **Shifted DC ids** (`core_types.h:43-73`, full table in A-E7): `shiftedDcId = dcId + 10000 * shift`. Every
  shifted id is an independent MTProto *session* (own session_id, own connection) sharing the bare DC's keys.
  Only shift 0 (main session) processes updates (`session.cpp:561-568`).
* **Threads.** All protocol work for one session runs on the SessionPrivate thread; results are pushed into
  `SessionData::haveReceivedMessages()` and handed to the main thread via `queueTryToReceive()`
  (`session_private.cpp:1428-1435`, `session.cpp:543-577`). The maps `toSend` (requestId→request),
  `haveSent` (msgId→request) are shared and locked (`session.h:122-129`).
* **Session lifecycle.** `Session::start()` creates a new `SessionPrivate` (`session.cpp:217-224`);
  `restart()` → `SessionPrivate::restartNow()` (resets backoff, `session_private.cpp:1009-1013`);
  `reInitConnection()` marks the DC connection as not inited (forces initConnection again, `session.cpp:260-267`).
* **Connection states** (`facade.h:117-124`): `DisconnectedState=0, ConnectingState=1, ConnectedState=2`; a negative
  state `-N` means "waiting N ms before retry" (`session_private.cpp:384-406`).
* **Key slots per DC** (`details/mtproto_dcenter.h:21-66`): one persistent key, temp keys
  `[Regular, MediaCluster]`, and an atomic "creating" flag per slot. `TemporaryKeyTypeByDcType(MediaCluster)`
  → MediaCluster slot, everything else → Regular (`details/mtproto_dcenter.cpp:49-53`).
* There is a **web-proxy** transport (`web_proxy/*`, ~2.8k lines, new in 2026): a browser/WebView page relays
  multiplexed streams over a local WebSocket using 8-byte frames `type(1) streamId(3, BE) size(4, BE)`
  (`web_proxy/web_proxy_frame.cpp:31-53`), types Open/Data/Close/Window/Ping/Pong/Hello/Welcome/AuthChallenge/
  AuthResponse/Bye (`web_proxy/web_proxy_frame.h:18-30`), 4 MB initial stream window. It is a
  tdesktop-specific censorship-circumvention feature, not part of MTProto; MTProto runs inside it unchanged
  (padded-intermediate framing via `WebProxySocket`, `connection_tcp.cpp:531-537`). Not needed for a first engine.

## A2. Outgoing message format and pipeline

### A2.1 SerializedRequest layout (`details/mtproto_serialized_request.h:30-41`)
In 32-bit ints: `[0..1] server_salt | [2..3] session_id | [4..5] msg_id | [6] seq_no | [7] message_data_length (bytes) | [8..] body | padding`.
The request buffer *is* the plaintext of an MTProto 2.0 message; salt/session are written right before
encryption (`session_private.cpp:2728-2729`). `RequestData` carries `after` (dependency for invokeAfterMsg),
`lastSentTime`, `requestId`, `needsLayer`, `forceSendInContainer` (`serialized_request.h:85-96`).

### A2.2 Padding (`details/mtproto_serialized_request.cpp:15-34,101-117`)
```
p = ((8 + bodyInts) % 4) ? 4 - ((8 + bodyInts) % 4) : 0   // align header+body to 16 bytes
if (p < 3) p += 4                                         // at least 12 bytes
p += (random_u8 & 0x0F) << 2                              // + 0..15 extra 16-byte blocks
```
Result: **12..264 bytes** of random padding, total plaintext a multiple of 16. For the bind inner message
(`forAuthKeyInner=true`) only 16-byte alignment, 0..12 bytes (MTProto 1.0 rules).

### A2.3 Encryption (`session_private.cpp:2713-2769`, `mtproto_auth_key.cpp:79-105`)
```
msg_key_large = SHA256(auth_key[88+x .. 88+x+32] || plaintext_with_padding)      x = 0 client→server, 8 server→client
msg_key       = msg_key_large[8..24]
sha256_a = SHA256(msg_key || auth_key[x .. x+36])
sha256_b = SHA256(auth_key[40+x .. 40+x+36] || msg_key)
aes_key  = sha256_a[0..8]  || sha256_b[8..24] || sha256_a[24..32]
aes_iv   = sha256_b[0..8]  || sha256_a[8..24] || sha256_b[24..32]
packet   = auth_key_id(8, LE u64) || msg_key(16) || AES-256-IGE(aes_key, aes_iv, plaintext)
```
`auth_key_id` = SHA1(auth_key)[12..20] read as LE u64 (`mtproto_auth_key.cpp:145-150`). MTProto 1.0 KDF
(`prepareAES_oldmtp`, `mtproto_auth_key.cpp:43-77`) is used **only** for the bind_auth_key_inner message:
```
sha1_a = SHA1(msg_key || key[x..x+32]); sha1_b = SHA1(key[32+x..48+x] || msg_key || key[48+x..64+x])
sha1_c = SHA1(key[64+x..96+x] || msg_key); sha1_d = SHA1(msg_key || key[96+x..128+x])
aes_key = sha1_a[0..8] || sha1_b[8..20] || sha1_c[4..16]
aes_iv  = sha1_a[8..20] || sha1_b[0..8] || sha1_c[16..20] || sha1_d[0..8]
```
`sendSecureRequest` refuses buffers < 9 ints or with `messageSize < 5` (`session_private.cpp:2716-2726`). After
sending, the connection remembers the key id it encrypted with (`setSentEncryptedWithKeyId`, used as an assertion
that a connection never switches keys, `session_private.cpp:2506,2761`).

### A2.4 Unencrypted (handshake) packets (`connection_abstract.h:171-208`, `connection_abstract.cpp:109-146,219-221`)
`auth_key_id = 0 (8) | msg_id (8) | message_data_length (4) | body | random padding`, where **tdesktop appends
0..63 random ints after the body and counts them in message_data_length** (`*messageLength = (body + padding) << 2`,
`connection_abstract.h:198`). The server tolerates trailing bytes after a complete TL object here; this is a
length-obfuscation measure against DPI. Response checks: `>= 6 ints`, `auth_key_id == 0`, `msg_id & 3 == 1`,
`1 <= length`, `length % 4 == 0`, `length <= available`. The ±300/60 s time check is deliberately commented out
because time is not synced yet (`connection_abstract.cpp:120-125`).

### A2.5 msg_id generation (`lib_base: base/unixtime.cpp:31-122`)
```
startId   = (uint64(now_server_adjusted_seconds) << 32) | random32      // random32 fixed per process
next()    = ((startId + floor((monotonic_now - startCounter) * 0xFFFF0000 / 1s)) & ~3) + (incrementedPart += 4)
```
* Uses a monotonic clock scaled by `0xFFFF0000` per second ("slightly slower than unixtime so we have time to
  reconfigure", `unixtime.cpp:52-55`), plus a process-global counter incremented by 4 per id (uniqueness, `% 4 == 0`).
* Re-based (`MsgIdManager::update`) whenever the server-time shift changes (`unixtime.cpp:157-168`). Because the
  random low part is fixed and the counter keeps growing, ids stay unique; after a *backwards* correction they can be
  lower than previously used ids — tdesktop relies on bad_msg 16/17 handling for that.
* `replaceMsgId` loops `while (_resendingIds|_ackedIds|haveSent contains newId) newId = mtproto_msg_id()`
  (`session_private.cpp:493-497`).
* tdlib (`tdlib:AuthData.cpp:107-125`): `t = server_time * 2^32`, XOR 22 random low bits, `& ~3`, and if
  `t <= last` then `last + 8 * (1..1024)`. tdlib guarantees **strict monotonicity per AuthData**; tdesktop
  guarantees uniqueness but monotonicity only between time corrections. Prefer tdlib's rule.

### A2.6 seq_no (`session_private.cpp:435-439`, `serialized_request.cpp:127-144`)
`seq = 2 * counter + (needAck ? 1 : 0); if (needAck) counter++`. `counter` resets to 0 on new session_id
(`changeSessionId`, `session_private.cpp:418-433`). Not content-related (even seqno, no ack expected):
`msg_container, msgs_ack, http_wait, bad_msg_notification, msgs_all_info, msgs_state_info, msg_detailed_info,
msg_new_detailed_info`. Everything else — including `ping`, `ping_delay_disconnect`, `msgs_state_req`,
`msg_resend_req`, `auth.bindTempAuthKey` and all RPCs — is content-related (odd). This satisfies P-152/P-153 and
uses the P-154 freedom ("ping, msgs_state_req MAY be either") in the "ask for acks" direction.

### A2.7 tryToSend — packet assembly (`session_private.cpp:576-996`)
Preconditions: a `_connection` and a `_keyId` exist (`:578-584`). Modes:
* `sendOnlyFirstPing = state != ConnectedState` → only the initial ping (to learn the salt) may go out (`:587-593`).
* `sendAll = Connected && !_keyCreator` → user requests may go out; while a temp key is still being bound
  (`_keyCreator` alive) only service messages + the bind request are sent (`:589`).
* First send in a new session (`markSessionAsStarted`) sets `forceNewMsgId`: all resent requests get fresh msg_ids,
  and the binder is restarted so the bind message gets a fresh msg_id too (`:601-604`).

Service items built per call (`:606-673`):
| item | when | TL |
|---|---|---|
| ping | `_pingIdToSend` set; non-main sessions and the first ping use `ping`, main session uses `ping_delay_disconnect(ping_id, 60)` and arms the 45 s ping timer | `:612-628` |
| acks | `_ackRequestData` non-empty | `msgs_ack` `:639-643` |
| resend req | `_resendRequestData` non-empty | `msg_resend_req` `:644-648` |
| state req | `_stateRequestData` non-empty | `msgs_state_req` `:649-657` |
| http_wait | HTTP transport | `http_wait(max_delay=100, wait_after=30, max_wait=25000)` `:658-661` |
| bind | `!_bindMsgId && keyCreator.readyToBind()` | `auth.bindTempAuthKey`, msg_id pre-set, seqno set here `:662-672` |

User requests are taken from `toSend` in requestId order until the running sum of `request->size()` (in **ints**)
reaches `kCutContainerOnSize = 16*1024` (i.e. ~64 KB); the rest is sent by a re-queued `tryToSend`
(`:731-747, 991-995`).

**Single message** if exactly one item and not `forceSendInContainer` (`:774-836`). **Container** otherwise
(`:837-988`), assembled in this order: bind, ping, user requests, state req, resend req, acks, http_wait;
the container's own msg_id is assigned **last**. `bigMsgId` is regenerated each time an inner msg_id reaches it
(`placeToContainer`, `:536-551, 904-906`), so the container msg_id is strictly greater than every inner msg_id.
Container body: `msg_container#73f1f8dc count:int [msg_id:long seqno:int bytes:int body]*` (`:864-865`).
Inner messages are copied as `msg_id|seqno|length|body` (no salt/session).

Bookkeeping: content-related requests with a requestId go into `haveSent[msgId]` and arm
`_checkSentRequestsTimer(10 s)`; non-content-related requests with a requestId go to `_ackedIds` immediately
(`:799-835, 908-937`); every container gets `_sentContainers[containerMsgId] = {sentTime, innerIds}` (`:875-983`);
state/resend requests are remembered in `_stateAndResendRequests` to match `msgs_state_info` (`:792-796, 946-963`).

### A2.8 Wrapping: invokeWithLayer + initConnection + invokeAfterMsg (`session_private.cpp:106-131, 675-713, 808-830, 911-926`)
* `needsLayer = !Dcenter.connectionInited()` (`:586`). The DC is "inited" after the first **non-error**
  `rpc_result` received while the session options (lang codes, proxy) did not change (`:1898-1907`,
  `session.cpp:52-64`). A new temp key resets it (`mtproto_dcenter.cpp:147`), as does `reInitConnection()`.
* Every request with `needsLayer` sent while not inited is wrapped (all of them, not just the first):
  `invokeWithLayer#da9b0d0d layer:int query:(initConnection#c1cd5ea9 ... query:X)`.
* initConnection fields (`:698-710`): `flags = params | (proxy if MTProxy/Web)`, `api_id`, `device_model`,
  `system_version` (both `"n/a"` on CDN DCs), `app_version` (e.g. `"6.x.y x64 Mac App Store"`, `:83-104`),
  `system_lang_code`, `lang_pack`, `lang_code`, `proxy = inputClientProxy(host, port)` (only for MTProxy/web
  proxy), `params = jsonObject([{"tz_offset": <local UTC offset rounded to 900 s, clamped to -12h..+14h>}])`
  (`prepareInitParams`, `:553-574`).
* Dependency: if `request->after` is still in `haveSent` (unanswered), the body is wrapped as
  `invokeAfterMsg#cb9f372d msg_id:long query:X`; if the dependency was already answered (not in haveSent) the
  request is sent plain (`WrapInvokeAfter`, `:106-131`). Final nesting:
  `invokeWithLayer(layer, initConnection(..., invokeAfterMsg(dep_msg_id, query)))`.
  **Docs conflict (D14):** /api/invoking says invokeAfterMsg(s) "must always be the outermost wrapper" (P-257), but
  both tdesktop and tdlib put it *inside* invokeWithLayer/initConnection (tdlib serializes the
  `MtprotoHeader` prefix before `InvokeAfter`, `tdlib:td/mtproto/CryptoStorer.h:142-160`,
  `tdlib:td/telegram/net/MtprotoHeader.cpp:31-34`). **[REC]** keep the wrapper order a single, tested decision point
  and verify both orders on a test DC before freezing it.
* tdesktop never gzips outgoing requests (no `deflate` in mtproto/). tdlib gzips large requests when it pays off.

## A3. Incoming pipeline (`session_private.cpp:1280-1458`)

Validation order for each transport packet — every failure is `restart()` (drop the TCP connection, reconnect
with backoff), never "ignore and continue":
1. `18 ints <= size <= 16 MB` (`kMaxMessageLength`) — 6 outer ints + 8 header ints + 4 (`:1289-1298`).
2. `auth_key_id == current key id` (`:1299-1302`).
3. Encrypted part = remainder truncated to a multiple of 16 bytes (`& ~0x03U` ints, `:1307-1309`);
   AES-IGE decrypt with x = 8.
4. **msg_key check first**: `SHA256(auth_key[96..128] || entire decrypted buffer incl. padding)[8..24]`
   compared in constant time (`ConstTimeIsDifferent`, `:133-144, 1327-1339`).
5. Then length checks: `message_data_length <= 16 MB`, `% 4 == 0`, `padding = decrypted - 32 - len` in
   `[12, 1024]` (unsigned underflow folds into the range check) (`:1304-1347`).
6. `session_id == ours` (`:1357-1360`).
7. `msg_id & 3 ∈ {1, 3}` (`:1362-1368`).
8. `badTime = server_time(msg_id>>32) > now + 60 || server_time < now - 300` (`:1370-1375`). Not a rejection:
   it switches the handlers into "only accept messages that reference msg_ids we sent" mode (see A6).
9. Salt: if the packet's salt differs and `!badTime` → adopt it; if state was Connecting → Connected + `resendAll()`
   (`:1378-1391`).
10. If seqno is odd → push msg_id to `_ackRequestData` (before dedupe, so duplicates are re-acked) (`:1393`).
11. `ReceivedIdsManager::registerMsgId` (`details/mtproto_received_ids_manager.cpp:12-25`): duplicate → skip
    handling; if 400 ids are stored and `msg_id < min` → **TooOld → ResetSession** (new session_id); else handle.
    Map is shrunk to the newest 400 after each packet (`kIdsBufferSize = 400`, `received_ids_manager.h:15`).
12. Results: `DestroyTemporaryKey` → drop temp key and restart; `ResetSession` → `_needSessionReset` then restart;
    `RestartConnection`/`ParseError` → restart. On success `_retryTimeout = 1` and `_startedConnectingAt = 0`
    (`:1437-1453`). Acks are flushed with up to 10 s coalescing (`kAckSendWaiting`, `:1422-1426`).

Not checked by tdesktop (but by the docs/tdlib): the ±300/30 s window (P-137) as a hard reject; incoming seqno
monotonicity/parity vs content type; inner container msg_ids being lower than the container's (P-161); nested
containers (P-162 forbids them, tdesktop handles them recursively). tdlib rejects even msg_id parity and, once time is synced, msg_ids outside (−300 s, +30 s)
(`tdlib:AuthData.cpp:139-167`) and keeps the duplicate window as a sorted array (`:19-46`).

### A3.1 Per-constructor handling (`handleOneReceived`, `session_private.cpp:1460-2031`)
* `gzip_packed` — inflate with zlib (`16+MAX_WBITS`, gzip header), budget **32 MB unpacked per packet**
  (`kMaxUnpackedMessageLength`), 1 MB chunks, **nesting ≤ 64**, result length must be a multiple of 4
  (`:1471-1493, 2063-2137`). Failure → RestartConnection.
* `msg_container` — for each inner: need ≥ 4 ints; `msg_id`, `seqno`, `bytes` with `bytes % 4 == 0 && bytes >= 4`
  and inner msg_id parity 1/3 (else RestartConnection); inner odd seqno → ack; dedupe; recurse; the first
  non-Success inner result aborts the rest of the container (`:1495-1564`).
* `msgs_ack` — if badTime: accept only if some acked id is ours (then fix time/salt), else Ignore; otherwise
  `correctUnixtimeByFastRequest` (A6) and `requestsAcked(ids)` (`:1566-1586`).
* `bad_msg_notification` / `bad_server_salt` — see A5.
* `msgs_state_info` — match `req_msg_id` in `_stateAndResendRequests`; if badTime fix time from it; parse the
  original `msgs_state_req`/`msg_resend_req` and apply `handleMsgsStates(ids, info)` (`:1728-1778`).
* `msgs_all_info` — ignored when badTime; else `handleMsgsStates` (`:1780-1800`).
* `msg_detailed_info` — (badTime → must reference our msg_id) ack the original request; if `answer_msg_id` was
  already received → ack it again, else add it to `msg_resend_req` (`:1802-1829`).
* `msg_new_detailed_info` — ignored when badTime; same answer handling (`:1831-1851`).
* `rpc_result` — read `req_msg_id`; badTime → must be ours (`requestsFixTimeSalt`) else Ignore; unpack gzip
  result; if `rpc_error(401, "AUTH_KEY_PERM_EMPTY")` → **DestroyTemporaryKey** (`IsDestroyedTemporaryKeyError`,
  `details/mtproto_bound_key_creator.cpp:80-90`); non-error → mark connection inited; `requestsAcked(byResponse)`;
  route to bind handler if it answers the bind msg; otherwise queue for the main thread (`:1853-1926`).
* `new_session_created` — (badTime → `first_msg_id` must be ours) adopt `server_salt`; resend every haveSent
  request with `msg_id < first_msg_id` (10 ms); forward the object to the main thread so it runs
  `updates.getDifference` (`:1928-1975`).
* `pong` — must answer a msg_id we sent (else Ignore); if `ping_id == _pingId` clear it; ack the ping
  (`:1977-2004`).
* anything else = updates: if badTime → **ResetSession**; else forwarded to the main thread only on Regular DCs
  (logged error for CDN/media) (`:2008-2030`).

## A4. Acks, resends, state requests

* **Acks out**: collected from every odd-seqno incoming message (incl. inner/duplicates); sent piggy-backed with
  up to 10 s delay (`kAckSendWaiting`, `session_private.cpp:66,1422-1426`). tdlib: `ACK_DELAY = 30 s`, flush when
  ≥ 100 unacked (`tdlib:SessionConnection.h:129`, `SessionConnection.cpp:906-907`).
* **Acks in** (`requestsAcked`, `session_private.cpp:2182-2261`): ack of a container → ack all inner ids; ack of a
  state/resend request → forget it; ack of a request **that has a callback is ignored unless it came with the
  response** (`byResponse`) — an msgs_ack never removes an RPC that still awaits its result (`:2209-2212`);
  otherwise move to `_ackedIds` (capped at 400). Acked ids found in `_resendingIds` cancel the pending resend.
* **State polling** (`checkSentRequests`, `:267-300`): every request in haveSent whose `lastSentTime <= now - 10 s`
  is added to `msgs_state_req` (and its `lastSentTime` reset); state requests are coalesced for 1 s
  (`kSendStateRequestWaiting`). A pending bind older than 10 s restarts the connection instead (`:270-276`).
* **msgs_state_info / msgs_all_info** (`handleMsgsStates`, `:2263-2306`): `info.size()` must equal ids count; per id,
  `(state & 7) != 4` ("not received") → `resend(id, 10 ms)`; `== 4` (received) → treat as acked.
* **resend(msgId)** (`:2317-2352`): a container id resends all inner ids; a request is moved
  `haveSent → toSend` with `forceSendInContainer = true` and tracked in `_resendingIds[oldMsgId]`. When re-sent,
  `prepareToSend` **keeps the original msg_id** if it is not greater than the new container's msg_id and the session
  did not restart (`:464-474`) — the docs-sanctioned "wrap the original message in a container with a new msg_id"
  approach (P-182, P-192), which lets the server deduplicate. A brand-new session forces new msg_ids.
* **resendAll** (`:2354-2372`) moves the whole haveSent into toSend (used when salt is first learned or changed
  while Connecting).
* **Container expiry**: containers not acked within 600 s (`kSentContainerLives`) get their inner messages resent
  (`clearOldContainers`, `:302-336`).
* **Cancel** = remove locally from toSend/haveSent; no `rpc_drop_answer` (`session.cpp:352-361`).
* **Not used by tdesktop**: `get_future_salts`, `destroy_session`, `rpc_drop_answer`, `msg_resend_ans_req`,
  quick-ack, `msg_copy` (grep over `mtproto/`; only `destroy_auth_key` is used, in `mtp_instance.cpp:1761`).

## A5. bad_msg_notification / bad_server_salt (`session_private.cpp:1588-1726`)

All branches first require `wasSent(bad_msg_id)` (`:2771-2796`: ping/bind/containers/haveSent/_resendingIds/
_ackedIds); unknown ids are ignored (or Ignored under badTime).

| code | meaning | tdesktop reaction | tdlib reaction (`tdlib:SessionConnection.cpp:322-381`) |
|---|---|---|---|
| 16 | msg_id too low | adopt outer salt if changed; **forced** time sync from the notification's msg_id; `resend(bad_msg_id)` (in a new container) | fail the message → re-sent by Session with new id |
| 17 | msg_id too high | same as 16 | clear to_send, reset time difference, close session (`on_session_failed`) |
| 18 | msg_id % 4 != 0 | fatal: answer the request with `rpc_error(500, "PROTOCOL_ERROR")` | "BUG", close session |
| 19 | container msg_id == older msg_id | fatal (as 18) | BUG, close |
| 20 | msg too old (server forgot) | fatal (as 18) — request fails with 500 | fail → resend (more robust) |
| 32 | seqno too low | if badTime fix time/salt; if binding → restart connection; else **ResetSession** (new session_id) | BUG, close |
| 33 | seqno too high | as 32 | BUG, close |
| 34/35 | even/odd seqno mismatch | fatal (as 18) | BUG, close |
| 48 | bad server salt (`bad_server_salt`) | salt = new_server_salt; non-forced time update; if binding → restart; if Connecting → Connected + resendAll; `resend(bad_msg_id)` | update salt, resend |
| 64 | invalid container | as 16 (resend inner messages) | BUG, close |

Any bad_msg/bad_server_salt received **while a bind is pending** restarts the connection (`:1649-1653,1660-1663,1713-1716`).

## A6. Salts and time synchronisation

* Initial salt = `new_nonce[0..8] XOR server_nonce[0..8]` of the *temp* key creation (`details/mtproto_dc_key_creator.cpp:769-770`,
  `session_private.cpp:2610`). Salt sources afterwards: any incoming packet's salt when time is good
  (`:1378-1391`), `bad_server_salt.new_server_salt` (`:1708`), `new_session_created.server_salt` (`:1946`).
  No `get_future_salts` — each salt rotation costs one bad_server_salt round trip. tdlib keeps future salts and
  switches by `valid_since` (`tdlib:AuthData.cpp:91-105,169-175`).
* `authKeyChecked()` always queues a ping "to get server_salt" (`:2653-2664`): if the salt is unknown the ping
  provokes `bad_server_salt`; state becomes Connected only once a salt is known.
* Server time (`lib_base: unixtime.cpp:135-169`): `now() = local + shift`. `update(t, force=false)` applies only
  the first time (and only if the shift changes by ≥ 3 s); `force=true` always applies. Sources:
  `server_DH_inner_data.server_time` (non-forced, `dc_key_creator.cpp:665`); `bad_server_salt` (non-forced,
  `session_private.cpp:1711`); bad_msg 16/17/64, msgs_state_info and `requestsFixTimeSalt` under badTime
  (forced, `correctUnixtimeWithBadLocal`, `:2177-2180`); `correctUnixtimeByFastRequest` (`:2153-2175`): an
  `msgs_ack` for a request sent less than `SyncTimeRequestDuration` (initially 500 ms, shrinks to the best
  observed RTT) ago updates time (non-forced) — "fast request" time sync.
* Fake-TLS sockets request an HTTP-Date based time sync on timeout (`syncTimeRequest`, `session_private.cpp:234-238`);
  `http_now()` is a separate shift (`unixtime.cpp:185-196`) used for the TLS hello timestamp.

## A7. Timers, keepalive and reconnection

| constant | value | ref | role |
|---|---|---|---|
| `kWaitForBetterTimeout` | 2 s | `session_private.cpp:34` | after a lower-priority probe connects, wait for a better one |
| `kMinConnectedTimeout`/`kMaxConnectedTimeout` | 1 s / 8 s | `:35-36` | connect timeout; doubles per failure up to max(8 s, connection `fullConnectTimeout`) (`:1242-1256`); reset to 1 s on success (`:2383`) |
| `kMinReceiveTimeout`/`kMaxReceiveTimeout` | 4 s / 64 s | `:37-38` | response watchdog after sending something that needs an answer |
| `kMarkConnectionOldTimeout` | 192 s | `:39` | no data for 192 s → "old" connection: receive timeout back to 4 s, no size scaling |
| `kPingDelayDisconnect` | 60 s | `:40` | `ping_delay_disconnect.disconnect_delay` (main session only) |
| `kPingSendAfter` | 30 s | `:41` | next ping due 30 s after the last one |
| `kPingSendAfterForce` | 45 s | `:42` | ping timer; if a ping is still unanswered when the next must go out → restart (`:1190-1207`) |
| `kTemporaryExpiresIn` | 86400 s | `:43` | temp key lifetime requested in `p_q_inner_data_temp_dc` |
| `kBindKeyAdditionalExpiresTimeout` | 30 s | `:44` | `expires_at = now + 86400 + 30` in bind |
| `kKeyOldEnoughForDestroy` | 60 s | `:45` | ENCRYPTED_MESSAGE_INVALID only kills a persistent key older than this |
| `kSentContainerLives` | 600 s | `:46` | unacked container → resend inner |
| `kFastRequestDuration` | 500 ms | `:47` | RTT threshold for ack-based time sync |
| `kRequestConfigTimeout` | 8 s | `:50` | connecting longer than this → `instance->requestConfigIfOld()` |
| `kMaxMessageLength` | 16 MB | `:53` | max packet / message_data_length |
| `kMaxUnpackedMessageLength` | 32 MB | `:54` | gzip budget per packet |
| `kMaxGzipNesting` | 64 | `:56` | |
| `kCheckSentRequestTimeout` | 10 s | `:59` | unanswered → msgs_state_req |
| `kSendStateRequestWaiting` | 1 s | `:63` | coalescing for state requests |
| `kAckSendWaiting` | 10 s | `:66` | coalescing for acks |
| `kCutContainerOnSize` | 16384 ints (64 KB) | `:68` | per-packet request budget |
| `kIdsBufferSize` | 400 | `received_ids_manager.h:15` | dedupe window / acked-ids cap |
| `kFullConnectionTimeout` (TCP/HTTP) | 8 s | `connection_tcp.cpp:24`, `connection_http.cpp:18` | |
| `kOneConnectionTimeout` (resolving) | 4 s per resolved IP | `connection_resolving.cpp:16` | |
| `kPacketSizeMax` | 64 MB | `connection_tcp.cpp:23` | padded-intermediate length bound |
| `kTestModeDcIdShift` | 10000 | `connection_abstract.h:30` | test DC ids in obfuscation header / p_q_inner_data dc |

**Receive watchdog** (`onSentSome`, `:1140-1161`; `onReceivedSome`, `:1163-1181`; `waitReceivedFailed`, `:1218-1240`):
after sending a packet that needs any response, arm `_waitForReceived`; for a not-old connection scale by size
(`size * waitForReceived / 8192`, i.e. assume ≥ 8 KB/s, clamp to [current, 64 s]). Any received byte cancels it; the
first response after a send updates `waitForReceived = max(2 * RTT, 4 s)` if that is smaller. On expiry: double
(≤ 64 s), disconnect, reconnect **immediately**, and notify `Instance::restartedByTimeout` (used to re-trigger
config/proxy logic).

**Keepalive** (`tryToSend :594-600, 612-628`): only the main session (shift 0) pings periodically:
`ping_delay_disconnect(random_id, 60)` every 30 s piggy-backed on sends, plus a 45 s timer; other sessions send a
single plain `ping` after connecting (salt discovery) and are otherwise kept alive/killed by `Instance`.
tdlib is RTT-adaptive (`tdlib:SessionConnection.h:146-164`): online → ping after `rtt*0.5..rtt`, disconnect if no
pong in `rtt*2.5` (main) / no read in `rtt*3.5`; offline → ping 30..60 s (+random), disconnect at 135 s; it sends
`ping_delay_disconnect(disconnect_delay = ping_disconnect_delay + 2)`.

**Restart backoff** (`retryByTimer`, `:998-1007`; `restart`, `:1120-1138`): delays `1, 2, 3 ms, then 1 s, 2 s, 4 s … 64 s`;
reset to 1 ms after any successfully handled packet (`:1445`) or `restartNow()`/`dcOptionsChanged()`.

## A8. Connection establishment and selection (`session_private.cpp:196-265, 1015-1118, 2374-2453`)

1. `connectToServer()` destroys all connections; if the DC type changed while creating a key → destroy temp key
   (`:1022-1025`). Snapshot `SessionOptions` (proxy, useIPv4/IPv6/Tcp/Http; `session.cpp:239-258`:
   `useTcp = proxy != HTTP`, `useHttp = proxy ∉ {MTProxy, Web}`, `useIPv4 = true`, `useIPv6 = settings.tryIPv6()`).
2. CDN DC without known CDN RSA keys → `requestCDNConfig()` and stop (`:1032-1037`).
3. MTProxy/Web proxy → exactly one TCP test connection to the proxy (`:1038-1041`). Otherwise for every
   `address ∈ {IPv4, IPv6}` × `protocol ∈ {TCP, HTTP}` (minus disabled ones) × every endpoint from
   `DcOptions::lookup(dc, type, throughProxy)` create a test connection (`:1043-1080`). "Temporary" DCs (from
   special/simple config) force IPv4 TCP only (`:1044-1052`).
4. Priority (`:203-205`): `(IPv6 ? (prefer-ipv6 ? 2 : 0) : 1) + (TCP ? 1 : 0) + (has secret ? 1 : 0)`.
5. Each probe connects and immediately sends an **unencrypted `req_pq#60469778` with a random nonce**
   (`preparePQFake`, `connection_abstract.cpp:148-165`; `connection_tcp.cpp:413-422,593-628`;
   `connection_http.cpp:71-94,196-236`). A probe counts as connected only when it receives a parseable `resPQ` with
   the same nonce; the elapsed time is its `pingTime` (RTT). Wrong nonce/garbage → error.
6. `onConnected` (`:2374-2407`): if some other probe has a **strictly higher priority**, wait up to 2 s
   (`_waitForBetterTimer`); else adopt immediately. `confirmBestConnection` (`:2421-2443`) picks the connected probe
   with max priority when the timer fires or when others fail/disconnect. All other probes are destroyed.
   **Compliance with P-283/P-285 (AUTH_KEY_DUPLICATED):** probes only ever carry the unencrypted `req_pq`;
   losers are destroyed (`_testConnections.clear()`) *before* `checkAuthKey()` lets the winner send its first
   encrypted packet, so at most one connection per session carries encrypted traffic.
7. No endpoints at all → `instance->requestConfig()` (or `keyWasPossiblyDestroyed` for key destroyers) (`:1081-1095`).
   Connecting for > 8 s → `requestConfigIfOld()` (`:1100-1106`).
8. `_waitForConnected` (1 s → 8 s) bounds the whole probe round; on expiry all probes are killed and a new round
   starts at once with a doubled timeout (`:1242-1256`).
9. Transport errors from the active connection (`onError`, `:2666-2696`): `-429` logged (transport flood, then plain
   restart/backoff), `-444` → `instance->badConfigurationError()` (reload DC config), `-404` →
   `destroyTemporaryKey()` (server does not know our key), anything else → restart with backoff.

Compared with tdlib: tdlib's address selection lives in `td/telegram/net/ConnectionCreator` (outside the
reviewed `td/mtproto`), uses TCP only and checks proxies with a ping round trip (`tdlib:PingConnection.cpp`).
tdesktop's "probe everything in parallel with a fake req_pq and pick the best-priority one within 2 s" is simple
and robust against broken IPv6 / blocked ports, at the cost of extra sockets per reconnect. Recommended for the
Rust engine: keep the parallel probe + priority + short "wait for better" window, but drop HTTP unless needed.

## A9. Transport layer (`connection_tcp.cpp`, `connection_http.cpp`, `details/mtproto_tcp_socket.cpp`)

**Always obfuscated.** tdesktop never sends the plain `0xEF` / `0xEEEEEEEE` prefixes; every TCP connection starts
with the 64-byte obfuscated init (`prepareConnectionStartPrefix`, `connection_tcp.cpp:448-494`):
```
repeat nonce = random(64) until isGoodStartNonce(nonce)          // TcpSocket rules below; TlsSocket: always good
send_key = nonce[8..40]            (or SHA256(nonce[8..40] || secret16) with a secret)
send_iv  = nonce[40..56]
rev      = reverse(nonce[8..56])   // 48 bytes
recv_key = rev[0..32]              (or SHA256(rev[0..32] || secret16))
recv_iv  = rev[32..48]
nonce[56..60] = protocol id (LE u32): 0xEFEFEFEF abridged | 0xDDDDDDDD padded intermediate
nonce[60..62] = dc id (LE int16): dc, +10000 test, negative for media-only ("MediaCluster") DCs
encrypted = AES-256-CTR(send_key, send_iv) over all 64 bytes      // keystream continues for all later bytes
wire      = nonce[0..56] || encrypted[56..64]
```
`isGoodStartNonce` (`details/mtproto_tcp_socket.cpp:59-82`): `nonce[0] != 0xEF`; first u32 (LE) not in
`{0x44414548 "HEAD", 0x54534F50 "POST", 0x20544547 "GET ", 0xEEEEEEEE, 0xDDDDDDDD, 0x02010316 (TLS "\x16\x03\x01\x02")}`;
second u32 `!= 0`. **Gap vs docs:** tdesktop's list lacks `0x4954504F` ("OPTI"), which the docs (P-061) and tdlib
(`tdlib:TcpTransport.cpp:99-100`) reject — implement the docs' full list.

**Protocol selection by secret** (`connection_tcp.cpp:235-248`, see also `DcOptions::ValidateSecret`):
| secret | protocol | framing |
|---|---|---|
| empty | Version0 | abridged, obfuscated, no key mixing |
| 16 bytes | Version1 | abridged, key = SHA256(key_part ‖ secret) |
| 17 bytes starting `0xDD` | VersionD | padded intermediate, secret = bytes 1..17 |
| ≥ 21 bytes starting `0xEE` | VersionD over **TlsSocket** | fake-TLS; secret = bytes 1..17, domain = bytes 17.. |

**Abridged framing** (`:86-137`): `len_ints < 0x7F` → 1 byte; else `0x7F` + 3-byte LE length. Reader accepts
`0x01..0x7E` or `0x7F` followed by a length ≥ 0x7F; anything with the high bit set (quick-ack form) is a hard error.
**Padded intermediate** (`:195-229`): 4-byte LE length (counts payload + padding), payload, `0..15` random bytes;
reader requires `8 <= len+4 < 64 MB`. Plain intermediate (`0xEEEEEEEE`) and full (CRC32) transports are not
implemented. **Quick-ack is not supported** (`:395-410, 596-605`).
Payloads `< 12 bytes` are not MTProto messages: first int32 `0` = nop, negative = transport error code passed to
`AbstractConnection::error` (`:399-407, 598-603`).

**Buffers**: 256 KB rolling buffer, grows to a dedicated large buffer for big packets, keeps ≥ 256 bytes free
(`connection_tcp.cpp:25-26, 263-392`).

**HTTP transport** (`connection_http.cpp`): `POST http://<ip>:80/api` (port always 80, IPv6 in brackets),
`Content-Type: application/x-www-form-urlencoded`, body = raw MTProto packet (no length prefix, no obfuscation);
each response body must be ≥ 8 bytes and `% 4 == 0` (else error −500); HTTP status N → error `-N` (so HTTP 404 →
`-404`). Long polling via `http_wait(100, 30, 25000)` and an extra send whenever no request is outstanding
(`needHttpWait`, `:246-252`; `session_private.cpp:1455-1457`).

**ResolvingConnection** (`connection_resolving.cpp`): wraps a connection to a proxy given by host name; resolves via
`Instance::resolveProxyDomain` (DNS-over-HTTPS), tries resolved IPs one after another with 4 s per IP, reports the
working IP back (`setGoodProxyDomain`), `fullConnectTimeout = 4 s × #IPs` (`:20-44, 120-129, 167-190`).

## A10. Auth key creation (`details/mtproto_dc_key_creator.cpp`, `mtproto_dh_utils.cpp`)

Runs over the already-chosen connection; key creation messages are unencrypted (A2.4). If no persistent key exists,
**one connection creates both**: persistent first, then temporary (`DcKeyCreator::done`, `:820-845`).

1. `req_pq_multi#be7e8ef1(nonce = random128)` (`pqSend`, `:505-512`). Answers are matched to the attempt by nonce
   (`attemptByNonce`, `:463-473`); unknown answers → fail.
2. `resPQ` (`pqAnswered`, `:514-585`): stage must be WaitingPQ; pick an RSA key by fingerprint from
   `DcOptions::getDcRSAKey(dc, fingerprints)` (built-in keys or CDN keys); none → `UnknownPublicKey` (for CDN this
   triggers `help.getCdnConfig`, `session_private.cpp:2588-2593`). `new_nonce = random256`.
   Factorise `pq`: Pollard-rho/Brent on u64 (from tdlib, `:62-115`) or BigNum for > 63 bits (`:117-173`); `p < q`;
   p and q are serialized as **4-byte big-endian strings** in the small case (`:193-206`).
3. Inner data (`:546-569`): persistent → `p_q_inner_data_dc#a9f55f95(pq, p, q, nonce, server_nonce, new_nonce, dc)`;
   temporary → `p_q_inner_data_temp_dc#56fddf88(..., dc, expires_in = 86400)`. `dc` = protocol dc id (A9:
   +10000 for test, negative for media cluster).
4. **RSA_PAD** (`EncryptPQInnerRSA`, `:232-324`): boxed inner data must be ≤ 144 bytes;
   `data_with_padding = data ‖ random → 192 bytes`; loop {
   `temp_key = random32`; `data_with_hash = reverse(data_with_padding) ‖ SHA256(temp_key ‖ data_with_padding)` (224 B);
   `aes_encrypted = AES256-IGE(temp_key, iv = 0^32, data_with_hash)`;
   `key_aes_encrypted = (temp_key XOR SHA256(aes_encrypted)) ‖ aes_encrypted` (256 B);
   accept if `key_aes_encrypted < n` as a big-endian integer (`IsGoodEncryptedInner`, `:209-230`) }; then raw RSA
   `c = m^e mod n`. Send `req_DH_params#d712e4be(nonce, server_nonce, p, q, fingerprint, encrypted_data)`.
5. `server_DH_params_fail` → check server_nonce and `new_nonce_hash == SHA1(new_nonce)[4..20]`, then fail
   (`:680-695`). `server_DH_params_ok` (`:594-679`): server_nonce must match; `encrypted_answer` length `% 16 == 0`
   and ≥ 24 bytes (P-099); temp AES:
   `tmp_aes_key = SHA1(new_nonce ‖ server_nonce) ‖ SHA1(server_nonce ‖ new_nonce)[0..12]`,
   `tmp_aes_iv = SHA1(server_nonce ‖ new_nonce)[12..20] ‖ SHA1(new_nonce ‖ new_nonce) ‖ new_nonce[0..4]`;
   decrypt (IGE); answer = `SHA1(inner)(20) ‖ server_DH_inner_data ‖ padding`; parse inner from offset 20; nonce and
   server_nonce must match; SHA1 over exactly the **TL-parsed** bytes must equal the first 20 bytes (correct per
   docs gotcha D4 — the sample's `answer` carries 8 padding bytes); then
   `unixtime::update(server_time)`.
6. DH prime check (`IsPrimeAndGood`, `mtproto_dh_utils.cpp:105-131`): fast path if `dh_prime` equals the built-in
   2048-bit prime (C71CAEB9…FCC5B, `:106-122`) **and** `g ∈ {3,4,5,7}`; otherwise full check
   (`IsPrimeAndGoodCheck`, `:17-84`): exactly 2048 bits, prime, `(p-1)/2` prime, and
   `g=2: p mod 8 = 7; g=3: p mod 3 = 2; g=4: ok; g=5: p mod 5 ∈ {1,4}; g=6: p mod 24 ∈ {19,23}; g=7: p mod 7 ∈ {3,5,6}`;
   any other g → fail.
7. `dhClientParamsSend` (`:698-741`), at most 5 tries (`retries > 5` → fail): `b = random256 XOR random256`
   (`CreateModExp`, `dh_utils.cpp:133-158`), retry until `g_b` passes `IsGoodModExpFirst`; check `g_a` the same way
   (`CreateAuthKey`, `:160-173`): `IsGoodModExpFirst(x, p)` (`:88-103`) = `x` and `p − x` both have
   **≥ 1984 bits** (i.e. ≥ 2^1983), `p − x` non-negative, `x` ≤ 256 bytes. auth_key = `g_a^b mod p`, left-padded with
   zeros to 256 bytes (`AuthKey::FillData`, `mtproto_auth_key.cpp:133-143`). `auth_key_aux_hash = SHA1(key)[0..8]`.
   Send `set_client_DH_params#f5045f1f(nonce, server_nonce, AES-IGE(tmp_key, tmp_iv, SHA1(inner) ‖ client_DH_inner_data(nonce, server_nonce, retry_id, g_b) ‖ random pad to 16))`
   (`EncryptClientDHInner`, `:326-358`).
8. Answer (`:743-812`): nonce and server_nonce must match; `new_nonce_hashN = SHA1(new_nonce ‖ byte(N) ‖ auth_key_aux_hash)[4..20]`
   with N = 1 (`dh_gen_ok`), 2 (`dh_gen_retry` → `retry_id = auth_key_aux_hash`, go to 7), 3 (`dh_gen_fail` → fail).
   OK → `server_salt = new_nonce[0..8] XOR server_nonce[0..8]` (as LE u64s).
9. All secrets are wiped with `OPENSSL_cleanse` (`Attempt::~Attempt`, `:368-376`).

Differences vs docs/tdlib to note for the Rust engine:
* tdesktop's g_a/g_b bound is "≥ 1984 bits" (≥ 2^1983); the docs require `2^(2048−64) ≤ g_a ≤ dh_prime − 2^(2048−64)`
  (≥ 2^1984). Implement the docs' bound exactly.
* tdesktop does not verify that the decrypted `server_DH_inner_data` padding is < 16 bytes nor that `1 < g_a < p−1`
  explicitly (implied by the bit-length check). The docs fork's checklist is the authority.
* tdesktop never uses `p_q_inner_data` (no-dc) nor `req_pq` for real handshakes (only for probes).

## A11. Temporary keys, PFS binding, key loss and destroy (`session_private.cpp:2455-2651`, `details/mtproto_dc_key_binder.cpp`, `details/mtproto_dcenter.cpp`)

tdesktop **always** uses PFS for regular and media DCs: traffic is encrypted with a 24 h temp key bound to the
persistent key; the persistent key never encrypts normal traffic. Temp keys are memory-only (new ones every launch);
there is no proactive rotation before expiry — expiry is discovered by the server answering `-404`
(→ `destroyTemporaryKey`) or `AUTH_KEY_PERM_EMPTY`.

**Slot acquisition** (`Dcenter::acquireKeyCreation`, `mtproto_dcenter.cpp:109-129`): if the slot's temp key exists
→ None (use it). MediaCluster with an existing Regular temp key → `TemporaryMediaCluster`. Otherwise CAS the
Regular slot's creating flag: winner gets `Persistent` (no persistent key and not CDN) or `TemporaryRegular`;
losers get None and wait for `dcTemporaryKeyChanged` (`session.cpp:179-194`). A media session that has to create
the regular key temporarily behaves as a Regular DC (`forceUseRegular`, `session_private.cpp:2648-2650`).

**Flow** (`tryAcquireKeyCreation` delegate, `:2585-2634`):
1. Unbound keys ready → `_sessionSalt = temp salt`; `temp.expiresAt = now + 86400 + 30`; for non-CDN take the new
   persistent key or the stored one (none → fail/restart) and `bind(persistent)`; `applyAuthKey(temp)` (new
   session_id, connection keeps the probe socket).
2. CDN: no binding; `releaseCdnKeyCreationOnDone(temp)` and go.
3. `tryToSend` sends only service messages and `auth.bindTempAuthKey` until bound (A2.7).

**Bind message** (`EncryptBindAuthKeyInner`, `dc_key_binder.cpp:23-73`; `prepareRequest`, `:82-105`):
```
nonce   = random64; msg_id = new msg_id (also used as the OUTER message's msg_id)
inner   = bind_auth_key_inner#75a3f765 nonce:long temp_auth_key_id:long perm_auth_key_id:long
                                       temp_session_id:long expires_at:int
plain   = random_salt(8) ‖ random_session_id(8) ‖ msg_id(8) ‖ seq_no=0(4) ‖ len(4) ‖ inner ‖ pad to 16 (0..12 bytes)
msg_key = SHA1(plain without padding)[4..20]                         // MTProto 1.0
encrypted_message = perm_auth_key_id(8) ‖ msg_key(16) ‖ AES-IGE(KDF_v1(perm_key, msg_key, x=0), plain)
request = auth.bindTempAuthKey#cdd42a05 perm_auth_key_id:long nonce:long expires_at:int encrypted_message:bytes
```
The outer request is pre-assigned the same msg_id; its seqno is assigned at send time (`session_private.cpp:670-671`).
If a new session starts before the bind is sent, the binder is recreated so inner/outer msg_ids stay equal
(`restartBinder`, `:601-604`).

**Bind response** (`handleResponse`, `dc_key_binder.cpp:107-126`; `handleBindResponse`, `session_private.cpp:2033-2061`):
* `boolTrue` → `Dcenter::releaseKeyCreationOnDone`: store temp key (and persistent key if newly created; persisted to
  disk via `dcPersistentKeyChanged`), clear creating flag, `connectionInited = false` (next requests get
  initConnection). If the DC's persistent key changed meanwhile → returns false → DestroyTemporaryKey.
* `rpc_error(400, "ENCRYPTED_MESSAGE_INVALID")` → DefinitelyDestroyed: if the persistent key is **older than 60 s**
  (or creation time unknown) → `instance->keyDestroyedOnServer(dc, keyId)` (drops the persistent key, i.e. the
  account is logged out on that DC / key recreated) and destroy temp key; if younger → treat as Failed. This is
  exactly the documented 60-second rule (P-239).
* other errors → Failed: keep the binder; the bind is simply sent again by the next `tryToSend`.
* bind unanswered for 10 s → restart connection (`checkSentRequests`, `:270-276`).

**Key loss signals**: transport `-404` → destroy temp key, recreate (`:2690-2711`); `rpc_error(401, AUTH_KEY_PERM_EMPTY)`
→ destroy temp key (temp key not bound, e.g. server forgot the binding) (`:1898-1901`); `Dcenter::destroyTemporaryKey`
resets `connectionInited` (`mtproto_dcenter.cpp:74-84`). Persistent key destruction is done by "keys destroyer"
Instances (`_instance->isKeysDestroyer()`), which connect with the **persistent** key directly (`checkAuthKey`,
`session_private.cpp:2455-2464`) and send `destroy_auth_key` (`mtp_instance.cpp:1761-1775`); a `-404` there means
"already destroyed" (`keyWasPossiblyDestroyed`, `:2698-2703`).

**One temp key per DC, shared by all sessions.** All shifted sessions of a DC (main, config, uploads, downloads
without media_only endpoints, …) encrypt with the same Regular temp key and differ only in session_id. The docs
require a separate bound temp key per session only when `tmp_sessions > 1` (P-243); tdesktop never requests that
mode, so sharing is compliant today but must be revisited if the engine supports parallel main sessions.

tdlib comparison: tdlib also uses PFS (`use_pfs`), but asks for a new temp key proactively when
`now > expires_at - refresh_margin` (`tdlib:AuthData.h:100-111`) and treats an expired temp key as absent
(`has_tmp_auth_key`, `:122-133`). Proactive rotation avoids a guaranteed `-404` + reconnect + re-handshake stall
every 24 h on long-lived connections; prefer it.

## A12. tdesktop vs tdlib — summary of behavioural differences (core)

| topic | tdesktop | tdlib | more robust |
|---|---|---|---|
| msg_id generation | monotonic clock × 0xFFFF0000/s + global +4 counter, fixed random low bits | server time × 2^32, 22 random low bits, strictly > last (+8·rand) | tdlib (strict monotonicity) |
| incoming time window | badTime (>+60 s / <−300 s) → only accept messages tied to own msg_ids; updates under badTime → new session | after time sync, drop msg_ids outside (−300, +30) s | tdlib for replay protection; tdesktop's "fix time from own msg ids" is a good recovery trick |
| duplicate window | 400 ids; lower-than-min → new session | sorted array; older-than-oldest → ignore | tdlib (no session churn) |
| decrypt failure | always drop connection | drop connection | equal; both check msg_key before length |
| padding out | 12..264 random | size buckets 64…1280 then ×448, or 0..255 random | tdlib (traffic-analysis resistance) |
| future salts | not used | `get_future_salts`, switch by valid_since | tdlib |
| bad_msg 20 | request fails with 500 PROTOCOL_ERROR | resend | tdlib |
| bad_msg 17 | resend after time fix | close session, reset time | tdesktop (fewer resets) — both OK |
| bad_msg 32/33 | new session | close session (BUG) | similar |
| keepalive | fixed 30/45/60 s, main session only | RTT-adaptive, per-connection | tdlib |
| receive watchdog | adaptive 4..64 s, size-scaled | read_disconnect_delay | similar |
| transport | always obfuscated; abridged (no secret / 16-byte secret) or padded intermediate (dd/ee); no quick-ack | always obfuscated (`using Transport = ObfuscatedTransport`, `tdlib:TcpTransport.h:177`); intermediate `0xEEEEEEEE` or padded `0xDDDDDDDD`; quick-ack supported (`TcpTransport.cpp:20-56`) | tdlib (quick-ack, intermediate is simpler to parse) |
| connection race | parallel probes (IPv4/IPv6 × TCP/HTTP × endpoints) + fake req_pq, priority + 2 s wait | handled outside td/mtproto (`td/telegram/net/ConnectionCreator`, not reviewed here) | tdesktop's is simple and well-proven |
| temp key rotation | reactive (on −404 / AUTH_KEY_PERM_EMPTY) | proactive: `need_tmp_auth_key(now, refresh_margin)` (`tdlib:AuthData.h:100-111`) | tdlib |
| outgoing gzip | never | when beneficial | tdlib |
| ack of RPC | msgs_ack never completes an RPC that awaits a result | same | equal |
| unencrypted padding | random 0..252 bytes counted in length (DPI) | none | tdesktop trick, optional |

---

# Part A-E — tdesktop MTProto edge modules (transport camouflage, bootstrap, instance, proxies)

Source pin: `telegramdesktop/tdesktop` @ `33261535a0e747f125e0ed25486f01e556330677` (commit date 2026-10-01).
All paths are relative to `Telegram/SourceFiles/mtproto/` unless they start with `../` (then relative to `Telegram/SourceFiles/`).
Line numbers refer to that commit. Code blocks marked "verbatim" are byte-for-byte copies extracted by script.

Statements about tdlib inside `td/mtproto/` were checked against tdlib `42e6a5259551` (`tdlib:` refs). Statements about tdlib code outside `td/mtproto/` (td/telegram/ConfigManager.cpp, td/telegram/net/NetQueryDelayer.cpp, …) were then checked against the same commit by adding `td/telegram/net`, `td/telegram/ConfigManager.*` and `tdnet/td/net/GetHostByNameActor.*` to the sparse checkout; refs to them are given as `tdlib:<path>:<line>`.

## A-E0. Module map

| File | Role |
|---|---|
| `details/mtproto_tls_socket.cpp` | Fake-TLS ("ee" secret) socket: ClientHello generation from a TL-described template, HMAC handshake, TLS record framing of the obfuscated stream |
| `details/mtproto_tcp_socket.cpp` | Plain QTcpSocket wrapper, reserved-first-bytes check for the obfuscation nonce |
| `details/mtproto_abstract_socket.cpp` | Factory that picks TLS vs plain socket from the secret |
| `details/mtproto_web_proxy_socket.cpp`, `web_proxy/*` | New "Web" proxy type (MTProto bytes relayed through a real browser tab over HTTPS) |
| `details/mtproto_domain_resolver.cpp` | DNS-over-HTTPS resolver used for proxy host names |
| `special_config_request.cpp` | "Simple config" bootstrap: DoH TXT / Firestore fetch, RSA+AES decrypt of `help.configSimple`; also HTTP-`Date` clock sync |
| `config_loader.cpp` | `help.getConfig` cadence, DC enumeration, use of simple-config endpoints |
| `details/mtproto_rsa_public_key.cpp` | RSA key parsing, fingerprint, raw RSA, OAEP |
| `mtproto_dc_options.cpp` | Built-in DC addresses + RSA keys, `dcOption` storage/lookup, CDN keys |
| `facade.h`, `core_types.h` | DC id "shift" scheme (one Session per shifted DC id) |
| `mtp_instance.cpp` | Request registry, error policy (migrate, flood, 5xx, 401, MSG_WAIT), auth export/import, logout, key destruction, config refresh |
| `mtproto_response.*`, `sender.h`, `mtproto_concurrent_sender.cpp` | Error parsing and caller-side "skip policies" |
| `mtproto_proxy_data.cpp`, `proxy_check.cpp` | Proxy types, MTProxy secret parsing/validation, proxy ping check |
| `details/mtproto_dcenter.cpp` | Per-DC key slots (persistent + 2 temporary) |
| `dedicated_file_loader.cpp`, `../storage/download_manager_mtproto.cpp` | Updater downloads; regular downloads incl. CDN redirect handling |

---

## A-E1. Fake-TLS transport (`details/mtproto_tls_socket.cpp`)

### A-E1.1 Activation and secret layout

- The socket type is chosen purely from the secret: `secret.size() >= 21 && secret[0] == 0xEE` gives `TlsSocket`, anything else gives `TcpSocket` (`details/mtproto_abstract_socket.cpp:20-28`). The same predicate is asserted in the constructor (`details/mtproto_tls_socket.cpp:606`).
- Secret layout: `0xEE || key[16] || domain[n]`.
  - `keyFromSecret()` = `secret[1..17)` (16 bytes) (`details/mtproto_tls_socket.cpp:646-648`). This key is the HMAC key and (in `connection_tcp.cpp`, covered in the core part) the 16-byte MTProxy obfuscation secret.
  - `domainFromSecret()` = `secret[17..]` (`details/mtproto_tls_socket.cpp:642-644`). Raw bytes; no IDNA/charset/length validation besides the overall 2048-byte hello limit (see A-E1.6).
- Accepted secret shapes for a DC option (`mtproto_dc_options.cpp:134-140`): `EE` + >=20 bytes, `DD` + 16 bytes (17 total), 16 bytes plain, or empty.
- Files sessions get 2 MiB socket send/receive buffers (`details/mtproto_abstract_socket.h:62-63`, applied at `details/mtproto_tls_socket.cpp:610-617` and `details/mtproto_tcp_socket.cpp:23-30`).
- The QTcpSocket gets the session's `QNetworkProxy`, but for MTProxy/Web proxies `ToNetworkProxy` returns `NoProxy` (`mtproto_proxy_data.cpp:578-580`), so fake TLS is never nested inside SOCKS/HTTP proxies.
- `isGoodStartNonce()` always returns `true` for TLS (`details/mtproto_tls_socket.cpp:859-861`): the 64-byte obfuscation init header travels inside a TLS record, so the reserved-prefix rejection used for raw TCP (A-E2) is skipped.

### A-E1.2 The hello template is data (TL schema)

The ClientHello is not hard-coded as bytes; it is a tree of `TlsBlock`s declared in the TL schema and interpreted by a small generator. This lets the template be updated without touching the generator.

Verbatim `scheme/mtproto.tl:105-117`:

```tl
tlsClientHello blocks:vector<TlsBlock> = TlsClientHello;

tlsBlockString data:string = TlsBlock;
tlsBlockRandom length:int = TlsBlock;
tlsBlockZero length:int = TlsBlock;
tlsBlockDomain = TlsBlock;
tlsBlockGrease seed:int = TlsBlock;
tlsBlockPublicKey = TlsBlock;
tlsBlockScope entries:Vector<TlsBlock> = TlsBlock;
tlsBlockPermutation entries:Vector<Vector<TlsBlock>> = TlsBlock;
tlsBlockM = TlsBlock;
tlsBlockE = TlsBlock;
tlsBlockPadding = TlsBlock;
```

Block semantics (generator: `details/mtproto_tls_socket.cpp:390-521`):

| Block | Builder letter | Output |
|---|---|---|
| `tlsBlockString data` | `S(bytes)` | literal bytes |
| `tlsBlockZero length` | `Z(n)` | n zero bytes; the **first** `Z(32)` marks the digest position (`:406-408`) |
| `tlsBlockGrease seed` | `G(i)` | 2 bytes, both equal to `greases[i]` (`:412-423`) |
| `tlsBlockRandom length` | `R(n)` | n CSPRNG bytes (`:425-432`) |
| `tlsBlockDomain` | `D()` | domain bytes from the secret (`:434-440`) |
| `tlsBlockPublicKey` | `K()` | a fresh X25519 public key, 32 bytes, generated by OpenSSL EVP; private key discarded (`:249-285`, `:442-449`) |
| `tlsBlockM` | `M()` | 1184-byte ML-KEM-768 encapsulation-key look-alike (`:484-506`) |
| `tlsBlockE` | `E()` | random bytes of length uniformly chosen from {144,176,208,240} (GREASE-ECH payload) (`:508-512`) |
| `tlsBlockPadding` | `P()` | if the buffer is shorter than 513 bytes, appends extension `00 15` with zero payload so the total becomes exactly 517 (`:514-521`) |
| `tlsBlockScope entries` | `OpenScope()/CloseScope()` | 2-byte big-endian length of the enclosed bytes, then the bytes (`:451-460`) |
| `tlsBlockPermutation entries` | `OpenPermutation()/StartPermutationElement()/ClosePermutation()` | renders every element separately, shuffles the list uniformly (`ranges::shuffle`), concatenates (`:462-482`) |

### A-E1.3 The template (verbatim)

Verbatim `details/mtproto_tls_socket.cpp:124-231`:

```cpp
	stack.emplace_back(Scope());

	S("\x16\x03\x01"_q);
	OpenScope();
	S("\x01\x00"_q);
	OpenScope();
	S("\x03\x03"_q);
	Z(32);
	S("\x20"_q);
	R(32);
	S("\x00\x20"_q);
	G(0);
	S(""
		"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9"
		"\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00"
		""_q);
	OpenScope();
	G(2);
	S("\x00\x00"_q);
	OpenPermutation(); {
		StartPermutationElement(); {
			S("\x00\x00"_q);
			OpenScope();
			OpenScope();
			S("\x00"_q);
			OpenScope();
			D();
			CloseScope();
			CloseScope();
			CloseScope();
		}
		StartPermutationElement(); {
			S("\x00\x05\x00\x05\x01\x00\x00\x00\x00"_q);
		}
		StartPermutationElement(); {
			S("\x00\x0a\x00\x0c\x00\x0a"_q);
			G(4);
			S("\x11\xec\x00\x1d\x00\x17\x00\x18"_q);
		}
		StartPermutationElement(); {
			S("\x00\x0b\x00\x02\x01\x00"_q);
		}
		StartPermutationElement(); {
			S(""
				"\x00\x0d\x00\x18\x00\x16\x09\x04\x09\x05\x09\x06\x04\x03"
				"\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01"_q);
		}
		StartPermutationElement(); {
			S(""
				"\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70"
				"\x2f\x31\x2e\x31"_q);
		}
		StartPermutationElement(); {
			S("\x00\x12\x00\x00"_q);
		}
		StartPermutationElement(); {
			S("\x00\x17\x00\x00"_q);
		}
		StartPermutationElement(); {
			S("\x00\x1b\x00\x03\x02\x00\x02"_q);
		}
		StartPermutationElement(); {
			S("\x00\x23\x00\x00"_q);
		}
		StartPermutationElement(); {
			S("\x00\x2b\x00\x07\x06"_q);
			G(6);
			S("\x03\x04\x03\x03"_q);
		}
		StartPermutationElement(); {
			S("\x00\x2d\x00\x02\x01\x01"_q);
		}
		StartPermutationElement(); {
			S("\x00\x33\x04\xef\x04\xed"_q);
			G(4);
			S("\x00\x01\x00\x11\xec\x04\xc0"_q);
			M();
			K();
			S("\x00\x1d\x00\x20"_q);
			K();
		}
		StartPermutationElement(); {
			S("\x44\xcd\x00\x05\x00\x03\x02\x68\x32"_q);
		}
		StartPermutationElement(); {
			S("\xfe\x0d"_q);
			OpenScope();
			S("\x00\x00\x01\x00\x01"_q);
			R(1);
			S("\x00\x20"_q);
			K();
			OpenScope();
			E();
			CloseScope();
			CloseScope();
		}
		StartPermutationElement(); {
			S("\xff\x01\x00\x01\x00"_q);
		}
	} ClosePermutation();
	G(3);
	S("\x00\x01\x00"_q);
	P();
	CloseScope();
	CloseScope();
	CloseScope();

	return MTP_tlsClientHello(MTP_vector<MTPTlsBlock>(Finish()));
```

### A-E1.4 Decoded layout of the generated ClientHello

Offsets are from the start of the TLS record. `L` = domain length, `E` = ECH payload length.

| Offset | Bytes | Meaning | Template source |
|---|---|---|---|
| 0 | `16 03 01` | TLS record: handshake, legacy version TLS 1.0 | `S("\x16\x03\x01")` |
| 3 | 2 | record length | `OpenScope()` |
| 5 | `01 00` + 2 | handshake type ClientHello (1), 24-bit length written as `00` + 16-bit scope | `S("\x01\x00"); OpenScope()` |
| 9 | `03 03` | client_version TLS 1.2 | `S("\x03\x03")` |
| 11 | 32 | client random = HMAC digest, last 4 bytes XOR timestamp | `Z(32)` |
| 43 | `20` + 32 | legacy_session_id (32 random bytes) | `S("\x20"); R(32)` |
| 76 | `00 20` | cipher suites length (32 bytes = 16 suites) | `S("\x00\x20")` |
| 78 | 2 | GREASE cipher suite | `G(0)` |
| 80 | 30 | `1301 1302 1303 c02b c02f c02c c030 cca9 cca8 c013 c014 009c 009d 002f 0035` | `S(...)` |
| 110 | `01 00` | compression methods: 1 method, null | tail of the same `S(...)` |
| 112 | 2 | extensions length | `OpenScope()` |
| 114 | `GG GG 00 00` | leading GREASE extension, empty | `G(2); S("\x00\x00")` |
| 118 | ... | 16 extensions in random order (below) | permutation |
| end-5 | `GG GG 00 01 00` | trailing GREASE extension with 1-byte body `00` | `G(3); S("\x00\x01\x00")` |
| end | (0 or more) | padding extension `00 15`, only if total < 513 (never in practice) | `P()` |

Permuted extensions (each rendered independently, then shuffled):

| # | Type | Body | Notes |
|---|---|---|---|
| 1 | `0000` server_name | `len(list) 00 len(name) <domain>` | three nested scopes around `00` + `D()` |
| 2 | `0005` status_request | `01 0000 0000` | OCSP |
| 3 | `000a` supported_groups | `000a` + `G(4)` + `11ec 001d 0017 0018` | GREASE, X25519MLKEM768, x25519, secp256r1, secp384r1 |
| 4 | `000b` ec_point_formats | `01 00` | uncompressed |
| 5 | `000d` signature_algorithms | `0016` + `0904 0905 0906 0403 0804 0401 0503 0805 0501 0806 0601` | includes ML-DSA-44/65/87 code points 0x0904-0x0906 |
| 6 | `0010` ALPN | `000c 02 "h2" 08 "http/1.1"` | |
| 7 | `0012` signed_certificate_timestamp | empty | |
| 8 | `0017` extended_master_secret | empty | |
| 9 | `001b` compress_certificate | `02 0002` | brotli |
| 10 | `0023` session_ticket | empty | |
| 11 | `002b` supported_versions | `06` + `G(6)` + `0304 0303` | GREASE, TLS1.3, TLS1.2 |
| 12 | `002d` psk_key_exchange_modes | `01 01` | psk_dhe_ke |
| 13 | `0033` key_share | ext len `04ef`, shares len `04ed`; `G(4) 0001 00`; `11ec 04c0` + `M()`(1184) + `K()`(32); `001d 0020` + `K()`(32) | GREASE share uses the **same** GREASE value (seed 4) as supported_groups, as Chrome does |
| 14 | `44cd` application_settings (new ALPS code point) | `0003 02 "h2"` | |
| 15 | `fe0d` encrypted_client_hello (GREASE ECH) | `00` outer, `0001` HKDF-SHA256, `0001` AES-128-GCM, `R(1)` config_id, `0020` + `K()` enc, scope(`E()`) payload | |
| 16 | `ff01` renegotiation_info | `00` | |

GREASE values (`details/mtproto_tls_socket.cpp:234-247`): 8 random bytes, each forced to the form `0x?A` (high nibble random, low nibble `A`); within each pair `(0,1) (2,3) (4,5) (6,7)` equal values are de-duplicated by XOR `0x10` on the odd one. Seeds 2 and 3 form a pair, so the leading and trailing GREASE extension types are always different (TLS forbids duplicate extension types). Each `G(i)` emits the byte twice (e.g. `3A 3A`).

### A-E1.5 Generator primitives (verbatim excerpt: M, E, P)

The remaining primitives are fully specified by the table in A-E1.2. `grow()` (`:365-376`) fails the whole hello once 2048 bytes would be exceeded.

Verbatim `details/mtproto_tls_socket.cpp:484-521`:

```cpp
void Generator::Part::writeBlock(const MTPDtlsBlockM &data) {
	constexpr auto kElements = 384;
	constexpr auto kAdded = 32;

	const auto storage = grow(kElements * 3 + kAdded);
	if (storage.empty()) {
		return;
	}

	auto random = bytes::vector(kElements * 8 + kAdded);
	bytes::set_random(random);

	auto chars = reinterpret_cast<char*>(storage.data());
	for (auto i = 0; i < kElements; ++i) {
		const auto pair = random.data() + i * 2 * sizeof(uint32);
		const auto a = int(qFromUnaligned<uint32>(pair) % 3329);
		const auto b = int(qFromUnaligned<uint32>(pair + sizeof(uint32)) % 3329);
		*chars++ = (char)(a & 255);
		*chars++ = (char)((a >> 8) + ((b & 15) << 4));
		*chars++ = (char)(b >> 4);
	}
	bytes::set_random(storage.subspan(kElements * 3));
}

void Generator::Part::writeBlock(const MTPDtlsBlockE &data) {
	const auto lengths = std::array{ 144, 176, 208, 240 };
	const auto length = lengths[base::RandomIndex(lengths.size())];
	writeBlock(MTP_tlsBlockRandom(MTP_int(length)));
}

void Generator::Part::writeBlock(const MTPDtlsBlockPadding &data) {
	const auto length = int(_result.size());
	if (length < 513) {
		const auto zero = MTP_tlsBlockZero(MTP_int(513 - length));
		writeBlock(MTP_tlsBlockString(MTP_bytes("\x00\x15"_q)));
		writeBlock(MTP_tlsBlockScope(MTP_vector<MTPTlsBlock>(1, zero)));
	}
}
```

### A-E1.6 Digest, timestamp and size

Verbatim `details/mtproto_tls_socket.cpp:523-559`:

```cpp
void Generator::Part::finalize(bytes::const_span key) {
	if (_error) {
		return;
	} else if (_digestPosition < 0) {
		_error = true;
		return;
	}
	writeDigest(key);
	injectTimestamp();
}

QByteArray Generator::Part::extractDigest() const {
	if (_digestPosition < 0) {
		return {};
	}
	return _result.mid(_digestPosition, kHelloDigestLength);
}

void Generator::Part::writeDigest(bytes::const_span key) {
	Expects(_digestPosition >= 0);

	bytes::copy(
		bytes::make_detached_span(_result).subspan(_digestPosition),
		openssl::HmacSha256(key, bytes::make_span(_result)));
}

void Generator::Part::injectTimestamp() {
	Expects(_digestPosition >= 0);

	const auto storage = bytes::make_detached_span(_result).subspan(
		_digestPosition + kHelloDigestLength - sizeof(int32),
		sizeof(int32));
	auto already = int32();
	bytes::copy(bytes::object_as_span(&already), storage);
	already ^= qToLittleEndian(int32(base::unixtime::http_now()));
	bytes::copy(storage, bytes::object_as_span(&already));
}
```

Algorithm (for the Rust implementation):

1. Render the template; the first `Z(32)` leaves 32 zero bytes at record offset 11.
2. `digest = HMAC-SHA256(key = secret[1..17), message = the whole record including its 5-byte header)`.
3. Write `digest` at offset 11.
4. XOR the last 4 bytes of the digest (offsets 39..43) with `int32_le(unixtime)`. tdesktop uses `base::unixtime::http_now()`, i.e. local time corrected by the last HTTP `Date` header seen (A-E1.9).
5. Remember the 32 bytes as sent (after the XOR): `_incoming = hello.digest` (`:666`). They seed the server-hello HMAC check.

Size: re-implementing the template gives `|hello| = 1572 + L + E` bytes, `E` in {144,176,208,240} (checked by script for several L/E). `kClientHelloLimit = 2048` (`:24`) is enforced in `grow()` (`:365-371`); exceeding it sets `_error`, `plainConnected()` logs "Could not generate Client Hello." and fails the socket (`:655-663`). Consequences: domains up to 236 bytes always work; 237-332 bytes fail randomly depending on `E`; more than 332 always fail. The padding block never fires because the hello is always at least 1573 bytes.

### A-E1.7 Server hello validation (`details/mtproto_tls_socket.cpp:687-797`)

Expected server flight (the MTProxy "fake TLS" response):

```
16 03 03 AA AA  <A bytes: ServerHello; server_random at flight offset 11>
14 03 03 00 01 01                     (ChangeCipherSpec)
17 03 03 BB BB  <B bytes: fake encrypted data>
```

Checks, in order:
1. The first 5 bytes start with `16 03 03`; read `A` (`checkHelloParts12`).
2. Bytes `5+A .. 5+A+9` equal `14 03 03 00 01 01 17 03 03`; read `B` (`checkHelloParts34`).
3. Total `5 + A + 9 + 2 + B <= 65536` (`kMaxServerHelloLength`, `:27`), checked at both stages.
4. Copy `server_random` (flight offset 11..43, `kServerHelloDigestPosition = 11`), zero it in place, compute `HMAC-SHA256(key, client_digest_32 || whole_flight_with_zeroed_random)`, compare with the copy. Mismatch gives "Bad Server Hello digest." and error.
5. Remove the client digest and the flight from the buffer; any bytes left over are parsed as application-data records on the next event-loop turn (`:786-793`); state becomes `Connected` and `connected` fires.

The comparison uses `bytes::compare` (memcmp, not constant time). The Rust engine should use a constant-time compare.

### A-E1.8 Data-phase framing (`details/mtproto_tls_socket.cpp:811-938`)

- Outgoing: the first `write()` carries the 64-byte obfuscation init header as `prefix`. When `prefix` is non-empty, a single ChangeCipherSpec record `14 03 03 00 01 01` is written first. The data is then sent as `17 03 03 <len16>` records with at most `kClientPartSize = 2878` payload bytes each (`:32`), and the prefix counts toward the first record.
- Incoming: every record must start with `17 03 03`, otherwise "Bad packet header." and error. Zero-length records are skipped. No limit beyond the 16-bit length. Record payloads are concatenated and handed to the obfuscation/AES-CTR layer (the TLS layer is pure framing; it adds no crypto after the handshake).

### A-E1.9 Coupling with clock synchronisation

- `TlsSocket::handleError()` fires `_syncTimeRequests` when the error happens before `Connected` (`:948-951`); `timedOut()` also fires it (`:863-865`).
- `session_private.cpp:234-237` forwards it to `Instance::syncHttpUnixtime()` (`mtp_instance.cpp:544-553`). If HTTP time is not yet valid, that starts a `SpecialConfigRequest` in time-only mode (Google + Mozilla DoH only). It parses the `Date:` header of any response (`special_config_request.cpp:137-181`, `:348-374`) into `base::unixtime::http_update()`.
- Rationale: MTProxy servers check the hello timestamp to block replays, so a skewed local clock silently breaks every `ee` proxy. tdesktop self-heals by learning wall time from the HTTPS `Date` header of well-known hosts.

### A-E1.10 vs tdlib / robustness notes

- Same protocol as tdlib `TlsInit` (HMAC over the hello with zeroed random, timestamp XOR into the last 4 bytes, server check `16 03 03` ... `14 03 03 00 01 01 17 03 03` ..., HMAC over `client_random || response_with_zeroed_random`). tdlib also splits outgoing data into records of at most 2878 bytes (confirmed: `MAX_TLS_PACKET_LENGTH = 2878`, `tdlib:TcpTransport.h:162`).
- tdlib historically produced key-share bytes as a random field element checked to be a valid x25519 x-coordinate (quadratic-residue test) instead of real keygen (confirmed still current: `get_y2`/`is_quadratic_residue`, `tdlib:TlsInit.cpp:429-430`; tdlib's template also carries the `44cd` ALPS extension, `TlsInit.cpp:226`). tdesktop uses real `EVP_PKEY_X25519` keygen, which is simpler and obviously valid. Leftover `BigNum` aliases at `:36-37` suggest tdesktop used the same trick before.
- tdesktop's template mirrors a 2025-2026 Chrome: X25519MLKEM768 hybrid share (0x11ec, 1216 bytes), GREASE ECH, new ALPS code point 0x44cd, and ML-DSA signature code points. It does this through the TL-declared template. **Recommendation:** keep the hello template as data in the Rust engine (versioned, unit-tested by structure), so a DPI fingerprint change needs no code change.
- Weak spots to avoid in Rust: memcmp for the HMAC check; no timeout inside the TLS state machine (it relies on the connection-level timers); `ranges::shuffle` uses a non-cryptographic URBG (only affects fingerprint entropy, not security); unbounded random choice of `E` can break long domains (validate domain length at secret-parse time instead).
- **Test idea:** a structural parser test. Generate a hello, parse it as TLS, assert the extension set and order invariants, and recompute the HMAC with the timestamp un-XORed. The shuffle and randomness make byte-exact vectors impossible without injecting an RNG. Design the Rust generator to accept an RNG plus a clock so golden vectors can be produced.

---

## A-E2. Plain TCP socket, reserved nonces, web-proxy socket

The reserved-prefix check (`details/mtproto_tcp_socket.cpp:59-82`) is quoted in A9.

- The obfuscated-transport init nonce is regenerated until it passes: first byte != `0xEF` (abridged marker); first LE u32 not `HEAD`, `POST`, `GET `, `0xEEEEEEEE`, `0xDDDDDDDD`, `0x02010316` (TLS-like); second u32 != 0.
- **Discrepancy:** the official transport docs and tdlib also reject `0x4954504F` (`OPTI`, i.e. `OPTIONS`) (confirmed: P-061 and `tdlib:TcpTransport.cpp:99-100`). tdesktop omits it. Harmless in practice (probability 2^-32), but the Rust engine should implement the complete list from the docs.
- `TcpSocket` forwards Qt signals and reports every `QAbstractSocket` error as a socket error (`details/mtproto_tcp_socket.cpp:122-125`; error classification for logs only at `details/mtproto_abstract_socket.cpp:31-69`).
- `WebProxySocket` (`details/mtproto_web_proxy_socket.cpp`) is a 2026 addition, the "Web" proxy type. MTProto bytes go over a localhost WebSocket (`ws://127.0.0.1:<port>/transport`) to a page in the user's real browser. That page relays them through an iframe on `https://<proxy host>/<base path>/?bridge=<capability>` (`web_proxy/web_proxy_transport.cpp:1600-1700`).
  - Stream-multiplexed frames with an 8-byte header: Open/Data/Close/Window/Ping/Pong/Hello/Welcome/AuthChallenge/AuthResponse/Bye (`web_proxy/web_proxy_frame.h:16-35`).
  - Per-stream flow-control window of 4 MiB (`kInitialStreamWindow`); `grantWindow` is called on read (`details/mtproto_web_proxy_socket.cpp:99-101`).
  - Capability = `base64url(HMAC-SHA256(key=mtproto-secret, "tdesktop-web-proxy-bridge-v1\n"+host))`, or the v2 context with the path (`mtproto_proxy_data.cpp:178-194`, with self-test vectors at `:359-379`).
  - Out of scope for the engine's first version. Worth knowing as a censorship-resistance path that rides on the browser's own TLS stack.

---

## A-E3. DNS-over-HTTPS resolver for proxy host names (`details/mtproto_domain_resolver.cpp`)

**Purpose:** resolve SOCKS5/MTProxy host names when the system resolver is poisoned. Used only when `ProxyData::tryCustomResolve()` holds: the type is Socks5 or Mtproto and the host is not a literal IPv4/IPv6 address (`mtproto_proxy_data.cpp:508-515`). It is triggered from `connection_resolving.cpp:38`; the IP that actually connected is promoted to the front of the list via `setGoodProxyDomain` (`mtp_instance.cpp:446-473`). Each resolved IP becomes a direct-IP proxy (`ToDirectIpProxy`, `mtproto_proxy_data.cpp:560-573`).

Behaviour (`details/mtproto_domain_resolver.cpp:25-70` constants/UA/padding, `:189-238` attempt list, `:274-315` request formats):
- IPv4 (`type=1`) and IPv6 (`type=28`) are resolved as independent attempts (`:189-192`).
- Attempt order: the first two are `dns.google.com` direct, and `<random google domain>/resolve` with `Host: dns.google.com` (domain fronting), shuffled with each other. Then `mozilla.cloudflare-dns.com/dns-query` (`accept: application/dns-json`). Then the remaining fronted Google domains from {google.com, www.google.com, google.ru, www.google.ru}.
- A new attempt starts every 800 ms (`kSendNextTimeout`) regardless of earlier ones, so requests run in parallel. The first non-empty JSON `Answer` wins and the rest are aborted (`:317-341`).
- TTL handling: each record's TTL is clamped to at least 10 s, the minimum is taken, and the cap is 300 s (`:329-335`).
- The callback fires only when a fresh IPv4 cache entry exists; IPv6 entries are appended if fresh (`:240-254`). **Finding:** an IPv6-only proxy host is never delivered.
- Every request carries a Chrome-151 `User-Agent` and `random_padding` of 13..128 alphanumeric chars, to mask the request length.
- **Live probe (2026-10-01, from the research machine):** `https://dns.google.com/resolve` direct gives HTTP 200. `https://google.ru/resolve` with `Host: dns.google.com` gives HTTP **404**: Google no longer honours this fronting, so in tdesktop only the direct attempt can succeed. `mozilla.cloudflare-dns.com` failed TLS from the probe network (the local resolver returned an ISP address, so this is inconclusive).

**vs tdlib:** tdlib resolves proxy and DC names through `GetHostByNameActor` (`tdlib:tdnet/td/net/GetHostByNameActor.h:26-36`), which tries resolvers **in order** (`Native` by default; `{Google DoH, Native}` when the `expect_blocking` option is set, with a 60 s OK-cache and no error cache, `tdlib:td/telegram/net/ConnectionCreator.cpp:253-262`). Rust recommendation: race native DNS with DoH; treat fronted DoH as a best-effort extra; deliver IPv6-only answers; keep TTL clamping.

---

## A-E4. Simple-config bootstrap (`special_config_request.cpp`)

### A-E4.1 When it runs

- **Config mode:** `ConfigLoader::enumerate()` calls `refreshSpecialLoader()` (`config_loader.cpp:115`, `:118-127`). It never runs while a proxy is enabled, or in KeysDestroyer mode. Timeline: `help.getConfig` goes to the main DC at start. If nothing arrives within 8 s (`kEnumerateDcTimeout`, `config_loader.cpp:21`), enumeration starts, and with it the special loader.
- **Time-only mode:** `Instance::syncHttpUnixtime()` (`mtp_instance.cpp:544-553`). Only the `Date` header is used.

### A-E4.2 Constants and attempt list (verbatim)

Verbatim `special_config_request.cpp:26-42`:

```cpp
constexpr auto kPublicKey = "\
-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEAyr+18Rex2ohtVy8sroGPBwXD3DOoKCSpjDqYoXgCqB7ioln4eDCF\n\
fOBUlfXUEvM/fnKCpF46VkAftlb4VuPDeQSS/ZxZYEGqHaywlroVnXHIjgqoxiAd\n\
192xRGreuXIaUKmkwlM9JID9WS2jUsTpzQ91L8MEPLJ/4zrBwZua8W5fECwCCh2c\n\
9G5IzzBm+otMS/YKwmR1olzRCyEkyAEjXWqBI9Ftv5eG8m0VkBzOG655WIYdyV0H\n\
fDK/NWcvGqa0w/nriMD6mDjKOryamw0OP9QuYgMN0C9xMW9y8SmP4h92OAWodTYg\n\
Y1hZCxdv6cs5UnW9+PWvS+WIbkh+GaWYxwIDAQAB\n\
-----END RSA PUBLIC KEY-----\
"_cs;

const auto kRemoteProject = "peak-vista-421";
const auto kFireProject = "reserve-5a846";
const auto kConfigKey = "ipconfig";
const auto kConfigSubKey = "v3";
const auto kApiKey = "AIzaSyC2-kAkpDsroixRXw-sTw-Wfqo4NxjMwwM";
const auto kAppId = "1:560508485281:web:4ee13a6af4e84d49e67ae0";
```

Verbatim `special_config_request.cpp:213-234`:

```cpp
	_attempts = {};
	_attempts.push_back({ Type::Google, "dns.google.com" });
	_attempts.push_back({ Type::Mozilla, "mozilla.cloudflare-dns.com" });
	if (!_timeDoneCallback) {
		_attempts.push_back({ Type::FireStore, "firestore" });
		for (const auto &domain : DnsDomains()) {
			_attempts.push_back({ Type::FireStore, domain, "firestore" });
		}
	}

	shuffle(0, 2);
	if (!_timeDoneCallback) {
		shuffle(_attempts.size() - (int(DnsDomains().size()) + 1), _attempts.size());
	}
	if (isTestMode) {
		_attempts.erase(ranges::remove_if(_attempts, [](
				const Attempt &attempt) {
			return (attempt.type != Type::Google)
				&& (attempt.type != Type::Mozilla);
		}), _attempts.end());
	}
	ranges::reverse(_attempts); // We go from last to first.
```

- Order: (Google DoH, Mozilla DoH) shuffled. Then (Firestore direct, Firestore fronted through each of google.com/www.google.com/google.ru/www.google.ru) shuffled. Attempts go out every 800 ms in parallel (`:268-279`).
- Test mode keeps only DoH (`:227-233`).
- `RemoteConfig` (Firebase Remote Config) and `Realtime` (Firebase RTDB) are implemented (`:307-320`) but **never scheduled**: dead code.

### A-E4.3 Exact requests (`special_config_request.cpp:281-346`)

| Type | Request (domain string `apv3.stel.com`, test `tapv3.stel.com`, `mtproto_config.cpp:28-30`) |
|---|---|
| Google | `GET https://dns.google.com/resolve?name=apv3.stel.com&type=ANY&random_padding=<13..128>` (response filtered to type 16) |
| Mozilla | `GET https://mozilla.cloudflare-dns.com/dns-query?name=apv3.stel.com&type=16&random_padding=...` + `accept: application/dns-json` |
| FireStore direct | `GET https://firestore.googleapis.com/v1/projects/reserve-5a846/databases/(default)/documents/ipconfig/v3` |
| FireStore fronted | same path on `https://{google.com,www.google.com,google.ru,www.google.ru}` + `Host: firestore.googleapis.com` |
| (dead) RemoteConfig | `POST https://firebaseremoteconfig.googleapis.com/v1/projects/peak-vista-421/namespaces/firebase:fetch?key=AIzaSyC2-kAkpDsroixRXw-sTw-Wfqo4NxjMwwM`, JSON `{"app_id":"1:560508485281:web:4ee13a6af4e84d49e67ae0","app_instance_id":"<22-char FID>"}`; value at `entries.ipconfigv3` |
| (dead) Realtime | `GET https://reserve-5a846.firebaseio.com/ipconfigv3.json`; value is a JSON string |

All requests use a `QNetworkAccessManager` with `NoProxy` (`:201`) and the Chrome UA. The server-provided `config.dc_txt_domain_name` is **ignored**: `Config::apply` never reads it (`mtproto_config.cpp:225-295`), and the domain is hard-coded.

**Live probe (2026-10-01):**
- Google DoH direct: 200. The TXT value is split into 2 strings of 250 + 94 chars; with `type=ANY`, Google returned the short chunk first. So **sorting is mandatory**.
- Firestore direct: 200. Firestore fronted via `www.google.com` with `Host: firestore.googleapis.com`: 200, so fronting still works for Firestore.
- DNS fronting via `google.ru`: 404.
- `tapv3.stel.com` (test) decrypts to a config that **expired 2019-08-11**, so it is always rejected.

### A-E4.4 Response extraction (verbatim)

Verbatim `special_config_request.cpp:82-88`:

```cpp
QByteArray ConcatenateDnsTxtFields(const std::vector<DnsEntry> &response) {
	auto entries = QMultiMap<int, QString>();
	for (const auto &entry : response) {
		entries.insert(INT_MAX - entry.data.size(), entry.data);
	}
	return QStringList(entries.values()).join(QString()).toLatin1();
}
```

- DNS: `Answer[]` entries with `type == 16`, `data` strings. They are concatenated **longest first** (QMultiMap keyed by `INT_MAX - size`). Equal lengths come out in implementation-defined order, which would make the SHA check fail if the publisher ever split into equal halves. **Rust:** sort by length descending, and on SHA failure retry the other orders (n <= 3).
- Firestore: `fields.data.stringValue`.

### A-E4.5 Decryption

Implementation: `SpecialConfigRequest::decryptSimpleConfig`, `special_config_request.cpp:421-485`.

Normative steps:
1. Remove every char not in `[A-Za-z0-9+/=]`. The result must be exactly 344 chars, and base64-decoding must give exactly 256 bytes.
2. `m = c^e mod n` with the simple-config RSA public key (`RSA_public_decrypt` with `RSA_NO_PADDING`; `details/mtproto_rsa_public_key.cpp:146-162`), as 256 bytes big-endian.
3. AES-256-CBC **decrypt** with `key = m[0..32)`, `iv = m[16..32)` (the IV overlaps the second half of the key), on `ciphertext = m[32..256)` (224 bytes).
4. `data = plain[0..208)`. Require `SHA256(data)[0..16) == plain[208..224)`.
5. `len = int32_le(data[0..4))` is the length **including the 4-byte length field**. It must satisfy `0 < len <= 208` and `len % 4 == 0`.
6. Parse a boxed `help.configSimple` from `data[4..)`. Require that exactly `208 - len` bytes remain after it, i.e. the object is exactly `len - 4` bytes and the rest is padding. The live vector confirms `len = 80 = 4 + 76`.

### A-E4.6 TL and rule semantics

Verbatim `scheme/mtproto.tl:100-103`:

```tl
ipPort#d433ad73 ipv4:int port:int = IpPort;
ipPortSecret#37982646 ipv4:int port:int secret:bytes = IpPort;
accessPointRule#4679b65f phone_prefix_rules:string dc_id:int ips:vector<IpPort> = AccessPointRule;
help.configSimple#5a592a6c date:int expires:int rules:vector<AccessPointRule> = help.ConfigSimple;
```

- `rules:vector<AccessPointRule>` and `ips:vector<IpPort>` are **bare** vectors (lower-case `vector`): count only, no `0x1cb5c415`. The elements are boxed (constructor id present).
- The IPv4 `int` is read little-endian into a u32 and printed most-significant-byte first (`(ip >> 24) & 0xFF` first, `:516-523`). Example: wire `32 fa dd c2` gives `0xc2ddfa32` = `194.221.250.50`.

Verbatim `special_config_request.cpp:64-80`:

```cpp
bool CheckPhoneByPrefixesRules(const QString &phone, const QString &rules) {
	static const auto RegExp = QRegularExpression("[^0-9]");
	const auto check = QString(phone).replace(
		RegExp,
		QString());
	auto result = false;
	for (const auto &prefix : rules.split(',')) {
		if (prefix.isEmpty()) {
			result = true;
		} else if (prefix[0] == '+' && check.startsWith(prefix.mid(1))) {
			result = true;
		} else if (prefix[0] == '-' && check.startsWith(prefix.mid(1))) {
			return false;
		}
	}
	return result;
}
```

Response handling (`special_config_request.cpp:487-548`):
- Freshness: rejected if `http_now() > expires`. `date` is not checked against the future. Empty `rules` are rejected.
- Phone prefix rules: the phone is reduced to digits and split on `,`. An empty item matches. `+P` matches when the phone starts with P. `-P` is an immediate veto. Before login the phone is empty, so only rules containing an empty item match.
- Each matching rule yields `(dc_id, ip, port, secret?)` callbacks, followed by a terminal `(0, "", 0, {})`, after which `ConfigLoader` drops the loader (`config_loader.cpp:146-148`).

### A-E4.7 How endpoints are used (`config_loader.cpp`)

Source: `config_loader.cpp:154-235`.

- Endpoints are de-duplicated against both the pending and the tried lists (`:165-168`). The first one schedules `sendSpecialRequest` after 1 ms (`:172-174`).
- A random pending endpoint is mapped to the **temporary DC id** `1000 + dc` (`getTemporaryIdFromRealDcId`, `facade.h:85-88`; `kTemporaryMainDc = 1000`, `mtp_instance.h:44`). It is added as a DC option with `tcpo_only | (secret ? f_secret : 0)`, and `help.getConfig` is sent there.
- Each endpoint gets 6 s (`kSpecialRequestTimeoutMs = 6000`; the comment at `config_loader.cpp:22` says "4 seconds" and is stale).
- The temporary DC **shares the real DC's `Dcenter`** (auth key): `getDcById` maps 100x to x (`mtp_instance.cpp:791-811`). No new key is needed if one exists.
- On success only `dc_options` is applied, overwriting the whole option table (`setFromList`). The full config is still awaited from the main DC.

### A-E4.8 TEST VECTOR — live simple config (captured 2026-10-01, valid until 2027-05-04)

Source: `GET https://dns.google/resolve?name=apv3.stel.com&type=16`. TXT answers in the order received (lengths 250 and 94):

```
# TXT string, 250 chars
oiVvQMgmCSOQvenEo/Ug1a+IzF4Q/13++Cq2zwvy0z75GVRblmruH6SBuEaPsfEz
pAdJw/1QoMphLuQx9bzCU2LgCMLNZ+4awO+Is8p4k0r4FgerDwWBFabdMBUl2sZM
OKI4c4soNa6LXal7q7kuVTZjFNSC6p9dcYTYtG1GnQPf5W7kD6hPZDr1PF5+Wga3
yp6hErN0iff2BMxmmmxAAbWOQ2TbaDlY36ViLkf9RUXcxAABU4Vg9d9mW0
# TXT string, 94 chars
35arl4mB8+LFXX7F4rGWpyGpsclPI6jq4L7OvFpmAAJtUp7pD8BSBtCJa7rgojCj
kjnYxGPQA/3MHeBCrT22Y5V+Y0KA==
```

Concatenated longest-first and filtered (344 chars):

```
oiVvQMgmCSOQvenEo/Ug1a+IzF4Q/13++Cq2zwvy0z75GVRblmruH6SBuEaPsfEz
pAdJw/1QoMphLuQx9bzCU2LgCMLNZ+4awO+Is8p4k0r4FgerDwWBFabdMBUl2sZM
OKI4c4soNa6LXal7q7kuVTZjFNSC6p9dcYTYtG1GnQPf5W7kD6hPZDr1PF5+Wga3
yp6hErN0iff2BMxmmmxAAbWOQ2TbaDlY36ViLkf9RUXcxAABU4Vg9d9mW035arl4
mB8+LFXX7F4rGWpyGpsclPI6jq4L7OvFpmAAJtUp7pD8BSBtCJa7rgojCjkjnYxG
PQA/3MHeBCrT22Y5V+Y0KA==
```

After raw RSA with the simple-config key (A-E5), 256 bytes; `key = [0..32)`, `iv = [16..32)`:

```
927fc91ff629d5f63c7c1c46453bb4dc545358db5dab9705e0c633a34ebb1fe2
895a93e2097d9c6a10103fb281dcd53f4824b9b8bfc0efb3f4b451dbcf92100c
06cfca8ce151cb20e5077b6028a4380486067696e5aacdefa403041460287e18
ade85178ee9a548a1ae58e46292ec4a339955ea3adaa56c1466d2d910f9e4e4c
440d383ce80ecc7928cf7b02460f02f1aebe0749740eb1e4f5a4fad689e80331
2dc6ee77eda825ce580c09c6134f79e9a6cee54b702f2fcd66425211a8408c0d
291d170123627db982e68d4d78366c53b1c0137dc0bff8a67d01396138c96d48
73beb3a5e5f483cef7062b1b82b444fbd61dfc55ec148fe309616bd8d3c1b5bf
```

After AES-256-CBC decrypt of bytes [32..256), 224 bytes: `data[0..208) || sha256(data)[0..16)`:

```
500000006c2a595a11e6f8699119da6b010000005fb679460000000004000000
010000004626983732faddc2bb0100001feef7f7da556b4bd989fd44c9bc7b7b
2a757777772e676f6f676c652e636f6d9c7ea2d9293fc56ab7605aed5d3b80db
bb81f63ccbf78dff694d26d2f70c5cff23ea3b1ced86ed4caf771d555f60ef89
d2843bc056c7ca481abce286fadecedcb47f978442224ef32790759b55e7f81d
ad416a7e4afb6c8c1281e5823bc9ec164781cad2f05ddd942489cf7dc03497b6
0cf413b5fc931998c6e97f90f21e87bbe95edb89928e97be58b3ad4f973652d4
```

Parsed:
```
len               = 0x50 = 80 (includes itself; object = 76 bytes; 128 bytes padding)
constructor       = 0x5a592a6c help.configSimple
date              = 1777919505 (2026-05-04 18:31:45 UTC)
expires           = 1809455505 (2027-05-04 18:31:45 UTC)
rules (bare)      = 1
  accessPointRule#4679b65f phone_prefix_rules="" dc_id=4 ips(bare)=1
    ipPortSecret#37982646 ipv4=0xc2ddfa32 -> 194.221.250.50 port=443
      secret(31) = ee f7f7da556b4bd989fd44c9bc7b7b2a75 7777772e676f6f676c652e636f6d
                   (0xEE fake-TLS, 16-byte key, domain "www.google.com")
SHA256(data)[0..16) check: OK
```

Second vector, Firestore (`fields.data.stringValue`, document updated 2026-07-24):

```
SIiJpKPAUg/1tqjnFQSFH78tMOqkYxeiiKkY6B4Ao1hBDp/UbDy9Zda2azORL1ib
t7mRfy6E8wPekcSqWvTHDPnaYk7ec9VkEWgSDBYUadtAZAI7mvAaV3rDdUS63lMc
teZf7BOVYX56GgXO3CSLmMx0P0CRybYwRwERDgQ5tY+QuPyTXPn5Xm+FoeqjH3ni
DmPi+8rOmw6Q3paCYJNtGr9+LyspCvWdL0Pto5g0XBLTpMMkj7nwB9bttrMrLbKu
0ToOIOwlYd8VkJVypR6KSLhCzs0tevQONL8FB+npIQCr1HdDukoLREofAtUsGc2k
aliZ2ORDeur24emaUaNI6g==
```
RSA output:
```
32f736eff4504f689b8785396d07830fa9bd1eef8c23903d8291b80fad5c4b94
b6a9b15b89590046372d0139ebf7bbfd5c70157faa24a7c58a8be107e9225e40
06630fef0e63fb3e7b5c2ee66dc484ab40447a30c1da0ce756218761d18ebdf0
c00760598eda67644a82fc89b3abbd5bf4e7ed88cc1a956a2e5088d1480e48e6
81e7bbd85b8c7426cc1ab343a4bb2c146035c334e8b7a12c93a18478e5987bd4
615da6d3a90e4cdf2bca44578cf6fdd7cf74f0dd44a8db0bb2884dcb42476a07
9e51dc80a827a639f0dec96e3aff59000f824fc17c61e47d1ef52d38ce554781
bf672e22aff6657825a2f1fa0e5e4bac683049ac45dd2fbc5699cb9d479bcb41
```
AES plaintext:
```
500000006c2a595a8564636a0598446c010000005fb679460000000004000000
0100000046269837654ca15fbb0100001feef7f7da556b4bd989fd44c9bc7b7b
2a757777772e676f6f676c652e636f6d954bd2fdaa343096d088016a434d9c1e
25222aa5d85f869a407daaf40143c9a1e8eda5e85be4f34415a133c8a91a7437
86128e85652fa9a0f8bb0096473a9ddd5cdf963b18ed6458a24ed6a7fee45ede
eeb1c12d5c9febbe185bc59e9235001c312dfaee8b84f611eb393bf813eb6568
ac408e402cbc2d667ff68d7e2c3ae4d158d4d0756ee16c2117b1f84b9e08a764
```
Parsed: `len=80`, date 1784898693 (2026-07-24 13:11:33), expires 1816434693 (2027-07-24 13:11:33), one rule `dc_id=4`, `ipPortSecret 95.161.76.101:443` with the same `ee...www.google.com` secret.

Independent re-check (2026-10-01, Python `pow` + macOS CommonCrypto AES-CBC, not the script that produced the
dump): the Google-DoH vector gives the same RSA output prefix `927fc91f…1fe2`, `SHA256(data)[0..16)` matches, and
`len=80, constructor=0x5a592a6c, date=1777919505, expires=1809455505, rules=1`.

Negative vector: `tapv3.stel.com` (test DCs) decrypts correctly (SHA OK) to `date=1562949126`, `expires=1565541126` (2019-08-11), `dc_id=2`, `139.59.210.98:14544`, secret `eefdda254c78d9fa202ac536079e88b8087777772e676f6f676c652e636f6d`. It **must be rejected** as expired. Live data changes; snapshot these bytes into fixtures rather than fetching them in tests.

### A-E4.9 vs tdlib / robustness

- tdlib `ConfigManager` uses the same RSA key, AES-CBC key/IV split and 16-byte SHA256 tag. It asks **one source per attempt**, rotating by `simple_config_turn_ % 9` (`tdlib:td/telegram/ConfigManager.cpp:755-772`): Google DoH (`dns.google/resolve`) on turns 0/3/7, Mozilla DoH on 1/4/6, Firestore on 2, Azure (`tcdnb.azureedge.net`) on 5, Firebase Realtime on 8 (Firebase Remote Config code exists but is not in the rotation), and it **does** pass `dc_txt_domain_name` from the server config (`:774-775`). tdesktop instead fires all sources staggered by 800 ms and ignores `dc_txt_domain_name`.
- Phone-rule evaluation is the same as tdesktop (`-P` vetoes, `+P`/empty item matches), except tdlib returns `true` up front when the rules string **or the phone** is empty (`tdlib:td/telegram/ConfigManager.cpp:546-564`), so before login every rule matches; tdesktop only matches rules that contain an empty item.
- tdesktop strengths: parallel staggered attempts (800 ms), HTTP-Date time sync, test-mode isolation. Weaknesses: dead Firebase code; equal-length TXT ordering hazard; `dc_txt_domain_name` ignored; no lower-bound check on `date`.

---

## A-E5. RSA public keys and fingerprints

### A-E5.1 Built-in keys (verbatim)

Verbatim `mtproto_dc_options.cpp:60-78`:

```cpp
const char *kTestPublicRSAKeys[] = { "\
-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR\n\
yy7mx66W0/sOFa7/1mAZtEoIokDP3ShoqF4fVNb6XeqgQfaUHd8wJpDWHcR2OFwv\n\
plUUI1PLTktZ9uW2WE23b+ixNwJjJGwBDJPQEQFBE+vfmH0JP503wr5INS1poWg/\n\
j25sIWeYPHYeOrFp/eXaqhISP6G+q2IeTaWTXpwZj4LzXq5YOpk4bYEQ6mvRq7D1\n\
aHWfYmlEGepfaYR8Q0YqvvhYtMte3ITnuSJs171+GDqpdKcSwHnd6FudwGO4pcCO\n\
j4WcDuXc2CTHgH8gFTNhp/Y8/SpDOhvn9QIDAQAB\n\
-----END RSA PUBLIC KEY-----" };

const char *kPublicRSAKeys[] = { "\
-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n\
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n\
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n\
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\n\
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n\
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n\
-----END RSA PUBLIC KEY-----" };
```

Only **one** production key ships now. The older four keys are gone. CDN keys come from `help.getCdnConfig` (A-E6.4).

### A-E5.2 Fingerprint and raw RSA

Verbatim `details/mtproto_rsa_public_key.cpp:192-204`:

```cpp
void RSAPublicKey::Private::computeFingerprint() {
	Expects(valid());

	const BIGNUM *n, *e;
	mtpBuffer string;
	RSA_get0_key(_rsa, &n, &e, nullptr);
	MTP_bytes(ToBytes(n)).write(string);
	MTP_bytes(ToBytes(e)).write(string);

	bytes::array<20> sha1Buffer;
	openssl::Sha1To(sha1Buffer, bytes::make_span(string));
	_fingerprint = *(uint64*)(sha1Buffer.data() + 12);
}
```

- `fingerprint = u64_le(SHA1(tl_bytes(n_be_minimal) || tl_bytes(e_be_minimal))[12..20))`, i.e. the lower 64 bits of SHA1 as in the docs.
- `encrypt()` = raw `RSA_NO_PADDING` on exactly 256 input bytes, output left-padded to 256. The MTProto RSA_PAD construction itself lives in `details/mtproto_dc_key_creator.cpp` (core part).
- `decrypt()` = raw public-key "decrypt" for the simple config. **Latent bug:** the re-alignment branch moves `subspan(zeroBytes - res, res)` instead of `subspan(zeroBytes, res)` (`:156-160`). It is unreachable because `RSA_NO_PADDING` always returns 256 bytes.
- `encryptOAEPpadding()` exists (`:164-186`) but nothing under `mtproto/` uses it.

### A-E5.3 Fingerprint TEST VECTORS (computed for this digest; production value matches the well-known 0xd09d1d85de64fd85)

```
production (mtproto_dc_options.cpp:70-78)
  n (hex, 2048 bits) =
    e8bb3305c0b52c6cf2afdf7637313489e63e05268e5badb601af417786472e5f
    93b85438968e20e6729a301c0afc121bf7151f834436f7fda680847a66bf64ac
    cec78ee21c0b316f0edafe2f41908da7bd1f4a5107638eeb67040ace472a14f9
    0d9f7c2b7def99688ba3073adb5750bb02964902a359fe745d8170e36876d4fd
    8a5d41b2a76cbff9a13267eb9580b2d06d10357448d20d9da2191cb5d8c93982
    961cdfdeda629e37f1fb09a0722027696032fe61ed663db7a37f6f263d370f69
    db53a0dc0a1748bdaaff6209d5645485e6e001d1953255757e4b8e42813347b1
    1da6ab500fd0ace7e6dfa3736199ccaf9397ed0745a427dcfa6cd67bcb1acff3
  e = 65537
  SHA1(TL bytes n || TL bytes e) = 0e654fa95e8a12079ada852085fd64de851d9dd0
  fingerprint = 0xd09d1d85de64fd85 (signed -3414540481677951611)
test (mtproto_dc_options.cpp:60-68)
  n (hex, 2048 bits) =
    c8c11d635691fac091dd9489aedced2932aa8a0bcefef05fa800892d9b52ed03
    200865c9e97211cb2ee6c7ae96d3fb0e15aeffd66019b44a08a240cfdd2868a8
    5e1f54d6fa5deaa041f6941ddf302690d61dc476385c2fa655142353cb4e4b59
    f6e5b6584db76fe8b1370263246c010c93d011014113ebdf987d093f9d37c2be
    48352d69a1683f8f6e6c2167983c761e3ab169fde5daaa12123fa1beab621e4d
    a5935e9c198f82f35eae583a99386d8110ea6bd1abb0f568759f62694419ea5f
    69847c43462abef858b4cb5edc84e7b9226cd7bd7e183aa974a712c079dde85b
    9dc063b8a5c08e8f859c0ee5dcd824c7807f20153361a7f63cfd2a433a1be7f5
  e = 65537
  SHA1(TL bytes n || TL bytes e) = 5e79685a3c1e70aef39bdb1303268d20df9858b2
  fingerprint = 0xb25898df208d2603 (signed -5595554452916591101)
simple-config (special_config_request.cpp:26-35)
  n (hex, 2048 bits) =
    cabfb5f117b1da886d572f2cae818f0705c3dc33a82824a98c3a98a17802a81e
    e2a259f87830857ce05495f5d412f33f7e7282a45e3a56401fb656f856e3c379
    0492fd9c596041aa1dacb096ba159d71c88e0aa8c6201dd7ddb1446adeb9721a
    50a9a4c2533d2480fd592da352c4e9cd0f752fc3043cb27fe33ac1c19b9af16e
    5f102c020a1d9cf46e48cf3066fa8b4c4bf60ac26475a25cd10b2124c801235d
    6a8123d16dbf9786f26d15901cce1bae7958861dc95d077c32bf35672f1aa6b4
    c3f9eb88c0fa9838ca3abc9a9b0d0e3fd42e62030dd02f71316f72f1298fe21f
    763805a87536206358590b176fe9cb395275bdf8f5af4be5886e487e19a598c7
  e = 65537
  SHA1(TL bytes n || TL bytes e) = 53c1ed69cc778f8b1ed4997a1577475111703a6f
  fingerprint = 0x6f3a701151477715 (signed 8014841706539611925)
```

### A-E5.4 Key selection

`DcOptions::getDcRSAKey` (`mtproto_dc_options.cpp:640-661`). **Finding:** if any CDN keys are known for a DC id, **only** CDN keys are searched for that DC. Otherwise only the built-in keys are searched. The server's `server_public_key_fingerprints` list is scanned in server order, and the first known key wins.

---

## A-E6. DC options (`mtproto_dc_options.cpp`)

### A-E6.1 Built-in addresses (verbatim)

Verbatim `mtproto_dc_options.cpp:31-58`:

```cpp
const BuiltInDc kBuiltInDcs[] = {
	{ 1, "149.154.175.50" , 443 },
	{ 2, "149.154.167.51" , 443 },
	{ 2, "95.161.76.100"  , 443 },
	{ 3, "149.154.175.100", 443 },
	{ 4, "149.154.167.91" , 443 },
	{ 5, "149.154.171.5"  , 443 },
};

const BuiltInDc kBuiltInDcsIPv6[] = {
	{ 1, "2001:0b28:f23d:f001:0000:0000:0000:000a", 443 },
	{ 2, "2001:067c:04e8:f002:0000:0000:0000:000a", 443 },
	{ 3, "2001:0b28:f23d:f003:0000:0000:0000:000a", 443 },
	{ 4, "2001:067c:04e8:f004:0000:0000:0000:000a", 443 },
	{ 5, "2001:0b28:f23f:f005:0000:0000:0000:000a", 443 },
};

const BuiltInDc kBuiltInDcsTest[] = {
	{ 1, "149.154.175.10" , 443 },
	{ 2, "149.154.167.40" , 443 },
	{ 3, "149.154.175.117", 443 }
};

const BuiltInDc kBuiltInDcsIPv6Test[] = {
	{ 1, "2001:0b28:f23d:f001:0000:0000:0000:000e", 443 },
	{ 2, "2001:067c:04e8:f002:0000:0000:0000:000e", 443 },
	{ 3, "2001:0b28:f23d:f003:0000:0000:0000:000e", 443 }
};
```

Built-in entries get `f_static` (IPv4) or `f_static | f_ipv6` (`:166-196`). Production DC2 has two IPv4 addresses. All built-in entries use port 443.

### A-E6.2 `dcOption` flags and how tdesktop uses them

`dcOption#18b7a10d flags:# ipv6:flags.0?true media_only:flags.1?true tcpo_only:flags.2?true cdn:flags.3?true static:flags.4?true this_port_only:flags.5?true id:int ip_address:string port:int secret:flags.10?bytes = DcOption;` (`scheme/api.tl:510`)

Lookup: `DcOptions::lookup` (`mtproto_dc_options.cpp:663-700`) and `FilterIfHasWithFlag` (`:717-735`).

| Flag | tdesktop behaviour |
|---|---|
| `ipv6` | buckets the endpoint into the IPv6 list |
| `media_only` | excluded unless the session's DC type is MediaCluster; for MediaCluster, if any media_only endpoints exist, only those are used |
| `tcpo_only` | excluded from the HTTP-transport list (kept for TCP) |
| `cdn` | `lookup(type=Cdn)` keeps only cdn endpoints; a DC is "CDN" if its **first** endpoint has the flag (`:737-745`) |
| `static` | when connecting through a SOCKS/HTTP proxy, if static endpoints exist only those are used |
| `this_port_only` | ignored |
| `secret` (flag 10) | stored; endpoints with invalid secrets are skipped; secret endpoints are TCP-only |
| `config.force_try_ipv6` | ignored |

### A-E6.3 Updates and persistence

- `setFromList` replaces the whole map (from `help.getConfig`). `addFromList` merges. An empty `dc_options` is ignored (`mtproto_config.cpp:288-292`).
- `ApplyOneOption` de-duplicates by `(ip, port)`; the **first** occurrence wins, and flags or secret of later duplicates are dropped (`:315-336`). A Rust implementation should key on `(ip, port, flags-relevant-to-transport)` or merge flags.
- `CountOptionsDifference` emits `changed(dcId)` per DC whose endpoint set changed (`:338-387`). Sessions then refresh their options.
- Persisted format v2: temporary DCs (id >= 1000) are skipped, `ip` is at most 45 bytes, `secret` at most 32 bytes, and CDN keys are stored as `(dcId, n, e)` (`:389-570`).
- `loadFromFile` is a debug override that makes options immutable (`:747-813`).

### A-E6.4 CDN config

`help.getCdnConfig` runs on demand: a session calls it when it needs a CDN DC whose keys are unknown (`session_private.cpp:1031-1036`), via `Instance::requestCDNConfig` (`mtp_instance.cpp:593-606`). `setCDNConfig` replaces all CDN keys (`mtproto_dc_options.cpp:613-633`), and they are written to settings.

### A-E6.5 `dcType()` (`:598-611`)

`Temporary` if bare id >= 1000. `Cdn` if the DC is in the CDN set. `MediaCluster` if the shifted id is a media-cluster shift (download, group-call stream, export media, updater) **and** the DC has media_only endpoints. Otherwise `Regular`.

---

## A-E7. DC-id shifting, sessions and threads

Constants: `core_types.h:43-54`.

`ShiftedDcId = shift * 10000 + dcId`. Each distinct shifted id is a separate `Session`, with its own session_id, connection and message queues. Shifted ids with the same bare DC share one `Dcenter`: the persistent key plus a regular and a media temporary key (see A1 and A11 for the slot logic).

| Shift | Use | Helper |
|---|---|---|
| 0 | main/user session (`0` alone means "current main DC") | `getSession(0)` |
| 0x01 | config enumeration (`help.getConfig` to other DCs) | `configDcId` (`facade.h:24-26`) |
| 0x02 | logout of guest DCs | `logoutDcId` (`facade.h:29-31`) |
| 0x03 | autoupdater downloads | `updaterDcId` |
| 0x04/0x05 | export (chat export) / export media | |
| 0x06 | group-call stream | `groupCallStreamDcId` |
| 0x07 | stats | |
| 0x10..0x1F | download sessions 0..15 per DC | `downloadDcId(dc, i)` (`facade.h:45-61`) |
| 0x20..0x2F | upload sessions 0..15 (bare id 0 = main DC) | `uploadDcId(i)` (`facade.h:92-109`) |
| 0x100+ | key-destroyer sessions (one per key) | `destroyKeyNextDcId` (`facade.h:111-114`) |
| bare 1000+x | temporary DC used for simple-config endpoints | `getTemporaryIdFromRealDcId` |

- Media-cluster shifts are download, group-call stream, export media and updater (`facade.h:63-69`). They use the "files" protocol flavour (bigger socket buffers) and, if the DC has media_only options, the media temporary key.
- Download/upload session counts are app-level: start with 1 download session and grow up to 8 per DC (`../storage/download_manager_mtproto.cpp:22-34`). Upload uses up to 8 sessions (`../storage/file_upload.cpp:69`). Part size is 128 KiB for downloads (`../storage/download_manager_mtproto.h:26`) and 32-512 KiB for uploads (`../storage/file_upload.cpp:46-58`). Idle sessions are killed after 15 s (`kKillSessionTimeout`).
- Threads: one main-session thread, one "other sessions" thread, and a pool of `2*max(idealThreadCount/2,1)` file threads, mirrored so downloads and uploads of the same index land on different threads (`mtp_instance.cpp:321-322`, `:1679-1727`).

---

## A-E8. `Instance` — request lifecycle and error policy (`mtp_instance.cpp`)

### A-E8.1 Bookkeeping

- Request ids come from a global atomic counter and wrap to 0 at `INT_MAX/2` (`:45-51`).
- Maps (`:262-283`):
  - `_requestsByDc` stores the **signed** shifted DC: negative means "sent to the main DC", and the request follows the main DC when it moves.
  - `_parserMap` holds callbacks; `_requestMap` holds the serialized request kept for resend.
  - `_delayedRequests` is a deque sorted by time.
  - `_dependentRequests` maps request to the request it waits for.
  - `_requestsDelays` holds the per-request 5xx backoff.
  - `_authWaiters` holds per-DC requests waiting for an auth import.
- `sendRequest` (`:1012-1050`):
  1. Store the callbacks and request, register the signed DC, stamp `lastSentTime` and `needsLayer`.
  2. If `afterRequestId` is set, `request->after = <that request>`. If the dependency is itself parked in `_dependentRequests`, park this one too.
  3. Otherwise `session->sendPrepared(request, msCanWait)`.
- API sends always use `needsLayer = true` (`mtp_instance.h:206-222`); `sendProtocolMessage` uses `false` (`mtp_instance.h:190-204`).
- `processCallback` (`:1146-1203`):
  - An empty reply becomes the local error `RESPONSE_PARSE_FAILED`.
  - A reply starting with `rpc_error` goes to the error path.
  - If the done handler returns `false` (parse failure), that becomes the local error `RESPONSE_PARSE_FAILED`.
  - When the error path returns false ("keep"), the handler is re-inserted for the retried request.

### A-E8.2 Who sees an error first (`mtp_instance.cpp:1223-1254`)

For **temporary** errors (`code < 0 || code >= 500 || FLOOD_WAIT_* || FLOOD_PREMIUM_WAIT_*`, `mtproto_response.h:43-58`) the caller's `onFail` runs first and may claim the error. Callers usually do not claim it: the `Simple` skip policy declines temporary errors, `HandleFlood` claims flood only, and `HandleAll` claims everything (`sender.h:25-29`, `:86-95`; same in `mtproto_concurrent_sender.cpp:54-62`). If the caller declined, `onErrorDefault` runs. If that does not handle the error either, `onFail` runs (again) and the request is cleaned up.

### A-E8.3 Default error handling (`Instance::Private::onErrorDefault`, `mtp_instance.cpp:1379-1622`)

Verbatim `mtp_instance.cpp:1385-1389`:

```cpp
	auto badGuestDc = (code == 400) && (type == u"FILE_ID_INVALID"_q);
	static const auto MigrateRegExp = QRegularExpression("^(FILE|PHONE|NETWORK|USER)_MIGRATE_(\\d+)$");
	static const auto FloodWaitRegExp = QRegularExpression("^FLOOD_WAIT_(\\d+)$");
	static const auto FloodPremiumWaitRegExp = QRegularExpression("^FLOOD_PREMIUM_WAIT_(\\d+)$");
	static const auto SlowmodeWaitRegExp = QRegularExpression("^SLOWMODE_WAIT_(\\d+)$");
```

| Error | Action | Lines |
|---|---|---|
| `(FILE`/`PHONE`/`NETWORK`/`USER)_MIGRATE_X` (regex above) | Request was for the main DC (signed < 0): `setMainDcId(new)`, which kills the old and new main sessions and starts a new main session; the request is re-registered as "main" and resent. Otherwise resend to the same shift on the new DC. Auth export/import for main-DC migration is disabled (commented out). `STATS_MIGRATE_X` is **not** matched here | `:1386-1452`, `:481-496` |
| `MSG_WAIT_TIMEOUT`, `MSG_WAIT_FAILED` | Only meaningful for dependent requests. If the `after` request is gone or on another DC, drop the dependency and resend at once. Otherwise park the request until `after` finishes (`unregisterRequest` then resends all transitively dependent requests) | `:1453-1491`, `:1059-1112` |
| `code < 0` or `code >= 500` | Retry the same request after 1, 2, 4, 8, 16, 32, 64, 64, 64... s per request id. **No retry limit** | `:1504-1524` |
| `FLOOD_WAIT_X` | Retry after X s (+10 ms); no cap (the `>= 60` cap is commented out) | `:1525-1527`, `:1534-1545` |
| `FLOOD_PREMIUM_WAIT_X` | Retry after X s and emit `nonPremiumDelayedRequests(requestId)`, which the UI uses for the upload speed upsell | `:1528-1530`, `:1547-1549` |
| `SLOWMODE_WAIT_X` with X < 3 | Auto-retry after X s; X >= 3 goes to the caller | `:1496-1497`, `:1531-1533` |
| `401` except `AUTH_KEY_PERM_EMPTY`; or `400 FILE_ID_INVALID` (first time on a non-main DC) | Request on the main DC, or no DC known: `globalFailHandler`, which runs `Account::logOut()` (`../main/main_account.cpp:468-472`). So `AUTH_KEY_UNREGISTERED`, `SESSION_REVOKED`, `SESSION_EXPIRED`, `USER_DEACTIVATED` etc. on the main DC all log out. Request on another DC: `auth.exportAuthorization(dc_id)` on the main DC, then `auth.importAuthorization(id, bytes)` on the target, then resend every waiter (one export per DC at a time). Export/import failures never log out ("perhaps this is a server side error") | `:1552-1589`, `:1256-1377` |
| `CONNECTION_NOT_INITED`, `CONNECTION_LAYER_INVALID` | `session->setConnectionNotInited()`, mark `needsLayer`, resend (initConnection plus invokeWithLayer get re-wrapped) | `:1590-1614` |
| `CONNECTION_LANG_CODE_INVALID` | Reset the cloud language to default; the error still goes to the caller | `:1615-1616` |
| `FROZEN_METHOD_INVALID` | Emit `frozenErrorReceived` (account frozen UI) | `:1617-1618` |
| Local errors (code 0, `CLIENT_*`) | Never retried | `mtproto_response.cpp:61-78` |
| `406` | Goes to the caller; the UI must not show a toast (`IgnoreError`) | `mtproto_response.h:60-62` |
| Transport `-404/-429/-444` | Handled in `session_private.cpp:2669-2705` (core part). `-444` calls `badConfigurationError()`, which in proxy mode shows a box and disables the proxy (`../core/application.cpp:925-939`) | |
| `AUTH_KEY_DUPLICATED` | No special case in `mtproto/`; it goes to the caller. `AUTH_KEY_PERM_EMPTY` is handled during temporary-key binding (`details/mtproto_bound_key_creator.cpp:88`, core part) | |

Other details:
- Delayed-queue scheduling: `sendAt = now + secs*1000 + 10`, inserted in sorted position. If the request is already queued, the new delay is ignored (`:1534-1543`). A single `base::Timer` fires for the head of the queue (`:979-1010`).
- `rpc_error` text parsing: `^([A-Z0-9_]+)(: .*)?$` gives type and description. Unparseable text becomes `INTERNAL_SERVER_ERROR` when `code < 0 || code >= 500`, else `CLIENT_BAD_RPC_ERROR` (`mtproto_response.cpp:26-44`).

### A-E8.4 Auth export/import (`mtp_instance.cpp:1256-1377`, `:1552-1589`)

Per target DC: the first request that hits 401 sends `auth.exportAuthorization(dc_id)` to the main DC and records `exportRequestId -> target shifted DC`. Later requests just join `_authWaiters[dc]`. On export success, `auth.importAuthorization(id, bytes)` is sent to the target shifted DC. On import success every waiter is re-pointed to the DC (`changeRequestByDc`) and resent; a waiter that was a main-DC request also switches the main DC. Temporary export errors (5xx/flood) are retried by the default policy. On a non-temporary export failure `_authWaiters[dc]` is cleared (`:1359-1377`), but the waiting requests stay registered and are never resent, so their callbacks never fire. **Rust:** fail the waiters explicitly.

### A-E8.5 Main DC, config refresh, CDN config

- `suggestMainDcId` applies only if the main DC was not forced: a stored main DC or an explicit set forces it (`:475-479`, `:363-366`). `setMainDcId` kills the old and the target sessions, starts a new main session, and requests a key write (`:481-496`).
- Config refresh:
  - At start: `requestConfig()` (`:388`).
  - On success: `_configExpiresAt = now + (config.expires - unixtime::now())` (`:940-942`); `requestConfigIfExpired` re-arms itself with `min(remaining, 1 h)` (`:581-591`).
  - `requestConfigIfOld()` reloads if the last success is at least 2 min old, or at least 8 s old in `blocked_mode` (`:34-35`, `:572-579`). The session triggers it when connecting has taken more than `kRequestConfigTimeout = 8 s` (`session_private.cpp:50`, `:1101-1106`).
- Network reachability changes restart all sessions (`:329-332`). A custom device-model change re-inits the connection on the main DC (`:337-345`).
- `new_session_created` arriving as an update triggers the session-reset handler, which on the main DC runs `updates.getDifference` (`../main/main_account.cpp:466`, `:479-485`).

### A-E8.6 Logout and guest DCs (`mtp_instance.cpp:721-766`)

`logout()` sends `auth.logOut` on the main DC; `done` runs on success **or** failure. In parallel, `auth.logOut` goes to every other DC with a stored key except the main DC and CDN DCs, through the `logoutDcId` shift (0x02). Each of those sessions is killed when its request completes either way.

### A-E8.7 Key destruction (KeysDestroyer mode, `mtp_instance.cpp:1729-1810`)

- `Account::destroyMtpKeys` creates a **separate** `Instance` in `KeysDestroyer` mode (`mainDcId = kNoneMainDc`, `../main/main_account.cpp:562-595`). Each key gets its own shifted DC (0x100, 0x101, ...).
- Non-CDN DCs: `auth.logOut` then `destroy_auth_key`. CDN DCs: `destroy_auth_key` only.
- Any outcome (`ok`/`none`/`fail`/error) counts as "possibly destroyed" and the slot is removed. When none remain, `allKeysDestroyed` fires.
- Stale keys read from older storage formats (`AuthKey::Type::ReadFromFile`) trigger destroying all keys and starting fresh (`../main/main_account.cpp:606-618`).

### A-E8.8 vs tdlib / robustness

- **5xx/negative codes:** tdesktop retries forever with backoff capped at 64 s. tdlib's `NetQueryDelayer` retries negative codes and 500s with a per-query doubling delay (1, 2, 4 … capped at ~60 s), but fails the query with `429 "Too Many Requests: retry after X"` once the accumulated waiting exceeds `total_timeout_limit_` (default **60 s**, `tdlib:td/telegram/net/NetQuery.h:314-315`, `NetQueryDelayer.cpp:76-108`); `-503` is converted to `502 Bad Gateway` unless the query opted into resend-on-503. That is more robust for user-visible operations. **Rust:** per-request retry budget plus the caller's deadline.
- **FLOOD_WAIT:** tdesktop auto-waits for any X unless the caller opts in with `HandleFlood`/`HandleAll`. tdlib parses `FLOOD_WAIT_/SLOWMODE_WAIT_/2FA_CONFIRM_WAIT_/TAKEOUT_INIT_DELAY_/FLOOD_PREMIUM_WAIT_` X (clamped 1 s..14 days), auto-waits, and returns the error once the total wait would exceed the query's limit (`NetQueryDelayer.cpp:35-63`); `FLOOD_PREMIUM_WAIT_` also emits a "speed limited" notification for uploads/downloads. **Rust:** surface long waits; never sleep invisibly for hours.
- **401 on main DC → logout** is the same in spirit as tdlib (`AUTH_KEY_UNREGISTERED` → logged-out state). tdlib excludes `SESSION_PASSWORD_NEEDED` from 401 handling; `AUTH_KEY_PERM_EMPTY` drops the temp key and is turned into a retryable 500; any other 401 on a non-main PFS session drops the temp key, and on a non-main DC drops that DC's perm key without logging out (`tdlib:td/telegram/net/Session.cpp:925-960`). tdesktop relies on callers handling `SESSION_PASSWORD_NEEDED` themselves, since the global handler only fires when a session exists.
- **Dependent requests:** tdesktop resends a dependent request only after the dependency is fully *unregistered* (answered or failed). tdlib attaches a list of dependency refs to each query and serializes `invokeAfterMsg` (one dependency) or `invokeAfterMsgs` (several) (`tdlib:td/mtproto/CryptoStorer.h:109-133`); if a dependency lives in another session or has no msg_id yet, the query is bounced with a "resend invoke after" error and re-dispatched (`tdlib:td/telegram/net/Session.cpp:1132-1146`).

---

## A-E9. Caller-facing error helpers

`mtproto_response.h:43-62`: `IsFloodError(type)` = prefix `FLOOD_WAIT_` or `FLOOD_PREMIUM_WAIT_`;
`IsTemporaryError(e)` = `code < 0 || code >= 500 || IsFloodError(e)` (this is also `IsDefaultHandledError`);
`IgnoreError(e)` = `code == 406`.

`ResponseHandler { DoneHandler done; FailHandler fail; }`. A done handler returns `false` to signal a parse failure. A fail handler returns `true` to claim the error (`mtproto_response.h:71-83`).

---

## A-E10. ConfigLoader (`config_loader.cpp`)

Source: `config_loader.cpp:21-127`.

Flow:
1. `load()`: `help.getConfig` to the main DC and an 8 s timer.
2. On timeout, `enumerate()`:
   1. Cancel the previous enumeration request and kill its session.
   2. Pick the next DC id after `_enumCurrent` in sorted `configEnumDcIds()` (non-CDN, non-temporary), wrapping around.
   3. Send `help.getConfig` to `configDcId(dc)` (shift 0x01).
   4. Re-arm the 8 s timer and refresh the special loader.
3. Any success calls `Instance::configLoadDone`, which destroys the loader (and with it all enumeration sessions).
4. KeysDestroyer mode starts with enumeration directly (`:44-50`).

---

## A-E11. Proxies (`mtproto_proxy_data.cpp`, `proxy_check.cpp`)

### A-E11.1 Types

`None, Socks5, Http, Mtproto, Web` (`mtproto_proxy_data.h:20-26`). Calls never go through a proxy (`supportsCalls()` returns false, `:504-506`).

### A-E11.2 MTProxy secret parsing (`mtproto_proxy_data.cpp:22-150`)

Rules:
- **Hex form:** at least 32 chars, even length, hex digits only. Valid when it decodes to 16 bytes, to 17 bytes starting `dd`, or to 21+ bytes starting `ee`. Fewer than 16 bytes is Invalid; anything else is Unsupported.
- **Base64url form:** at least 22 chars, `len % 4 != 1`, alphabet `[A-Za-z0-9_-]` plus up to 2 trailing `=`. Valid sizes are 16, 17 with the first char `3` and second in `[Q-Za-f]` (that is, the first byte is `0xDD`), or 21+ with `7` followed by `[g-v]` (that is, `0xEE`). A base64 secret starting with letters `ee` and at least 21 bytes is `IncorrectSecret` (hex `ee...` pasted where base64 was parsed).
- `secretFromMtprotoPassword()` decodes hex first, then base64url (`:517-526`).

### A-E11.3 How a session uses a proxy

- **MTProxy / Web:** a single "test connection" whose host, port and secret come from the proxy (`session_private.cpp:1038-1041`).
  - The DC is selected by the protocol DC id inside the obfuscated header. That id is the DC number, plus 10000 for test DCs, negated for media-cluster sessions; temporary DC 100x maps to x (`session_private.cpp:254-265`; `connection_abstract.h:30`).
  - Every DC, including file sessions, goes through the same proxy.
  - `initConnection` gets `proxy: inputClientProxy(host, port)` (`session_private.cpp:690-701`).
- **SOCKS5/HTTP:** `QNetworkProxy` on the socket (`ToNetworkProxy`, `mtproto_proxy_data.cpp:575-590`). DC options are looked up with `throughProxy = true`, so static endpoints are preferred. An HTTP proxy probes with the HTTP transport (`proxy_check.cpp:55-57`).
- **Proxy hostnames:** DoH-resolved (A-E3) and expanded to one direct-IP proxy per resolved address.
- The proxy list rotation policy lives in app code (`Core::Application::checkProxyRotation`, `../core/application.cpp:915-919`) and is not reviewed here.
- `-444` from the server while a proxy is enabled leads to a "proxy configuration error" box that disables the proxy (`../core/application.cpp:925-939`).

### A-E11.4 Proxy check (`proxy_check.cpp:41-112`)

For MTProxy: one connection to the proxy with its secret, targeting the main DC. For SOCKS/HTTP: an IPv4 connection, and optionally an IPv6 one, to the first endpoint of the main DC with the proxy applied. Web proxies are not checked. The check is connection-level: success means the transport connected and a ping round-trip was measured (`pingTime()`). There is no API call.

### A-E11.5 Web proxy validation

- Host is IDNA-normalised. Rejected: IP literals (including WHATWG numeric shorthand such as `127.1` and `0x7f.1`), ports, paths in the host, and hosts without a dot (`:152-173`, `:267-302`).
- Base path: segments of `[A-Za-z0-9][A-Za-z0-9_-]*`, at most 128 chars (`:233-258`). Port is fixed at 443. An `ee` secret is Unsupported for Web (`:480-495`).
- A link carrying a base path encodes the secret as `base64url(0x70 || secret)`, so that old clients reject it (`:196-203`, `:395-430`).

---

## A-E12. Per-DC key slots

Covered in A1 and A11 (`details/mtproto_dcenter.cpp:109-163`). One extra fact: `destroyConfirmedForgottenKey`
drops the persistent key and both temporary keys when the server reports the key as gone
(`details/mtproto_dcenter.cpp:86-97`; called via `Instance::keyDestroyedOnServer`, `mtp_instance.cpp:1797-1810`).

---

## A-E13. Downloads and CDN (`../storage/download_manager_mtproto.cpp`), updater loader

- `upload.getFile` is sent with `cdn_supported` to `downloadDcId(file.dc_id, session)`, i.e. directly to the file's DC. Because of that, FILE_MIGRATE is rarely seen, and auth on that DC is imported on demand through the 401 path (A-E8.3).
- `upload.fileCdnRedirect` (`:629-631`, `:978-989`) starts CDN mode:
  - Store `dc_id`, `file_token`, the 32-byte `encryption_key` and 16-byte `encryption_iv`, and the initial `file_hashes`. A wrong key or IV size cancels the download (`:1001-1023`).
  - All in-flight requests are re-sent as `upload.getCdnFile(file_token, offset, limit)` to `downloadDcId(cdn_dc, session)` (`:516-528`).
- Decryption is AES-256-CTR: `iv` with bytes 12..15 replaced by big-endian `offset >> 4` (`:688-702`).
- Integrity check:
  - The SHA-256 of the decrypted part is compared with the `fileHash` stored for **exactly that offset** (`:724-737`).
  - Parts without a known hash are parked, and `upload.getCdnFileHashes(file_token, offset)` is sent to the **master** DC (`:601-618`, `:749-797`).
  - A mismatch cancels the download.
  - **Rust:** verify every `[hash.offset, hash.offset+hash.limit)` range covered by a part rather than assuming part size equals hash chunk size (both are 128 KiB today).
- `upload.cdnFileReuploadNeeded{request_token}` leads to `upload.reuploadCdnFile(file_token, request_token)` on the master DC; the hashes it returns are added, and the part is retried (`:658-674`, `:739-747`).
- `FILE_TOKEN_INVALID` or `REQUEST_TOKEN_INVALID` from the CDN path drops CDN mode and returns to the master DC (`:954-973`). `FILE_REFERENCE_*` (400) triggers a file-reference refresh and retry (`:925-938`).
- `DedicatedLoader` (updater) downloads 128 KiB chunks with 2 in flight, 20 ms apart, files up to 256 MiB, on `updaterDcId` sessions. It has **no** CDN support (`dedicated_file_loader.h:51-52`, `:147-148`; `dedicated_file_loader.cpp:338-357`).

---

## A-E14. Constants (edge layer)

| Constant | Value | Where |
|---|---|---|
| `kClientHelloLimit` | 2048 B | `details/mtproto_tls_socket.cpp:24` |
| `kMaxGrease` | 8 | `:23` |
| `kMaxServerHelloLength` | 65536 B | `:27` |
| `kServerHelloDigestPosition` | 11 | `:30` |
| `kClientPartSize` (max TLS record payload sent) | 2878 B | `:32` |
| hello size | `1572 + len(domain) + {144,176,208,240}` | computed (A-E1.6) |
| file socket buffers | 2 MiB send / 2 MiB recv | `details/mtproto_abstract_socket.h:62-63` |
| DoH next-attempt stagger | 800 ms | `details/mtproto_domain_resolver.cpp:25`, `special_config_request.cpp:24` |
| DoH TTL clamp | 10 s .. 300 s | `details/mtproto_domain_resolver.cpp:26-27` |
| DoH random padding | 13..128 chars | `details/mtproto_domain_resolver.cpp:47-48` |
| simple config base64 / RSA / data | 344 chars / 256 B / 208 B + 16 B tag | `special_config_request.cpp:434-457` |
| `kEnumerateDcTimeout` | 8000 ms | `config_loader.cpp:21` |
| `kSpecialRequestTimeoutMs` | 6000 ms | `config_loader.cpp:22` |
| `kConfigBecomesOldIn` / blocked mode | 120 s / 8 s | `mtp_instance.cpp:34-35` |
| config expiry re-arm cap | 1 h | `mtp_instance.cpp:585` |
| 5xx backoff | 1,2,4,...,64 s, then 64 s forever | `mtp_instance.cpp:1519-1524` |
| flood resend slack | +10 ms | `mtp_instance.cpp:1534` |
| `SLOWMODE_WAIT` auto-retry threshold | < 3 s | `mtp_instance.cpp:1496-1497` |
| request id wrap | `INT_MAX/2` | `mtp_instance.cpp:47` |
| `kTemporaryMainDc` | 1000 | `mtp_instance.h:44` |
| `kDefaultMainDc` | 2 | `mtp_instance.h:43` |
| `kDcShift` | 10000 | `core_types.h:43` |
| `kTestModeDcIdShift` (protocol DC id in obfuscated header) | +10000 | `connection_abstract.h:30` |
| `kMaxMediaDcCount` | 16 | `core_types.h:51` |
| download / upload sessions | 1..8 / up to 8 | `../storage/download_manager_mtproto.cpp:25-26`, `../storage/file_upload.cpp:69` |
| download part | 128 KiB | `../storage/download_manager_mtproto.h:26` |
| updater chunk / parallel / delay | 128 KiB / 2 / 20 ms | `dedicated_file_loader.h:51,147-148` |
| `webFileDcId` default | 4 (test: 2) | `mtproto_config.cpp:27` |
| `kRequestConfigTimeout` (session) | 8 s | `session_private.cpp:50` |
| `kMarkConnectionOldTimeout` | 192 s | `session_private.cpp:39` |

---

## A-E15. Findings and recommendations for the Rust engine

1. **Fake-TLS hello as data.** Port the `TlsBlock` interpreter and the current template (A-E1.3) verbatim. Inject the RNG and clock so golden vectors are possible. Use constant-time HMAC comparison. Reject domains over 236 bytes when parsing the secret.
2. **Clock skew kills `ee` proxies.** Implement an HTTP-`Date` time source, as tdesktop does, and fall back to server time learned from MTProto `msg_id`s. Use the corrected time for the TLS timestamp and simple-config expiry.
3. **Full reserved-nonce list.** Include `0x4954504F` (OPTI) in addition to tdesktop's list.
4. **Simple config.**
   - Sort TXT chunks by length, and retry other permutations on SHA failure.
   - `len` includes itself.
   - Vectors are bare and their elements boxed.
   - Check `expires` (and sanity-check `date` against the future).
   - Map endpoints to a temporary DC that shares the real DC's key.
   - Use them only for `help.getConfig`, and apply only `dc_options`.
   - Ship the live vectors in A-E4.8 as fixtures.
5. **Bootstrap sources.**
   - Google DoH direct and Firestore (direct and fronted) work today; Google DNS fronting returns 404.
   - Keep the source list configurable.
   - Do not hard-code `apv3.stel.com` alone: also honour `config.dc_txt_domain_name`, which tdesktop ignores.
6. **Error policy.**
   - Bound 5xx retries and flood waits with per-request deadlines.
   - Expose `FLOOD_PREMIUM_WAIT` and long `FLOOD_WAIT` to callers.
   - Treat 401 on the main DC as logged out, except `SESSION_PASSWORD_NEEDED` during login and `AUTH_KEY_PERM_EMPTY` (rebind).
   - 401 on another DC leads to export/import with one export per DC and a waiter queue.
7. **Migration.**
   - Match `(FILE|PHONE|NETWORK|USER|STATS)_MIGRATE_X`.
   - For main-DC migration, switch the main DC atomically and resend.
   - For non-main requests, preserve the shift (download/upload index) on the new DC.
8. **DC options.**
   - De-duplicate by `(ip, port)` but merge flags; tdesktop drops later duplicates.
   - Honour `media_only`, `tcpo_only`, `cdn`, `static` (for SOCKS), and `secret`.
   - Consider `this_port_only` and `force_try_ipv6`, which tdesktop ignores.
9. **CDN.**
   - Use only CDN keys for CDN DCs.
   - Fetch `help.getCdnConfig` lazily.
   - Use AES-256-CTR with the IV's last 4 bytes set to big-endian `offset/16`.
   - Verify hashes by covered range; handle reupload and token-invalid fallback.
10. **IPv6-only proxy hosts** must resolve; tdesktop's DoH resolver never delivers them.
11. **Test fixtures produced in this digest:** RSA fingerprints for the production, test and simple-config keys (A-E5.3); two live and one expired simple-config vectors (A-E4.8); the TLS hello size formula and structural invariants (A-E1.4, A-E1.6); GREASE generation rules (A-E1.4).

---

# Part B. Official documentation: protocol checklist, test vectors, error table

Source: core.telegram.org, fetched 2026-10-01 with `curl` (raw HTML). The HTML was converted to text by a small script that copies `<pre>`/`<code>` blocks unchanged, so every hex dump below is byte-exact. All arithmetic in the auth-key sample was then re-run with an independent Python implementation (stdlib SHA1/SHA256/pow plus a pure-Python AES-256 that passes FIPS-197 and NIST SP800-38A known-answer tests). Every documented intermediate value matched (see B3.2).

Conventions used in this part:

- `P-NNN` ids are stable and can be cited by tests. Each item ends with its source page and anchor in `[...]`.
- **MUST**, **SHOULD** and **MAY** follow the strength of the docs' own wording ("must", "is to", "required" map to MUST; "recommended", "should", "it makes sense" map to SHOULD).
- `[derived]` marks a rule the docs imply but do not state outright: something tdlib or MadelineProto does, or a robustness check that follows from the layout. Tests may cite these, but they are not normative.
- `substr(s, off, len)` and `s[a:b]` are byte slices with 0-based offsets. `+` means concatenation.

## B0. Discrepancies and gotchas found in the docs

| # | Finding | Where | Engine consequence |
|---|---|---|---|
| D1 | Salt lifetime is given as "changed every 30 minutes … old salt accepted for a further 1800 seconds" in one place and "a single salt's lifespan is 1 hour … salts overlap one another by half an hour" in another. | /mtproto/description#server-salt vs /api/optimisation#server-salt | Never hard-code a lifetime. Use `future_salt.valid_since/valid_until` and handle `bad_server_salt` at any time. |
| D2 | `FILE_MIGRATE_X` is listed under **303 SEE_OTHER** on /api/errors but under **400** in /api/errors.json. | /api/errors#303-see-other, errors.json | Dispatch migrations on the error **string prefix** (`*_MIGRATE_`), never on `error_code == 303` alone. |
| D3 | In the samples page, the TL lines are shown with fake ids (`req_pq_multi#00000000`, `dh_gen_ok#00000004`, `Vector<strlong>`). The real ids are in the hex dumps and in /schema/mtproto. | /mtproto/samples-auth_key | Take constructor ids from the schema (B3.9), not from the sample's TL lines. |
| D4 | The sample's `answer = …` value is 572 bytes: the 564-byte `server_DH_inner_data` **plus 8 random padding bytes** (`A674223E982CE5E5`). SHA1 matches only over the first 564 bytes. | /mtproto/samples-auth_key step 6 | The SHA1 check must cover the TL-parsed length of `server_DH_inner_data`, not "everything after the 20-byte hash". |
| D5 | `server_DH_params_fail` and the old `p_q_inner_data` (without dc) are gone from the current MTProto schema. Only `server_DH_params_ok`, `p_q_inner_data_dc` and `p_q_inner_data_temp_dc` remain. | /schema/mtproto | The decoder MAY still accept `server_DH_params_fail#79cb045d` for robustness `[derived from older schemas]`. On receipt, treat it as a handshake failure. |
| D6 | /mtproto/auth_key writes `pq:string` and `Vector long`, while the schema writes `pq:bytes` and `Vector<long>`. | — | The wire format is identical (`string` and `bytes` serialize the same way). |
| D7 | `retry_id` is said to come "from the previous failed attempt (see Item 9)" on auth_key, but "(see Item 7)" on the samples page. | — | Item 9 is the right one: `retry_id = auth_key_aux_hash` of the previous `dh_gen_retry`. |
| D8 | The obfuscation prose lists the forbidden first ints as `0xdddddddd`, `0xeeeeeeee`, POST, GET, HEAD "or any HTTP method". The pseudocode adds `0x4954504f` ("OPTI", from OPTIONS) and `0x02010316` (a TLS record header `16 03 01 02`). | /mtproto/mtproto-transports#transport-obfuscation | Use the pseudocode list (P-061). |
| D9 | Fake-TLS MTProxy secrets (`ee` prefix) are **not documented** anywhere on core.telegram.org. Only the 16-byte and `dd` 17-byte forms are described. | — | Take the fake-TLS spec from the tdesktop digest (`mtproto_tls_socket.cpp`). |
| D10 | Server RSA public keys are **not printed** on core.telegram.org; they are only on my.telegram.org. The sample uses fingerprint bytes `85FD64DE851D9DD0`, i.e. `long` 0xd09d1d85de64fd85. | /mtproto/samples-auth_key | Take the PEMs from tdesktop or tdlib sources. Assert that this fingerprint is computed from the production key. |
| D11 | The current layer is 225 on the method pages and /api/layers, but errors.json reports `"layer": 227`. | — | Informational only. |
| D12 | **New (2025–26) rule:** parallel main sessions are allowed only up to `tmp_sessions`. Going over it causes `AUTH_KEY_DUPLICATED`, which **invalidates the authorization key**. | /api/datacenter#parallel-sessions, /api/errors#406-not-acceptable | Main-DC connection racing must never send requests over two TCP connections at once (see P-283..P-286). |
| D13 | `msg_detailed_info` and `msg_new_detailed_info` are specified only as notifications. The docs never say what the client must do with `answer_msg_id`. | /mtproto/service_messages_about_messages | Use tdlib's behaviour (P-205, `[derived]`). |
| D14 | /api/invoking: "invokeAfterMsg / invokeAfterMsgs must always be the outermost wrapper" when combined with invokeWithLayer etc. Both reference clients do the opposite while the connection is not yet inited: `invokeWithLayer(initConnection(invokeAfterMsg(query)))` (tdesktop `session_private.cpp:808-830`; tdlib `td/mtproto/CryptoStorer.h:142-160`). | /api/invoking#sequential-requests | Make the wrapper order one tested decision point (see A2.8); verify on a test DC. |

## B1. Source pages (all fetched 2026-10-01)

| Page | URL | Status |
|---|---|---|
| MTProto overview | https://core.telegram.org/mtproto | 200 |
| Detailed description (2.0) | https://core.telegram.org/mtproto/description | 200 |
| Detailed description (1.0, deprecated; needed for bind KDF) | https://core.telegram.org/mtproto/description_v1 | 200 |
| MTProto 1.0 landing | https://core.telegram.org/mtproto_v1 | 200 |
| Service messages | https://core.telegram.org/mtproto/service_messages | 200 |
| Service messages about messages | https://core.telegram.org/mtproto/service_messages_about_messages | 200 |
| Creating an authorization key | https://core.telegram.org/mtproto/auth_key | 200 |
| Auth key example (test vector) | https://core.telegram.org/mtproto/samples-auth_key | 200 |
| Security guidelines | https://core.telegram.org/mtproto/security_guidelines | 200 |
| MTProto transports (abridged/intermediate/padded/full, quick ack, transport errors, obfuscation) | https://core.telegram.org/mtproto/mtproto-transports | 200 |
| Transports (TCP/WS/HTTP) | https://core.telegram.org/mtproto/transports | 200 |
| TL language | https://core.telegram.org/mtproto/TL | 200 |
| Binary serialization | https://core.telegram.org/mtproto/serialize | 200 |
| TL abstract types | https://core.telegram.org/mtproto/TL-abstract-types | 200 |
| TL combinators (conditional fields) | https://core.telegram.org/mtproto/TL-combinators | 200 |
| TL formal (built-ins, True, flags) | https://core.telegram.org/mtproto/TL-formal | 200 |
| TL tl.tl | https://core.telegram.org/mtproto/TL-tl | 200 |
| TL types / polymorph / dependent / optargs | https://core.telegram.org/mtproto/TL-types, TL-polymorph, TL-dependent, TL-optargs | 200 |
| MTProto TL schema | https://core.telegram.org/schema/mtproto | 200 |
| PFS (cloud chats) | https://core.telegram.org/api/pfs | 200 |
| auth.bindTempAuthKey | https://core.telegram.org/method/auth.bindTempAuthKey | 200 |
| auth.dropTempAuthKeys, auth.logOut | https://core.telegram.org/method/auth.dropTempAuthKeys, /method/auth.logOut | 200 |
| Calling methods (layers, initConnection, invokeAfterMsg, gzip) | https://core.telegram.org/api/invoking | 200 |
| invokeWithLayer / initConnection / invokeAfterMsg(s) / invokeWithoutUpdates | https://core.telegram.org/method/… | 200 |
| Datacenters (+ parallel sessions, tmp_sessions) | https://core.telegram.org/api/datacenter | 200 |
| dcOption / config / help.getConfig / help.getNearestDc | https://core.telegram.org/constructor/dcOption, /constructor/config, /method/help.getConfig, /method/help.getNearestDc | 200 |
| Client configuration | https://core.telegram.org/api/config | 200 |
| Errors | https://core.telegram.org/api/errors and https://core.telegram.org/api/errors.json (layer 227) | 200 |
| Files | https://core.telegram.org/api/files | 200 |
| upload.getFile / saveFilePart / saveBigFilePart / getFileHashes | https://core.telegram.org/method/… | 200 |
| CDN | https://core.telegram.org/cdn | 200 |
| upload.getCdnFile / reuploadCdnFile / getCdnFileHashes / help.getCdnConfig / upload.fileCdnRedirect | https://core.telegram.org/method/…, /constructor/… | 200 |
| Updates (network-relevant parts only) | https://core.telegram.org/api/updates | 200 |
| Auth (test DCs, future auth tokens) | https://core.telegram.org/api/auth | 200 |
| Optimisation (salts, quick ack, ping_delay_disconnect) | https://core.telegram.org/api/optimisation | 200 |
| Deep links (MTProxy link syntax) | https://core.telegram.org/api/links#mtproxy-links | 200 |
| Technical FAQ | https://core.telegram.org/techfaq | 200 |
| MTProxy README (secret `dd` prefix) | https://raw.githubusercontent.com/TelegramMessenger/MTProxy/master/README.md | 200 |

Pages that do **not exist** (the server returns the generic "Page not found" body with HTTP 200): `/mtproto/pfs`, `/mtproto/MTProxy`, `/mtproto/mtproto-proxy`, `/mtproto/obfuscation`, `/mtproto/http_wait`, `/mtproto/schema`, `/mtproto/TL-schema`, `/mtproto/end-to-end`, `/mtproto/samples-auth_key_v1`, `/api/cdn` (the real page is `/cdn`), `/api/proxy`, `/api/recaptcha`, `/schema/mtproto-json` (empty body). The page-level constructor/method pages for MTProto service objects (`/constructor/msgs_ack`, `/method/req_pq_multi`, `/method/destroy_auth_key`, …) also do not exist; those objects are documented only on the /mtproto/* pages and /schema/mtproto. Obfuscation is documented at `/mtproto/mtproto-transports#transport-obfuscation`, and MTProxy at that same anchor plus /api/links.

---

## B2. PROTOCOL CHECKLIST

### B2.1 TL serialization

- **P-001** Every TL value is a sequence of 32-bit words, and each word goes on the wire as 4 little-endian bytes. Test: `getUsers([2,3,4])` serializes to `F5 D5 84 2D 15 C4 B5 1C 03 00 00 00 02 00 00 00 03 00 00 00 04 00 00 00` (B3.5). [/mtproto/TL#example-of-an-rpc-query]
- **P-002** `int` is one 32-bit signed LE word. `long` is 64-bit signed LE (two words). `double` is a 64-bit IEEE-754 value, LE. [/mtproto/serialize#base-types]
- **P-003** `int128 = 4*[int]` and `int256 = 8*[int]`: raw 16 and 32 bytes, copied as-is (nonces are opaque byte strings). [/schema/mtproto]
- **P-004** `string`/`bytes` with length L ≤ 253: one byte holding L, then L bytes, then 0..3 zero bytes so that the total length is divisible by 4. Test: `pq` = `08 2E 9C DB 98 C8 0C DA 4B 00 00 00`. [/mtproto/serialize#base-types]
- **P-005** `string`/`bytes` with L ≥ 254: the byte `0xFE`, then 3 bytes of L (LE), then L bytes, then 0..3 zero bytes so the total is divisible by 4. Test: a 256-byte `g_a` starts with `FE 00 01 00` and has 0 padding bytes. A 336-byte `encrypted_data` is serialized as `FE 50 01 00` + 336 bytes (0x150 = 336; 340 bytes on the wire). [/mtproto/serialize#base-types; /mtproto/samples-auth_key]
- **P-006** `[derived]` The decoder MUST reject a length prefix byte of `0xFF`, any length that runs past the buffer, and any non-4-aligned remaining buffer. It MUST accept padding bytes with any value (the server sends zeros; do not require zeros).
- **P-007** A boxed value starts with its 32-bit constructor number. A bare value (lowercase type name or `%Type`) omits it. All base types (`int`, `long`, `double`, `string`) are bare. [/mtproto/serialize#boxed-and-bare-types]
- **P-008** The constructor number is the CRC32 (zlib/IEEE) of the normalized combinator description: no trailing `;`, single spaces between lexemes, parentheses removed, `{t:Type}` braces removed, `<…>` written as space-separated applications. Tests (all verified, B3.6): `crc32("vector t:Type # [ t ] = Vector t") = 0x1cb5c415`, `crc32("user id:int first_name:string last_name:string = User") = 0xd23c81a3`, `crc32("getUsers Vector int = Vector User") = 0x2d84d5f5`. [/mtproto/TL, /mtproto/serialize#polymorphic-type-constructors]
- **P-009** Boxed `Vector t` is `0x1cb5c415`, then an `int` count N, then N values of `t` (boxed or bare, as the schema says). The element type is never serialized; it comes from the expected type. [/mtproto/serialize#built-in-composite-types-vectors-and-associative-arrays]
- **P-010** Lowercase `vector<…>` is the **bare** vector: count + elements, with no `0x1cb5c415`. This applies to `msg_container#73f1f8dc messages:vector<%Message>` and `future_salts#ae500895 … salts:vector<future_salt>` (whose elements are bare `future_salt` without `0x0949d9dc`). [/schema/mtproto]
- **P-011** `Bool` is boxed: `boolTrue#997275b5`, `boolFalse#bc799737`. [/method/auth.bindTempAuthKey; /mtproto/TL-formal]
- **P-012** The `#` type is a 32-bit natural number (0..2^31-1) used as a flags word. A field `name:flags.N?T` is present on the wire iff bit N of the named earlier `#` field is set. `flags.N?true` has zero-length serialization; its value is the bit itself. The decoder must not read anything for it. [/mtproto/TL-combinators#conditional-fields; /mtproto/TL-formal]
- **P-013** The client MUST NOT set flag bits that its schema layer does not define. A bit for an undefined or `False`-typed field makes the request fail to deserialize. [/mtproto/TL-formal]
- **P-014** The `Object` pseudotype is any boxed value; decode it by dispatching on the constructor number (`rpc_result.result`, `message.body`, `gzip_packed`). [/mtproto/serialize#object-pseudotype]
- **P-015** `gzip_packed#3072cfa1 packed_data:bytes = Object` can stand in for any object. The server uses it in `rpc_result.result` and **also for updates**. The decoder MUST transparently gunzip and re-dispatch wherever an `Object` is expected. The client MAY send RPC queries gzip-packed. [/mtproto/service_messages#packed-object; /api/invoking#decompressing-data]
- **P-016** Big numbers (`pq`, `p`, `q`, `dh_prime`, `g_a`, `g_b`, RSA values) are big-endian byte strings inside TL `bytes`. Everything else is little endian. [/mtproto#high-level-component-rpc-query-language-api]
- **P-017** When a `long`/`int128` is defined as "the lower-order 64/128 bits of SHA1(x)", take the **last** 8/16 bytes of the 20-byte digest as-is (do not byte-swap) and interpret them LE as the integer. "Higher-order 64 bits" means the first 8 bytes. [/mtproto/auth_key intro]
- **P-018** A function call serializes as the function's constructor number followed by its arguments. Wrapper functions with a `query:!X` field (`invokeWithLayer`, `initConnection`, `invokeAfterMsg`, `invokeWithoutUpdates`) serialize the inner call inline, with no length prefix. [/mtproto/TL-abstract-types#-modifier; /api/invoking#sequential-requests]
- **P-019** The response type of a function is known before decoding, so `Vector<User>` responses decode with the universal `vector` constructor plus the element type from the call (TL page example). [/mtproto/TL#example-of-an-rpc-query]

### B2.2 Message layout

- **P-020** An **unencrypted** message is `auth_key_id = 0 (int64) | message_id (int64) | message_data_length (int32) | message_data`. Only a very limited set of message types may be sent in plain text (key creation and time sync). [/mtproto/description#unencrypted-message]
- **P-021** `[derived]` The only valid plain-text exchanges are `req_pq_multi`/`resPQ`, `req_DH_params`/`server_DH_params_ok`, and `set_client_DH_params`/`dh_gen_*`. Any other incoming plain-text message MUST be dropped, and updates from an unencrypted connection MUST be ignored. [/api/updates#subscribing-to-updates]
- **P-022** An **encrypted** message is `auth_key_id (int64) | msg_key (int128) | encrypted_data`. [/mtproto/description#encrypted-message]
- **P-023** The plaintext of `encrypted_data` is `salt (int64) | session_id (int64) | message_id (int64) | seq_no (int32) | message_data_length (int32) | message_data | padding (12..1024 bytes)`. The total length MUST be divisible by 16. [/mtproto/description#encrypted-message-encrypted-data]
- **P-024** A message body (`message_data`) is always a multiple of 4 bytes. [/mtproto#high-level-component-rpc-query-language-api]
- **P-025** Only one protocol version (MTProto 1.0 or 2.0) is allowed per TCP connection; the server detects it from the first message. The engine MUST use 2.0 for everything except the `bindTempAuthKey` inner payload (P-234). [/mtproto/description#using-mtproto-2-0-instead-of-mtproto-1-0]

### B2.3 Transport framing (MTProto transports)

Abridged [/mtproto/mtproto-transports#abridged]
- **P-030** Before anything else, the client sends a single `0xef` byte, once per connection and only before the first packet. The server never echoes it. (With obfuscation, this tag goes at offset 56 instead; see P-062.)
- **P-031** If `len/4 < 127`, send one byte `len/4`. Otherwise send `0x7f` followed by 3 bytes of `len/4` (LE). The payload length is always a multiple of 4.
- **P-032** Server packets use the same length encoding. A normal server length byte is always ≤ `0x7f`.
- **P-033** To request a quick ack, send `(len/4) | 0x80` as the single length byte, or `0xff` as the header byte in the long form.
- **P-034** The server sends a quick ack as a standalone 4-byte packet with no length header, holding the token **byte-swapped**. It is recognized because its first byte has the MSB set.

Intermediate [/mtproto/mtproto-transports#intermediate]
- **P-035** Before anything else, the client sends `0xeeeeeeee` (4 bytes) once.
- **P-036** Each packet is a 4-byte LE length followed by the payload.
- **P-037** To request a quick ack, set `len | 0x80000000`. The server's quick ack is a standalone 4-byte value (no length header), in LE. A 4-byte header read as LE `uint32 ≥ 0x80000000` is therefore a quick-ack token, never a length.

Padded intermediate [/mtproto/mtproto-transports#padded-intermediate]
- **P-038** Before anything else, the client sends `0xdddddddd` (4 bytes) once. This transport is meant for use with obfuscation.
- **P-039** Each packet is a 4-byte LE `tlen` (payload + padding), the payload, then 0..15 random padding bytes.
- **P-040** To request a quick ack, set `len | 0x80000000`. The server's quick ack is a normally framed packet of 8..16 bytes: `FFFFFFFF | token(4) | 0..8 random bytes`. Recognize it by `tlen ≤ 16` and a first word of `0xFFFFFFFF`, which distinguishes it from a transport error.
- **P-041** `[derived]` The receiver has to strip the padding. For encrypted payloads, `payload_len = 24 + 16*floor((tlen-24)/16)`. For plain-text payloads, `payload_len = 20 + message_data_length`. For 4-byte transport errors, `tlen` is 4..19 and the first int is negative.

Full [/mtproto/mtproto-transports#full]
- **P-042** Each packet is `len (4, LE; counts len+seqno+payload+crc, i.e. payload+12) | seqno (4) | payload | crc32 (4)`. The CRC32 covers len, seqno and payload. There is no init byte.
- **P-043** The transport seqno counts packets per TCP connection: the first packet the client sends is 0, then 1, and so on. It is unrelated to the MTProto `msg_seqno`.
- **P-044** `[derived]` The CRC is standard IEEE CRC32 (zlib), written LE. The receiver SHOULD verify the CRC and the server's increasing seqno, and close the connection on mismatch.

### B2.4 Quick ack [/mtproto/mtproto-transports#quick-ack]

- **P-045** To request a quick ack, set the MSB of the length field as described per transport (P-033, P-037, P-040). The client MUST generate and store a token for each payload that requests one.
- **P-046** `ack_token = LE_uint32(msg_key_large[0:4]) | 0x80000000`, where `msg_key_large = SHA256(substr(auth_key, 88, 32) + plaintext + padding)` (the same hash used for `msg_key`, but taking its **first** 32 bits).
- **P-047** A quick ack only means "received, decrypted and accepted for processing". It says nothing about whether the RPC executed. The server still sends `msgs_ack` and results as usual. [/api/optimisation#simplified-acknowledgment-of-message-delivery]

### B2.5 Transport errors [/mtproto/mtproto-transports#transport-errors]

- **P-048** A transport error is a packet framed by the current transport whose payload is exactly 4 bytes: a signed LE int32 holding the negated code (e.g. `-404` = `6C FE FF FF`). In abridged it arrives as length byte `0x01` + 4 bytes; in intermediate as `04 00 00 00` + 4 bytes. This is how it differs from a quick ack (P-034, P-037).
- **P-049** **-404**: the DC cannot find the auth key ID. It is also returned during the handshake if any query is incorrect, and in normal operation if MTProto fields are wrong (e.g. the MTProto length exceeds the transport length). During the handshake, the handshake MUST be restarted: every later request also returns -404, even correct ones. [/mtproto/auth_key step 6 note]
- **P-050** **-429**: transport flood. Too many transport connections to the same IP in a short time, or a container/service-message limit was hit. The engine SHOULD back off before reconnecting `[derived]`.
- **P-051** **-444**: invalid DC. Returned while creating an auth key with a test DC id on a production DC (or the reverse), when connecting to an MTProxy with a bad DC, and in other contexts.
- **P-052** **-403**: corresponds to HTTP 403 situations. [same page]
- **P-053** On HTTP/HTTPS, transport errors arrive as HTTP status codes and the HTTP payload MUST be ignored.
- **P-054** On WebSocket, the close code is always `1000`. The close description is the decimal error code, possibly whitespace-padded, and MAY be ignored. [/mtproto/transports#websocket]

### B2.6 Transport obfuscation and MTProxy [/mtproto/mtproto-transports#transport-obfuscation]

- **P-060** Before connecting, generate a 64-byte random init payload.
- **P-061** Regenerate the payload until **all** of these hold: `init[0] != 0xef`; the first LE int is not one of `0x44414548` ("HEAD"), `0x54534f50` ("POST"), `0x20544547` ("GET "), `0x4954504f` ("OPTI"), `0x02010316` (TLS record `16 03 01 02`), `0xdddddddd`, `0xeeeeeeee`; and `init[4:8] != 00 00 00 00`.
- **P-062** Write the protocol tag at `init[56:60]`: `0xefefefef` for abridged (the 1-byte tag repeated to 4 bytes), `0xeeeeeeee` for intermediate, `0xdddddddd` for padded intermediate. The standalone tag MUST NOT be sent afterwards.
- **P-063** Write the DC id at `init[60:62]` as an int16 LE: add 10000 for test DCs, negate for a media (non-CDN) DC (example: media DC 4 is `-4` = `FC FF`). The docs require this only for MTProxy ("only in this case"). Sending it on direct connections is harmless `[derived]`.
- **P-064** Let `rev = reverse(init)`. Then `encKey = init[8:40]`, `encIV = init[40:56]`, `decKey = rev[8:40]`, `decIV = rev[40:56]`.
- **P-065** With an MTProxy secret: `encKey = SHA256(encKey + secret16)` and `decKey = SHA256(decKey + secret16)`. The IVs are unchanged. For a 17-byte secret, ignore the first byte.
- **P-066** A 17-byte secret selects the transport by its first byte (`0xdd` means padded intermediate). Clients SHOULD default to padded intermediate whenever the secret has the extra byte. (README: the `dd` prefix enables random padding.)
- **P-067** Use AES-256-CTR in each direction, with a single counter stream per direction for the lifetime of the TCP/WS connection. The counter is never reset between packets.
- **P-068** The init payload itself is the first thing encrypted, which advances the encrypt stream by 64 bytes. Send `init[0:56] + encrypt(init)[56:64]` as the first 64 bytes after the TCP handshake.
- **P-069** Obfuscation is required on WebSocket transports, and on `tcpo_only` DC options, where the secret is `dcOption.secret` (flags.10). [/mtproto/transports#websocket; /constructor/dcOption]
- **P-070** Proxy link syntax: `tg://proxy?server=<host>&port=<port>&secret=<secret>` or `t.me/proxy?…`. The secret is distributed hex-encoded. [/api/links#mtproxy-links]
- **P-071** The client SHOULD call `help.getPromoData#c0977421` at startup, again after `help.PromoData.expires` seconds, and **every time a new MTProxy connection is established**. With `proxy` and `peer` set, the reply names the proxy's sponsor channel, which is pinned. [/api/config (PSA / MTProxy sponsor)]

### B2.7 Network transports [/mtproto/transports]

- **P-075** TCP runs on ports 80, 443, 5222, or another port returned by `help.getConfig`.
- **P-076** If `dcOption.this_port_only` is set, the client MUST use only that port. [/mtproto/transports#tcp; /constructor/dcOption]
- **P-077** If `config.force_try_ipv6` is set, the client MUST prefer IPv6 over IPv4 for all MTProto transports, even when IPv4 is available. [/mtproto/transports#tcp; /constructor/config]
- **P-078** TCP has no implicit acks: every message must be acknowledged explicitly (P-170).
- **P-079** On TCP, when a connection closes and a new one opens, the server resends content-related messages that were not yet acknowledged. [/mtproto/description#content-related-message]
- **P-080** A session is not tied to a connection. Messages may flow in either direction over any connection of the session, and a response may come back on a different connection of the same session, but never on a connection of another session. [/mtproto#high-level-component]
- **P-081** WebSocket requires the header `Sec-WebSocket-Protocol: binary`. The URI path is `/api(w)(s)`, with `s` enabling WebSocket and `w` adding CORS, e.g. `ws://X.X.X.X:80/apiws`. WSS is only available on `(name)(-1).web.telegram.org:443`. WebSocket message boundaries carry no meaning; treat the stream as bytes. [/mtproto/transports#websocket]
- **P-082** HTTP: `POST /api` over HTTP/1.1 keepalive. The server forgets queued messages after 10 minutes, or sooner under pressure. The client MUST store recent received msg_ids and ignore duplicates. [/mtproto/transports#http]
- **P-083** URI hosts are `pluto` = DC1, `venus` = DC2, `aurora` = DC3, `vesta` = DC4, `flora` = DC5, `(name)(-1).web.telegram.org`, with the `_test` suffix for test DCs and `w` (CORS) / `s` (WebSocket) path flags. [/mtproto/transports#uri-format]

### B2.8 Authorization key creation [/mtproto/auth_key]

- **P-090** Step 1: send `req_pq_multi#be7e8ef1 nonce:int128` with a fresh random `nonce`.
- **P-091** Step 2: in `resPQ#05162463`, the client MUST check that `nonce` equals what it sent (security guidelines). Store `server_nonce`. `pq` is a big-endian product of two distinct odd primes and is normally ≤ 2^63-1.
- **P-092** `server_public_key_fingerprints` holds 64-bit values: the lower 64 bits of `SHA1(rsa_public_key n:string e:string)`, computed over the **bare TL serialization** of (n, e) as big-endian byte strings. Pick a key the client knows. If none matches, the handshake fails `[derived]`. Test: bytes `85FD64DE851D9DD0` = `long 0xd09d1d85de64fd85`.
- **P-093** Step 3: factor `pq` into primes `p < q`. Test: `3358800871349344843 = 1786331737 * 1880278339`. Send `p` and `q` as minimal big-endian byte strings (4 bytes each in the sample).
- **P-094** Step 4: `new_nonce` is 32 bytes from a good RNG.
- **P-095** Step 4: `data = p_q_inner_data_dc#a9f55f95 pq p q nonce server_nonce new_nonce dc` (or `p_q_inner_data_temp_dc#56fddf88 … dc expires_in` for a temporary key). `dc` is the DC id, +10000 for test servers and **negative for a media (non-CDN) DC**.
- **P-096** RSA_PAD (step 4.1), exactly in this order:
  1. Check `len(data) ≤ 144`.
  2. `data_with_padding = data + random`, making exactly 192 bytes.
  3. `data_pad_reversed = BYTE_REVERSE(data_with_padding)`.
  4. Generate a random 32-byte `temp_key`.
  5. `data_with_hash = data_pad_reversed + SHA256(temp_key + data_with_padding)`. This is 224 bytes. The hash is over the **unreversed** data.
  6. `aes_encrypted = AES256_IGE(data_with_hash, temp_key, IV = 32 zero bytes)`.
  7. `temp_key_xor = temp_key XOR SHA256(aes_encrypted)`.
  8. `key_aes_encrypted = temp_key_xor + aes_encrypted`. This is 256 bytes.
  9. If `key_aes_encrypted` read as a BE integer is ≥ the RSA modulus, go back to step 4 with a new `temp_key`.
  10. `encrypted_data = key_aes_encrypted^e mod n`, output as exactly 256 BE bytes with leading zeros kept.
- **P-097** Step 5: send `req_DH_params#d712e4be nonce server_nonce p q public_key_fingerprint encrypted_data`.
- **P-098** Step 6: on `server_DH_params_ok#d0e8075c`, check both `nonce` and `server_nonce`. Derive `tmp_aes_key = SHA1(new_nonce + server_nonce) + SHA1(server_nonce + new_nonce)[0:12]` and `tmp_aes_iv = SHA1(server_nonce + new_nonce)[12:20] + SHA1(new_nonce + new_nonce) + new_nonce[0:4]`. Then `answer_with_hash = AES256_IGE_decrypt(encrypted_answer, tmp_aes_key, tmp_aes_iv)`.
- **P-099** The client MUST check that `answer_with_hash[0:20] == SHA1(answer)`, where `answer` is the TL-parsed `server_DH_inner_data#b5890dba` **without** the 0..15 padding bytes (see D4). It MUST also check that `answer.nonce` and `answer.server_nonce` match. `len(encrypted_answer) % 16 == 0`. [/mtproto/security_guidelines#checking-sha1-hash-values-during-key-generation]
- **P-100** If a handshake query is incorrect, the server returns transport error `-404` and the handshake MUST restart. `-444` means a test/prod DC id mismatch in `p_q_inner_data`.
- **P-101** `dh_prime` MUST be a safe 2048-bit prime: `2^2047 < p < 2^2048`, with both `p` and `(p-1)/2` prime.
- **P-102** `g ∈ {2,3,4,5,6,7}`, and `g` must be a quadratic residue mod p. For `g=2`: `p mod 8 = 7`. For `g=3`: `p mod 3 = 2`. For `g=4`: no condition. For `g=5`: `p mod 5 ∈ {1,4}`. For `g=6`: `p mod 24 ∈ {19,23}`. For `g=7`: `p mod 7 ∈ {3,5,6}`. Test: in the sample, g=3 and `p mod 3 = 2`.
- **P-103** The verification result MAY be cached. The client MAY embed known-good primes (the current one is in B3.3). With 15 Miller–Rabin iterations the error probability is ≤ 1e-9; more rounds can follow in the background.
- **P-104** Both sides check `1 < g < dh_prime-1`, `1 < g_a < dh_prime-1` and `1 < g_b < dh_prime-1`. They SHOULD also check `2^(2048-64) ≤ g_a ≤ dh_prime - 2^(2048-64)`, and the same for g_b. The client MUST apply these checks to its own g_b too `[derived: regenerate b if g_b fails]`.
- **P-105** Store the time offset `server_time - local_time` from `server_DH_inner_data.server_time`. Use it for msg_id generation.
- **P-106** Step 7: `b` is a 2048-bit secret from a CSPRNG. Server-provided randomness may only be **mixed** into the PRNG, never used directly. `g_b = g^b mod dh_prime`. [/mtproto/security_guidelines#using-secure-pseudorandom-number-generator]
- **P-107** Build `data = client_DH_inner_data#6643b654 nonce server_nonce retry_id g_b` and `data_with_hash = SHA1(data) + data + (0..15 random)` with `len % 16 == 0`. Then `encrypted_data = AES256_IGE(data_with_hash, tmp_aes_key, tmp_aes_iv)` and send `set_client_DH_params#f5045f1f`.
- **P-108** `retry_id = 0` on the first attempt; otherwise it is the `auth_key_aux_hash` from the previous failed attempt.
- **P-109** Step 8: `auth_key = g_a^b mod dh_prime`, represented as 256 big-endian bytes.
- **P-110** Step 9: on `dh_gen_ok#3bcbf734`, `dh_gen_retry#46dc1fb9` or `dh_gen_fail#a69dae02`, check `nonce` and `server_nonce`. Then check `new_nonce_hashN == SHA1(new_nonce + [N] + auth_key_aux_hash)[4:20]`, with N = 1, 2, 3 respectively. `auth_key_aux_hash = SHA1(auth_key)[0:8]` (the higher-order 64 bits). Do not confuse it with `auth_key_hash`, which is the lower 64 bits.
- **P-111** On `dh_gen_retry`, go back to step 7 with a new `b` and `retry_id = auth_key_aux_hash`. On `dh_gen_fail`, restart from step 1 `[derived]`.
- **P-112** On `dh_gen_ok`: set `auth_key_id = SHA1(auth_key)[12:20]` and the initial `server_salt = new_nonce[0:8] XOR server_nonce[0:8]`. Forget all temporary data. Start an encrypted session with a new random `session_id`.
- **P-113** If a response is lost, the client MAY resend the **identical** query (all parameters the same). The server remembers responses for up to 10 minutes. If the server has forgotten, start again from step 1.
- **P-114** Keys must be unique by `auth_key_id`. The server checks this, and a collision leads to retry/regeneration.
- **P-115** For a CDN DC, the client MUST confirm that the RSA key it uses is one of the keys returned by `help.getCdnConfig` (from the main DC). [/cdn#getting-files-from-a-cdn]
- **P-116** Plain-text handshake message ids follow the usual rule `(unixtime << 32) + N*4` for the client; the server's are `≡ 1 mod 4` (see B3.2). The security guidelines say nonce fields MUST be checked in **every** message that carries them.

### B2.9 MTProto 2.0 encryption [/mtproto/description#defining-aes-key-and-initialization-vector]

- **P-120** `msg_key_large = SHA256(substr(auth_key, 88+x, 32) + plaintext + random_padding)` and `msg_key = substr(msg_key_large, 8, 16)`. `x = 0` for client→server, `x = 8` for server→client.
- **P-121** `sha256_a = SHA256(msg_key + substr(auth_key, x, 36))` and `sha256_b = SHA256(substr(auth_key, 40+x, 36) + msg_key)`.
- **P-122** `aes_key = sha256_a[0:8] + sha256_b[8:24] + sha256_a[24:32]` and `aes_iv = sha256_b[0:8] + sha256_a[8:24] + sha256_b[24:32]`.
- **P-123** Encrypt everything after the 24-byte external header with AES-256-IGE. `[derived, verified against the docs' vectors]`: the IGE IV convention is OpenSSL's. `iv[0:16]` is the "previous ciphertext block" XORed into the first plaintext block before encryption, and `iv[16:32]` is the "previous plaintext block" XORed into the first output.
- **P-124** Padding is 12..1024 random bytes, and plaintext plus padding must be divisible by 16.
- **P-125** The lower-order 1024 bits of auth_key (big-endian bytes 128..255) are not used by the 2.0 KDF, which reads at most bytes 0..127 with x=8. The v1 KDF reads up to byte 135. Those lower bits MAY be used for local storage encryption. The server does not store the lowest 512 bits.
- **P-126** Before encrypting, every message must contain the server salt, session id, sequence number, length and time (inside msg_id). [/mtproto/description Note 1]

### B2.10 Mandatory checks on received encrypted messages [/mtproto/security_guidelines#mtproto-encrypted-messages]

- **P-130** `[derived]` `auth_key_id` in the packet MUST equal the key in use for this connection. `len(encrypted_data) % 16 == 0` and `len(encrypted_data) ≥ 32 + 12`. Otherwise drop (and treat it like a failed `msg_key` check).
- **P-131** After decrypting, the client MUST recompute `msg_key` with `x = 8` over the **entire** decrypted plaintext, padding included, and it MUST equal the received `msg_key`.
- **P-132** If any error is found **before** the msg_key check, the client must still perform the msg_key check before returning a result. The visible reaction to any pre-check error MUST be identical to the reaction to a failed msg_key check (no oracle).
- **P-133** `message_data_length` must be ≥ 0, divisible by 4, and ≤ `len(plaintext) - 32`. The padding (`len(plaintext) - 32 - message_data_length`) must be in **12..1024**. The client must never read past the decryption buffer.
- **P-134** `session_id` MUST equal the client's active session id.
- **P-135** The server's `msg_id` MUST be odd (it is ≡ 1 or 3 mod 4). Client msg_ids are even, ≡ 0 mod 4.
- **P-136** The client keeps the last N received msg_ids. A message whose msg_id is lower than all stored values or equal to any of them is ignored. Otherwise the id is added, and the lowest is evicted once more than N are stored.
- **P-137** msg_ids more than 30 s in the future or more than 300 s in the past SHOULD be ignored, but only when the client is confident about its clock (i.e. it has synced with the server).
- **P-138** Service messages carrying client data (salt changes, time-correction notifications such as `bad_server_salt` and `bad_msg_notification` 16/17) MAY be processed even when their time looks "incorrect".
- **P-139** If any check fails, discard the whole message and use none of its information. It is RECOMMENDED to close and reopen the TCP connection and retry the operation (or the whole key generation). Crashing is better than continuing with invalid data. Invalid messages occasionally arise from ordinary network errors. [/mtproto/security_guidelines#behavior-in-case-of-mismatch]

### B2.11 Message identifiers (msg_id) [/mtproto/description#message-identifier-msg-id]

- **P-140** A client msg_id is approximately `server_corrected_unixtime * 2^32`. It MUST be divisible by 4 and MUST increase strictly monotonically within a session.
- **P-141** The lower 32 bits of a client msg_id MUST NOT be zero and MUST encode the fractional part of the creation time (anti-replay).
- **P-142** A server msg_id is ≡ 1 mod 4 for responses to client messages and ≡ 3 mod 4 otherwise.
- **P-143** The server rejects messages more than 300 s after or more than 30 s before their creation time. Such a message must be resent with a new msg_id, or placed in a container with a higher msg_id.
- **P-144** A container's msg_id MUST be strictly greater than the msg_ids of all messages it contains.
- **P-145** If time correction is neglected, the client has to create a new session to keep msg_ids monotonic. [/mtproto#time-synchronization]
- **P-146** On `bad_msg_notification` 16/17 (and `bad_server_salt`), first verify that `bad_msg_id` is a message recently sent by this client. Then set the time offset from the server's msg_id (`server_time ≈ server_msg_id >> 32`) and resend with a fresh msg_id. [/mtproto/service_messages_about_messages#notice-of-ignored-error-message]

### B2.12 Sequence numbers (msg_seqno) [/mtproto/description#message-sequence-number-msg-seqno]

- **P-150** A content-related message has `seqno = current_seqno*2 + 1`, after which `current_seqno += 1`. A non-content-related message has `seqno = current_seqno*2` and does not increment.
- **P-151** An incoming message is content-related iff `seqno & 1 == 1`.
- **P-152** The client MUST mark every API-level RPC query as content-related; otherwise the server returns `bad_msg_notification` 35.
- **P-153** The client MUST NOT mark `msgs_ack`, `msg_container`, `msg_copy` or `gzip_packed` as content-related; otherwise the server returns 34.
- **P-154** Other constructors (ping, msgs_state_req, …) MAY be either. Marking them content-related asks the server for acks and improves reliability.
- **P-155** A container is generated after all of its contents, so its seqno is ≥ the seqnos of its messages (it is non-content-related, so it gets `2*current_seqno` after the inner increments).
- **P-156** The seqno counter is per `(auth_key_id, session_id)`. A new session starts at 0. [/api/datacenter#parallel-sessions]
- **P-157** `[derived]` On `bad_msg_notification` 32/33 (seqno too low/high), the session's seqno state is irrecoverable. Create a new session and resend the pending queries with new msg_ids. This is what tdlib does.

### B2.13 Containers, copies, gzip [/mtproto/service_messages#containers]

- **P-160** The layout is `msg_container#73f1f8dc` + `int count` + count × (`msg_id:long seqno:int bytes:int body`). This is a bare vector of bare `message` (P-010), and `bytes` is the length of `body`.
- **P-161** Every msg_id inside a container MUST be lower than the container's msg_id.
- **P-162** A container MUST NOT contain another container. A container does not itself require an ack.
- **P-163** A container holds at most **1024** messages.
- **P-164** A container is accepted or rejected as a whole. On resend, messages MAY be regrouped into different containers or sent individually.
- **P-165** Empty containers are valid. The server uses them, for example, when an `http_wait` timeout expires.
- **P-166** `msg_copy#e06046b2 orig_message:Message` is unused today. If it is received, process the inner message unless `orig_message.msg_id` was already received, in which case acknowledge both. `orig_message.msg_id` must be lower than the copy's msg_id.
- **P-167** `bad_msg_notification` 64 means an invalid container. 19 means the container msg_id equals the msg_id of a message received earlier. The generator MUST ensure that 19 never happens.
- **P-168** gzip: compress a query (the whole serialized body, starting at the method number) with gzip. Send `gzip_packed` only if the result is smaller. Do not bother for media data or messages ≤ 255 bytes. [/api/invoking#data-compression]

### B2.14 Acknowledgments [/mtproto/service_messages_about_messages#acknowledgment-of-receipt]

- **P-170** `msgs_ack#62d6b459 msg_ids:Vector<long>` carries at most **8192** ids per constructor.
- **P-171** The client MUST acknowledge every content-related message it receives (`seqno` odd) with `msgs_ack`. This includes `rpc_result` and `new_session_created`. [/mtproto/description#content-related-message]
- **P-172** Normally the ack rides along with the next query. If nothing needs sending for a long time (the docs suggest acks generated 60–120 s after receipt are too late to piggyback) or more than ~16 server messages are unacked, the client sends a standalone ack.
- **P-173** Acks are never content-related and are never themselves acked.
- **P-174** These messages do not require an ack: `msgs_ack`, `bad_msg_notification`, `bad_server_salt`, `msgs_state_info`, `msgs_all_info`, `msg_detailed_info`, `msg_new_detailed_info`, `pong`, `future_salts`, `http_wait`, and containers.
- **P-175** The client SHOULD group acks, state requests and resend requests into three **separate** constructors (`msgs_ack`, `msgs_state_req`, `msg_resend_req`) of at most 8192 ids each. [/mtproto/service_messages#simple-container]
- **P-176** An RPC response acknowledges its query. The server may send an explicit `msgs_ack` first if the response will take a long time.

### B2.15 Message status, resend [/mtproto/service_messages_about_messages]

- **P-180** `msgs_state_req#da69fb52 msg_ids:Vector<long>` (≤ 8192) is answered by `msgs_state_info#04deb57d req_msg_id:long info:bytes`, with exactly one status byte per requested id. `msgs_state_info` is not acked and acts as the ack for the request.
- **P-181** Status byte values: 1 = nothing known (msg_id too low, may have been forgotten); 2 = not received (msg_id within the stored range); 3 = not received (msg_id too high); 4 = received. Flags: +8 already acked, +16 does not need an ack, +32 RPC query being processed or done, +64 content-related response already generated, +128 the other party knows the message was received.
- **P-182** If the other side lacks a message, never resend it alone with the **same** msg_id. Either wrap it in a container, or first check with `msgs_state_req` and, if it was not received, resend it with a **new** msg_id.
- **P-183** `msgs_all_info#8cc0d131 msg_ids info:bytes` is voluntary, needs no ack, and omits messages flagged +128 or +16 (unless +32 is set without +64).
- **P-184** `msg_resend_req#7d861a08 msg_ids:Vector<long>` (≤ 8192) makes the remote side resend immediately, usually on the same connection. If any id is unknown, forgotten, or has the requester's own parity, the reply is `msgs_state_info` for **all** the ids.
- **P-185** `msg_detailed_info#276d3ec6 msg_id answer_msg_id bytes status` is the server's reply to a duplicate msg_id whose answer already exists (large answers are not resent). `msg_new_detailed_info#809db6df answer_msg_id bytes status` covers a server-initiated message that was sent earlier but never acked. Currently `status = 0`. Neither needs an ack.
- **P-186** `[derived, tdlib]` On `msg_detailed_info`/`msg_new_detailed_info`: if `answer_msg_id` was already received, ack it. Otherwise send `msg_resend_req [answer_msg_id]`. For `msg_detailed_info`, also treat the original `msg_id` as delivered.

### B2.16 Ignored-message notifications [/mtproto/service_messages_about_messages#notice-of-ignored-error-message]

- **P-190** The messages are `bad_msg_notification#a7eff811 bad_msg_id bad_msg_seqno error_code` and `bad_server_salt#edab447b bad_msg_id bad_msg_seqno error_code new_server_salt`. They are not content-related and need no ack. They are only produced when the server decoded the message correctly.
- **P-191** The client MUST check that it recently sent a message with `bad_msg_id`. Only then may it update the time offset and/or salt and resend.
- **P-192** Code **16**: msg_id too low (client clock is behind). Sync the time from the notification's msg_id and resend with a correct msg_id, or wrap the original in a container with a new msg_id if it waited too long.
- **P-193** Code **17**: msg_id too high. Sync the time and resend with a correct msg_id.
- **P-194** Code **18**: the two low msg_id bits are wrong (the server expects msg_id % 4 == 0). This is a client bug.
- **P-195** Code **19**: the container msg_id equals that of an earlier message. "Must never happen."
- **P-196** Code **20**: the message is too old and the server cannot verify whether it received it. `[derived]` Use `msgs_state_req`, or resend with a new msg_id while accepting the risk of a duplicate (RPCs with a `random_id` are deduplicated server-side, see P-301).
- **P-197** Code **32**: msg_seqno too low. Code **33**: too high. Code **34**: even seqno expected but odd received. Code **35**: odd expected but even received. (Recovery for 32/33 is in P-157.)
- **P-198** Code **48**: wrong server salt. The `bad_server_salt` carries the right one. Store `new_server_salt` and resend the message with it (`[derived]`: with a new msg_id).
- **P-199** Code **64**: invalid container. The codes are grouped by `error_code >> 4`; 0x40–0x4f are container decomposition errors.

### B2.17 Server salt [/mtproto/description#server-salt; /mtproto/service_messages#request-for-several-future-salts; /api/optimisation#server-salt]

- **P-200** Every encrypted message carries the current 64-bit server salt. The salt changes periodically (see D1). Messages with the previous salt are accepted for a further 1800 s.
- **P-201** `get_future_salts#b921bd04 num:int` (1..64) returns `future_salts#ae500895 req_msg_id now salts:vector<future_salt>`. The client MUST check that `req_msg_id` equals its query's msg_id. The response acts as the ack and needs none itself. The server may return fewer than `num` salts.
- **P-202** Salts belong to the auth key, not the session, so future salts MAY be persisted and reused across sessions. Use the salt with the longest remaining lifetime among the valid ones. Salts overlap by 30 minutes.
- **P-203** The client MAY also take the salt from RPC responses (or containers carrying them) that match a recently sent query. If in doubt, do not update (replay risk).
- **P-204** Salt sources at session start: `new_nonce[0:8] XOR server_nonce[0:8]` after key creation, `new_session_created.server_salt`, `bad_server_salt.new_server_salt`, and `future_salts`.

### B2.18 Sessions, new_session_created [/mtproto/description#session; /mtproto/service_messages#new-session-creation-notification]

- **P-205** `session_id` is a random 64-bit value. `(auth_key_id, session_id)` identifies a session with its own msg_id/seqno space, salt usage and ack state. The client may create a new session at any time.
- **P-206** A message meant for one session MUST NOT be sent into another session.
- **P-207** The server may forget sessions unilaterally (inactivity, memory, reboot) without notifying the client. The client MUST handle `new_session_created#9ec20908 first_msg_id unique_id server_salt` gracefully. The message MUST be acked. Its `server_salt` is valid. Because updates may have been lost, the client MUST run `updates.getDifference` (see P-320). [/api/updates#recovering-gaps]
- **P-208** `[derived, tdlib]` Client messages with `msg_id < first_msg_id` that have not been answered may be lost and SHOULD be resent with new msg_ids. A later `new_session_created` with an even smaller `first_msg_id` for the same session is normal.
- **P-209** `unique_id` changes every time the server (re)creates the session. `[derived]` It can be used to detect a duplicate notification.

### B2.19 RPC results and errors [/mtproto/service_messages]

- **P-210** `rpc_result#f35c6d01 req_msg_id:long result:Object`. The result may be `rpc_error`, `gzip_packed`, or the method's result type. The client MUST ack it (it is content-related), and it acknowledges the query.
- **P-211** `rpc_error#2144ca19 error_code:int error_message:string`. The error_message has the form `/[A-Z_0-9]+/`, possibly with numeric parameters (`FLOOD_WAIT_%d`). See B4.
- **P-212** `rpc_drop_answer#58e4a740 req_msg_id` is answered (inside `rpc_result`, which needs an ack) by one of: `rpc_answer_unknown#5e2ad36e` (nothing known or already answered); `rpc_answer_dropped_running#cd78e586` (the query still runs to completion, and the same value is also returned as the answer to the original query, both needing acks); `rpc_answer_dropped#a43ad8b7 msg_id seq_no bytes` (removed from the outgoing queue). The last two also ack the original query.
- **P-213** Cutting the TCP connection does **not** cancel a response: the server resends it on the next connection. To cancel, either use `rpc_drop_answer`, or open a new session and `destroy_session` the old one.

### B2.20 Ping [/mtproto/service_messages#ping-messages-ping-pong]

- **P-215** `ping#7abe77ec ping_id:long` is answered with `pong#347773c5 msg_id:long ping_id:long`, usually on the same connection. Neither needs an ack. Only pings produce pongs, and either side may ping.
- **P-216** `ping_delay_disconnect#f3427b8c ping_id disconnect_delay:int` makes the server close the connection `disconnect_delay` seconds later unless another one arrives (each one resets the timer). Example: ping every 60 s with `disconnect_delay = 75`. The same delay also controls when the server starts grouping updates for a lost connection. [/api/optimisation#grouping-updates]

### B2.21 Destroy session / auth key [/mtproto/service_messages]

- **P-218** `destroy_session#e7512126 session_id` → `destroy_session_ok#e22045fc` / `destroy_session_none#62d350c9`. It is meant for **other** sessions on the same auth key; the effect on the current session is undefined. Extra sessions (e.g. file sessions) MUST be deleted when no longer needed. [/api/optimisation#downloading-files-and-uploading-data-to-the-server]
- **P-219** `destroy_auth_key#d1435160` → `destroy_auth_key_ok#f660e1d4` / `_none#0a9f2259` / `_fail#ea109b13`. It SHOULD be called whenever a permanent auth key is no longer needed (e.g. after logout).

### B2.22 HTTP long poll [/mtproto/service_messages#http-wait-long-poll]

- **P-220** `http_wait#9299359f max_delay wait_after max_wait` (all in ms) is valid only on HTTP. It needs no response and no ack. Without it the defaults are 0 / 0 / 25000. `max_wait` takes precedence over `max_delay`, which takes precedence over `wait_after`. If several appear in one container, the last one wins.

### B2.23 Perfect Forward Secrecy and temp-key binding [/api/pfs; /method/auth.bindTempAuthKey]

- **P-230** Create the permanent key with `p_q_inner_data_dc` and the temporary key with `p_q_inner_data_temp_dc` (they may run in parallel on different connections). Store `expires_at = time + expires_in`.
- **P-231** With PFS, the client MUST never use the permanent `auth_key_id` directly. Every message is encrypted with a temp key that has been bound to the perm key.
- **P-232** An unbound temp key may only call `auth.bindTempAuthKey`, `help.getConfig` and `help.getNearestDc`. Any other method returns `401 AUTH_KEY_PERM_EMPTY`.
- **P-233** The binding message is `bind_auth_key_inner#75a3f765 nonce:long temp_auth_key_id:long perm_auth_key_id:long temp_session_id:long expires_at:int`, 40 bytes serialized including the constructor.
- **P-234** `encrypted_message` uses **MTProto v1** under the **perm** key:
  - `plaintext = random:int128 + msg_id:long + seqno:int(=0) + msg_len:int(=40) + bind_auth_key_inner` (72 bytes). The `random:int128` replaces salt+session_id. `msg_id` MUST be the same msg_id used for the `auth.bindTempAuthKey` request.
  - `msg_key = SHA1(plaintext)[4:20]` (v1: the lower 128 bits of SHA1, padding excluded).
  - Pad `plaintext` to a multiple of 16 with random bytes.
  - Derive the AES key/IV with the v1 KDF (P-238), `x = 0`, from `perm_auth_key` and `msg_key`, and encrypt with AES-256-IGE.
  - `encrypted_message = perm_auth_key_id + msg_key + ciphertext`.
- **P-235** Send `auth.bindTempAuthKey#cdd42a05 perm_auth_key_id:long nonce:long expires_at:int encrypted_message:bytes` encrypted with the **temp** key (MTProto 2.0) in session `temp_session_id`. `nonce` and `expires_at` MUST equal the inner values. The result is `Bool`.
- **P-236** After a successful bind, the client MUST call `initConnection` again (rewriting the client info).
- **P-237** Errors: `400 ENCRYPTED_MESSAGE_INVALID`, `400 EXPIRES_AT_INVALID`, `400 TEMP_AUTH_KEY_ALREADY_BOUND` (the temp key is bound to another perm key), `400 TEMP_AUTH_KEY_EMPTY`.
- **P-238** The MTProto v1 KDF ([/mtproto/description_v1#defining-aes-key-and-initialization-vector]):
  - `sha1_a = SHA1(msg_key + substr(auth_key, x, 32))`
  - `sha1_b = SHA1(substr(auth_key, 32+x, 16) + msg_key + substr(auth_key, 48+x, 16))`
  - `sha1_c = SHA1(substr(auth_key, 64+x, 32) + msg_key)`
  - `sha1_d = SHA1(msg_key + substr(auth_key, 96+x, 32))`
  - `aes_key = sha1_a[0:8] + sha1_b[8:20] + sha1_c[4:16]`
  - `aes_iv = sha1_a[8:20] + sha1_b[0:8] + sha1_c[16:20] + sha1_d[0:8]`
- **P-239** Handling `ENCRYPTED_MESSAGE_INVALID`: **iff** the perm key was created more than 60 s ago, drop both the temp and perm keys (if the perm key was the main logged-in key, the user is now logged out), recreate both, and retry the bind. On success, if the dropped key was not the main key, re-import the authorization from the home DC. **Otherwise** (perm key younger than 60 s), just retry the bind.
- **P-240** When the temp key expires, create a new temp key and bind it to the same perm key. It MAY be pre-generated before expiry.
- **P-241** A temp key may vanish before `expires_at`, since the server keeps it only in RAM. A non-existent key yields transport error **-404** (and RPC `401 AUTH_KEY_UNREGISTERED`, "for example, a PFS temporary key has expired"). The engine must regenerate the key and bind again.
- **P-242** The client MAY keep temp keys in RAM only.
- **P-243** When `tmp_sessions > 1`, PFS is mandatory for all sessions: each session generates and binds its own temp key, all bound to the same perm key. [/api/pfs; /api/datacenter#parallel-sessions]
- **P-244** `auth.dropTempAuthKeys#8e48a188 except_auth_keys:Vector<long>` drops every temp key except those listed.

### B2.24 Invoking: layers, initConnection, ordering [/api/invoking]

- **P-250** `invokeWithLayer#da9b0d0d layer:int query:!X` may only be used together with `initConnection#c1cd5ea9 flags api_id device_model system_version app_version system_lang_code lang_pack lang_code proxy:flags.0?InputClientProxy params:flags.1?JSONValue query:!X`. The canonical first call is `invokeWithLayer(layer, initConnection(…, query))`.
- **P-251** `initConnection` MUST be called on the first API call after an app restart, whenever any parameter may have changed, and after every `auth.bindTempAuthKey`. The layer it is wrapped in is saved, and afterwards calls need no `invokeWithLayer`.
- **P-252** `initConnection.params` currently supports only `tz_offset` (seconds). `proxy` carries MTProxy info (`InputClientProxy`).
- **P-253** `400 CONNECTION_NOT_INITED`: call `initConnection` before other queries. `400 CONNECTION_LAYER_INVALID`, `CONNECTION_API_ID_INVALID`, `CONNECTION_DEVICE_MODEL_EMPTY`, `CONNECTION_SYSTEM_EMPTY`, `CONNECTION_APP_VERSION_EMPTY`, `CONNECTION_SYSTEM_LANG_CODE_EMPTY`, `CONNECTION_LANG_PACK_INVALID`: these are bad initConnection fields.
- **P-254** The API may return constructors from an older layer, e.g. for updates from big channels. Clients SHOULD treat this as a `500`: close and reopen the TCP socket, re-run `initConnection`, and call `getDifference`.
- **P-255** `invokeWithoutUpdates#bf9459b7 query:!X` invokes without subscribing this connection to updates. This is the default behaviour for file queries.
- **P-256** By default the server processes parallel requests **in arbitrary order**. To enforce ordering, use `invokeAfterMsg#cb9f372d msg_id query` or `invokeAfterMsgs#3dc4b4f0 msg_ids query`.
- **P-257** When combined with other wrappers, `invokeAfterMsg(s)` MUST be the **outermost** wrapper.
- **P-258** `MSG_WAIT_TIMEOUT` (code -503) means the dependency did not finish within 0.5 s. Resend the same request, still wrapped with the **same** dependency id(s).
- **P-259** `MSG_WAIT_FAILED` (400/500) means a dependency failed with any RPC error, including FLOOD_WAIT. The simplest recovery: wait for the responses to all dependencies, then resend. For chains, resend the failed tail as a new chain (scenario 1.1/1.2). For `invokeAfterMsgs`, either wait for all dependencies, or resend with `msg_ids` minus the failed one. Only re-wrap in a new `invokeAfterMsg` when the previous request is itself being resent.
- **P-260** Simplest correct strategy: use only chained `invokeAfterMsg` (scenario 1), never `invokeAfterMsgs`.
- **P-261** Unauthenticated connections may call only the methods in `errors.json.unauthed_allowed`, which include: `initConnection`, `invokeWithLayer`, `auth.bindTempAuthKey`, `auth.importAuthorization`, `auth.importBotAuthorization`, `auth.sendCode`, `auth.signIn`, `auth.signUp`, `auth.checkPassword`, `auth.exportLoginToken`, `auth.importLoginToken`, `help.getConfig`, `help.getNearestDc`, `help.getAppConfig`, `help.getCountriesList`, `langpack.*`, `account.getPassword`, and some payment/email/passkey methods (40 in total, layer 227).

### B2.25 Datacenters, config, migration [/api/datacenter; /constructor/dcOption; /constructor/config]

- **P-265** `help.getConfig#c4f9186b` returns `config#cc1a241e`, whose `dc_options:Vector<DcOption>` lists every DC. IPs and ports may change frequently. Each DC typically has at least one IPv4 and one IPv6 endpoint.
- **P-266** `dcOption#18b7a10d` flags: `ipv6` (0), `media_only` (1, use only for file up/download), `tcpo_only` (2, obfuscation required, with `secret` in flags.10), `cdn` (3), `static` (4, "this IP should be used when connecting through a proxy"), `this_port_only` (5).
- **P-267** `config.expires` is the date at which the config must be refetched. `config.date` is the server date. `this_dc` is the DC that answered. `dc_txt_domain_name` is the domain for fetching the encrypted DC list from a DNS TXT record. `test_mode` reports whether these are test DCs. The config must be refetched immediately on `updateConfig`. `updateDcOptions` must be applied, even when not logged in. [/api/config#mtproto-configuration; /api/updates#subscribing-to-updates]
- **P-268** `help.getNearestDc#1fb33026` returns `nearestDc country this_dc nearest_dc`. It is allowed unauthenticated and on an unbound temp key.
- **P-269** The client must use the connection to the nearest access point for its main queries. 95% of DC redirects happen on `auth.sendCode`.
- **P-270** `PHONE_MIGRATE_X` (phone registered on DC X), `NETWORK_MIGRATE_X` (IP associated with DC X, during registration) and `USER_MIGRATE_X` (the account moved to DC X) all mean: connect to DC X, make it the home DC (for USER/PHONE), and repeat the query there.
- **P-271** `FILE_MIGRATE_X`: the file lives on DC X. Repeat the file query on DC X. Files are downloadable only from their `dc_id`. `STATS_MIGRATE_X`: channel statistics live on DC X.
- **P-272** Auth keys are **not** shared between DCs: each DC needs its own key. To carry a login across, call `auth.exportAuthorization#e5bfffcd dc_id` on the current (authorized) DC to get `auth.exportedAuthorization#b434e2b8 id bytes`, then call `auth.importAuthorization#a57a7dad id bytes` on the target DC (allowed unauthenticated). Errors: `DC_ID_INVALID`, `AUTH_BYTES_INVALID`, `USER_ID_INVALID`.
- **P-273** Test DCs: there are 3. Add `10000` to the DC id in `p_q_inner_data*_dc` and in the obfuscation header. Test phone numbers are `99966XYYYY` (X = DC 1..3) with login code `XXXXX`. A test DC 2 account `999662YYYY` with code `22222` can exercise CDN redirects. [/api/auth#test-accounts; /cdn#testing-cdn-redirects]
- **P-274** Media sessions: large file queries (`upload.getFile`, `upload.saveFilePart`, `upload.getWebFile`) SHOULD go through separate sessions and separate connections that run nothing else. If a `media_only` dcOption exists for the DC, those queries **must** be sent to it.
- **P-275** Updates go to the last active **non-file** connection of an authorized user. To start receiving them, the client must init the connection and call some API method (e.g. `updates.getState`).
- **P-276** While not logged in (on an encrypted connection), the only updates handled are `updateLoginToken`, `updateSentPhoneCode`, `updateDcOptions`, `updateConfig`, `updateLangPackTooLong` and `updateLangPack`. Updates on an unencrypted connection are always ignored.

### B2.26 Parallel sessions and AUTH_KEY_DUPLICATED [/api/datacenter#parallel-sessions; /api/errors#406-not-acceptable]

- **P-280** A single auth key may serve several independent MTProto sessions: same `auth_key_id`, different `session_id`, each with its own msg_id/seqno space, salt usage and acks. With PFS, each parallel session also needs its own temp key.
- **P-281** **Main (RPC) sessions to the home DC**: the client may open at most `tmp_sessions` parallel main sessions. That value comes from `config.tmp_sessions` (flags.0) or `auth.authorization.tmp_sessions`; when absent or ≤ 1, exactly **one** main session is allowed.
- **P-282** When `tmp_sessions > 1`, PFS is mandatory for all sessions. Every main session may receive updates (sharing pts/seq/qts); each update goes to exactly one randomly chosen session.
- **P-283** Opening more parallel main sessions than allowed (multiple session_ids over the same key **or multiple TCP connections to the main DC sending requests in parallel**, from the same or different IPs) makes the server terminate all of them with **`406 AUTH_KEY_DUPLICATED`**. That error **invalidates the authorization key**: the user must generate a new key and log in again.
- **P-284** File-transfer sessions to media DCs are exempt and may always run in parallel ("allowed and actually recommended").
- **P-285** `[derived]` Connection racing or "happy eyeballs" on the main DC is safe only if at most one connection carries encrypted requests of the main session at any moment. Probe candidates with transport-only or unauthenticated traffic, or abandon losers before sending session traffic.
- **P-286** "Session" in the AUTH_KEY_DUPLICATED rule means a logged-in authorization (visible in `account.getAuthorizations`), not an MTProto session id.

### B2.27 Files (upload/download) [/api/files]

- **P-290** Upload: the client assigns a random 64-bit `file_id` and splits the file into parts of one fixed `part_size` with `part_size % 1024 == 0` and `524288 % part_size == 0`, i.e. at most 512 KB. Only the last part may be smaller.
- **P-291** `file_part` runs 0..`upload_max_fileparts_*`−1 (appConfig: default 4000, premium 8000, sample values). 512 KB parts are recommended.
- **P-292** Use `upload.saveBigFilePart#de7b673d file_id file_part file_total_parts bytes` + `inputFileBig` when the file is **> 10 MB**. Otherwise use `upload.saveFilePart#b304a621` + `inputFile` (`md5_checksum` optional, checked by the server).
- **P-293** Streamed upload: always use `saveBigFilePart` with `file_total_parts = -1` on every part but the last. The last part carries `ceil(total/part_size)`, and it may be an empty part.
- **P-294** Upload errors: `FILE_PARTS_INVALID`, `FILE_PART_INVALID`, `FILE_PART_TOO_BIG`, `FILE_PART_EMPTY`, `FILE_PART_SIZE_INVALID`, `FILE_PART_SIZE_CHANGED`, `FILE_PART_X_MISSING` (re-upload part X), `MD5_CHECKSUM_INVALID`, and `FLOOD_PREMIUM_WAIT_X`, which MUST be retried automatically after X seconds.
- **P-295** Part storage lives from minutes to hours. Use a local call queue of X parallel parts per connection (not `invokeAfterMsgs`), and optionally Y parallel connections.
- **P-296** Download with `upload.getFile#be5335be flags precise:flags.0?true cdn_supported:flags.1?true location offset:long limit:int`. Without `precise`: `offset % 4096 == 0`, `limit % 4096 == 0`, `1048576 % limit == 0`. With `precise`: `offset % 1024 == 0`, `limit % 1024 == 0`, `limit ≤ 1048576`. **Always**: `offset / 2^20 == (offset + limit - 1) / 2^20`.
- **P-297** Limit concurrent downloads per DC to `small_queue_max_active_operations_count` (files < 20 MB, sample 5) and `large_queue_max_active_operations_count` (≥ 20 MB, sample 2).
- **P-298** Download errors: `FILE_REFERENCE_EXPIRED`/`FILE_REFERENCE_INVALID` (refetch the file reference from its source), `FILE_ID_INVALID`, `OFFSET_INVALID`, `LIMIT_INVALID`, `FILE_MIGRATE_X`, `FLOOD_WAIT_X`, `FLOOD_PREMIUM_WAIT_X` (auto-retry after X).
- **P-299** `upload.getFileHashes#9156982a location offset` returns `Vector<fileHash#f39b035c offset:long limit:int hash:bytes>`, the SHA-256 of each `[offset, offset+limit)` range. Verifying is recommended for master-DC downloads and mandatory for CDN.
- **P-300** Use separate download/upload sessions, and delete them when they are no longer needed. Keep 2+ queries in flight per connection to hide RTT. [/api/optimisation]
- **P-301** `random_id` deduplicates sends server-side: reusing one returns the previous result, or `500 RANDOM_ID_DUPLICATE` if the earlier call is still in flight. [/api/updates#updatemessageid-updates]

### B2.28 CDN [/cdn]

- **P-305** Set `cdn_supported` in `upload.getFile` to allow redirects. The reply may be `upload.fileCdnRedirect#f18cda44 dc_id file_token encryption_key encryption_iv file_hashes:Vector<FileHash>`.
- **P-306** The CDN DC's address is in `help.getConfig` `dc_options` with the `cdn` flag. Before creating a key there, check the CDN RSA key against `help.getCdnConfig#52029342` → `cdnConfig#5725e40a public_keys:Vector<cdnPublicKey#c982eaba dc_id public_key:string>`.
- **P-307** CDN DCs support only `upload.getCdnFile`, `initConnection` and `invokeWithLayer`. Their auth key may be deleted at any time (-404), in which case a new key must be generated.
- **P-308** The client MUST NOT accept updates from CDN DCs, MUST NOT let CDN DCs substitute replies to queries sent elsewhere, and MUST NOT send private user info from `initConnection` to CDNs.
- **P-309** Call `upload.getCdnFile#395f69da file_token offset limit` for each offset. For files of unknown size, repeat until an empty reply. The result is `upload.cdnFile#a99fca4f bytes`, or `upload.cdnFileReuploadNeeded#eea8e46e request_token`.
- **P-310** On `cdnFileReuploadNeeded`, send `upload.reuploadCdnFile#9b2754a8 file_token request_token` → `Vector<FileHash>` to the DC that received the original `upload.getFile` (the file's master DC), then ask the CDN again.
- **P-311** Decrypt with AES-256-CTR, key `encryption_key`. The IV is `encryption_iv` with its **last 4 bytes replaced by `offset/16` as a big-endian uint32**.
- **P-312** The client MUST verify the SHA-256 of every part against the hashes from the master DC (from the redirect, the reupload, or `upload.getCdnFileHashes#91dc3f31 file_token offset` for missing ranges) before saving it.
- **P-313** `FILE_TOKEN_INVALID` (getCdnFile/reuploadCdnFile/getCdnFileHashes) and `REQUEST_TOKEN_INVALID` mean: continue with `upload.getFile` on the master DC. `CDN_UPLOAD_TIMEOUT` (500) can come from reuploadCdnFile. `CDN_METHOD_INVALID` means a master-DC method was called on a CDN DC.
- **P-314** The offset/limit rules are the same as for getFile without `precise` (4 KB alignment, `1 MB % limit == 0`, within one 1 MB block).

### B2.29 Updates: network-relevant rules [/api/updates]

- **P-320** Call `updates.getDifference` on: startup; a gap in seq/pts/qts (after waiting up to 0.5 s for reordering); **`new_session_created`**; an update that fails to deserialize; a short update missing data; **no updates for 15 minutes or more**; `updatesTooLong`.
- **P-321** While gaps are being filled, socket updates must be held back, and the same sequence must not be gap-filled concurrently.
- **P-322** Updates may arrive gzip-packed, exactly like RPC results.

### B2.30 Security guidelines (complete list) [/mtproto/security_guidelines]

- **P-330** DH: validate `dh_prime` and `g` (P-101..P-103), and `g_a`/`g_b` ranges (P-104).
- **P-331** Key generation: check the SHA1 in `answer_with_hash` (P-099).
- **P-332** Key generation: check `nonce`, `server_nonce` and `new_nonce` (via `new_nonce_hash`) in every message that contains them.
- **P-333** Generate `a`/`b` with a CSPRNG and only ever *mix* server entropy into it.
- **P-334** Encrypted messages: check `msg_key` (P-131), with constant behaviour on failure (P-132).
- **P-335** Encrypted messages: check the length and padding range (P-133).
- **P-336** Encrypted messages: check `session_id` (P-134).
- **P-337** Encrypted messages: check msg_id parity, the replay window and the time window (P-135..P-138).
- **P-338** On any mismatch: discard, use nothing from the message, and reconnect and retry (P-139).
- **P-339** The client MAY password-protect a stored auth key: prepend `SHA256(key)`, then encrypt with AES-CBC under a password-derived key. [/mtproto/description#storing-an-authorization-key-on-a-client-device]

---

## B3. TEST VECTORS

### B3.1 /mtproto/samples-auth_key, verbatim

What follows is the complete page body as text. The `<pre>` blocks are byte-exact and the tables are flattened to `| … |` rows. Transport headers are omitted (as on the page). Read D3 and D4 before using it: the TL lines show fake ids (`#00000000`, `#00000004`), and `answer` includes 8 padding bytes. The temporary RSA `temp_key` used in step 4.1 is **not** given, so `encrypted_data` from step 4 cannot be reproduced. Every other value can (B3.2).

~~~~text
 

In the examples below, the transport headers are omitted:

>  

For example, for the abridged version of the transport », the client sends `0xef` as the first byte (important: only prior to the very first data packet), then the packet length is encoded with a single byte (`0x01-0x7e` = data length divided by 4; or `0x7f` followed by 3 bytes (little endian) divided by 4) followed by the data itself. In this case, server responses have the same structure (although the server does not send `0xef`as the first byte). Detailed documentation on creating authorization keys is available here ».

#### DH exchange initiation

##### 1) Client sends query to server

Sent payload (excluding transport headers/trailers):

```
0000 | 00 00 00 00 00 00 00 00 78 F4 04 00 61 70 46 6A
0010 | 14 00 00 00 F1 8E 7E BE 51 A1 14 3F C7 A3 66 6B
0020 | E4 BE 54 D6 89 0A 02 DC

```

Payload (de)serialization:

```
req_pq_multi#00000000 nonce:int128 = ResPQ;

```

|  Parameter |  Offset, Length in bytes |  Value |  Description |    
|  auth_key_id |  0, 8 |  `0000000000000000` |  0 since the message is in plain text |  
|  message_id |  8, 8 |  `78F404006170466A` |  Message ID generated as specified here » (unixtime() << 32) + (N*4) |  
|  message_length |  16, 4 |  `14000000` (20 in decimal) |  Message body length |  
|  %(req_pq_multi) |  20, 4 |  `f18e7ebe` |  req_pq_multi constructor number from TL schema |  
|  nonce |  24, 16 |  `51A1143FC7A3666BE4BE54D6890A02DC` |  Random number |   

##### 2) Server sends response of the form

Received payload (excluding transport headers/trailers):

```
0000 | 00 00 00 00 00 00 00 00 01 F4 CC C2 61 70 46 6A
0010 | 50 00 00 00 63 24 16 05 51 A1 14 3F C7 A3 66 6B
0020 | E4 BE 54 D6 89 0A 02 DC 63 24 8F 67 48 21 4E AB
0030 | 8A 2F 4C C8 76 E1 19 74 08 2E 9C DB 98 C8 0C DA
0040 | 4B 00 00 00 15 C4 B5 1C 03 00 00 00 85 FD 64 DE
0050 | 85 1D 9D D0 A5 B7 F7 09 35 5F C3 0B 21 6B E8 6C
0060 | 02 2B B4 C3

```

Payload (de)serialization:

```
resPQ#00000000 nonce:int128 server_nonce:int128 pq:string server_public_key_fingerprints:Vector<strlong> = ResPQ;

```

|  Parameter |  Offset, Length in bytes |  Value |  Description |    
|  auth_key_id |  0, 8 |  `0000000000000000` |  0 since the message is in plain text |  
|  message_id |  8, 8 |  `01F4CCC26170466A` |  Message ID generated as specified here » (unixtime() << 32) + (N*4) |  
|  message_length |  16, 4 |  `50000000` (80 in decimal) |  Message body length |  
|  %(resPQ) |  20, 4 |  `63241605` |  resPQ constructor number from TL schema |  
|  nonce |  24, 16 |  `51A1143FC7A3666BE4BE54D6890A02DC` |  Value generated by client in Step 1 |  
|  server_nonce |  40, 16 |  `63248F6748214EAB8A2F4CC876E11974` |  Server-generated random number |  
|  pq |  56, 12 |  `082E9CDB98C80CDA4B000000`
TL byte deserialization 
=> bigendian conversion to decimal
=> 3358800871349344843 |  Single-byte prefix denoting length, an 8-byte string, and three bytes of padding |  
|  %(Vector strlong) |  68, 4 |  `15c4b51c` |  Vector t constructor number from TL schema |  
|  count |  72, 4 |  `03000000` |  Number of elements in server_public_key_fingerprints |  
|  server_public_key_fingerprints[0] |  76, 8 |  `85FD64DE851D9DD0` |  64 lower-order bits of `SHA1(server_public_key)` |  
|  server_public_key_fingerprints[1] |  84, 8 |  `A5B7F709355FC30B` |  64 lower-order bits of `SHA1(server_public_key)` |  
|  server_public_key_fingerprints[2] |  92, 8 |  `216BE86C022BB4C3` |  64 lower-order bits of `SHA1(server_public_key)` |   

In our case, the client only has the following public keys, with the following fingerprints:

- `85FD64DE851D9DD0` 

Let's choose the only matching key, the one with fingerprint equal to `85FD64DE851D9DD0`.

#### Proof of work

##### 3) Client decomposes pq into prime factors such that p < q.

```
pq = 3358800871349344843

```

Decompose into 2 prime cofactors `p < q`: `3358800871349344843 = 1786331737 * 1880278339`

```
p = 1786331737
q = 1880278339

```

#### Presenting proof of work; Server authentication

##### 4) `encrypted_data` payload generation

First of all, generate an `encrypted_data` payload as follows:

Generated payload (excluding transport headers/trailers):

```
0000 | 95 5F F5 A9 08 2E 9C DB 98 C8 0C DA 4B 00 00 00
0010 | 04 6A 79 42 59 00 00 00 04 70 12 C5 43 00 00 00
0020 | 51 A1 14 3F C7 A3 66 6B E4 BE 54 D6 89 0A 02 DC
0030 | 63 24 8F 67 48 21 4E AB 8A 2F 4C C8 76 E1 19 74
0040 | BF 8C B5 BD 9C 5B 4F E7 CF 24 D6 4D 28 1F 89 31
0050 | 15 76 D5 3C 0D A6 5A 83 26 7E 57 31 54 14 C9 A6
0060 | 02 00 00 00

```

Payload (de)serialization:

```
p_q_inner_data_dc#00000000 pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 dc:int = P_Q_inner_data;

```

|  Parameter |  Offset, Length in bytes |  Value |  Description |    
|  %(p_q_inner_data_dc) |  0, 4 |  `955ff5a9` |  p_q_inner_data_dc constructor number from TL schema |  
|  pq |  4, 12 |  `082E9CDB98C80CDA4B000000`
TL byte deserialization 
=> bigendian conversion to decimal
=> 3358800871349344843 |  Single-byte prefix denoting length, 8-byte string, and three bytes of padding |  
|  p |  16, 8 |  `046A794259000000`
TL byte deserialization 
=> bigendian conversion to decimal
=> 1786331737 |  First prime cofactor: single-byte prefix denoting length, 4-byte string, and three bytes of padding |  
|  q |  24, 8 |  `047012C543000000`
TL byte deserialization 
=> bigendian conversion to decimal
=> 1880278339 |  Second prime cofactor: single-byte prefix denoting length, 4-byte string, and three bytes of padding |  
|  nonce |  32, 16 |  `51A1143FC7A3666BE4BE54D6890A02DC` |  Value generated by client in Step 1 |  
|  server_nonce |  48, 16 |  `63248F6748214EAB8A2F4CC876E11974` |  Value received from server in Step 2 |  
|  new_nonce |  64, 32 |  `BF8CB5BD9C5B4FE7CF24D64D281F8931` `1576D53C0DA65A83267E57315414C9A6` |  Client-generated random number |  
|  dc |  96, 4 |  `02000000` (2 in decimal) |  DC ID: `10000` (decimal) has to be added to the DC ID to connect to the test servers; it has to be made negative if the DC we're connecting to is a media (not CDN) DC. |   

The serialization of P_Q_inner_data produces data, which is used to generate encrypted_data as specified in step 4.1.
 These are the inputs to the algorithm specified in step 4.1:

```
data = 955FF5A9082E9CDB98C80CDA4B000000046A794259000000047012C54300000051A1143FC7A3666BE4BE54D6890A02DC63248F6748214EAB8A2F4CC876E11974BF8CB5BD9C5B4FE7CF24D64D281F89311576D53C0DA65A83267E57315414C9A602000000
random_padding_bytes = CAA2EE40A79783204C32BE8CB0EB37F550E2B037C8D587641F0AA0CC5A00ED9A482D035C8535ECC4E1D7FD961765525AD4E09497F9152C013CC14E9D50357A280F33E60E86AEF0B92775947BDF76D95966CCD0FF47E06FA6F2C8ACDF

```

And this is the output:

```
encrypted_data = 07FB235B4C7728558405705E3F18B09E5E2434977C42112E50DDE7C339D5893F966E40D8C951E37D9E32538189A83D59E005502B7CC125FBCD346EE75E33D0A26EDFFF456914245AC707B427E1DA7C7EAADBE1DD868B81B675D516E8DD20193FD51CACDE5A2281DCC57A724C77872511F7D156AAA032C7E731F971F3F4C9BE9233A3A1EE782C3311B0D380C0639386B57366AB38CA232B08805095D182C1382F1E0274D3EAE59F08AB7C8F50BB9CE75AB7A2B727A052F720B115BE65F455128B02BF182D243255894E1D376C4B287D45218012FBA1B9CD7619B1CF827FEAB4E00EB9722A126CC022A1DDCC094F3B7F258FDEE75FA21C8DA61F4136C23BADDB0C

```

The length of the final string is 256 bytes.

##### 5) Send req_DH_params query with generated `encrypted_data`

Sent payload (excluding transport headers/trailers):

```
0000 | 00 00 00 00 00 00 00 00 F4 DD 0B 00 61 70 46 6A
0010 | 40 01 00 00 BE E4 12 D7 51 A1 14 3F C7 A3 66 6B
0020 | E4 BE 54 D6 89 0A 02 DC 63 24 8F 67 48 21 4E AB
0030 | 8A 2F 4C C8 76 E1 19 74 04 6A 79 42 59 00 00 00
0040 | 04 70 12 C5 43 00 00 00 85 FD 64 DE 85 1D 9D D0
0050 | FE 00 01 00 07 FB 23 5B 4C 77 28 55 84 05 70 5E
0060 | 3F 18 B0 9E 5E 24 34 97 7C 42 11 2E 50 DD E7 C3
0070 | 39 D5 89 3F 96 6E 40 D8 C9 51 E3 7D 9E 32 53 81
0080 | 89 A8 3D 59 E0 05 50 2B 7C C1 25 FB CD 34 6E E7
0090 | 5E 33 D0 A2 6E DF FF 45 69 14 24 5A C7 07 B4 27
00A0 | E1 DA 7C 7E AA DB E1 DD 86 8B 81 B6 75 D5 16 E8
00B0 | DD 20 19 3F D5 1C AC DE 5A 22 81 DC C5 7A 72 4C
00C0 | 77 87 25 11 F7 D1 56 AA A0 32 C7 E7 31 F9 71 F3
00D0 | F4 C9 BE 92 33 A3 A1 EE 78 2C 33 11 B0 D3 80 C0
00E0 | 63 93 86 B5 73 66 AB 38 CA 23 2B 08 80 50 95 D1
00F0 | 82 C1 38 2F 1E 02 74 D3 EA E5 9F 08 AB 7C 8F 50
0100 | BB 9C E7 5A B7 A2 B7 27 A0 52 F7 20 B1 15 BE 65
0110 | F4 55 12 8B 02 BF 18 2D 24 32 55 89 4E 1D 37 6C
0120 | 4B 28 7D 45 21 80 12 FB A1 B9 CD 76 19 B1 CF 82
0130 | 7F EA B4 E0 0E B9 72 2A 12 6C C0 22 A1 DD CC 09
0140 | 4F 3B 7F 25 8F DE E7 5F A2 1C 8D A6 1F 41 36 C2
0150 | 3B AD DB 0C

```

Payload (de)serialization:

```
req_DH_params#00000000 nonce:int128 server_nonce:int128 p:string q:string public_key_fingerprint:long encrypted_data:string = Server_DH_Params;

```

|  Parameter |  Offset, Length in bytes |  Value |  Description |    
|  auth_key_id |  0, 8 |  `0000000000000000` |  0 since the message is in plain text |  
|  message_id |  8, 8 |  `F4DD0B006170466A` |  Message ID generated as specified here » (unixtime() << 32) + (N*4) |  
|  message_length |  16, 4 |  `40010000` (320 in decimal) |  Message body length |  
|  %(req_DH_params) |  20, 4 |  `bee412d7` |  req_DH_params constructor number from TL schema |  
|  nonce |  24, 16 |  `51A1143FC7A3666BE4BE54D6890A02DC` |  Value generated by client in Step 1 |  
|  server_nonce |  40, 16 |  `63248F6748214EAB8A2F4CC876E11974` |  Value received from server in Step 2 |  
|  p |  56, 8 |  `046A794259000000`
TL byte deserialization 
=> bigendian conversion to decimal
=> 1786331737 |  First prime cofactor: single-byte prefix denoting length, 4-byte string, and three bytes of padding |  
|  q |  64, 8 |  `047012C543000000`
TL byte deserialization 
=> bigendian conversion to decimal
=> 1880278339 |  Second prime cofactor: single-byte prefix denoting length, 4-byte string, and three bytes of padding |  
|  public_key_fingerprint |  72, 8 |  `85FD64DE851D9DD0` |  `fingerprint` of public key used |  
|  encrypted_data |  80, 260 |  `FE00010007FB235B4C7728558405705E` `3F18B09E5E2434977C42112E50DDE7C3` `39D5893F966E40D8C951E37D9E325381` `89A83D59E005502B7CC125FBCD346EE7` `5E33D0A26EDFFF456914245AC707B427` `E1DA7C7EAADBE1DD868B81B675D516E8` `DD20193FD51CACDE5A2281DCC57A724C` `77872511F7D156AAA032C7E731F971F3` `F4C9BE9233A3A1EE782C3311B0D380C0` `639386B57366AB38CA232B08805095D1` `82C1382F1E0274D3EAE59F08AB7C8F50` `BB9CE75AB7A2B727A052F720B115BE65` `F455128B02BF182D243255894E1D376C` `4B287D45218012FBA1B9CD7619B1CF82` `7FEAB4E00EB9722A126CC022A1DDCC09` `4F3B7F258FDEE75FA21C8DA61F4136C2`
 `3BADDB0C` |  Value generated above |   

##### 6) Server responds with:

Received payload (excluding transport headers/trailers):

```
0000 | 00 00 00 00 00 00 00 00 01 C8 63 F4 61 70 46 6A
0010 | 78 02 00 00 5C 07 E8 D0 51 A1 14 3F C7 A3 66 6B
0020 | E4 BE 54 D6 89 0A 02 DC 63 24 8F 67 48 21 4E AB
0030 | 8A 2F 4C C8 76 E1 19 74 FE 50 02 00 C3 34 D3 13
0040 | 06 41 74 F4 43 CE 90 E1 3C 83 5F AE A6 AE 96 77
0050 | 08 9A 07 81 CC 8C 17 AD C8 FF 5B 50 72 93 4C 1D
0060 | FB 1F 2B 92 22 19 7D E8 06 18 6E 66 12 E0 CF A2
0070 | 59 38 09 B4 B9 1B 49 F0 06 FF BB D9 EA AA DE 1E
0080 | ED CA 04 6F 50 0A 77 BB 53 8E 3C 2F 02 A4 A6 81
0090 | 4D F0 BC 77 99 3E 49 3B 7F 2C 98 34 4F 67 44 55
00A0 | A9 0A 54 10 70 74 0F 4B 81 1F FF 4B 80 B1 61 73
00B0 | 7E 0E 86 7F F2 0D 03 BE 6B 52 BA 66 F7 31 9D 03
00C0 | B6 21 73 2E 1C 88 02 02 EA F6 1D F3 1D E8 31 E7
00D0 | AC 97 B0 FF DB FF FF A7 01 9D 39 95 53 F3 7B 64
00E0 | 59 13 23 84 43 F4 C5 60 A5 9A 5B A6 AA 6B FA EB
00F0 | 15 9F D2 29 1F CD A4 9A 23 E8 00 91 96 B8 06 2D
0100 | D4 24 F4 5D 3B 43 53 8C 68 B2 C0 70 A8 45 C2 60
0110 | 05 2D D3 C2 66 65 9F A6 C0 C6 A8 FF 36 FB FF 8D
0120 | AB 36 E0 6B EB 5E 18 AF E3 80 27 FD A4 5E 65 88
0130 | 4A 50 34 02 84 0E 21 C1 86 91 01 F4 C6 13 E9 ED
0140 | A6 1C 2E B0 AA 98 70 46 F8 06 9C 2C 00 2E E4 8A
0150 | 95 84 4D D6 2E 0E 4B 61 22 57 39 1B 01 4D 3B 04
0160 | 3D 7C 19 3F 93 63 52 F9 D7 99 CC 40 17 CA 54 48
0170 | 96 BB 09 B3 B5 B8 B7 0C 2C 5E 48 29 5A 82 CF 13
0180 | BC F5 FB 0B A5 29 91 EC 5C 25 18 8A B7 83 CB CE
0190 | D3 57 3B AB B2 55 E8 27 41 EA F4 94 16 09 AE FF
01A0 | 96 0A 4F 2B 41 F9 2E 78 59 51 41 EB C7 36 77 E0
01B0 | 91 04 B8 69 0D 3E 3C 30 FC A7 8B B0 F9 7B 43 36
01C0 | E9 25 BC B0 C8 5A 80 54 58 EE 7B 8D AD 75 99 38
01D0 | 8C 33 83 94 FB 31 7C 0C 6B D5 EC 2C D5 64 17 7E
01E0 | C0 59 E9 70 5E FA F2 04 8E D0 B0 14 EA 89 C6 0E
01F0 | E4 8C C5 47 FE 51 CE 4D 0F 13 DE A2 AB EA 9F 24
0200 | 25 B3 FA 29 87 D9 60 ED EF 61 9B 67 92 1B 2E 92
0210 | 21 9C 81 F7 09 C2 92 44 14 93 22 57 D5 F3 EE B1
0220 | 2D 0A AF 2B 29 51 19 88 DA CC 96 67 92 D7 E2 6F
0230 | 04 EF 5F 78 CC 18 F8 A9 C6 20 66 8F D7 6A 66 8A
0240 | C6 E6 D4 34 74 BF B5 CF C9 27 C1 5B 5D 1F D5 31
0250 | F5 0B 7E DF FC D5 0F 6F 04 A0 88 45 66 CC 85 8D
0260 | 05 A2 B8 46 D6 9A 87 99 D3 60 22 11 2A CC CA 56
0270 | 7D 6B 5E FE 79 9A C9 3D E4 39 A7 D1 6C E6 1C 16
0280 | B0 2F 89 AD 9A CB D0 45 11 1B C5 F1

```

Payload (de)serialization:

```
server_DH_params_ok#00000000 nonce:int128 server_nonce:int128 encrypted_answer:string = Server_DH_Params;

```

|  Parameter |  Offset, Length in bytes |  Value |  Description |    
|  auth_key_id |  0, 8 |  `0000000000000000` |  0 since the message is in plain text |  
|  message_id |  8, 8 |  `01C863F46170466A` |  Message ID generated as specified here » (unixtime() << 32) + (N*4) |  
|  message_length |  16, 4 |  `78020000` (632 in decimal) |  Message body length |  
|  %(server_DH_params_ok) |  20, 4 |  `5c07e8d0` |  server_DH_params_ok constructor number from TL schema |  
|  nonce |  24, 16 |  `51A1143FC7A3666BE4BE54D6890A02DC` |  Value generated by client in Step 1 |  
|  server_nonce |  40, 16 |  `63248F6748214EAB8A2F4CC876E11974` |  Value received from server in Step 2 |  
|  encrypted_answer |  56, 596 |  `FE500200C334D313064174F443CE90E1` `3C835FAEA6AE9677089A0781CC8C17AD` `C8FF5B5072934C1DFB1F2B9222197DE8` `06186E6612E0CFA2593809B4B91B49F0` `06FFBBD9EAAADE1EEDCA046F500A77BB` `538E3C2F02A4A6814DF0BC77993E493B` `7F2C98344F674455A90A541070740F4B` `811FFF4B80B161737E0E867FF20D03BE` `6B52BA66F7319D03B621732E1C880202` `EAF61DF31DE831E7AC97B0FFDBFFFFA7` `019D399553F37B645913238443F4C560` `A59A5BA6AA6BFAEB159FD2291FCDA49A` `23E8009196B8062DD424F45D3B43538C` `68B2C070A845C260052DD3C266659FA6` `C0C6A8FF36FBFF8DAB36E06BEB5E18AF` `E38027FDA45E65884A503402840E21C1` `869101F4C613E9EDA61C2EB0AA987046` `F8069C2C002EE48A95844DD62E0E4B61` `2257391B014D3B043D7C193F936352F9` `D799CC4017CA544896BB09B3B5B8B70C` `2C5E48295A82CF13BCF5FB0BA52991EC` `5C25188AB783CBCED3573BABB255E827` `41EAF4941609AEFF960A4F2B41F92E78` `595141EBC73677E09104B8690D3E3C30` `FCA78BB0F97B4336E925BCB0C85A8054` `58EE7B8DAD7599388C338394FB317C0C` `6BD5EC2CD564177EC059E9705EFAF204` `8ED0B014EA89C60EE48CC547FE51CE4D` `0F13DEA2ABEA9F2425B3FA2987D960ED` `EF619B67921B2E92219C81F709C29244` `14932257D5F3EEB12D0AAF2B29511988` `DACC966792D7E26F04EF5F78CC18F8A9` `C620668FD76A668AC6E6D43474BFB5CF` `C927C15B5D1FD531F50B7EDFFCD50F6F` `04A0884566CC858D05A2B846D69A8799` `D36022112ACCCA567D6B5EFE799AC93D` `E439A7D16CE61C16B02F89AD9ACBD045`
 `111BC5F1` |  See below |   

Decrypt `encrypted_answer` using the reverse of the process specified in step 6:

```
encrypted_answer = C334D313064174F443CE90E13C835FAEA6AE9677089A0781CC8C17ADC8FF5B5072934C1DFB1F2B9222197DE806186E6612E0CFA2593809B4B91B49F006FFBBD9EAAADE1EEDCA046F500A77BB538E3C2F02A4A6814DF0BC77993E493B7F2C98344F674455A90A541070740F4B811FFF4B80B161737E0E867FF20D03BE6B52BA66F7319D03B621732E1C880202EAF61DF31DE831E7AC97B0FFDBFFFFA7019D399553F37B645913238443F4C560A59A5BA6AA6BFAEB159FD2291FCDA49A23E8009196B8062DD424F45D3B43538C68B2C070A845C260052DD3C266659FA6C0C6A8FF36FBFF8DAB36E06BEB5E18AFE38027FDA45E65884A503402840E21C1869101F4C613E9EDA61C2EB0AA987046F8069C2C002EE48A95844DD62E0E4B612257391B014D3B043D7C193F936352F9D799CC4017CA544896BB09B3B5B8B70C2C5E48295A82CF13BCF5FB0BA52991EC5C25188AB783CBCED3573BABB255E82741EAF4941609AEFF960A4F2B41F92E78595141EBC73677E09104B8690D3E3C30FCA78BB0F97B4336E925BCB0C85A805458EE7B8DAD7599388C338394FB317C0C6BD5EC2CD564177EC059E9705EFAF2048ED0B014EA89C60EE48CC547FE51CE4D0F13DEA2ABEA9F2425B3FA2987D960EDEF619B67921B2E92219C81F709C2924414932257D5F3EEB12D0AAF2B29511988DACC966792D7E26F04EF5F78CC18F8A9C620668FD76A668AC6E6D43474BFB5CFC927C15B5D1FD531F50B7EDFFCD50F6F04A0884566CC858D05A2B846D69A8799D36022112ACCCA567D6B5EFE799AC93DE439A7D16CE61C16B02F89AD9ACBD045111BC5F1
tmp_aes_key = 16F548177058E8D39C41CBAD4D419446BEB12EB9B8F5AD28EA824B8015F17D81
tmp_aes_iv = C4D14166C1378E35C698460047DBB6075441BE9984611C28837357EBBF8CB5BD

```

Yielding:

```
answer_with_hash = 8BB20017894315B136AE5F4BAAD0F0BA20334342BA0D89B551A1143FC7A3666BE4BE54D6890A02DC63248F6748214EAB8A2F4CC876E1197403000000FE000100C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F642477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5BFE0001008539DB1E497692EE8BD112463F5F26699039792151BE8B575AA56D8914EDBAA242C2A8096FFAB06211B36291FC4994CB0FDFD37389DF8886F2C6B634C0D01B1C8EBD3E9BE1F49B4A8BD33C3952EF1CEC5E9425CD9C2136CA482A521F9ACC86BEA7D8E224F3D6D78A7F734961EED863EA52EC399C58AE94B733E4CB0AFC728926FB2F457D4AB89576D8067489E323DF8702DEC6EFA2EAF1D85548748D2DFA62925920563076F143D8AE852BCAE61553371BEDA580FEBD952AC7C7C1AFBB3F15934CE815716C6C362F9382BE91DC6F964E97C1A308D63FC1E4DFB2B8395A3E7B9A996C2DD3086488EB281301BEEC1ECEDD00296D76AC7EF7B786EA82F0FA7896DB6170466AA674223E982CE5E5
answer = BA0D89B551A1143FC7A3666BE4BE54D6890A02DC63248F6748214EAB8A2F4CC876E1197403000000FE000100C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F642477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5BFE0001008539DB1E497692EE8BD112463F5F26699039792151BE8B575AA56D8914EDBAA242C2A8096FFAB06211B36291FC4994CB0FDFD37389DF8886F2C6B634C0D01B1C8EBD3E9BE1F49B4A8BD33C3952EF1CEC5E9425CD9C2136CA482A521F9ACC86BEA7D8E224F3D6D78A7F734961EED863EA52EC399C58AE94B733E4CB0AFC728926FB2F457D4AB89576D8067489E323DF8702DEC6EFA2EAF1D85548748D2DFA62925920563076F143D8AE852BCAE61553371BEDA580FEBD952AC7C7C1AFBB3F15934CE815716C6C362F9382BE91DC6F964E97C1A308D63FC1E4DFB2B8395A3E7B9A996C2DD3086488EB281301BEEC1ECEDD00296D76AC7EF7B786EA82F0FA7896DB6170466AA674223E982CE5E5

```

Generated payload (excluding transport headers/trailers):

```
0000 | BA 0D 89 B5 51 A1 14 3F C7 A3 66 6B E4 BE 54 D6
0010 | 89 0A 02 DC 63 24 8F 67 48 21 4E AB 8A 2F 4C C8
0020 | 76 E1 19 74 03 00 00 00 FE 00 01 00 C7 1C AE B9
0030 | C6 B1 C9 04 8E 6C 52 2F 70 F1 3F 73 98 0D 40 23
0040 | 8E 3E 21 C1 49 34 D0 37 56 3D 93 0F 48 19 8A 0A
0050 | A7 C1 40 58 22 94 93 D2 25 30 F4 DB FA 33 6F 6E
0060 | 0A C9 25 13 95 43 AE D4 4C CE 7C 37 20 FD 51 F6
0070 | 94 58 70 5A C6 8C D4 FE 6B 6B 13 AB DC 97 46 51
0080 | 29 69 32 84 54 F1 8F AF 8C 59 5F 64 24 77 FE 96
0090 | BB 2A 94 1D 5B CD 1D 4A C8 CC 49 88 07 08 FA 9B
00A0 | 37 8E 3C 4F 3A 90 60 BE E6 7C F9 A4 A4 A6 95 81
00B0 | 10 51 90 7E 16 27 53 B5 6B 0F 6B 41 0D BA 74 D8
00C0 | A8 4B 2A 14 B3 14 4E 0E F1 28 47 54 FD 17 ED 95
00D0 | 0D 59 65 B4 B9 DD 46 58 2D B1 17 8D 16 9C 6B C4
00E0 | 65 B0 D6 FF 9C A3 92 8F EF 5B 9A E4 E4 18 FC 15
00F0 | E8 3E BE A0 F8 7F A9 FF 5E ED 70 05 0D ED 28 49
0100 | F4 7B F9 59 D9 56 85 0C E9 29 85 1F 0D 81 15 F6
0110 | 35 B1 05 EE 2E 4E 15 D0 4B 24 54 BF 6F 4F AD F0
0120 | 34 B1 04 03 11 9C D8 E3 B9 2F CC 5B FE 00 01 00
0130 | 85 39 DB 1E 49 76 92 EE 8B D1 12 46 3F 5F 26 69
0140 | 90 39 79 21 51 BE 8B 57 5A A5 6D 89 14 ED BA A2
0150 | 42 C2 A8 09 6F FA B0 62 11 B3 62 91 FC 49 94 CB
0160 | 0F DF D3 73 89 DF 88 86 F2 C6 B6 34 C0 D0 1B 1C
0170 | 8E BD 3E 9B E1 F4 9B 4A 8B D3 3C 39 52 EF 1C EC
0180 | 5E 94 25 CD 9C 21 36 CA 48 2A 52 1F 9A CC 86 BE
0190 | A7 D8 E2 24 F3 D6 D7 8A 7F 73 49 61 EE D8 63 EA
01A0 | 52 EC 39 9C 58 AE 94 B7 33 E4 CB 0A FC 72 89 26
01B0 | FB 2F 45 7D 4A B8 95 76 D8 06 74 89 E3 23 DF 87
01C0 | 02 DE C6 EF A2 EA F1 D8 55 48 74 8D 2D FA 62 92
01D0 | 59 20 56 30 76 F1 43 D8 AE 85 2B CA E6 15 53 37
01E0 | 1B ED A5 80 FE BD 95 2A C7 C7 C1 AF BB 3F 15 93
01F0 | 4C E8 15 71 6C 6C 36 2F 93 82 BE 91 DC 6F 96 4E
0200 | 97 C1 A3 08 D6 3F C1 E4 DF B2 B8 39 5A 3E 7B 9A
0210 | 99 6C 2D D3 08 64 88 EB 28 13 01 BE EC 1E CE DD
0220 | 00 29 6D 76 AC 7E F7 B7 86 EA 82 F0 FA 78 96 DB
0230 | 61 70 46 6A

```

Payload (de)serialization:

```
server_DH_inner_data#00000000 nonce:int128 server_nonce:int128 g:int dh_prime:string g_a:string server_time:int = Server_DH_inner_data;

```

|  Parameter |  Offset, Length in bytes |  Value |  Description |    
|  %(server_DH_inner_data) |  0, 4 |  `ba0d89b5` |  server_DH_inner_data constructor number from TL schema |  
|  nonce |  4, 16 |  `51A1143FC7A3666BE4BE54D6890A02DC` |  Value generated by client in Step 1 |  
|  server_nonce |  20, 16 |  `63248F6748214EAB8A2F4CC876E11974` |  Value received from server in Step 2 |  
|  g |  36, 4 |  `03000000` (3 in decimal) |  Value received from server in Step 2 |  
|  dh_prime |  40, 260 |  `FE000100C71CAEB9C6B1C9048E6C522F` `70F13F73980D40238E3E21C14934D037` `563D930F48198A0AA7C14058229493D2` `2530F4DBFA336F6E0AC925139543AED4` `4CCE7C3720FD51F69458705AC68CD4FE` `6B6B13ABDC9746512969328454F18FAF` `8C595F642477FE96BB2A941D5BCD1D4A` `C8CC49880708FA9B378E3C4F3A9060BE` `E67CF9A4A4A695811051907E162753B5` `6B0F6B410DBA74D8A84B2A14B3144E0E` `F1284754FD17ED950D5965B4B9DD4658` `2DB1178D169C6BC465B0D6FF9CA3928F` `EF5B9AE4E418FC15E83EBEA0F87FA9FF` `5EED70050DED2849F47BF959D956850C` `E929851F0D8115F635B105EE2E4E15D0` `4B2454BF6F4FADF034B10403119CD8E3`
 `B92FCC5B` |  2048-bit prime, in big-endian byte order, to be checked as specified in the auth key docs |  
|  g_a |  300, 260 |  `FE0001008539DB1E497692EE8BD11246` `3F5F26699039792151BE8B575AA56D89` `14EDBAA242C2A8096FFAB06211B36291` `FC4994CB0FDFD37389DF8886F2C6B634` `C0D01B1C8EBD3E9BE1F49B4A8BD33C39` `52EF1CEC5E9425CD9C2136CA482A521F` `9ACC86BEA7D8E224F3D6D78A7F734961` `EED863EA52EC399C58AE94B733E4CB0A` `FC728926FB2F457D4AB89576D8067489` `E323DF8702DEC6EFA2EAF1D85548748D` `2DFA62925920563076F143D8AE852BCA` `E61553371BEDA580FEBD952AC7C7C1AF` `BB3F15934CE815716C6C362F9382BE91` `DC6F964E97C1A308D63FC1E4DFB2B839` `5A3E7B9A996C2DD3086488EB281301BE` `EC1ECEDD00296D76AC7EF7B786EA82F0`
 `FA7896DB` |  `g_a` diffie-hellman parameter |  
|  server_time |  560, 4 |  `6170466A` (1783001185 in decimal) |  Server time |   

##### 7) Client computes random 2048-bit number b (using a sufficient amount of entropy) and sends the server a message

First, generate a secure random 2048-bit number b:

```
b = 96E8D3D298D05AA574B92495F566D0C71C2CA5E1A1FCB18CEFF2408CC57F9E5D5EBD18F3DAFB5FA3DA41F6A73ADB14CF36642882D403A39FD640B9A3B4DEAD433DB0FFA55262EBC89A44324E6F3BEDEA1EB9CA19E465E1135B73497B8567ED842DFCC8F02EB2A8E4C8F923826CDF98D717FBF6F6D55313779163D40E3B18289A7BBCD9CC2B2280B888DCC36117E342D352BE67944CC9C723D928339877E7CB47917A582AB8DAB59A9BFFBEC88A21ECCAF93BAEF9AFB4EE3FB69FFF55A1D7EFAE03328C585E39750506D7C795E5737AFC3FF6CA79C7C205269A8BCB3F03D74DF36CE727E8E3D52663F208AE31B786EC852F1BA4C36EFEE2F8528AD1945E2C7ECF

```

Then compute `g_b = pow(g, b) mod dh_prime`

```
g_b = 2EE7B6CC1343B2D39A1AAB034551C9912E5DEE8047C6C62FFBD42B5E1894CFCB79EFEF794135A9FAA3F32C88D5D6D19F75289A5362984AC02A53A4E49E78C07E78C35FF505BC707F7F64E9AAA4BFBD0DBB11E3CACE330048C629DB154463731A2833E11130328EDE8C1230B246D1D999A0336CAC5B32BE5780253DE10BAA6513A5A079F2B9D6A59DB7799E97915F556C89407617BE822C7F65532C8E37792442EDD83793940F5606BC1994B4964ED3458C9AD513977F217699D32368315C7BB07D99C9EE77DE069E62E4A4DFDB16F4F911AA1AEF7373A2F49185501BE684A777772BFC4BD99E38FA51014A3E059543BDCF213977FE913E8A3D881C2EB5523B04

```
  7.1) generation of encrypted_data  

Generated payload (excluding transport headers/trailers):

```
0000 | 54 B6 43 66 51 A1 14 3F C7 A3 66 6B E4 BE 54 D6
0010 | 89 0A 02 DC 63 24 8F 67 48 21 4E AB 8A 2F 4C C8
0020 | 76 E1 19 74 00 00 00 00 00 00 00 00 FE 00 01 00
0030 | 2E E7 B6 CC 13 43 B2 D3 9A 1A AB 03 45 51 C9 91
0040 | 2E 5D EE 80 47 C6 C6 2F FB D4 2B 5E 18 94 CF CB
0050 | 79 EF EF 79 41 35 A9 FA A3 F3 2C 88 D5 D6 D1 9F
0060 | 75 28 9A 53 62 98 4A C0 2A 53 A4 E4 9E 78 C0 7E
0070 | 78 C3 5F F5 05 BC 70 7F 7F 64 E9 AA A4 BF BD 0D
0080 | BB 11 E3 CA CE 33 00 48 C6 29 DB 15 44 63 73 1A
0090 | 28 33 E1 11 30 32 8E DE 8C 12 30 B2 46 D1 D9 99
00A0 | A0 33 6C AC 5B 32 BE 57 80 25 3D E1 0B AA 65 13
00B0 | A5 A0 79 F2 B9 D6 A5 9D B7 79 9E 97 91 5F 55 6C
00C0 | 89 40 76 17 BE 82 2C 7F 65 53 2C 8E 37 79 24 42
00D0 | ED D8 37 93 94 0F 56 06 BC 19 94 B4 96 4E D3 45
00E0 | 8C 9A D5 13 97 7F 21 76 99 D3 23 68 31 5C 7B B0
00F0 | 7D 99 C9 EE 77 DE 06 9E 62 E4 A4 DF DB 16 F4 F9
0100 | 11 AA 1A EF 73 73 A2 F4 91 85 50 1B E6 84 A7 77
0110 | 77 2B FC 4B D9 9E 38 FA 51 01 4A 3E 05 95 43 BD
0120 | CF 21 39 77 FE 91 3E 8A 3D 88 1C 2E B5 52 3B 04

```

Payload (de)serialization:

```
client_DH_inner_data#00000000 nonce:int128 server_nonce:int128 retry_id:long g_b:string = Client_DH_Inner_Data;

```

|  Parameter |  Offset, Length in bytes |  Value |  Description |    
|  %(client_DH_inner_data) |  0, 4 |  `54b64366` |  client_DH_inner_data constructor number from TL schema |  
|  nonce |  4, 16 |  `51A1143FC7A3666BE4BE54D6890A02DC` |  Value generated by client in Step 1 |  
|  server_nonce |  20, 16 |  `63248F6748214EAB8A2F4CC876E11974` |  Value received from server in Step 2 |  
|  g_b |  36, 260 |  `FE0001002EE7B6CC1343B2D39A1AAB03` `4551C9912E5DEE8047C6C62FFBD42B5E` `1894CFCB79EFEF794135A9FAA3F32C88` `D5D6D19F75289A5362984AC02A53A4E4` `9E78C07E78C35FF505BC707F7F64E9AA` `A4BFBD0DBB11E3CACE330048C629DB15` `4463731A2833E11130328EDE8C1230B2` `46D1D999A0336CAC5B32BE5780253DE1` `0BAA6513A5A079F2B9D6A59DB7799E97` `915F556C89407617BE822C7F65532C8E` `37792442EDD83793940F5606BC1994B4` `964ED3458C9AD513977F217699D32368` `315C7BB07D99C9EE77DE069E62E4A4DF` `DB16F4F911AA1AEF7373A2F49185501B` `E684A777772BFC4BD99E38FA51014A3E` `059543BDCF213977FE913E8A3D881C2E`
 `B5523B04` |  Single-byte prefix denoting length, a 256-byte (2048-bit) string, and zero bytes of padding |  
|  retry_id |  296, 8 |  `0000000000000000` |  Equal to zero at the time of the first attempt; otherwise, it is equal to `auth_key_aux_hash` from the previous failed attempt (see Item 7). |   

The serialization of Client_DH_Inner_Data produces a string data. This is used to generate encrypted_data as specified in step 6, using the following inputs:

```
data = 54B6436651A1143FC7A3666BE4BE54D6890A02DC63248F6748214EAB8A2F4CC876E119740000000000000000FE0001002EE7B6CC1343B2D39A1AAB034551C9912E5DEE8047C6C62FFBD42B5E1894CFCB79EFEF794135A9FAA3F32C88D5D6D19F75289A5362984AC02A53A4E49E78C07E78C35FF505BC707F7F64E9AAA4BFBD0DBB11E3CACE330048C629DB154463731A2833E11130328EDE8C1230B246D1D999A0336CAC5B32BE5780253DE10BAA6513A5A079F2B9D6A59DB7799E97915F556C89407617BE822C7F65532C8E37792442EDD83793940F5606BC1994B4964ED3458C9AD513977F217699D32368315C7BB07D99C9EE77DE069E62E4A4DFDB16F4F911AA1AEF7373A2F49185501BE684A777772BFC4BD99E38FA51014A3E059543BDCF213977FE913E8A3D881C2EB5523B04
padding = A813B31F76CD0D537283454A
tmp_aes_key = 16F548177058E8D39C41CBAD4D419446BEB12EB9B8F5AD28EA824B8015F17D81
tmp_aes_iv = C4D14166C1378E35C698460047DBB6075441BE9984611C28837357EBBF8CB5BD

```

Process:

```
data_with_hash := SHA1(data) + data + padding (0-15 random bytes such that total length is divisible by 16)
encrypted_data := AES256_ige_encrypt (data_with_hash, tmp_aes_key, tmp_aes_iv);

```

Output:

```
encrypted_data = 136CA7E1F58C243372404792D3519F815AA6EC5E0324B2B11D89197CE5FFCDC2E53C5444A399E9C2111C143D1DFDA34932FC5F290EF51E28BE6AD31F68FB6CE9A8273EAD64262D78A5E132E5789E2620CD9C6E4C0A259E8B154FB07BA4725E9F883D2FA8EC59CAA7F683586CC35C3231B2023675C2759CB4194F6BBBC46EA47827CF2B07242357B6FC300EF086AF41D98E06C4DE2FCC41CD9216AF01D30A0DBA421D928D1D7386ECA1D18CA6772466169173425C272A22D78D9E55BEA4DB25EB9BD32D31115563AE2BFCD0374CEAEF3E42661F9059228BFCA3DF79F2E77C4AA5CBCF03963783CE0D6257399F7A4DD644BF1E57F19A9DF46172ECED9610C4F6A5A57FA4D08173732B1BA95B992B8B633A474A9D8FD18BDC673077178C5C20506FD226399C1F87D022C5C395428D92B8E4E39218EA68D3D6E010BBFFE839F8D124C5C458BCDF8FE5F25190F97C0C46C206

```

The length of the final string is 336 bytes.
 7.2) set_client_DH_params query  

Sent payload (excluding transport headers/trailers):

```
0000 | 00 00 00 00 00 00 00 00 E0 73 0E 00 61 70 46 6A
0010 | 78 01 00 00 1F 5F 04 F5 51 A1 14 3F C7 A3 66 6B
0020 | E4 BE 54 D6 89 0A 02 DC 63 24 8F 67 48 21 4E AB
0030 | 8A 2F 4C C8 76 E1 19 74 FE 50 01 00 13 6C A7 E1
0040 | F5 8C 24 33 72 40 47 92 D3 51 9F 81 5A A6 EC 5E
0050 | 03 24 B2 B1 1D 89 19 7C E5 FF CD C2 E5 3C 54 44
0060 | A3 99 E9 C2 11 1C 14 3D 1D FD A3 49 32 FC 5F 29
0070 | 0E F5 1E 28 BE 6A D3 1F 68 FB 6C E9 A8 27 3E AD
0080 | 64 26 2D 78 A5 E1 32 E5 78 9E 26 20 CD 9C 6E 4C
0090 | 0A 25 9E 8B 15 4F B0 7B A4 72 5E 9F 88 3D 2F A8
00A0 | EC 59 CA A7 F6 83 58 6C C3 5C 32 31 B2 02 36 75
00B0 | C2 75 9C B4 19 4F 6B BB C4 6E A4 78 27 CF 2B 07
00C0 | 24 23 57 B6 FC 30 0E F0 86 AF 41 D9 8E 06 C4 DE
00D0 | 2F CC 41 CD 92 16 AF 01 D3 0A 0D BA 42 1D 92 8D
00E0 | 1D 73 86 EC A1 D1 8C A6 77 24 66 16 91 73 42 5C
00F0 | 27 2A 22 D7 8D 9E 55 BE A4 DB 25 EB 9B D3 2D 31
0100 | 11 55 63 AE 2B FC D0 37 4C EA EF 3E 42 66 1F 90
0110 | 59 22 8B FC A3 DF 79 F2 E7 7C 4A A5 CB CF 03 96
0120 | 37 83 CE 0D 62 57 39 9F 7A 4D D6 44 BF 1E 57 F1
0130 | 9A 9D F4 61 72 EC ED 96 10 C4 F6 A5 A5 7F A4 D0
0140 | 81 73 73 2B 1B A9 5B 99 2B 8B 63 3A 47 4A 9D 8F
0150 | D1 8B DC 67 30 77 17 8C 5C 20 50 6F D2 26 39 9C
0160 | 1F 87 D0 22 C5 C3 95 42 8D 92 B8 E4 E3 92 18 EA
0170 | 68 D3 D6 E0 10 BB FF E8 39 F8 D1 24 C5 C4 58 BC
0180 | DF 8F E5 F2 51 90 F9 7C 0C 46 C2 06

```

Payload (de)serialization:

```
set_client_DH_params#00000000 nonce:int128 server_nonce:int128 encrypted_data:string = Set_client_DH_params_answer;

```

|  Parameter |  Offset, Length in bytes |  Value |  Description |    
|  auth_key_id |  0, 8 |  `0000000000000000` |  0 since the message is in plain text |  
|  message_id |  8, 8 |  `E0730E006170466A` |  Message ID generated as specified here » (unixtime() << 32) + (N*4) |  
|  message_length |  16, 4 |  `78010000` (376 in decimal) |  Message body length |  
|  %(set_client_DH_params) |  20, 4 |  `1f5f04f5` |  set_client_DH_params constructor number from TL schema |  
|  nonce |  24, 16 |  `51A1143FC7A3666BE4BE54D6890A02DC` |  Value generated by client in Step 1 |  
|  server_nonce |  40, 16 |  `63248F6748214EAB8A2F4CC876E11974` |  Value received from server in Step 2 |  
|  encrypted_data |  56, 340 |  `FE500100136CA7E1F58C243372404792` `D3519F815AA6EC5E0324B2B11D89197C` `E5FFCDC2E53C5444A399E9C2111C143D` `1DFDA34932FC5F290EF51E28BE6AD31F` `68FB6CE9A8273EAD64262D78A5E132E5` `789E2620CD9C6E4C0A259E8B154FB07B` `A4725E9F883D2FA8EC59CAA7F683586C` `C35C3231B2023675C2759CB4194F6BBB` `C46EA47827CF2B07242357B6FC300EF0` `86AF41D98E06C4DE2FCC41CD9216AF01` `D30A0DBA421D928D1D7386ECA1D18CA6` `772466169173425C272A22D78D9E55BE` `A4DB25EB9BD32D31115563AE2BFCD037` `4CEAEF3E42661F9059228BFCA3DF79F2` `E77C4AA5CBCF03963783CE0D6257399F` `7A4DD644BF1E57F19A9DF46172ECED96` `10C4F6A5A57FA4D08173732B1BA95B99` `2B8B633A474A9D8FD18BDC673077178C` `5C20506FD226399C1F87D022C5C39542` `8D92B8E4E39218EA68D3D6E010BBFFE8` `39F8D124C5C458BCDF8FE5F25190F97C`
 `0C46C206` |  Encrypted client_DH_inner_data generated previously, serialized as a TL byte string |   

##### 8) Auth key generation

The client computes the auth_key using formula `g_a^b mod dh_prime`:

```
auth_key = 8E1081A1B5CA1B399A9A9D7E08BB9A9182AB634F8C03F2A49F944E2F944A9C71EDBA61A32A70D3DADEB33752AE515B16B2D8E75039C40EBE18136775C3727372A8DF486606D671FD63842DF0A44ACC31E68B7B1EC6A731A1DC5C748F0CB46AC00FDE363F0520B51D9B59EAE519EA511A8E8591FC7010DF0B07CDBAB04013DD85172CB54555DC5C982EA0A5DCF4411E798D338B823161FD8C93100B7A426186B4C16F9113521081C8D2075872F4A0CF238034843DC01F2C26828721A2E2FFD93A9B0142B8DF6355C43D9AEF5B448F1CC0D84E0E72A7FF494D4CC3B1650050DDEC5DC321ADA68E420F45098280CEAB58A1CBFAA60FFF3218E56B4741143AC5A6F0

```

##### 9) Final server reply

The server verifies and confirms that auth_key_hash is unique: since it's unique, it replies with the following:

Received payload (excluding transport headers/trailers):

```
0000 | 00 00 00 00 00 00 00 00 01 A4 4A EF 62 70 46 6A
0010 | 34 00 00 00 34 F7 CB 3B 51 A1 14 3F C7 A3 66 6B
0020 | E4 BE 54 D6 89 0A 02 DC 63 24 8F 67 48 21 4E AB
0030 | 8A 2F 4C C8 76 E1 19 74 AA 40 4B 58 DF 40 4D 8F
0040 | 36 37 72 B1 4C E5 A5 6F

```

Payload (de)serialization:

```
dh_gen_ok#00000004 nonce:int128 server_nonce:int128 new_nonce_hash1:int128 = Set_client_DH_params_answer;

```

|  Parameter |  Offset, Length in bytes |  Value |  Description |    
|  auth_key_id |  0, 8 |  `0000000000000000` |  0 since the message is in plain text |  
|  message_id |  8, 8 |  `01A44AEF6270466A` |  Message ID generated as specified here » (unixtime() << 32) + (N*4) |  
|  message_length |  16, 4 |  `34000000` (52 in decimal) |  Message body length |  
|  %(dh_gen_ok) |  20, 4 |  `34f7cb3b` |  dh_gen_ok constructor number from TL schema |  
|  nonce |  24, 16 |  `51A1143FC7A3666BE4BE54D6890A02DC` |  Value generated by client in Step 1 |  
|  server_nonce |  40, 16 |  `63248F6748214EAB8A2F4CC876E11974` |  Value received from server in Step 2 |  
|  new_nonce_hash1 |  56, 16 |  `AA404B58DF404D8F363772B14CE5A56F` |  The 128 lower-order bits of SHA1 of the byte string derived from the `new_nonce` string by adding a single byte with the value of 1, 2, or 3, and followed by another 8 bytes with `auth_key_aux_hash`. Different values are required to prevent an intruder from changing server response dh_gen_ok into dh_gen_retry. |   

 

 
~~~~

### B3.2 Independent verification of the sample, plus derived values

These were computed by `verify_authkey.py` (Python stdlib + pure-Python AES verified against FIPS-197 C.3). Every line marked `ok` is an assertion that passed against the documented value. The `DERIVED` lines are values the page does not print but that follow deterministically from its data. Use them as extra assertions.

```text
pq factorization ok
tmp_aes_key/iv ok
encrypted_answer IGE decrypt ok; SHA1(answer[:564]) ok; NOTE doc answer includes 8 pad bytes: A674223E982CE5E5
g 3 server_time 1783001185 answer len 564
dh_prime == documented built-in prime
p mod 3 = 2 (g=3 requires 2); p mod 8 = 3 ; p mod 24 = 11 ; p mod 5 = 3 ; p mod 7 = 6
g_b ok
client_DH_inner_data encryption ok, len 336
auth_key ok
new_nonce_hash1 ok
DERIVED auth_key SHA1          = 0314F29BC8B246FC73EB6AA01107FDAD56DF3016
DERIVED auth_key_id (bytes, as on wire) = 1107FDAD56DF3016  as LE int64 = 0x1630df56adfd0711
DERIVED auth_key_aux_hash (bytes) = 0314F29BC8B246FC
DERIVED new_nonce_hash1 = AA404B58DF404D8F363772B14CE5A56F
DERIVED new_nonce_hash2 = 3D22465ABBB1E7D4108388FC9422029C
DERIVED new_nonce_hash3 = DBC41564D2177F5A2F4DA44914CC2793
DERIVED server_salt (bytes) = DCA83ADAD47A014C  as LE int64 = 0x4c017ad4da3aa8dc
DERIVED time: server_time 1783001185
msg_id 78F404006170466A -> 0x6a4670610004f478 unixtime 1783001185 mod4 0
msg_id 01F4CCC26170466A -> 0x6a467061c2ccf401 unixtime 1783001185 mod4 1
msg_id F4DD0B006170466A -> 0x6a467061000bddf4 unixtime 1783001185 mod4 0
msg_id 01C863F46170466A -> 0x6a467061f463c801 unixtime 1783001185 mod4 1
msg_id E0730E006170466A -> 0x6a467061000e73e0 unixtime 1783001185 mod4 0
msg_id 01A44AEF6270466A -> 0x6a467062ef4aa401 unixtime 1783001186 mod4 1
p_q_inner_data_dc len 100 + padding 92 = 192
fingerprint as LE int64 = 0xd09d1d85de64fd85
```

How to read this:

- The 6 message ids decode to unixtime 1783001185/1783001186 (2026-07-02 UTC). Client ids are ≡ 0 mod 4 and server ids ≡ 1 mod 4 (all server messages here are responses).
- `auth_key_id` on the wire is the byte string `1107FDAD56DF3016` (the last 8 bytes of SHA1). As a `long`, it is `0x1630df56adfd0711`.
- `server_salt` on the wire is `DCA83ADAD47A014C`.
- Test plan for the engine: feed the sample's received payloads (steps 2, 6 and 9) into the handshake state machine, with `nonce`, `new_nonce` and `b` injected and the RSA step stubbed (or `temp_key` injected and the encrypted bytes compared only by length). Assert `auth_key`, `auth_key_id`, `server_salt` and the time offset `1783001185 - local_time`.
- Negative tests to derive from the sample:
  - flip one byte of `encrypted_answer`: SHA1 check fails;
  - change `nonce` in the step 6 response: rejected;
  - change `new_nonce_hash1`: rejected;
  - swap in the `dh_gen_retry` constructor (`b9 1f dc 46`) with `new_nonce_hash2 = 3D22465ABBB1E7D4108388FC9422029C`: retry path taken with `retry_id = 0314F29BC8B246FC` (bytes; LE long `0xfc46b2c89bf21403`);
  - `g_a = 1`, `g_a = dh_prime-1`, or `g_a < 2^1984`: rejected;
  - `g = 2` with this prime (p mod 8 = 3 ≠ 7): rejected;
  - `g = 5` (p mod 5 = 3): rejected;
  - `g = 7` (p mod 7 = 6): **accepted**;
  - `g = 4`: accepted.

### B3.3 Built-in DH prime (from /mtproto/auth_key and /mtproto/security_guidelines, identical on both pages)

`g = 3` in the sample, and `dh_prime mod 3 = 2`, `mod 8 = 3`, `mod 24 = 11`, `mod 5 = 3`, `mod 7 = 6`.

```text
C7 1C AE B9 C6 B1 C9 04 8E 6C 52 2F 70 F1 3F 73 98 0D 40 23 8E 3E 21 C1 49 34 D0 37 56 3D 93 0F 48 19 8A 0A A7 C1 40 58 22 94 93 D2 25 30 F4 DB FA 33 6F 6E 0A C9 25 13 95 43 AE D4 4C CE 7C 37 20 FD 51 F6 94 58 70 5A C6 8C D4 FE 6B 6B 13 AB DC 97 46 51 29 69 32 84 54 F1 8F AF 8C 59 5F 64 24 77 FE 96 BB 2A 94 1D 5B CD 1D 4A C8 CC 49 88 07 08 FA 9B 37 8E 3C 4F 3A 90 60 BE E6 7C F9 A4 A4 A6 95 81 10 51 90 7E 16 27 53 B5 6B 0F 6B 41 0D BA 74 D8 A8 4B 2A 14 B3 14 4E 0E F1 28 47 54 FD 17 ED 95 0D 59 65 B4 B9 DD 46 58 2D B1 17 8D 16 9C 6B C4 65 B0 D6 FF 9C A3 92 8F EF 5B 9A E4 E4 18 FC 15 E8 3E BE A0 F8 7F A9 FF 5E ED 70 05 0D ED 28 49 F4 7B F9 59 D9 56 85 0C E9 29 85 1F 0D 81 15 F6 35 B1 05 EE 2E 4E 15 D0 4B 24 54 BF 6F 4F AD F0 34 B1 04 03 11 9C D8 E3 B9 2F CC 5B
```

### B3.4 RSA server key

The docs do not print a PEM (D10). The sample uses fingerprint bytes `85FD64DE851D9DD0` (`long` 0xd09d1d85de64fd85); `resPQ` also advertises `A5B7F709355FC30B` and `216BE86C022BB4C3`. Test: compute `SHA1(serialize_bare(rsa_public_key n:bytes e:bytes))[12:20]` for each built-in key taken from tdesktop or tdlib, and assert that one of them is `85FD64DE851D9DD0`. **Confirmed:** tdesktop's single production key (A-E5.1) gives `SHA1 = 0e654fa95e8a12079ada852085fd64de851d9dd0`, i.e. exactly these bytes (A-E5.3).

### B3.5 TL serialization examples (from /mtproto/TL), verbatim

```text
// schema used by the example
user#d23c81a3 id:int first_name:string last_name:string = User;
no_user#c67599d1 id:int = User;
getUsers#2d84d5f5 (Vector int) = Vector User;

// getUsers([2,3,4]) as 32-bit words
0x2d84d5f5 0x1cb5c415 0x3 0x2 0x3 0x4

// as a byte stream
F5 D5 84 2D 15 C4 B5 1C 03 00 00 00 02 00 00 00 03 00 00 00 04 00 00 00

// a possible response (words)
0x1cb5c415 0x3 0xd23c81a3 0x2 0x74655005 0x00007265 0x72615006 0x72656b 0xc67599d1 0x3 0xd23c81a3 0x4 0x686f4a04 0x6e 0x656f4403

// meaning
[{"id":2,"first_name":"Peter", "last_name":"Parker"},{},{"id":4,"first_name":"John","last_name":"Doe"}]
```

Notes for test authors:

- In the response, the string "Peter" is `05 'P' 'e' 't' 'e' 'r' 00 00`, i.e. the words `0x74655005 0x00007265`.
- "Parker" (6 bytes) is `06 'P' 'a' 'r' 'k' 'e' 'r' 00`, i.e. `0x72615006 0x0072656b`.
- "John" is `04 'J' 'o' 'h' 'n' 00 00 00`, i.e. `0x686f4a04 0x0000006e`.
- "Doe" is `03 'D' 'o' 'e'`, i.e. `0x656f4403`.
- The docs write `0x72656b` and `0x6e` without leading zeros.

Further string-encoding vectors from the sample:

- `pq` (8 bytes): `08 2E9CDB98C80CDA4B 000000`.
- `p` (4 bytes): `04 6A794259 000000`.
- The 256-byte strings `dh_prime`, `g_a` and `g_b` each take `FE 00 01 00` + 256 bytes, with 0 padding.
- The 596-byte `encrypted_answer` field is `FE 50 02 00` (len 0x250 = 592) + 592 bytes, with 0 padding.
- The 260-byte `encrypted_data` field (step 5) is `FE 00 01 00` + 256 bytes.
- The 340-byte field (step 7.2) is `FE 50 01 00` + 336 bytes.

### B3.6 CRC32 constructor-id vectors (all verified with zlib.crc32)

```text
crc32('user id:int first_name:string last_name:string = User') = 0xd23c81a3 OK
crc32('vector t:Type # [ t ] = Vector t') = 0x1cb5c415 OK
crc32('msgs_ack msg_ids:Vector long = MsgsAck') = 0x62d6b459 OK
crc32('req_pq_multi nonce:int128 = ResPQ') = 0xbe7e8ef1 OK
crc32('ping ping_id:long = Pong') = 0x7abe77ec OK
crc32('rpc_result req_msg_id:long result:Object = RpcResult') = 0xf35c6d01 OK
crc32('int ? = Int') = 0xa8509bda OK
crc32('getUsers Vector int = Vector User') = 0x2d84d5f5 OK
crc32('bind_auth_key_inner nonce:long temp_auth_key_id:long perm_auth_key_id:long temp_session_id:long expires_at:int = BindAuthKeyInner') = 0x75a3f765 OK
```

### B3.7 Obfuscation: the docs' pseudocode, verbatim

```text
protocol := 0xdddddddd
dc := 0xfcff

while True:
    init := (56 random bytes) + protocol + dc + (2 random bytes)

    if init[0] == 0xef:
      continue

	first_int := substr(init, 0, 4)
	if first_int == 0x44414548 || first_int == 0x54534f50 || first_int == 0x20544547 || first_int == 0x4954504f || first_int == 0x02010316 || first_int == 0xdddddddd || first_int == 0xeeeeeeee:
      continue

	second_int := substr(init, 4, 4)
    if second_int == 0x00000000:
      continue

	break

initRev := strrev(init)

encryptKey := substr(init, 8, 32)
encryptIV := substr(init, 40, 16)

decryptKey := substr(initRev, 8, 32)
decryptIV := substr(initRev, 40, 16)

secret := substr(0xdd99999999999999999999999999999999, 1, 16)

encryptKey = SHA256(encryptKey + secret)
decryptKey = SHA256(decryptKey + secret)

encryptedInit := CTR(encryptKey, encryptIV, init)

finalInit := substr(init, 0, 56) + substr(encryptedInit, 56, 8)

write(finalInit)
```

### B3.8 Self-computed vectors, NOT in the docs (labelled DERIVED)

These were produced by `derived.py`, using the pure-Python AES above (AES-256 checked against FIPS-197 C.3 and the AES-256-CTR NIST SP800-38A F.5.5 block 1) together with the formulas in P-046, P-064..P-068, P-120..P-122, P-234/P-238 and P-311. The `auth_key` is the one from the sample. Treat these as **regression** vectors. **Cross-check done (2026-10-01):** every value below (MTProto 2.0 msg_key/aes_key/aes_iv/ciphertext in both directions, the quick-ack token, the v1 bind `encrypted_message`, the obfuscation send/receive keys and both `finalInit` values) was recomputed by an independent script that uses macOS CommonCrypto AES (not the pure-Python AES) and follows tdesktop's formulas (`mtproto_auth_key.cpp:43-105`, `dc_key_binder.cpp:23-73`, `connection_tcp.cpp:448-494`; reversal of `init[8..56]` rather than of the whole buffer). All values matched byte for byte.

The fixed inputs:

- MTProto 2.0 ping: `session_id = 0123456789ABCDEF` (bytes), `msg_id = 0x6a46706200000004`, `seqno = 1`, body `ping#7abe77ec ping_id=0x1122334455667788`, padding `A0 A1 … B3` (20 bytes).
- Bind: `nonce = 0x0102030405060708`, `temp_auth_key_id` bytes `AABBCCDDEEFF0011`, `temp_session_id` bytes `1122334455667788`, `expires_at = 1783087585`, `random:int128 = 00..0F`, `msg_id = 0x6a46706200000008`, padding `B0..B7`.
- Obfuscation: `init[0:56]` = bytes `(0x10 + 3*i) & 0xff`, tag `dddddddd`, dc = `-4`, then `5A5A`. The secret is `dd` + 16 × `0x99` (the docs' sample secret).
- CDN IV: `encryption_iv = 00112233445566778899AABBCCDDEEFF`, `offset = 1048576`.

```text
AES-256-CTR NIST KAT ok
== MTProto2 client->server (x=0) ping vector
auth_key_id = 1107FDAD56DF3016
server_salt = DCA83ADAD47A014C
session_id = 0123456789ABCDEF
msg_id = 040000006270466A
seqno = 01000000
body = EC77BE7A8877665544332211
padding(20) = A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3
plaintext(64) = DCA83ADAD47A014C0123456789ABCDEF040000006270466A010000000C000000EC77BE7A8877665544332211A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3
msg_key_large = AD0F5FC2AF733D5133FB3D6B33BB37A7656E16DD77404BCF0FC6AA24065E4C5B
msg_key = 33FB3D6B33BB37A7656E16DD77404BCF
aes_key = 29A05995CC6B70F0F7A467E049598D0C64FC61CCEB1886F1F9D5CFDEF829FA87
aes_iv = D43C8C00E125ED8B2C263F53A36C2B6585A6E2C272592858D0F47510AD49DCC6
encrypted_data = 5740649F0ABF0D95AA63D15A29EF4E99B13E2D3484DC586776E16CBC2FD9F2379CEFA6881D7A161F33327DC301F97AAA39D8F7527E28CD89A1EF09F0E8B6FD82
full_packet(88) = 1107FDAD56DF301633FB3D6B33BB37A7656E16DD77404BCF5740649F0ABF0D95AA63D15A29EF4E99B13E2D3484DC586776E16CBC2FD9F2379CEFA6881D7A161F33327DC301F97AAA39D8F7527E28CD89A1EF09F0E8B6FD82
quick_ack_token (LE uint32) = 0xc25f0fad ; intermediate wire bytes = AD0F5FC2 ; abridged wire bytes (bswapped) = C25F0FAD
== MTProto2 server->client (x=8) same body, msg_id=0x6a46706200000401
plaintext = DCA83ADAD47A014C0123456789ABCDEF010400006270466A010000000C000000EC77BE7A8877665544332211A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3
msg_key = 422C07960DBA37681F9AEED07AF7F0F9
aes_key = 0BDA88EA346D40731A55B131DABD4FCF716F0B63014AA70393C524786CC1E34A
aes_iv = 6EEB1D6DA5DB1B1471414C2D1CEC58504AFA7081D1777F0564911D63FAD2D26B
encrypted_data = 1B45EE845D45A7DC9BF9172B43F82FC6A9273E281326D756863ABD9921B3A61A5392B3DE8CB3C71D618BF0235235585712ED61C61B7836D78E487C93C61E7BF8
== auth.bindTempAuthKey encrypted_message (MTProto v1 under perm key)
bind_auth_key_inner = 65F7A3750807060504030201AABBCCDDEEFF00111107FDAD56DF30161122334455667788E1C1476A
random:int128 = 000102030405060708090A0B0C0D0E0F
msg_id = 080000006270466A
v1 plaintext (72) = 000102030405060708090A0B0C0D0E0F080000006270466A000000002800000065F7A3750807060504030201AABBCCDDEEFF00111107FDAD56DF30161122334455667788E1C1476A
padding (8) = B0B1B2B3B4B5B6B7
msg_key=SHA1(plaintext)[4:20] = 5021465D86626CB290FCFC633C976682
aes_key_v1 = D90E6E8C9D45FCBE4F61C66895E7730645F44523F916D82A5240AE0708501FA6
aes_iv_v1 = ED35CFEFB58BB2FB93E01F4C38C3830B9570EC61E5FE19720C4EC536AF49EAD4
encrypted_message (104) = 1107FDAD56DF30165021465D86626CB290FCFC633C9766820B4E36CDF8683511AF48C52400E965AC601EDBBFE0B597F6AA6F976A595DC50EAF24B53FB9634F40619584B592D25C469BA6E0E14CFE5BD1EA1A412CBF9C17D56166766F34C6F7A96E3A980F71B42103
== Obfuscated2 init (MTProxy secret dd99.., padded intermediate, media DC 4 -> dc=-4)
init = 101316191C1F2225282B2E3134373A3D404346494C4F5255585B5E6164676A6D707376797C7F8285888B8E9194979A9DA0A3A6A9ACAFB2B5DDDDDDDDFCFF5A5A
encryptKey(raw) = 282B2E3134373A3D404346494C4F5255585B5E6164676A6D707376797C7F8285
encryptIV = 888B8E9194979A9DA0A3A6A9ACAFB2B5
decryptKey(raw) = B5B2AFACA9A6A3A09D9A9794918E8B8885827F7C797673706D6A6764615E5B58
decryptIV = 55524F4C494643403D3A3734312E2B28
secret(16) = 99999999999999999999999999999999
encryptKey=SHA256(k+secret) = 6D395698F7E4AC0F1BDFA0C6852B793033B71572E051CB683035B9E5C8CD4EB7
decryptKey=SHA256(k+secret) = 2B4524109B862F64F7BCB7152C974E2018DFB2FE574358D40978CF13068120A6
encryptedInit = 23BF7C761825E05F7A2305AC1E0A40ACC30A5236E8A9E08F4DFEBDC310DCCB77E4286A9443E869A3D0FF4BAF469879CF78645D9140BA47FDBC13505B6388CAC0
finalInit (sent) = 101316191C1F2225282B2E3134373A3D404346494C4F5255585B5E6164676A6D707376797C7F8285888B8E9194979A9DA0A3A6A9ACAFB2B5BC13505B6388CAC0
no-secret abridged dc2 finalInit = 101316191C1F2225282B2E3134373A3D404346494C4F5255585B5E6164676A6D707376797C7F8285888B8E9194979A9DA0A3A6A9ACAFB2B589866B1CCB3584BA
== CDN iv for offset 1048576 = 00112233445566778899AABB00010000
```

### B3.9 MTProto service TL schema, verbatim from /schema/mtproto

```text
int ? = Int;
long ? = Long;
double ? = Double;
string ? = String;
vector {t:Type} # [ t ] = Vector t;
int128 4*[ int ] = Int128;
int256 8*[ int ] = Int256;
resPQ#05162463 nonce:int128 server_nonce:int128 pq:bytes server_public_key_fingerprints:Vector<long> = ResPQ;
p_q_inner_data_dc#a9f55f95 pq:bytes p:bytes q:bytes nonce:int128 server_nonce:int128 new_nonce:int256 dc:int = P_Q_inner_data;
p_q_inner_data_temp_dc#56fddf88 pq:bytes p:bytes q:bytes nonce:int128 server_nonce:int128 new_nonce:int256 dc:int expires_in:int = P_Q_inner_data;
server_DH_params_ok#d0e8075c nonce:int128 server_nonce:int128 encrypted_answer:bytes = Server_DH_Params;
server_DH_inner_data#b5890dba nonce:int128 server_nonce:int128 g:int dh_prime:bytes g_a:bytes server_time:int = Server_DH_inner_data;
client_DH_inner_data#6643b654 nonce:int128 server_nonce:int128 retry_id:long g_b:bytes = Client_DH_Inner_Data;
dh_gen_ok#3bcbf734 nonce:int128 server_nonce:int128 new_nonce_hash1:int128 = Set_client_DH_params_answer;
dh_gen_retry#46dc1fb9 nonce:int128 server_nonce:int128 new_nonce_hash2:int128 = Set_client_DH_params_answer;
dh_gen_fail#a69dae02 nonce:int128 server_nonce:int128 new_nonce_hash3:int128 = Set_client_DH_params_answer;
bind_auth_key_inner#75a3f765 nonce:long temp_auth_key_id:long perm_auth_key_id:long temp_session_id:long expires_at:int = BindAuthKeyInner;
rpc_result#f35c6d01 req_msg_id:long result:Object = RpcResult;
rpc_error#2144ca19 error_code:int error_message:string = RpcError;
rpc_answer_unknown#5e2ad36e = RpcDropAnswer;
rpc_answer_dropped_running#cd78e586 = RpcDropAnswer;
rpc_answer_dropped#a43ad8b7 msg_id:long seq_no:int bytes:int = RpcDropAnswer;
future_salt#0949d9dc valid_since:int valid_until:int salt:long = FutureSalt;
future_salts#ae500895 req_msg_id:long now:int salts:vector<future_salt> = FutureSalts;
pong#347773c5 msg_id:long ping_id:long = Pong;
destroy_session_ok#e22045fc session_id:long = DestroySessionRes;
destroy_session_none#62d350c9 session_id:long = DestroySessionRes;
new_session_created#9ec20908 first_msg_id:long unique_id:long server_salt:long = NewSession;
msg_container#73f1f8dc messages:vector<%Message> = MessageContainer;
message msg_id:long seqno:int bytes:int body:Object = Message;
msg_copy#e06046b2 orig_message:Message = MessageCopy;
gzip_packed#3072cfa1 packed_data:bytes = Object;
msgs_ack#62d6b459 msg_ids:Vector<long> = MsgsAck;
bad_msg_notification#a7eff811 bad_msg_id:long bad_msg_seqno:int error_code:int = BadMsgNotification;
bad_server_salt#edab447b bad_msg_id:long bad_msg_seqno:int error_code:int new_server_salt:long = BadMsgNotification;
msg_resend_req#7d861a08 msg_ids:Vector<long> = MsgResendReq;
msgs_state_req#da69fb52 msg_ids:Vector<long> = MsgsStateReq;
msgs_state_info#04deb57d req_msg_id:long info:bytes = MsgsStateInfo;
msgs_all_info#8cc0d131 msg_ids:Vector<long> info:bytes = MsgsAllInfo;
msg_detailed_info#276d3ec6 msg_id:long answer_msg_id:long bytes:int status:int = MsgDetailedInfo;
msg_new_detailed_info#809db6df answer_msg_id:long bytes:int status:int = MsgDetailedInfo;
destroy_auth_key_ok#f660e1d4 = DestroyAuthKeyRes;
destroy_auth_key_none#0a9f2259 = DestroyAuthKeyRes;
destroy_auth_key_fail#ea109b13 = DestroyAuthKeyRes;
http_wait#9299359f max_delay:int wait_after:int max_wait:int = HttpWait;
---functions---
req_pq_multi#be7e8ef1 nonce:int128 = ResPQ;
req_DH_params#d712e4be nonce:int128 server_nonce:int128 p:bytes q:bytes public_key_fingerprint:long encrypted_data:bytes = Server_DH_Params;
set_client_DH_params#f5045f1f nonce:int128 server_nonce:int128 encrypted_data:bytes = Set_client_DH_params_answer;
rpc_drop_answer#58e4a740 req_msg_id:long = RpcDropAnswer;
get_future_salts#b921bd04 num:int = FutureSalts;
ping#7abe77ec ping_id:long = Pong;
ping_delay_disconnect#f3427b8c ping_id:long disconnect_delay:int = Pong;
destroy_session#e7512126 session_id:long = DestroySessionRes;
destroy_auth_key#d1435160 = DestroyAuthKeyRes;
```

Related API-level constructors that the engine has to know (verbatim from their method pages):

```text
boolFalse#bc799737 = Bool;
boolTrue#997275b5 = Bool;
invokeAfterMsg#cb9f372d {X:Type} msg_id:long query:!X = X;
invokeAfterMsgs#3dc4b4f0 {X:Type} msg_ids:Vector<long> query:!X = X;
initConnection#c1cd5ea9 {X:Type} flags:# api_id:int device_model:string system_version:string app_version:string system_lang_code:string lang_pack:string lang_code:string proxy:flags.0?InputClientProxy params:flags.1?JSONValue query:!X = X;
invokeWithLayer#da9b0d0d {X:Type} layer:int query:!X = X;
invokeWithoutUpdates#bf9459b7 {X:Type} query:!X = X;
auth.bindTempAuthKey#cdd42a05 perm_auth_key_id:long nonce:long expires_at:int encrypted_message:bytes = Bool;
auth.dropTempAuthKeys#8e48a188 except_auth_keys:Vector<long> = Bool;
auth.exportedAuthorization#b434e2b8 id:long bytes:bytes = auth.ExportedAuthorization;
auth.exportAuthorization#e5bfffcd dc_id:int = auth.ExportedAuthorization;
auth.importAuthorization#a57a7dad id:long bytes:bytes = auth.Authorization;
auth.authorization#2ea2c0d4 flags:# setup_password_required:flags.1?true otherwise_relogin_days:flags.1?int tmp_sessions:flags.0?int future_auth_token:flags.2?bytes user:User = auth.Authorization;
auth.loggedOut#c3a2835f flags:# future_auth_token:flags.0?bytes = auth.LoggedOut;
auth.logOut#3e72ba19 = auth.LoggedOut;
dcOption#18b7a10d flags:# ipv6:flags.0?true media_only:flags.1?true tcpo_only:flags.2?true cdn:flags.3?true static:flags.4?true this_port_only:flags.5?true id:int ip_address:string port:int secret:flags.10?bytes = DcOption;
nearestDc#8e1a1775 country:string this_dc:int nearest_dc:int = NearestDc;
help.getConfig#c4f9186b = Config;
help.getNearestDc#1fb33026 = NearestDc;
updateConfig#a229dd06 = Update;
upload.file#096a18d5 type:storage.FileType mtime:int bytes:bytes = upload.File;
upload.fileCdnRedirect#f18cda44 dc_id:int file_token:bytes encryption_key:bytes encryption_iv:bytes file_hashes:Vector<FileHash> = upload.File;
upload.getFile#be5335be flags:# precise:flags.0?true cdn_supported:flags.1?true location:InputFileLocation offset:long limit:int = upload.File;
upload.saveFilePart#b304a621 file_id:long file_part:int bytes:bytes = Bool;
upload.saveBigFilePart#de7b673d file_id:long file_part:int file_total_parts:int bytes:bytes = Bool;
fileHash#f39b035c offset:long limit:int hash:bytes = FileHash;
upload.getFileHashes#9156982a location:InputFileLocation offset:long = Vector<FileHash>;
upload.cdnFileReuploadNeeded#eea8e46e request_token:bytes = upload.CdnFile;
upload.cdnFile#a99fca4f bytes:bytes = upload.CdnFile;
cdnPublicKey#c982eaba dc_id:int public_key:string = CdnPublicKey;
cdnConfig#5725e40a public_keys:Vector<CdnPublicKey> = CdnConfig;
upload.getCdnFile#395f69da file_token:bytes offset:long limit:int = upload.CdnFile;
upload.reuploadCdnFile#9b2754a8 file_token:bytes request_token:bytes = Vector<FileHash>;
upload.getCdnFileHashes#91dc3f31 file_token:bytes offset:long = Vector<FileHash>;
help.getCdnConfig#52029342 = CdnConfig;
updatesTooLong#e317af7e = Updates;
```

The `config#cc1a241e` line (very long) is in /api/datacenter. The network-relevant fields are listed in P-267, and `tmp_sessions` is flags.0, `force_try_ipv6` flags.14.

---

## B4. ERROR TABLE (/api/errors + /api/errors.json, layer 227)

General rules from the page:

> There will be errors when working with the API, and they must be correctly handled on the client.

- An error has a numeric **code** ("similar to HTTP status", required) and a **type** (a string literal `/[A-Z_0-9]+/`, optional).
- The engine MUST dispatch on the **type string** (and its prefix/suffix pattern, with `%d` placeholders for numbers), because the code alone is ambiguous (D2).
- errors.json maps `code → {type → [methods]}` and `descriptions[type]`, and carries `user_only`, `bot_only`, `business_supported`, `unauthed_allowed` and `layer`. `%d` in a type maps to the number in the actual error string.
- "Clients should always provide localized versions of errors returned by the server … to inform the user as to why an attempted operation has failed." This is UI-level; the engine only has to pass the type through untouched.
- "If a server returns an error with a code other than the ones listed above, it may be considered the same as a 500 error."

### B4.1 Error classes

| Code | Name | Docs meaning (quoted or close paraphrase) | Required client action (docs) | Engine policy `[derived]` |
|---|---|---|---|---|
| 303 | SEE_OTHER | "The request must be repeated, but directed to a different data center." | Resend to DC X (X is parsed from the type). | Parse `_MIGRATE_(\d+)$`. PHONE/NETWORK/USER: switch the home DC (create a key there, export/import authorization if already logged in) and replay. STATS: reroute that request only. Cap redirect loops (e.g. 5). |
| 400 | BAD_REQUEST | "The query contains errors… the user should be notified that the data must be corrected before the query is repeated." | Do not retry blindly. Surface to the caller. | Never auto-retry, except for the specific strings in B4.2 (FILE_MIGRATE_X, MSG_WAIT_FAILED, CONNECTION_NOT_INITED, FILE_PART_X_MISSING, FILE_REFERENCE_*, …). |
| 401 | UNAUTHORIZED | "An unauthorized attempt to use functionality available only to authorized users." | See B4.2. Not every 401 means a logout (`SESSION_PASSWORD_NEEDED` is a 401). | Map by type: logout-class vs PFS-class vs 2FA. |
| 403 | FORBIDDEN | "Privacy violation." | Surface to the caller. | No retry. |
| 404 | NOT_FOUND | "An attempt to invoke a non-existent object, such as a method." (errors.json: `METHOD_INVALID`, `PEER_ID_INVALID`) | Surface. | No retry. Not to be confused with transport `-404`. |
| 406 | NOT_ACCEPTABLE | "Similar to 400 BAD_REQUEST, but the app must display the error to the user a bit differently. **Do not display any visible error to the user when receiving the rpc_error constructor: instead, wait for an updateServiceNotification update**", which is emitted independently (as a normal update, not inside rpc_result) right after the 406 and carries the localized popup text. | Do not show the rpc_error. Show the `updateServiceNotification` popup. **Exception: `AUTH_KEY_DUPLICATED`.** | The engine flags 406 as "silent" for the UI layer. AUTH_KEY_DUPLICATED is fatal for the key (B4.2). |
| 420 | FLOOD | "The maximum allowed number of attempts to invoke the given method with the given input parameters has been exceeded." | Wait X seconds (FLOOD_WAIT_X, FLOOD_PREMIUM_WAIT_X, SLOWMODE_WAIT_X, …). | Per-method/per-DC backoff timers. Auto-retry is allowed for file transfer `FLOOD_PREMIUM_WAIT_X` ("must be automatically repeated by the client after X seconds"). For user actions, surface X to the caller. |
| 500 | INTERNAL | "An internal server error occurred… If a client receives a 500 error… collect as much information as possible… and send it to the developers." | Report. Retry is allowed for specific types (AUTH_KEY_UNSYNCHRONIZED: "please repeat the method call"). | Bounded retry with backoff for idempotent requests. Log it. |
| -503 | (timeout) | Present only in errors.json: `Timeout` ("Timeout while fetching data.") and `MSG_WAIT_TIMEOUT`. | MSG_WAIT_TIMEOUT: resend with the same invokeAfterMsg wrapper (P-258). | Treat `-503 Timeout` as transient: retry with backoff (the request may or may not have run, so dedupe through random_id). |
| other | — | "may be considered the same as a 500 error" | as 500 | as 500 |
| transport -404/-429/-444/-403 | (not rpc_error) | See B2.5. | -404: new key or restart handshake. -429: back off. -444: wrong DC id. | — |

### B4.2 Special error strings and the required handling

| Type | Code | errors.json description | Required action (docs) and engine note |
|---|---|---|---|
| `AUTH_KEY_UNREGISTERED` | 401 | "The specified authorization key is not registered in the system (for example, a PFS temporary key has expired)." | If this is a temp key: regenerate it and rebind (P-241). If the perm key on the home DC: the user is logged out. On a non-home DC: re-import authorization (export/import). |
| `AUTH_KEY_INVALID` | 401 | "The specified auth key is invalid." | Drop the key, create a new one, and treat the account as logged out on that DC. |
| `AUTH_KEY_PERM_EMPTY` | 401 | "The method is unavailable for temporary authorization keys, not bound to a permanent authorization key." | Bind the temp key first (P-232), then resend. |
| `USER_DEACTIVATED` | 401 | "The current account was deleted by the user." | Logout. |
| `USER_DEACTIVATED_BAN` | 401 | "…deleted and banned by Telegram's antispam system." | Logout. |
| `SESSION_REVOKED` | 401 | "The session was revoked by the user." (the authorization was invalidated by terminating all sessions) | Logout. Drop the key (destroy_auth_key is optional). |
| `SESSION_EXPIRED` | 401 | "The session has expired." | Logout. |
| `SESSION_PASSWORD_NEEDED` | 401 | "2FA is enabled, use a password to login." | **Not a logout**: continue the auth flow with `account.getPassword`/`auth.checkPassword`. |
| `AUTH_KEY_DUPLICATED` | 406 | "Concurrent usage of the current session from multiple connections was detected, the current session was invalidated by the server for security reasons!" | "The session was already invalidated by the server and the user must generate a new auth key and login again." Root cause: more parallel main sessions/connections than `tmp_sessions` (P-283). |
| `FLOOD_WAIT_X` | 420 | "Please wait %d seconds before repeating the action." | Wait X s. MAY also break `invokeAfterMsg` chains (it triggers MSG_WAIT_FAILED on dependants). |
| `FLOOD_PREMIUM_WAIT_X` | 420 | "Please wait %d seconds…, or purchase a Telegram Premium subscription to remove this rate limit." | For uploads/downloads: **automatically repeat after X s**. Optionally show the Premium modal (rate-limited by `upload_premium_speedup_notify_period`, and only when the file is visible). |
| `SLOWMODE_WAIT_X` | 420 | "Slowmode is enabled in this chat: wait %d seconds…" | Surface X. Do not auto-retry. |
| `TAKEOUT_INIT_DELAY_X`, `2FA_CONFIRM_WAIT_X`, `PREMIUM_SUB_ACTIVE_UNTIL_X`, `FROZEN_METHOD_INVALID` | 420 | (see errors.json) | Surface. Not network-level. |
| `PHONE_MIGRATE_X` | 303 | "Your phone number is associated to DC %d, please re-send the query to that DC." | Switch the home DC to X and resend (usually auth.sendCode). |
| `NETWORK_MIGRATE_X` | 303 | "Your IP address is associated to DC %d…" | Switch the home DC to X and resend. |
| `USER_MIGRATE_X` | 303 | "Your account is associated to DC %d…" | Switch the home DC to X and resend. If already logged in, export/import the authorization first. |
| `STATS_MIGRATE_X` | 303 | "Channel statistics for the specified channel are stored on DC %d…" | Resend this request on DC X (with imported auth). |
| `FILE_MIGRATE_X` | 303 (page) / 400 (json) | "The file currently being accessed is stored in DC %d, please re-send the query to that DC." | Resend the file request to DC X (media session, imported auth). |
| `MSG_WAIT_FAILED` | 400, 500 | "A waiting call returned an error." | P-259. |
| `MSG_WAIT_TIMEOUT` | -503 | "Spent too much time waiting for a previous query in the invokeAfterMsg request queue, aborting!" | Resend with the same wrapper and the same dependency ids (P-258). |
| `Timeout` | -503 | "Timeout while fetching data." | Transient. Retry with backoff. |
| `CONNECTION_NOT_INITED` | 400 | "Please initialize the connection using initConnection before making queries." | Wrap the next call in `invokeWithLayer(initConnection(…))` and resend. |
| `CONNECTION_LAYER_INVALID` | 400 | "Layer invalid." | Engine bug or layer too new or too old. Fatal for the request. |
| `CONNECTION_API_ID_INVALID`, `API_ID_INVALID` | 400 | "The provided API id is invalid." / "API ID invalid." | Fatal configuration error. |
| `API_ID_PUBLISHED_FLOOD` | 400 | "This API id was published somewhere, you can't use it now." | Fatal configuration error. |
| `CONNECTION_DEVICE_MODEL_EMPTY`, `CONNECTION_SYSTEM_EMPTY`, `CONNECTION_APP_VERSION_EMPTY`, `CONNECTION_SYSTEM_LANG_CODE_EMPTY`, `CONNECTION_LANG_PACK_INVALID`, `CONNECTION_ID_INVALID` | 400 | (empty/invalid initConnection fields) | Fix the initConnection parameters. |
| `INPUT_METHOD_INVALID`, `INPUT_CONSTRUCTOR_INVALID`, `INPUT_FETCH_ERROR`, `INPUT_FETCH_FAIL`, `INPUT_LAYER_INVALID`, `INPUT_REQUEST_TOO_LONG` | 400 | "The specified method is invalid." / "…TL constructor is invalid." / "An error occurred while parsing the provided TL constructor." / "The specified layer is invalid." / "The request payload is too long." | Serializer or schema bug (or a request that is too big). Do not retry. Log the request. |
| `ENCRYPTED_MESSAGE_INVALID` | 400 | "Encrypted message invalid." | bindTempAuthKey only: P-239 (the 60-second rule). |
| `TEMP_AUTH_KEY_EMPTY`, `TEMP_AUTH_KEY_ALREADY_BOUND`, `EXPIRES_AT_INVALID` | 400 | — | Regenerate the temp key and rebind. ALREADY_BOUND: the temp key belongs to another perm key, so create a fresh temp key. |
| `AUTH_BYTES_INVALID`, `USER_ID_INVALID`, `DC_ID_INVALID` | 400 | — | Export/import failed: re-export from the home DC and retry once. |
| `AUTH_KEY_UNSYNCHRONIZED` | 500 | "Internal error, please repeat the method call." | Retry. |
| `AUTH_RESTART`, `AUTH_RESTART_%d` | 500 | "Restart the authorization process." / "Internal error (debug info %d), please repeat the method call." | Restart the login flow, or retry. |
| `PERSISTENT_TIMESTAMP_OUTDATED` | 500 | "Channel internal replication issues, try again later (treat this like an RPC_CALL_FAIL)." | Retry later. |
| `RANDOM_ID_DUPLICATE` | 500 | "You provided a random ID that was already used." | The previous identical call is still in flight. Wait for updates or getDifference. |
| `CDN_UPLOAD_TIMEOUT` | 500 | "A server-side timeout occurred while reuploading the file to the CDN DC." | Retry `reuploadCdnFile`, or fall back to the master DC. |
| `FILE_TOKEN_INVALID`, `REQUEST_TOKEN_INVALID` | 400 | "…Continue downloading the file from the master DC using upload.getFile." | Fall back to `upload.getFile` on the master DC (P-313). |
| `CDN_METHOD_INVALID` | 400 | "You can't call this method in a CDN DC." | Routing bug. |
| `FILE_REFERENCE_EXPIRED`, `FILE_REFERENCE_INVALID`, `FILE_REFERENCE_EMPTY`, `FILE_REFERENCE_%d_*` | 400 | "File reference expired, it must be refetched…" | Refetch the reference from its source object, then retry (an upper-layer callback). |
| `FILE_PART_%d_MISSING` | 400 | "Part %d of the file is missing from storage. Try repeating the method call to resave the part." | Re-upload part X, then repeat the final call. |
| `FILE_PART_*`, `FILE_PARTS_INVALID`, `LIMIT_INVALID`, `OFFSET_INVALID`, `MD5_CHECKSUM_INVALID` | 400 | (see P-294, P-298) | Engine bug in chunking. Do not retry. |
| `PEER_ID_INVALID`, `METHOD_INVALID` | 404 (also 400/406 for PEER_ID_INVALID) | — | Surface. |
| `UPDATE_APP_TO_LOGIN`, `SEND_CODE_UNAVAILABLE`, `PHONE_PASSWORD_FLOOD`, `FRESH_*`, … | 406 | (various) | 406 rule: no rpc_error UI. Wait for updateServiceNotification. |

### B4.3 Engine dispatch order `[derived]`

1. Transport-level 4-byte negative payloads (B2.5) are handled before decryption.
2. In `rpc_result.result`, unwrap `gzip_packed`, then check for `rpc_error`.
3. For `rpc_error`, match the type in this order: `*_MIGRATE_X` (any code), `FLOOD_WAIT_X`/`FLOOD_PREMIUM_WAIT_X`/`SLOWMODE_WAIT_X` (parse X), `MSG_WAIT_*`, the 401 family, `AUTH_KEY_DUPLICATED`, `CONNECTION_NOT_INITED`, the PFS family, then the generic code class.
4. A `-503` or `500` on a non-idempotent request without `random_id`: do not auto-retry blindly. Surface "unknown outcome" to the caller.


---

# Part C — Consolidated recommendations for the Rust engine

This part merges the docs' MUST rules (Part B) with what proved robust in tdesktop and tdlib (Part A). It is a
requirements list for design review, not engine code. Each item cites its evidence.

## C1. Crypto and framing
1. MTProto 2.0 for all traffic. Keep the MTProto 1.0 KDF only for the `bind_auth_key_inner` payload
   (P-025, P-234, P-238; A2.3, A11).
2. Decrypt in this order: size bounds → auth_key_id → AES-IGE → constant-time msg_key check → length/padding
   (12..1024) → session_id → msg_id parity. Any failure drops the connection (P-130..P-139; A3;
   `tdlib:Transport.cpp:240-300`). Validation must have no oracle: every failure gets the same reaction (P-132).
3. Outgoing padding: 12..1024 random bytes with size bucketing (tdlib uses 64/128/…/1280, then multiples of 448),
   instead of tdesktop's 12..264 (P-124; A12).
4. Always obfuscate. Use padded intermediate (`0xDDDDDDDD`) when a secret is present; otherwise intermediate or
   abridged. Implement quick-ack parsing even if we never request it, so a stray ack token cannot desync framing
   (P-030..P-041, P-060..P-068; A9).
5. Use the docs' full forbidden-prefix list for the obfuscation nonce, which includes "OPTI"; tdesktop's list
   lacks it (P-061; A9).
6. Fake TLS: port tdesktop's hello template as data, with the RNG and clock injected. Compare HMACs in constant
   time. Reject domains over 236 bytes when parsing the secret (A-E1, A-E15.1).

## C2. Session state machine
7. msg_id: use the tdlib algorithm (server-time based, strictly monotonic, `% 4 == 0`, non-zero low 32 bits).
   A container's msg_id must be greater than every inner msg_id (P-140, P-141, P-144, P-161; A2.5, A2.7).
8. Inbound: keep a sorted window of at least 400 msg_ids. Re-ack duplicates but do not reprocess them. Ignore ids
   older than the window (tdlib) instead of resetting the session (tdesktop) (P-136; A3).
9. Time: copy tdesktop's "badTime" recovery. While the clock looks wrong, trust only messages that reference our
   own msg_ids, and resync time from them. Once synced, enforce the (−300 s, +30 s) window (P-137, P-138; A3, A6).
10. An ack never completes an RPC; only `rpc_result` does (P-176; A4).
11. If an RPC is unanswered for 10 s, send `msgs_state_req`. If the state is `(s & 7) != 4`, resend inside a
    container with the original msg_id. Use a new msg_id only after a session change (P-180..P-182; A4).
12. bad_msg codes:
    - 16/17/64: resync time and resend.
    - 20: check with `msgs_state_req`, or resend with a new msg_id.
    - 32/33: new session, then resend.
    - 18/19/34/35: engine bug. Fail the request and log loudly.
    - 48: take the new salt and resend.
    (P-190..P-199, P-157; A5.)
13. Salts: use `get_future_salts` (tdlib). Still accept salts from `bad_server_salt`, from `new_session_created`,
    and from verified responses (P-200..P-204; A6).
14. On `new_session_created`:
    - take its salt;
    - resend everything unanswered with `msg_id < first_msg_id`;
    - raise an event so the update layer runs getDifference.
    (P-207, P-208, P-320; A3.1.)
15. gzip: cap the total unpacked size per packet (tdesktop: 32 MB) and the nesting depth. Gzip outgoing requests
    only when the result is smaller and the body is over 255 bytes (P-015, P-168; A3.1).
16. Make the invokeAfterMsg / initConnection wrapper order a single, tested decision point. The docs (P-257) and
    both reference clients disagree (D14; A2.8). Re-run initConnection after every new temp key (P-236, P-251).

## C3. Keys
17. PFS always on. The persistent key is used only for binding; a 24 h temp key carries traffic. Bind before any
    user RPC (P-231, P-232; A11).
18. Rotate temp keys before they expire (tdlib `refresh_margin`). Still handle `-404` and `AUTH_KEY_PERM_EMPTY`
    after the fact (P-240, P-241; A11).
19. `ENCRYPTED_MESSAGE_INVALID` on bind drops the persistent key only if that key is older than 60 s. tdesktop
    implements exactly this (P-239; A11).
20. Allow one key creation per (DC, slot) at a time, and notify the waiters (A1, A11).
21. Check g_a and g_b against the docs' exact bound 2^(2048−64), not tdesktop's bit-length approximation.
    Compute SHA1 over the TL-parsed `server_DH_inner_data` (P-099, P-104, D4; A10).
22. If `tmp_sessions > 1` is ever used, give each main session its own bound temp key. tdesktop shares one temp
    key per DC across all its sessions (P-243; A11).

## C4. Connectivity and bootstrap
23. Probe every endpoint in parallel with an unencrypted `req_pq` (random nonce). Rank by priority: IPv4 + TCP +
    secret first. Wait at most 2 s for a better candidate. Close the losers **before** sending any encrypted packet,
    because of AUTH_KEY_DUPLICATED (P-283, P-285; A8).
24. Connect timeout: 1 s, doubling up to 8 s. Reconnect backoff: 1 ms, 2 ms, 3 ms, 1 s, 2 s, … 64 s, reset after
    the first decrypted packet (A7).
25. Keepalive: RTT-adaptive `ping_delay_disconnect` (tdlib), plus a hard rule that a missing pong means reconnect
    (P-216; A7).
26. Transport errors: `-404` → drop the temp key, or restart the handshake. `-444` → reload DC config. `-429` →
    back off (P-048..P-051; A8).
27. After 8 s without a connection, refresh the config. Then fall back to simple config (DoH TXT and Firestore,
    with configurable sources). Honour `config.dc_txt_domain_name`, which tdlib does and tdesktop does not
    (A-E4, A-E10).
28. Fake TLS needs a correct clock. Add an HTTP `Date` time source (A-E1.9).

## C5. RPC error policy
29. Dispatch on the error *type string*, never on the numeric code alone (D2; B4).
30. Bound retries for 5xx and negative codes with a per-request budget. tdlib fails a query once its total wait
    passes 60 s; tdesktop retries forever (A-E8.8).
31. `FLOOD_WAIT_X` / `FLOOD_PREMIUM_WAIT_X`: auto-wait only up to the caller's deadline and expose longer waits.
    Retry file transfers automatically after `FLOOD_PREMIUM_WAIT_X` (B4.2; A-E8.3).
32. 401 on the home DC means logged out, with these exceptions:
    - `SESSION_PASSWORD_NEEDED`: continue the login flow.
    - `AUTH_KEY_PERM_EMPTY`: rebind the temp key.
    401 on another DC means export/import the authorization, one export per DC with a queue of waiters. Fail those
    waiters explicitly if the export fails; tdesktop leaves them hanging (A-E8.4).
33. `AUTH_KEY_DUPLICATED` (406) invalidates the key: drop it and require a new login. Never auto-retry it
    (P-283; B4.2).
34. Migrations: match `(FILE|PHONE|NETWORK|USER|STATS)_MIGRATE_X`. Switch the main DC atomically for
    PHONE/NETWORK/USER. Keep the download or upload index when a file request moves (P-270, P-271; A-E8.3).
