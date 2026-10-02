# tdlib MTProto + networking layer: implementation digest

Purpose: an implementation-grade description of how tdlib does MTProto, written so a Rust engine can port its
algorithms, constants and edge cases. Everything below was read from the tdlib sources, not from the public spec.
Where tdlib departs from the spec or does something unusual, the entry says so and is tagged **[quirk]**. Behaviour
the port should copy is tagged **[MUST]**.

Source revision: tdlib `1.8.49` (`CMakeLists.txt:3`), git `e894536b2f46caad93f997448d2daff9431b19dd` (2025-05-27),
API layer `MTPROTO_LAYER = 203` (`td/telegram/Version.h:13`). Checked out at
`submodules/telegram-ios/third-party/td/td/`. All `file:line` references are relative to that directory.

Conventions:
- All integers on the wire are little-endian unless the entry says "big-endian". `int128`/`int256` are raw byte
  strings (nonces).
- `LE32(x)` and `LE64(x)` mean "read 4 or 8 bytes as a little-endian integer".
- `now` is a monotonic clock (`Time::now()`). `server_time(now) = now + server_time_difference`.
- "msg_id time" means `msg_id / 2^32` as a double.

---

## 0. Architecture map (where things live)

| Layer | tdlib class | File | Role |
|---|---|---|---|
| Crypto primitives | `aes_ige_*`, `AesCtrState`, `sha*`, `pbkdf2_*`, `pq_factorize` | `tdutils/td/utils/crypto.cpp` | OpenSSL wrappers plus hand-written IGE and Pollard–Brent |
| Bignum | `BigNum` | `tdutils/td/utils/BigNum.cpp` | OpenSSL BN wrapper |
| Key exchange | `AuthKeyHandshake`, `DhHandshake`, `RSA`, `KDF` | `td/mtproto/Handshake.cpp`, `DhHandshake.cpp`, `RSA.cpp`, `KDF.cpp` | create auth keys |
| Handshake driving | `HandshakeActor`, `HandshakeConnection` | `td/mtproto/HandshakeActor.cpp`, `HandshakeConnection.h` | timeout, unencrypted framing |
| Packet crypto | `Transport` | `td/mtproto/Transport.cpp` | MTProto 1.0 and 2.0 encrypt/decrypt and checks |
| Stream transports | `tcp::ObfuscatedTransport`, `tcp::OldTransport`, `http::Transport` | `td/mtproto/TcpTransport.cpp`, `HttpTransport.cpp` | framing, obfuscation, fake-TLS records |
| Fake-TLS handshake | `TlsInit` | `td/mtproto/TlsInit.cpp` | ClientHello and ServerHello check |
| Socket + transport | `RawConnection` | `td/mtproto/RawConnection.cpp` | read/write loop, quick-ack map |
| MTProto session protocol | `SessionConnection` | `td/mtproto/SessionConnection.cpp` | containers, acks, pings, service messages |
| Per-session state | `AuthData` | `td/mtproto/AuthData.{h,cpp}` | keys, salts, msg_id, seq_no, time diff, duplicate filters |
| Query bookkeeping | `Session` | `td/telegram/net/Session.cpp` | sent queries, resend, PFS bind, key lifecycle |
| Session fan-out | `SessionProxy`, `SessionMultiProxy` | `td/telegram/net/SessionProxy.cpp`, `SessionMultiProxy.cpp` | N sessions per DC per purpose |
| Routing | `NetQueryDispatcher`, `NetQueryDelayer`, `SequenceDispatcher` | `td/telegram/net/NetQueryDispatcher.cpp`, `NetQueryDelayer.cpp`, `td/telegram/SequenceDispatcher.cpp` | DC routing, migrate, flood wait, invokeAfter chains |
| Cross-DC auth | `DcAuthManager` | `td/telegram/net/DcAuthManager.cpp` | export/import authorization |
| Shared per-DC data | `AuthDataShared` | `td/telegram/net/AuthDataShared.cpp` | persisted perm key, salts |
| Connections | `ConnectionCreator`, `DcOptionsSet` | `td/telegram/net/ConnectionCreator.cpp`, `DcOptionsSet.cpp` | address choice, proxies, flood control |

Thread model (for orientation only): every box is an actor. `SessionConnection` is a synchronous state machine
driven by `Session::loop()`. A Rust port can keep the same split: a pure, synchronous "session protocol" core and
an async driver around it.

---

## 1. Auth key handshake

### 1.1 Orchestration and timeouts

- `Session::auth_loop` (`Session.cpp:1486-1496`) starts a `GenAuthKeyActor` when the perm ("main") key is missing,
  or, with PFS, when the temp key is missing or will expire within the refresh margin. The margin is `2*60` s if
  the temp key is persisted (`persist_tmp_auth_key`), otherwise `60*60` s.
- `GenAuthKeyActor` (`Session.cpp:100-208`) takes a slot from a per-thread semaphore of capacity **50**
  (`Session.cpp:157`) before it asks `ConnectionCreator` for a fresh raw connection (`auth_data = nullptr`). It runs
  `HandshakeActor` with timeout **10 s** (`Session.cpp:205`). More than 100 live GenAuthKeyActors counts as "high
  load" (`MIN_HIGH_LOAD_ACTOR_COUNT = 100`, `Session.cpp:150`).
- If the network generation changes, the GenAuthKeyActor closes its HandshakeActor (`Session.cpp:131-135`).
- `HandshakeActor` (`HandshakeActor.cpp:34-61`) sets an actor timeout of `timeout` and calls
  `handshake.set_timeout_in(timeout)`. Inside the handshake:
  - resPQ must be processed before `start + 0.6*timeout` (6 s), else "Handshake ResPQ timeout expired"
    (`Handshake.cpp:87`);
  - server_DH_params before `start + 0.8*timeout` (8 s) (`Handshake.cpp:164`);
  - the dh_gen answer has no phase deadline; the actor timeout (10 s) covers it.
- On success the raw connection is **not** closed: it goes back to the Session as `cached_connection_` and is reused
  for the first encrypted connection if picked up within 10 s (`Session.cpp:1215-1219`, `1508-1510`,
  `1468-1476`).
- On any handshake error the state is cleared (`Handshake.cpp:340-343`) and the next attempt starts again from
  `req_pq_multi` with a new connection. **There is no in-place dh_gen_retry** (see 1.11).
- If the transport returns error `-404` during a handshake, `HandshakeConnection::flush` clears the handshake
  (`HandshakeConnection.h:50-57`).

### 1.2 Unencrypted message framing (as tdlib does it)

Writer (`NoCryptoStorer.h:17-40`, `Transport.cpp:330-341`, `HandshakeConnection.h:64-66`):

```
auth_key_id   : int64 = 0
msg_id        : int64 = 0            <-- [quirk] tdlib sends msg_id 0 for every handshake message
message_length: int32 = len(body) + len(pad)
body          : TL-serialized function (boxed)
pad           : random bytes, len = (-len(body) & 15) + 16 * (secure_rand % 16)   (0..255 bytes)
```

- **[quirk]** msg_id is literally `MessageId()` = 0 (`HandshakeConnection.h:65`). The ping helper uses msg_id 1
  (`PingConnection.cpp:51-52`). The server tolerates this. A spec-compliant engine should send a real msg_id
  (`time*2^32`, divisible by 4); both work.
- **[quirk]** the random padding after the TL object is counted in `message_length`. The server parses the TL object
  and ignores the trailing bytes. (The likely purpose is to hide the exact sizes of the handshake messages.)

Reader (`HandshakeConnection.h:68-82`):
- the packet must have `auth_key_id == 0` ("Expected not encrypted packet");
- must be at least 12 bytes after the auth_key_id; tdlib skips 12 bytes (`msg_id` + `length`) **without
  validating** them;
- truncates the rest to a multiple of 4 (removes transport padding);
- parses with `check_end = false` (`Handshake.cpp:32-46`, called with `false`), so trailing bytes are allowed. A TL
  parse error is reported as error code 500.

### 1.3 Step 1: req_pq_multi

`on_start` (`Handshake.cpp:315-325`): `nonce = 16 secure random bytes`, send
`req_pq_multi#be7e8ef1 nonce:int128`. State `ResPQ`.

### 1.4 resPQ handling and RSA key selection

`on_res_pq` (`Handshake.cpp:86-161`):
1. Parse `resPQ#05162463 nonce server_nonce pq:string server_public_key_fingerprints:Vector<long>`.
2. `nonce` must equal ours, else "Nonce mismatch".
3. Store `server_nonce`.
4. `public_rsa_key->get_rsa_key(fingerprints)`: iterate the **server's** list in order and return the first one we
   know (`PublicRsaKeySharedMain.cpp:54-63`). If none matches: call `drop_keys()` (no-op for main DCs, clears the
   CDN key set so the CDN config is fetched again), then fail.
5. Factorize `pq` (section 1.5). If that fails: "Failed to factorize".
6. `new_nonce = 32 secure random bytes`.

RSA fingerprint (`RSA.cpp:111-123`): `fingerprint = LE64(SHA1(TL(rsa_public_key n:string e:string))[12..20])`, where
`n` and `e` are big-endian minimal byte strings serialized as TL `string` (bytes). Example values are in
Appendix B. Keys must have `RSA_size == 256` (`RSA.cpp:70-76`). `RSA::encrypt` asserts that `n` has 2041..2048
bits (`RSA.cpp:134`).

### 1.5 pq factorization

Entry point `pq_factorize(Slice pq_str, ...)` (`crypto.cpp:231-255`):
- `pq_str` is big-endian. If it is longer than 8 bytes, or exactly 8 bytes with the top bit set (pq ≥ 2^63), use
  the BigNum path `pq_factorize_big`. Otherwise use the u64 path.
- Output: `p < q`, each as minimal big-endian bytes (`as_big_endian_string` strips leading zeros,
  `crypto.cpp:157-169`). Returns -1 when `p == 0` or `pq % p != 0`.

u64 path `pq_factorize(uint64 pq)` (`crypto.cpp:103-140`): Pollard's rho with Brent-style cycle detection (the saved
point `y` is refreshed at powers of two), modular multiplication by double-and-add so nothing overflows:

```
if pq <= 2 or pq > 2^63: return 1
if pq even: return 2
g = 0
i = 0; iter = 0
while i < 3 or iter < 1000:
    c = Random::fast(17, 32) % (pq - 1)            # additive constant
    x = Random::fast_uint64() % (pq - 1) + 1
    y = x
    lim = 1 << (min(5, i) + 18)                    # 2^18 .. 2^23
    for j in 1 .. lim-1:
        iter += 1
        x = (c + x*x) mod pq                       # pq_add_mul(c, x, x, pq)
        z = (x - y) mod pq (as x<y ? pq+x-y : x-y)
        g = binary_gcd(z, pq)                      # pq_gcd: Stein's algorithm, b must be odd
        if g != 1: break
        if j is a power of two (j & (j-1) == 0): y = x
    if 1 < g < pq: break
    i += 1
if g != 0: g = min(g, pq / g)
return g
```

`pq_add_mul(c, a, b, pq)` (`crypto.cpp:86-101`) computes `(c + a*b) % pq` by shift-and-add with conditional
subtraction. This is safe because pq < 2^63. `pq_gcd(a, b)` (`crypto.cpp:59-83`): returns `b` if `a == 0`, strips
factors of two from `a`, then subtractive binary gcd.

BigNum path `pq_factorize_big` (`crypto.cpp:171-229`): same structure with BigNum, `t = Random::fast(17, 32)`,
`a = Random::fast_uint32()`, `lim = 1 << (i + 23)`, `a = a*a mod pq; a += t; if a >= pq: a -= pq`,
`q = |a - b|`, `p = gcd(q, pq)`, stop when `p != 1`. Afterwards `q = pq / p`, swap so `p <= q`.

Rust port note: pq from Telegram is always below 2^63 in practice. A u128 multiply-mod is a simpler and faster
replacement for `pq_add_mul`. Keep the BigNum fallback (or a u128 rho) for robustness.

### 1.6 p_q_inner_data

`Handshake.cpp:114-125`:
- Perm key (`expires_in == 0`, Mode Main): `p_q_inner_data_dc#a9f55f95 pq p q nonce server_nonce new_nonce dc:int`.
- Temp key (Mode Temp): `p_q_inner_data_temp_dc#56fddf88 pq p q nonce server_nonce new_nonce dc:int expires_in:int`.
  `expires_at = now + expires_in` is recorded **at this point** (local monotonic time, `Handshake.cpp:121`).

`pq`, `p`, `q` are TL `string`s holding big-endian bytes (`pq` is echoed exactly as received).

`dc` value (`SessionProxy.cpp:231-238`): `raw_dc_id`, plus `10000` on the test servers, negated when the session is
media-only (`allow_media_only && !is_cdn`). CDN DCs use the positive raw id. The test/proxy check uses the raw
`dc_id` (`ConnectionCreator.cpp:465`).

Temp key lifetime: `expires_in = Random::fast(23*60*60, 24*60*60)` seconds, i.e. a uniform 82800..86400
(`Session.cpp:1443`). The same random lifetime is used for CDN "main" keys (CDN keys are always temp-style, see 5.11).

### 1.7 RSA_PAD (the new padding)

`Handshake.cpp:127-155`. Exact byte layout:

```
data            = TL(p_q_inner_data*)                       # must be <= 144 bytes, else "Too big data"
data_with_padding = data || random(192 - len(data))         # exactly 192 bytes
loop:
    temp_key        = random(32)                            # tdlib calls it aes_key
    data_with_hash  = REVERSE(data_with_padding) || SHA256(temp_key || data_with_padding)   # 192 + 32 = 224
    aes_encrypted   = AES256_IGE_ENCRYPT(key = temp_key, iv = 32 zero bytes, data_with_hash)  # 224 bytes
    temp_key_xor    = temp_key XOR SHA256(aes_encrypted)    # 32 bytes
    key_aes_encrypted = temp_key_xor || aes_encrypted       # 256 bytes
    x = big-endian integer(key_aes_encrypted)
    if x >= n: continue                                     # pick a new temp_key and retry
    encrypted_data = (x ^ e mod n) as 256 big-endian bytes (left zero-padded)
    break
```

Notes:
- The SHA256 input uses the **non-reversed** padded data. Only the first 192 bytes of `data_with_hash` are reversed
  (`std::reverse(begin, begin + 192)`).
- RSA is textbook (`BN_mod_exp`), with no PKCS#1 padding (`RSA.cpp:130-146`).
- Then `req_DH_params#d712e4be nonce server_nonce p q public_key_fingerprint:long encrypted_data:string` is sent. State
  `ServerDHParams`.

### 1.8 server_DH_params handling

`on_server_dh_params` (`Handshake.cpp:163-254`):
1. Deadline check (0.8 × timeout).
2. Parse `Server_DH_Params`. tdlib's schema only has `server_DH_params_ok#d0e8075c`. A `server_DH_params_fail` reply
   is an unknown constructor, so it fails as a parse error (code 500) and the handshake restarts.
3. `nonce`, then `server_nonce` must match. `encrypted_answer.size() % 16 == 0`, else "Bad padding for encrypted part".
4. `tmp_KDF(server_nonce, new_nonce)` (`KDF.cpp:52-72`):
   ```
   tmp_aes_key = SHA1(new_nonce || server_nonce) || SHA1(server_nonce || new_nonce)[0..12]          # 20 + 12
   tmp_aes_iv  = SHA1(server_nonce || new_nonce)[12..20] || SHA1(new_nonce || new_nonce) || new_nonce[0..4]   # 8 + 20 + 4
   ```
5. AES-IGE decrypt in place. `aes_ige_decrypt` writes the updated IV back into its argument, so tdlib saves the
   original IV and restores it afterwards (`Handshake.cpp:184-188`).
6. Layout `answer_with_hash = SHA1(answer)[20] || answer || pad(0..15)`. Parse: 20-byte hash, then the int32
   constructor must be `server_DH_inner_data#b5890dba`, then the body. `pad = remaining bytes` must be **< 16**
   ("Too much pad"). Recompute `SHA1(answer_with_hash[20 .. len - pad])` and compare.
7. Inner `nonce` and `server_nonce` must match.
8. `server_time_diff = server_time - now` (`Handshake.cpp:221`). This becomes the session's time difference, see 1.10.
9. DH: `set_config(g, dh_prime)` draws `b` and computes `g_b` immediately; `set_g_a(g_a)`; then
   `run_checks(false, dh_callback)` (section 1.9).

### 1.9 DH validation

`DhHandshake::check_config` (`DhHandshake.cpp:21-93`):
- `dh_prime` must have exactly **2048** bits ("p is not 2048-bit number").
- `g`-dependent quadratic-residue conditions, from the switch in the source:

| g | condition on p |
|---|---|
| 2 | `p mod 8 == 7` |
| 3 | `p mod 3 == 2` |
| 4 | none |
| 5 | `p mod 5 ∈ {1, 4}` |
| 6 | `p mod 24 ∈ {19, 23}` |
| 7 | `p mod 7 ∈ {3, 5, 6}` |
| other | reject ("Bad prime mod 4g") |

- Safe-prime check: first ask the cache `DhCallback::is_good_prime(prime_bytes)` (1 = good, 0 = bad, -1 = unknown).
  On a cache miss, require `is_prime(p)` and `is_prime((p-1)/2)` and record the result with
  `add_good_prime`/`add_bad_prime`. The production cache (`td/telegram/DhCache.cpp:23-53`) hard-codes the standard
  Telegram 2048-bit prime as good (hex in Appendix B.4) and persists other results in the key-value store under
  `"good_prime:" + prime_bytes`.
- `BigNum::is_prime` (`BigNum.cpp:150-158`): `BN_check_prime` on OpenSSL 3; on older OpenSSL `BN_is_prime_ex` with
  **64** Miller–Rabin rounds for ≤2048 bits, 128 above. A Rust port should use ≥64 MR rounds (plus trial division)
  and cache the verdict per prime.

`DhHandshake::dh_check` (`DhHandshake.cpp:95-126`):
```
left  = 2^(2048-64)
right = p - left
require left <= g_a <= right and left <= g_b <= right
```
(tdlib rejects `g_a < left` or `g_a > right`; equality is allowed.) The spec's `1 < g < p-1` check is implied by the
`g ∈ {2..7}` table.

`b` generation (`DhHandshake.cpp:136`): `BN_rand(b, 2048, top=-1, bottom=0)`, i.e. uniform in `[0, 2^2048)`. It is
not reduced mod p and only checked indirectly through the `g_b` range check (a bad `b` makes `g_b` fail, which fails
the handshake). `g_b = g^b mod p` (`DhHandshake.cpp:142`).

`g_a_hash`/`set_g_a_hash` exist for secret-chat and call DH and are unused by the auth-key handshake.

### 1.10 client_DH_params, auth key, salt, time

`Handshake.cpp:227-252`:
```
data  = TL(client_DH_inner_data#6643b654 nonce server_nonce retry_id:long = 0 g_b:string)   # retry_id is ALWAYS 0
plain = SHA1(data) || data || random pad up to a multiple of 16 (0..15 bytes)
encrypted_data = AES256_IGE_ENCRYPT(tmp_aes_key, tmp_aes_iv, plain)   # tmp_KDF recomputed with the same inputs
send set_client_DH_params#f5045f1f nonce server_nonce encrypted_data:string
auth_key      = (g_a ^ b mod p) as exactly 256 big-endian bytes (left zero-padded)   # gen_key, DhHandshake.cpp:219-223
auth_key_id   = LE64(SHA1(auth_key)[12..20])                                         # calc_key_id, DhHandshake.cpp:225-229
created_at    = server_time from server_DH_inner_data (seconds, stored as double)
expires_at    = (temp keys) local now_at_resPQ + expires_in
server_salt   = LE64(new_nonce[0..8]) XOR LE64(server_nonce[0..8])                  # Handshake.cpp:250
```
- `g_b` and `g` are serialized as minimal big-endian byte strings (`BigNum::to_binary()` with no size).
- The auth key is kept even though the server has not confirmed it yet. It is only exposed after `dh_gen_ok`.

### 1.11 dh_gen answer

`on_dh_gen_response` (`Handshake.cpp:256-285`):
- `dh_gen_ok#3bcbf734`: check `nonce`, `server_nonce`, and
  `new_nonce_hash1 == SHA1(new_nonce || 0x01 || SHA1(auth_key)[0..8])[4..20]`. On success, state `Finish`.
- `dh_gen_retry#46dc1fb9` → error "DhGenRetry"; `dh_gen_fail#a69dae02` → error "DhGenFail". In both cases the handshake
  is cleared and restarts from scratch. **[quirk]** tdlib never sends a non-zero `retry_id` and never checks
  `new_nonce_hash2`/`hash3`. A from-scratch restart is a valid simplification.

### 1.12 After the handshake (Session side)

`Session::on_handshake_ready` (`Session.cpp:1390-1432`):
- Main handshake: `set_main_auth_key`, then persist through `AuthDataShared::set_auth_key`.
- Temp handshake: `set_tmp_auth_key`; on the main DC also register the key with `TempAuthKeyWatchdog`; then
  persist (only if `persist_tmp_auth_key`).
- Close both connections (they used the old key).
- Salt: `if (use_pfs XOR is_main_handshake) set_server_salt(handshake.server_salt)`. So a temp-key handshake under
  PFS sets the salt, a main-key handshake without PFS sets the salt, and a main-key handshake under PFS does not
  overwrite the temp key's salt (salts are per auth key).
- `update_server_time_difference(handshake.server_time_diff)`; if it changed, propagate with `force = true`.

### 1.13 Where the RSA keys come from

- Main DCs: exactly **one** hard-coded production key and **one** test key (`PublicRsaKeySharedMain.cpp:14-52`),
  shared by all DCs. Fingerprints: production `0xd09d1d85de64fd85`, test `0xb25898df208d2603` (Appendix B).
- CDN DCs: `PublicRsaKeySharedCdn` per CDN dc_id, filled from `help.getCdnConfig#52029342`
  (`cdnConfig#5725e40a public_keys:Vector<cdnPublicKey#c982eaba dc_id:int public_key:string>`) by
  `PublicRsaKeyWatchdog` (`PublicRsaKeyWatchdog.cpp:60-137`). The config is cached in the key-value store keyed by
  layer (`"cdn_config" + layer`). On a fingerprint mismatch, `drop_keys()` clears the CDN keys and the watchdog
  re-requests the config (flood control: effectively at most 1 request/s; the limits at `:46-48` are
  `add_limit(1,1)`, `add_limit(2,60)`, `add_limit(3,120)` with `(duration_s, count)` semantics, so only the first
  one binds).

---

## 2. Message encryption (Transport.cpp, KDF.cpp, AuthKey.h, PacketInfo.h)

### 2.1 AuthKey object

`AuthKey.h:18-131`. Fields: `auth_key_id (u64)`, `auth_key (256 bytes)`, `auth_flag` (main key: "authorized",
temp key: "bound"), `have_header_` (default true), `header_expires_at_`, `expires_at` (local monotonic), and
`created_at` (server unix time).
- Persistence format (`store`/`parse`, `AuthKey.h:76-121`): `u64 id`, `i32 flags` (1 = AUTH_FLAG,
  4 = HAS_CREATED_AT, 8 = HAS_EXPIRES_AT), `string key`, `[double created_at]`,
  `[double time_left, double system_time_at_save]`. On load, the wall-clock time elapsed since the save is
  subtracted from `time_left` and `expires_at = now + time_left`. `have_header_` is reset to true on load.
- `break_key()` (`AuthKey.h:21-24`) is a debugging hook (increments the id and the first key byte).

### 2.2 Packet layout

```
CryptoHeader (packed, 4-byte alignment)        Transport.cpp:36-69
  +0   auth_key_id : u64
  +8   msg_key     : 16 bytes
  -- encrypted part starts here --
  +24  salt        : u64
  +32  session_id  : u64
CryptoPrefix                                   Transport.cpp:71-75
  +40  msg_id      : u64
  +48  seq_no      : u32
  +52  message_data_length : u32
  +56  message_data[message_data_length]
       padding (random)
```

`PacketInfo` (`PacketInfo.h:16-30`) carries `salt`, `session_id`, `message_id`, `seq_no`, `version` (1 or 2),
`no_crypto_flag`, `use_random_padding`, `check_mod4 = true` and `message_ack` (the quick-ack token, output).

### 2.3 MTProto 2.0 msg_key and AES key/iv

Direction parameter `X`: **client→server X = 0** (`write_crypto` passes 0, `Transport.cpp:385`), **server→client
X = 8** (`read_crypto` passes 8, `Transport.cpp:306`).

`calc_message_key2` (`Transport.cpp:148-164`):
```
msg_key_large = SHA256(auth_key[88+X .. 88+X+32] || plaintext_including_padding)
msg_key       = msg_key_large[8 .. 24]
quick_ack     = LE32(msg_key_large[0..4]) | 0x80000000
```
`plaintext_including_padding` is everything from `salt` to the end of the padding (the encrypted region).

`KDF2` (`KDF.cpp:74-104`):
```
sha256_a = SHA256(msg_key || auth_key[X .. X+36])
sha256_b = SHA256(auth_key[40+X .. 40+X+36] || msg_key)
aes_key  = sha256_a[0..8]  || sha256_b[8..24] || sha256_a[24..32]
aes_iv   = sha256_b[0..8]  || sha256_a[8..24] || sha256_b[24..32]
```
Encryption: `AES256_IGE(aes_key, aes_iv)` over the whole encrypted region.

### 2.4 Padding policy (client → server)

`calc_crypto_size2` (`Transport.cpp:166-197`), with `enc_size = 16` (salt + session_id) and
`data_size = 16 (prefix) + message_data_length`:

- **Basic (default)** (`do_calc_crypto_size2_basic`):
  ```
  encrypted_size = (16 + data_size + 12 + 15) & ~15          # at least 12 bytes of padding, 16-aligned
  pick the first bucket >= encrypted_size among {64,128,192,256,384,512,768,1024,1280}
  otherwise encrypted_size = ceil((encrypted_size - 1280) / 448) * 448 + 1280
  total = 24 + encrypted_size
  ```
  So the padding is 12..(12 + bucket gap + 15) bytes and message sizes are quantized, which hides the exact length.
  (The `std::array<size_t,10>` has a trailing implicit 0 entry that never matches.)
- **Random** (`do_calc_crypto_size2_rand`), used when the transport says `use_random_padding()`, i.e. when the
  MTProxy secret is ≥17 bytes (`dd…` or `ee…` secrets, `ProxySecret.h:44-46`):
  ```
  encrypted_size = (16 + data_size + (secure_u32 & 0xff) + 12 + 15) & ~15
  ```
- Padding bytes are `Random::secure_bytes` (`Transport.cpp:350-352`).

Both policies always stay inside the 12..1024 padding bound that receivers check: at most about 474 bytes in basic
mode (12 + 447 + 15, in the 448-byte steps) and 282 bytes in random mode (12 + 255 + 15).

### 2.5 Write path

`Transport::write` (`Transport.cpp:450-461`) → `write_crypto` (`:368-388`) → `write_crypto_impl` (`:343-366`):
1. Compute `padded_size`; allocate with the transport's prepend/append reserve.
2. `header.auth_key_id = auth_key.id(); salt; session_id`.
3. Serialize the storer (the prefix `msg_id|seq_no|len` and the body come from `SessionConnection`'s
   `CryptoImpl`, see 4.3) into `header.data`.
4. Fill the padding with random bytes.
5. v2: `(message_ack, msg_key) = calc_message_key2(auth_key, 0, encrypted_region)`, then
   `KDF2(auth_key, msg_key, 0)`, then IGE encrypt in place.

`RawConnection::send_crypto` (`RawConnection.cpp:62-87`) always uses `version = 2` and
`use_random_padding = transport.use_random_padding()`.

### 2.6 Read path and validity checks

`Transport::read` (`Transport.cpp:418-448`):
1. `size < 4` → error "smaller than 4 bytes".
2. `size < 16`: interpret `LE32(first 4 bytes)` as a code:
   - `0` → `Nop` (ignored);
   - `-1` and `size >= 8` → quick ack with token `LE32(bytes 4..8)` (HTTP-style quick ack; TCP quick acks are
     detected earlier in framing, see 3.2);
   - anything else → transport **error code** (e.g. `-404`, `-429`, `-444`).
3. `auth_key_id == 0` (first 8 bytes) → unencrypted packet (valid only during the handshake).
4. Encrypted with an empty key → error "auth key is empty".
5. `read_crypto_impl` (`Transport.cpp:214-300`), v2 branch:
   - `size >= sizeof(CryptoHeader) = 40`, else "too small";
   - `to_decrypt = bytes[24 ..]` truncated down to a multiple of 16 (trailing transport junk is ignored);
   - `header.auth_key_id == auth_key.id()`, else "auth_key_id mismatch";
   - `KDF2(auth_key, header.msg_key, X = 8)`, IGE decrypt in place;
   - `tail_size = size - 40` (bytes after session_id, **including** any non-aligned trailing junk); require
     `tail_size >= 16`;
   - recompute `msg_key` over `to_decrypt` with X = 8; compare with a **constant-time OR-accumulate loop**
     (`Transport.cpp:264-272`) → "message_key mismatch";
   - `message_data_length % 4 == 0` (check_mod4) → "not divisible by four";
   - `tail_size - 16 >= message_data_length` → else "message_data_length is too big";
   - `pad_size = tail_size - (16 + message_data_length)` must be in **[12, 1024]** → "invalid padding length".
   - The msg_key check happens **before** the length checks, so length fields are only trusted after
     authentication.
6. Returns `PacketInfo{salt, session_id, msg_id, seq_no}` and the data slice
   `[msg_id .. msg_id + 16 + message_data_length]` (the prefix included). The decrypt happens in place in the
   receive buffer.

**Not checked here**: the salt (never checked by tdlib: `SessionConnection.cpp:55` "TODO: Should I check input
salt?"), session_id and msg_id. Those are checked in `AuthData::check_packet` (2.7).

`RawConnection::flush_read` (`RawConnection.cpp:158-219`) copies the packet if it is not 4-byte aligned (only a
memory alignment detail), and a successful decrypt with a non-empty key calls `stats.on_pong()`, which marks the DC
option as OK.

### 2.7 Session-level checks: AuthData::check_packet

`AuthData.cpp:139-167`, called from `SessionConnection::on_raw_packet` (`SessionConnection.cpp:710-744`):
1. `session_id == our session_id`, else error (the connection closes).
2. `msg_id` must be **odd** (`msg_id & 1`), else "Receive invalid message". Only parity is checked, not `% 4 ∈ {1,3}`.
3. Duplicate filter `MessageIdDuplicateChecker<1000>` (`AuthData.cpp:19-46`): a sorted array of capacity 2N=2000
   that is compacted to the newest N when full:
   - `msg_id > max seen` → insert (fast path);
   - `count >= N and msg_id < min stored` → error code **2** "Ignore very old message";
   - `msg_id` already present → error code **1** "Ignore already processed";
   - otherwise insert in sorted position.
4. `update_server_time_difference(LE32(msg_id >> 32) - now)` (seconds only, i.e. `(uint32)(msg_id >> 32)`);
   see 4.9.
5. If the time difference has ever been set, the msg_id time must be within `(server_time - 300, server_time + 30)`
   (`is_valid_inbound_msg_id`, `AuthData.cpp:133-137`), else "Ignore too old or too new message" (generic error →
   the connection closes).

Error handling in `on_raw_packet`:
- code 1 (duplicate) → **send an ack for it** and ignore;
- code 2 (too old) → `on_session_failed("Receive too old packet")` → the whole Session is recreated with a new
  session_id (5.3), and the connection closes;
- any other error → the connection closes (the Session keeps its session_id).

### 2.8 MTProto 1.0 (used only for the auth.bindTempAuthKey inner message)

- `calc_message_ack_and_key` (`Transport.cpp:132-138`):
  `sha = SHA1(plaintext WITHOUT padding)`, `msg_key = sha[4..20]`, `ack = LE32(sha[0..4]) | 0x80000000`.
- `calc_crypto_size` v1 (`:140-145`): `24 + ((16 + data_size + 15) & ~15)`, i.e. padding 0..15 bytes only.
- `KDF` v1 (`KDF.cpp:17-50`), `x = X` (0 for client→server):
  ```
  a = SHA1(msg_key || auth_key[x .. x+32])
  b = SHA1(auth_key[32+x .. 48+x] || msg_key || auth_key[48+x .. 64+x])
  c = SHA1(auth_key[64+x .. 96+x] || msg_key)
  d = SHA1(msg_key || auth_key[96+x .. 128+x])
  aes_key = a[0..8]  || b[8..20] || c[4..16]                # 8 + 12 + 12
  aes_iv  = a[8..20] || b[0..8]  || c[16..20] || d[0..8]    # 12 + 8 + 4 + 8
  ```
- The v1 read path (not needed by a client) checks `len % 4`, exact expected size, and recomputes SHA1 over either
  the data or the whole tail to avoid a timing leak (`Transport.cpp:254-259`).

### 2.9 Quick ack

- Outgoing: `SessionConnection::flush_packet` requests a quick ack if any query in the packet has a
  `quick_ack_promise`. The token is the packet's "parent" msg_id (the container id, or the single message id)
  (`SessionConnection.cpp:1014`, `1025`).
- `RawConnection::send_crypto` stores `quick_ack_to_token_[packet_info.message_ack] = token` (collisions are logged
  and quick ack is skipped) and sets the quick-ack bit in the transport frame (`RawConnection.cpp:73-85`).
- Incoming quick ack (`RawConnection.cpp:234-249`): the high bit must be set, else ignore; unknown → ignore; known →
  erase and call `on_message_ack(token)`, which acks every query in that container (5.3). The map is per raw
  connection and dies with it.
- HTTP transport: no quick ack (`support_quick_ack() == false`).

### 2.10 Transport-level error codes

`RawConnection::on_read_mtproto_error` (`RawConnection.cpp:221-232`):

| code | handling |
|---|---|
| `-429` | `stats.on_mtproto_error()` (feeds `mtproto_error_flood_control`, see 6.2), connection closed with status **500** → all unacknowledged queries on that connection are returned with error 500 and re-sent through `NetQueryDelayer` (5.4) |
| `-404` | connection closed with status code **-404**: the auth key is unknown to the server. Cascade described in 5.9 |
| other (`-444` etc.) | connection closed with a generic error; unacknowledged queries become "unknown" and are re-checked on the next connection |

---

## 3. Transports

### 3.1 Transport types

`TransportType{type ∈ {Tcp, ObfuscatedTcp, Http}, int16 dc_id, ProxySecret secret}` (`TransportType.h:16-24`).
`create_transport` (`IStreamTransport.cpp:15-25`):
- `Tcp` → `tcp::OldTransport`: plain intermediate framing, **no obfuscation**. Only used by tests.
- `ObfuscatedTcp` → `tcp::ObfuscatedTransport(dc_id, secret)`: used for **all** production TCP connections, with
  or without a proxy. With an empty secret it is obfuscated2 + intermediate.
- `Http` → `http::Transport(secret = "host|Proxy-Authorization")`.

**tdlib does not implement the abridged transport** (`0xef`) or the "full" transport (with seq and crc32) at all.
It only speaks intermediate (`0xeeeeeeee`) and padded intermediate (`0xdddddddd`).

### 3.2 Intermediate and padded intermediate framing

`IntermediateTransport` (`TcpTransport.cpp:20-78`):
- Stream init: 4-byte magic `ee ee ee ee` (intermediate) or `dd dd dd dd` (padded). For `OldTransport` it is sent in
  the clear. For obfuscated transports it sits at bytes 56..60 of the obfuscation header, not as a separate prefix.
- Frame write (`write_prepare_inplace`):
  ```
  size = len(packet)            # CHECK size % 4 == 0, size < 2^24
  if quick_ack: size |= 0x80000000
  append_size = with_padding ? secure_u32 % 16 : 0  (random bytes appended)
  LE32 header = size + append_size      # note: quick-ack bit and padding are combined into one u32
  frame = header || packet || random(append_size)
  ```
- Frame read (`read_from_stream`):
  - fewer than 4 bytes available → wait for 4;
  - `u = LE32(first 4)`; if `u & 0x80000000` → this is a **quick ack** (4 bytes consumed, token = `u`);
  - otherwise need `4 + u` bytes; the packet is the next `u` bytes. Padding is not stripped here (Transport::read
    ignores the non-16-aligned tail and HandshakeConnection truncates to a multiple of 4).
- Max inbound frame: `RawConnection` rejects an expected size > `(1 << 22) + 1024` = 4,195,328 bytes
  (`RawConnection.cpp:168-171`).
- Prepend/append reserve: `max_prepend_size = 4` (+5 for TLS, +6 for the first TLS packet, + the pending header
  size, rounded up to a multiple of 4); `max_append_size = 15` (`TcpTransport.h:78-84`, `124-141`).

### 3.3 Obfuscated2 init header

`ObfuscatedTransport::init` (`TcpTransport.cpp:80-143`):
```
header = 64 random bytes, regenerated (at most 10 tries, CHECKed) while any of these hold (skipped when fake-TLS):
    header[0] == 0xef
    LE32(header[0..4]) ∈ {0x44414548 "HEAD", 0x54534f50 "POST", 0x20544547 "GET ", 0x4954504f "OPTI",
                          0xdddddddd, 0xeeeeeeee, 0x02010316 (TLS record start "16 03 01 02")}
    LE32(header[4..8]) == 0
header[56..60] = LE32(0xdddddddd if padded else 0xeeeeeeee)
if dc_id != 0: header[60..62] = LE16(dc_id)          # int16, may be negative; header[62..64] stay random
rheader = REVERSE(header)                             # all 64 bytes reversed
dec_key = rheader[8..40], dec_iv = rheader[40..56]    # server→client stream
enc_key = header[8..40],  enc_iv = header[40..56]     # client→server stream
if proxy_secret non-empty (16 bytes, see 3.4):
    enc_key = SHA256(enc_key || proxy_secret); dec_key = SHA256(dec_key || proxy_secret)
enc = AES256-CTR(enc_key, enc_iv); dec = AES256-CTR(dec_key, dec_iv)
encrypted = enc.encrypt(header)                       # consumes 64 bytes of keystream
sent_header = header[0..56] || encrypted[56..64]
```
- The CTR counter is the full 16-byte IV incremented as a 128-bit **big-endian** integer (`crypto.cpp:289-311`,
  OpenSSL `EVP_aes_256_ctr`), and it wraps (verified by the `iv = ff…ff` test vector in 9.2).
- All later outbound bytes (intermediate frames) continue the same `enc` stream. The header is prepended to the
  first written packet (`do_write_main`, `:164-171`), so the header and the first frame go out in one write.
- `dc_id` for the obfuscation header (`ConnectionCreator.cpp:780-807`): `raw_dc_id + 10000` on test servers, negated
  when the **chosen DC option** is `media_only`. This is the option's flag, not the session's `allow_media_only`
  (contrast with the handshake dc in 1.6). Test-proxy requests use the raw dc_id.

### 3.4 MTProxy secrets

`ProxySecret` (`ProxySecret.{h,cpp}`):
- Link decoding: try hex, then base64url, then base64 (`from_link`, `:15-27`).
- Accepted raw forms (`from_binary`, `:29-46`):
  - 16 bytes → plain obfuscated2 with a key salt (intermediate, no padding);
  - 17 bytes with first byte `0xdd` → padded intermediate + random MTProto padding;
  - ≥18 bytes with first byte `0xee` → fake-TLS; `secret[1..17]` is the key, `secret[17..]` is the domain
    (`get_domain`), max domain length **182** (`MAX_DOMAIN_LENGTH`, so the ClientHello fits in 517 bytes); longer
    secrets are rejected unless `truncate_if_needed`;
  - fewer than 16 bytes → "Wrong proxy secret"; anything else → "Unsupported proxy secret".
- `get_proxy_secret()` = `secret[1..17]` when the length is ≥17, else the whole 16 bytes. `use_random_padding()` =
  length ≥17. `emulate_tls()` = length ≥17 and first byte `0xee`.
- Encoding for links: base64url for `ee` secrets, hex otherwise (`get_encoded_secret`).
- DC options from `help.getConfig` may carry a `secret` (`dcOption.secret`, flag 10). tdlib then uses
  `ObfuscatedTcp` with that secret directly against the DC IP (`ConnectionCreator.cpp:805`). The
  `dcOption.this_port_only` flag is **ignored** by tdlib.

### 3.5 Fake-TLS ("ee" secrets)

Two stages: `TlsInit` (a TransparentProxy actor) does the fake handshake on the raw socket, then the socket is
handed to `ObfuscatedTransport` with `emulate_tls()` true, which wraps every write in TLS application-data records.

#### 3.5.1 ClientHello generation

`TlsObfusaction::generate_header(domain, secret16, unix_time)` (`TlsInit.cpp:478-499`), driven by an op list
(`TlsHello::get_default`, `:100-173`). Op semantics:
- `str(bytes)` emits literal bytes; `zero(n)` emits zeros; `random(n)` emits secure random bytes;
- `domain` emits the domain truncated to 182 bytes;
- `grease(i)` emits two bytes `G[i], G[i]` from a 7-byte GREASE table;
- `begin_scope`/`end_scope` reserve and backfill a **big-endian u16 length** of the enclosed bytes (max < 2^14);
- `key` emits a 32-byte fake X25519 public key;
- `permutation(parts)` renders each part and emits them in `Random::shuffle` order.

GREASE table (`Grease::init`, `TlsInit.cpp:26-36`): 7 random bytes, each mapped to `(b & 0xF0) | 0x0A`. Then for
every odd index `i`, if `G[i] == G[i-1]`, set `G[i] ^= 0x10` (so the pairs (0,1), (2,3) and (4,5) differ). Every
GREASE value therefore has the form `?A ?A`.

Fake key (`TlsInit.cpp:348-368`): loop { `k = random(32)`; `k[31] &= 0x7f`; `x = big-endian(k)`;
`y = x^3 + 486662*x^2 + x mod (2^255-19)`; if `y` is a quadratic residue (`y^((p-1)/2) == 1`) then replace `x` by
x-only point doubling applied **3 times** (`x2 = (x^2-1)^2 / (4*y(x))`, so ×8 into the prime-order subgroup), emit
`x` as **32 little-endian** bytes, break }.
(The random bytes are read big-endian, `k[31] &= 0x7f` is applied before that read, and the output is written
little-endian. This only needs to look like a curve point, so byte-exactness does not matter for interop. Replicate
it anyway for fingerprint parity.)

Template used on Apple platforms (`#if TD_DARWIN`, `TlsInit.cpp:104-136`). Hex, `|` separates ops:
```
16 03 01 02 00 01 00 01 fc 03 03        record hdr (type 22, ver 3.1, len 0x200) + Handshake ClientHello len 0x1fc + ver 3.3
zero(32)                                client_random (filled with HMAC later)
20 | random(32)                         session_id len 32 + random session id
00 2a | grease(0)                       cipher_suites length 42, GREASE suite
13 01 13 02 13 03 c0 2c c0 2b cc a9 c0 30 c0 2f cc a8 c0 0a c0 09 c0 14 c0 13 00 9d 00 9c 00 35 00 2f c0 08 c0 12 00 0a
01 00                                   compression methods: 1, null
01 89                                   extensions length 393
grease(2) | 00 00                       GREASE extension, empty
00 00 | scope{ scope{ 00 scope{domain} } }        server_name
00 17 00 00                             extended_master_secret
ff 01 00 01 00                          renegotiation_info
00 0a 00 0c 00 0a | grease(4) | 00 1d 00 17 00 18 00 19          supported_groups: GREASE, x25519, P-256, P-384, P-521
00 0b 00 02 01 00                       ec_point_formats
00 10 00 0e 00 0c 02 68 32 08 68 74 74 70 2f 31 2e 31          ALPN "h2","http/1.1"
00 05 00 05 01 00 00 00 00              status_request
00 0d 00 18 00 16 04 03 08 04 04 01 05 03 02 03 08 05 08 05 05 01 08 06 06 01 02 01   signature_algorithms
00 12 00 00                             signed_certificate_timestamp
00 33 00 2b 00 29 | grease(4) | 00 01 00 00 1d 00 20 | key()   key_share: GREASE(1 byte 00), x25519(32)
00 2d 00 02 01 01                       psk_key_exchange_modes
00 2b 00 0b 0a | grease(6) | 03 04 03 03 03 02 03 01           supported_versions
00 1b 00 03 02 00 01                    compress_certificate (zlib)
grease(3) | 00 01 00                    GREASE extension with 1 byte 00
00 15 | scope{ zero(pad) }              padding extension
```

Template used elsewhere (`#else`, `TlsInit.cpp:138-168`); extension order is **shuffled** per connection:
```
16 03 01 02 00 01 00 01 fc 03 03 | zero(32) | 20 | random(32)
00 20 | grease(0) | 13 01 13 02 13 03 c0 2b c0 2f c0 2c c0 30 cc a9 cc a8 c0 13 c0 14 00 9c 00 9d 00 2f 00 35
01 00 | 01 93                           compression, extensions length 403
grease(2) | 00 00
permutation of:
  00 00 scope{scope{00 scope{domain}}}            server_name
  00 05 00 05 01 00 00 00 00                       status_request
  00 0a 00 0a 00 08 grease(4) 00 1d 00 17 00 18    supported_groups
  00 0b 00 02 01 00                                ec_point_formats
  00 0d 00 12 00 10 04 03 08 04 04 01 05 03 08 05 05 01 08 06 06 01   signature_algorithms
  00 10 00 0e 00 0c 02 68 32 08 68 74 74 70 2f 31 2e 31               ALPN
  00 12 00 00                                      SCT
  00 17 00 00                                      extended_master_secret
  00 1b 00 03 02 00 02                             compress_certificate (brotli)
  00 23 00 00                                      session_ticket
  00 2b 00 07 06 grease(6) 03 04 03 03             supported_versions
  00 2d 00 02 01 01                                psk_key_exchange_modes
  00 33 00 2b 00 29 grease(4) 00 01 00 00 1d 00 20 key()   key_share
  44 69 00 05 00 03 02 68 32                       application_settings (ALPS) "h2"
  ff 01 00 01 00                                   renegotiation_info
grease(3) | 00 01 00 | 00 15 | scope{ zero(pad) }
```

Padding and length (`TlsHelloCalcLength::finish` `:281-300`, `TlsHelloStore::finish` `:412-424`):
- Before the final padding the hello must be ≤ **514** bytes ("Too long for zero padding") and ≥ 43.
- `zero_pad = 515 - current_size`, emitted inside a 2-byte length scope. The total ClientHello is therefore
  **always 517 bytes** (5-byte record header + 512). The hard-coded `01 89`/`01 93` extension lengths and the
  `02 00`/`01 fc` lengths stay consistent because of that fixed total.

HMAC and timestamp (`TlsHelloStore::finish`, `:412-424`):
```
hash = HMAC-SHA256(key = secret16, msg = entire 517-byte hello with client_random still all-zero)
hash[28..32] = LE32(hash[28..32]) XOR (int32)unix_time       # little-endian xor of the last 4 bytes
hello[11..43] = hash                                          # client_random
```
`unix_time = (int32)(Time::now() + G()->get_dns_time_difference())` (`TlsInit.cpp:502-503`,
`ConnectionCreator.cpp:918`), i.e. best-known server or DNS time, so a wrong local clock does not break the MTProxy
replay window.

#### 3.5.2 ServerHello verification

`TlsInit::wait_hello_response` (`TlsInit.cpp:509-543`): the response must start with
```
16 03 03 | len_hi len_lo | <len bytes>                               (ServerHello record)
14 03 03 00 01 01 17 03 03 | len_hi len_lo | <len bytes>           (ChangeCipherSpec + first app-data record)
```
(an incomplete prefix waits; a mismatch → "First part of response to hello is invalid"). Then:
```
response = all bytes of the two parts above
server_random = response[11..43]; zero those 32 bytes in response
require HMAC-SHA256(secret16, client_random || response_with_zeroed_random) == server_random
```
→ else "Response hash mismatch". Then the TransparentProxy finishes. **If any extra bytes are already buffered
after these records**, tear_down fails with "Proxy has sent too many data" (`TransparentProxy.cpp:36-48`). The whole
TLS init has a **10 s** timeout (`TransparentProxy.cpp:57`).

#### 3.5.3 TLS record layer after the handshake

- Write (`ObfuscatedTransport::write` + `do_write_tls`, `TcpTransport.cpp:154-213`): frame with intermediate, then
  AES-CTR encrypt, then split into chunks so that each record payload is ≤ **2878** bytes (`MAX_TLS_PACKET_LENGTH`,
  `TcpTransport.h:162`; the 64-byte obfuscation header counts toward the first record). Each record is
  `17 03 03 len_hi len_lo || payload`. The **very first** record is preceded by the fake ChangeCipherSpec
  `14 03 03 00 01 01`. The obfuscation header is sent (inside the first record) without any forbidden-prefix check.
- Read (`TlsReaderByteFlow::loop`, `TlsReaderByteFlow.cpp:15-37`): each record must begin `17 03 03` (anything else
  closes with "Invalid bytes at the beginning of a packet (emulated tls)"); the length is a big-endian u16 (no
  upper bound check beyond 65535); payloads are concatenated and fed to AES-CTR decrypt, then to the intermediate
  reader.

### 3.6 HTTP transport

`http::Transport` (`HttpTransport.cpp:27-104`): strictly request/response (`turn_` alternates Write/Read; one
in-flight request per connection).
- Direct: `POST /api HTTP/1.1`, `Host: ` (empty), `Connection: keep-alive`, `Content-Length`.
- Via an HTTP caching proxy (`secret = "host|basic base64(user:pass)"`): `POST HTTP://<dc_ip>:80/api HTTP/1.1`,
  `Host: <dc_ip>`, `User-Agent: curl/7.35.0`, `Accept: */*`, `Proxy-Connection: keep-alive`, optional
  `Proxy-Authorization`.
- The response body is the raw MTProto packet. No quick ack, no random padding.
- Session uses HTTP mode with two connections: main (`http_wait max_wait=0`) and long-poll (5.4/4.10).

### 3.7 SOCKS5 and HTTP CONNECT (tdnet)

- SOCKS5 (`tdnet/td/net/Socks5.cpp:17-168`): greeting `05 01 00` or `05 02 00 02` (when a username is set);
  username/password sub-negotiation `01 len user len pass` (each <128 bytes) expecting `01 00`; CONNECT
  `05 01 00 01 <ipv4 4B> <port BE>` or `05 01 00 04 <ipv6 16B> <port BE>` (always by IP, never by domain); reply
  `05 00 00 (01 + 4B | 04 + 16B) + 2B port` (other address types → "Invalid response").
- HTTP CONNECT (`tdnet/td/net/HttpProxy.cpp:19-95`): `CONNECT ip:port HTTP/1.1\r\nHost: ip:port\r\n`
  `[Proxy-Authorization: Basic b64(user:pass)\r\n]\r\n`; the response must start with `HTTP/1.1 2dd` or
  `HTTP/1.0 2dd`; headers are skipped until the empty line.
- Both use the 10 s TransparentProxy timeout. Leftover bytes after the proxy handshake cause an error.

---

## 4. SessionConnection: the MTProto session protocol (the core)

`td/mtproto/SessionConnection.{h,cpp}`. One `SessionConnection` wraps one `RawConnection` for one MTProto session
(`AuthData*` is owned by the `Session` and outlives connections). The `Session` drives it by calling
`flush(callback)` whenever an event arrives or a timer fires. `flush` reads, dispatches, writes, and returns the next
wakeup time.

Modes: `Tcp`, `Http` (main HTTP connection) and `HttpLongPoll` (the second HTTP connection, which only sends
`http_wait`).

### 4.1 msg_id generation

`AuthData::next_message_id(now)` (`AuthData.cpp:107-125`) **[MUST]**:
```
t  = (uint64)(server_time(now) * 2^32)
rx = secure_int32()
t ^= rx & ((1 << 22) - 1)            # randomize the low 22 bits (sub-millisecond part) for low-precision clocks
id = t & ~3                          # client→server ids are divisible by 4
if last_message_id >= id:
    id = last_message_id + 8 * (((rx >> 22) & 1023) + 1)     # bump by 8..8192, keeps id % 4 == 0
last_message_id = id
```
- Strictly increasing per `AuthData` (i.e. per Session/session_id). Uses the **server** time (local time plus the
  time difference).
- Outbound validity window used for resend decisions (`is_valid_outbound_msg_id`, `AuthData.cpp:127-131`):
  `server_time - 150 < id_time < server_time + 30`.

### 4.2 seq_no

`AuthData::next_seq_no(is_content_related)` (`AuthData.h:267-274`):
```
res = seq_no_
if content_related: res |= 1; seq_no_ += 2
return res
```
- Queries (RPC calls) are content-related: they get their seq_no when they are **queued** (`send_query`,
  `SessionConnection.cpp:818`), not when they are flushed.
- Service messages (msgs_ack, ping, http_wait, get_future_salts, msgs_state_req, msg_resend_req, rpc_drop_answer,
  destroy_auth_key) and containers get `next_seq_no(false)` (the current even value) at flush time
  (`CryptoStorer.h:42-43`, `253`). Several non-content messages in one packet share the same even seq_no.
  **[quirk]** tdlib marks **every** service message it sends as non-content (even seq_no), including ping,
  get_future_salts, msgs_state_req, msg_resend_req, rpc_drop_answer, destroy_auth_key and http_wait. The spec treats
  most of these as content-related; the server accepts tdlib's choice and does not raise error 34/35 for it. The
  practical effect is that the server never needs to ack them.
- The bind inner message uses seq_no 0. `clear_seq_no()` exists for the ping-pong checker connection.
- seq_no is never reset during a Session's lifetime. A new session_id means a new `AuthData` and seq_no 0.

### 4.3 Building an outgoing packet (`flush_packet`, `SessionConnection.cpp:911-1064`)

Inputs collected at flush time:
1. **Ping**: if `has_salt && may_ping()` → `last_ping_at = now`, `ping_id = next_message_id(now)` (the ping_id is a
   msg_id-shaped value), sent as `ping_delay_disconnect#f3427b8c ping_id disconnect_delay` with
   `disconnect_delay = (int)(ping_disconnect_delay() + 2.0)` (`:1020`).
2. **http_wait**: Http and HttpLongPoll modes only: `http_wait#9299359f max_delay=30 wait_after=10 max_wait`, where
   `max_wait = 0` for Http and `1000 * clamp(min(last_pong + ping_disconnect_delay, last_read +
   read_disconnect_delay) - now - rtt, 0.1, 25.0)` ms for LongPoll (`:921-935`).
3. **get_future_salts(64)**: when not LongPoll, `need_future_salts(now)` holds, and none was sent in the last 60 s
   (`:937-945`).
4. **Queries**: only if `has_salt`. Take from `to_send_` while `count < 1000` (`MAX_QUERY_COUNT`) and
   `bytes_so_far < 32768` (the size check happens before adding, so one large query can exceed 32 KB)
   (`:947-964`).
5. **destroy_auth_key**: if requested and not yet sent (sent once; `destroy_auth_key_send_time = now`).
6. **Acks, msgs_state_req ids, msg_resend_req ids, rpc_drop_answer ids**: trimmed with
   `cut_tail(list, limit)`: if there are more than `limit` ids, the **newest** `limit` are sent and the older ones
   stay queued. Limits: resend 8192, state 8192, acks 8192, cancels `1000 - queries.size()`
   (`:987-1011`).

If everything is empty, nothing is sent and `force_send_at_ = 0`.

**Packing** (`CryptoImpl`, `CryptoStorer.h:205-368`):
- Message ids are assigned in member-initialization order: msgs_ack, http_wait, get_future_salts, msgs_state_req,
  msg_resend_req, each rpc_drop_answer, destroy_auth_key, ping. Then the container id is assigned **last** (it is
  generated in the constructor body), so `container_msg_id > every inner msg_id`. Query ids were assigned earlier, at
  queue time.
- Element order inside the container: `queries…, msgs_ack, http_wait, get_future_salts, msgs_state_req,
  msg_resend_req, rpc_drop_answer…, destroy_auth_key, ping_delay_disconnect`.
- Each element is `msg_id:long seqno:int bytes:int body` (`ObjectImpl::do_store`, `CryptoStorer.h:46-54`).
- `cnt = queries + one per present service message + number of cancels`.
- **Container decision** (`CryptoStorer.h:249-287`): use `msg_container#73f1f8dc` if `cnt > 1` **or** the single
  item is a query whose msg_id is no longer a valid outbound id (outside (-150 s, +30 s)). **[quirk]/[MUST]** A stale
  query keeps its original msg_id and is wrapped in a fresh container, so the server sees a fresh outer msg_id.
  Otherwise the single message is sent bare.
- `parent_message_id` = the container id or the single message's id. It is the quick-ack token, and the Session
  links contained query ids to the container id through `on_container_sent(container_id, query_ids)`.
- The ids of `msgs_state_req` and `msg_resend_req` are remembered in `service_queries_` together with their
  container id, so that a `bad_msg_notification`/`bad_server_salt` naming the container re-queues the requested ids
  (`:1029-1057`).
- `last_ping_message_id_` and `last_ping_container_message_id_` are remembered. If either of them fails
  (bad_msg/salt), the ping restarts immediately (`:602-607`).

### 4.4 Query wire format

`QueryImpl::do_store` (`CryptoStorer.h:136-166`). The body of a query message is:
```
[header]                         = auth_data.get_header(): invokeWithLayer#da9b0d0d layer initConnection#c1cd5ea9 ...   (may be empty)
[invokeAfterMsg#cb9f372d msg_id:long]            if exactly 1 dependency
[invokeAfterMsgs#3dc4b4f0 0x1cb5c415 n msg_id*]  if ≥2 dependencies
query                            = raw TL bytes, or gzip_packed#3072cfa1 packed_data:string(zlib bytes) if gzip_flag
```
- The header and the invokeAfter wrappers are **outside** `gzip_packed`. Only the innermost query is compressed, and
  it was compressed once at creation time (see 5.13).
- The header is added to **every** query in the packet while `need_header()` holds (5.12).

### 4.5 Acknowledgement policy

- For every received message (including each message inside a container, and the outer message) with an **odd**
  seq_no, `send_ack(msg_id)` (`on_slice_packet`, `:501-503`). This happens **before** the body is processed, so even
  malformed content-related messages are acked.
- Duplicates (code 1 in check_packet) are acked too (`:728-731`).
- `send_ack` (`:886-900`): if the queue was empty, schedule a send at `now + ACK_DELAY` (**30 s**). Consecutive
  duplicate ids are skipped (gzip unwrap can deliver the same id twice). When **≥100** ids are pending
  (`MAX_UNACKED_PACKETS`), schedule an immediate send.
- Acks also ride along with any other flush (queries, pings), so in practice they leave much sooner than 30 s.
- `force_ack()` (`:880-884`) sends pending acks immediately. The Session calls it when an `rpc_error` arrives for an
  unknown request (`Session.cpp:984-987`).
- tdlib does **not** ack its own outgoing service messages and does not track acks for them, except ping (via pong)
  and destroy_auth_key (via timeout).

### 4.6 Incoming dispatch

`on_raw_packet` → `check_packet` (2.7) → `on_main_packet` (`:569-594`):
- **Every** successfully decrypted packet sets `last_pong_at_ = now` ("Real pong can be delayed by many big
  packets"), so any traffic proves liveness.
- First packet: `connected_flag_ = true`, `on_connected()` (the main session takes a ConnectionManager token).
- An unencrypted packet in a session → error.
- `parse_packet`: `parse_message` (`:187-212`) reads `msg_id:long seqno:int bytes:int` (bytes must be % 4 == 0 and
  within the buffer), then `on_slice_packet`, then `parser.fetch_end()`. Trailing garbage after the top-level message
  is an error.

`on_slice_packet` (`:500-560`):
1. Ack if seq_no is odd.
2. Body shorter than 4 bytes → `on_session_failed("Receive too small packet")` and error.
3. Constructor `msg_container#73f1f8dc` → `on_packet_container`: `count:int`, then `count` × `parse_packet`
   (recursive, so nested containers are accepted). The current container id is kept for diagnostics. Inner
   messages are **not** run through check_packet (no duplicate, parity or time-window check), only the outer packet
   is.
4. Constructor `rpc_result#f35c6d01` → `on_packet_rpc_result` (4.7.1).
5. Any constructor in `mtproto_api` (the Appendix A schema) → parse fully (`fetch_end`) and call the matching
   `on_packet` (4.7). Unknown-but-schema constructors without a handler log "Unsupported" and are ignored.
6. Anything else is an **update** (`Updates` from the API layer):
   - `check_update(msg_id)` with a separate `MessageIdDuplicateChecker<1000>` keyed by the **inner** msg_id; a
     second `recheck` checker of size 100 is used only for logging;
   - code 1 (duplicate) → skip silently;
   - code 2 (older than all stored, with ≥1000 stored) → `on_session_failed("Receive too old update")` and error;
   - otherwise `callback.on_update(bytes)`. The Session forwards it and rejects updates on CDN sessions with an
     error.

### 4.7 Message handlers

#### 4.7.1 rpc_result

`on_packet_rpc_result` (`:239-278`):
- `req_msg_id:long`; `0` → error "Receive an update in rpc_result" (the connection closes).
- **Time sanity**: if `this_msg_id < req_msg_id - 15*2^32` (the server's message is more than 15 s "older" than our
  request id, meaning our clock ran ahead), `reset_server_time_difference(this_msg_id)` (forced) (`:251-253`).
- Body constructor:
  - `rpc_error#2144ca19 error_code:int error_message:string` → `on_message_result_error(req_msg_id, code, msg)`;
  - `gzip_packed#3072cfa1` → `gzdecode` (auto-detects gzip or zlib) → `on_message_result_ok(req, decoded,
    original_size)`. On a decode failure the result is an empty buffer, which fails later at the API parsing layer;
  - otherwise the raw bytes after req_msg_id → `on_message_result_ok`.
- `original_size` is the message's `bytes` field, used for the dropped-result accounting (5.3).

#### 4.7.2 Service message handlers

| Constructor | tdlib action | Ref |
|---|---|---|
| `new_session_created#9ec20908 first_msg_id unique_id server_salt` | Map `first_msg_id` to its container id if it was a service query; `on_new_session_created(unique_id, first_msg_id)` (5.5). **[quirk]** The `server_salt` field is **ignored** (salt arrives via bad_server_salt/future_salts). `unique_id` is not deduplicated. | `:309-322` |
| `bad_msg_notification#a7eff811 bad_msg_id bad_msg_seqno error_code` | see the table below | `:324-387` |
| `bad_server_salt#edab447b bad_msg_id bad_msg_seqno error_code new_server_salt` | `set_server_salt(new, now)` (valid for 10 min, clears future salts) → `on_server_salt_updated` → `on_message_failed(bad_msg_id)` (resend). error_code (48) is not checked. | `:389-397` |
| `msgs_ack#62d6b459 msg_ids` | `on_message_ack(id)` for each (Session expands container ids) | `:399-406` |
| `gzip_packed#3072cfa1` (top level / in a container) | `gzdecode`, then re-dispatch via `on_slice_packet` with the **same** MsgInfo (so the ack is deduplicated by the consecutive-id rule) | `:408-412` |
| `pong#347773c5 msg_id ping_id` | Time sanity: `this_msg_id < pong.msg_id - 15*2^32` → forced time reset. If destroy_auth_key was sent >60 s ago → error (close). `last_pong_at = now`. `on_pong(ping_time = ping_id/2^32, pong_time = msg_id/2^32, server_now)` (5.3 dead-query check). | `:414-433` |
| `future_salts#ae500895 req_msg_id now salts` | `set_future_salts([...])` (4.8); `req_msg_id` and `now` are ignored | `:435-449` |
| `msgs_state_info#04deb57d req_msg_id info:string` | Look up `service_queries_[req_msg_id]` (must be a GetStateInfo, else error); `info.size()` must equal the id count, else error; `on_message_info(id, info[i], 0, 0, source = 1)` | `:451-477` |
| `msgs_all_info#8cc0d131 msg_ids info` | the same, source 1 | `:479-482` |
| `msg_detailed_info#276d3ec6 msg_id answer_msg_id bytes status` | `on_message_info(msg_id, status, answer_msg_id, bytes, source = 2)` | `:484-490` |
| `msg_new_detailed_info#809db6df answer_msg_id bytes status` | `on_message_info(0, 0, answer_msg_id, bytes, source = 0)`, so the Session requests a resend of `answer_msg_id` | `:492-498` |
| `destroy_auth_key_ok#f660e1d4` / `_none#0a9f2259` / `_fail#ea109b13` | If destroy was requested: `on_destroy_auth_key()` (drop the main key, close). Otherwise log and ignore. All three outcomes are treated the same. | `:286-307` |
| `rpc_answer_*`, `destroy_session_*`, `msg_copy`, `msg_resend_req` (from the server) | not handled specially: `rpc_drop_answer` replies arrive as rpc_result for an id the Session does not know and are dropped; destroy_session is not implemented | — |

`bad_msg_notification` codes (`:328-386`):

| code | meaning | tdlib action |
|---|---|---|
| 16 | msg_id too low | `on_message_failed(bad_msg_id)` → **resend with a new msg_id**. The time difference was already raised from this notification's own msg_id in check_packet. |
| 17 | msg_id too high | clear `to_send_`, **forced** `reset_server_time_difference(this notification's msg_id)`, `on_session_failed` (the whole Session is recreated with a new session_id and every sent or pending query is re-dispatched, so non-idempotent queries may run twice), close |
| 18 | msg_id not divisible by 4 | error, close the connection ("BUG") |
| 19 | container msg_id equals that of an older message | error, close |
| 20 | message too old | `on_message_failed` → resend with a new msg_id |
| 32 | seq_no too low | error, close |
| 33 | seq_no too high | error, close |
| 34 | even seq_no expected | error, close |
| 35 | odd seq_no expected | error, close |
| 48 | (bad server salt) | not expected here (it arrives as `bad_server_salt`); falls into "unknown" |
| 64 | invalid container | error, close |
| other | unknown | error, close |

"Close" means the connection closes with an error status, the Session keeps its session_id, and unacknowledged
queries become "unknown" (5.4).

`on_message_failed(id)` (`:596-618`) first tells the Session (which resends the query or the whole container's
queries), clears `sent_destroy_auth_key_` (so destroy is sent again), restarts the ping if the id is the ping or its
container, and re-queues the ids of any `msgs_state_req`/`msg_resend_req` that lived in that container (or was that
message).

### 4.8 Salt management

`AuthData` (`AuthData.h:220-249`, `AuthData.cpp:91-105`, `169-175`):
- Initial state: `salt = random`, `valid_since = valid_until = -1e10`, so `has_salt` is false.
- `set_server_salt(salt, now)`: `valid_since = server_time`, `valid_until = server_time + 600` (10 min); **clears
  future salts**. Called from the handshake salt and from bad_server_salt.
- `is_server_salt_valid`: `valid_until > server_time + 60`.
- `has_salt(now)`: `update_salt(now)`, then `is_server_salt_valid`.
- `need_future_salts(now)`: `update_salt(now)`, then `future_salts.empty() || !is_server_salt_valid`.
- `set_future_salts(list)`: if the list is empty, ignore; else replace the list, **sort by valid_since descending**,
  then `update_salt`.
- `update_salt(now)`: while the oldest future salt has `valid_since < server_time`, make it current and pop it.
  So the current salt is always the newest one whose window has started.
- `get_server_salt(now)` (used for every write) calls `update_salt` first.
- Requests: `get_future_salts#b921bd04 num = 64` at most once per **60 s** while needed (`:937-945`). When there is no
  valid salt at all, `must_flush_packet` sends a packet just for that (first time immediately, then every 60 s,
  `:683-693`). Queries and pings are held until `has_salt` (`:916`, `:950`).
- Persistence: without PFS the Session writes `get_future_salts()` (future list + current) to the shared per-DC
  store `"salt<dc>"` on every salt update (`Session.cpp:607-613`, `AuthDataShared.cpp:76-87`). With PFS the salts
  belong to the temp key and are kept in `SessionProxy` memory only.
- A wrong or old salt costs one round trip: `bad_server_salt` sets the new salt and the message is resent.

### 4.9 Time synchronization

- `server_time_difference` is per `AuthData`, initialized from the global value (`Session.cpp:251`). The
  "was_updated" flag starts false, so the first observation always sets the value.
- From the handshake: `server_time - now` at DH params time (`Handshake.cpp:221`), applied via
  `update_server_time_difference` (`Session.cpp:1425-1427`).
- From every accepted packet: `diff = (double)(uint32)(msg_id >> 32) - now`. `update_server_time_difference(diff)`
  (`AuthData.cpp:70-83`) sets the value the first time, then only **increases** it, by more than 1e-4. Rationale
  (`AuthData.h:214-215`): `msg_id/2^32 ≈ server time at send ≤ server time now`, so the maximum seen is the best
  lower bound.
- **Forced reset** `reset_server_time_difference(msg_id)` (sets the value, clears was_updated, notifies with force):
  on bad_msg 17, and when a response's msg_id is more than 15 s below the request's msg_id (rpc_result or pong).
- Global propagation (`Session.cpp:615-617` → `Global::update_server_time_difference`, `Global.cpp:189-197`): the
  global value is replaced if forced, if not set yet, or if larger; it is persisted.
- tdlib uses only the integer-seconds part of the msg_id for the time difference.

### 4.10 Ping, liveness and timeouts

All in `SessionConnection.h:145-169`. `raw_rtt` = the RTT measured by the connection-check ping (6.6), or 0 if the
connection was not checked. `random_delay` = uniform 0..5 s, chosen per SessionConnection
(`SessionConnection.cpp:758`).

| Quantity | online (`online_flag_`) | offline |
|---|---|---|
| `rtt()` | `max(2.0, raw_rtt*1.5 + 1)` | same |
| `ping_may_delay` (piggyback a ping on any flush after) | `rtt*0.5` | `30 + random_delay` |
| `ping_must_delay` (force a flush just to ping) | `rtt` | `60 + random_delay` |
| `ping_disconnect_delay` (no packet for this long → close) | `rtt*2.5` if also `is_main_` (= the Session's `is_primary`, i.e. main-purpose sessions), else `135 + random_delay` | `135 + random_delay` |
| `read_disconnect_delay` (no bytes read for this long → close) | `rtt*3.5` | `135 + random_delay` |
| `ping_delay_disconnect.disconnect_delay` sent to the server | `(int)(ping_disconnect_delay + 2)` | same |

- `may_ping = last_ping_at == 0 || (mode != LongPoll && last_ping_at + ping_may_delay < now)`; `must_ping` is the same
  with `ping_must_delay`. **No pings on long-poll connections** after the first.
- Close conditions checked after each `flush` (`do_flush`, `:1098-1115`):
  `now > last_pong_at + ping_disconnect_delay` → "Ping timeout"; `now > last_read_at + read_disconnect_delay` →
  "Read timeout". Both also mark the DC option stat as error.
- `last_read_at` updates on any bytes read (`on_read`). `last_pong_at` updates on any decrypted packet and on pong.
- Wakeup (`flush`, `:1130-1146`): `min(last_pong_at + ping_disconnect_delay + 0.002, last_read_at +
  read_disconnect_delay + 0.002, flush_packet_at)`.
- Effective numbers: with the default `rtt() = 2` s, an online primary connection pings about every 2 s of idleness
  (must) and dies after 5 s without any packet. An offline connection pings every 60..65 s and dies after
  135..140 s; the server drops the TCP connection about 137..142 s after the last ping if the client disappears.
- `init()` (first flush) sets `last_pong_at = last_read_at = now`, so a fresh connection gets a full window.

### 4.11 Online and offline switching

`set_online(online_flag, is_main)` (`:781-797`):
```
need_ping = online_flag || !old_online_flag          # going online, staying online, or staying offline
if need_ping:
    last_pong_at = now - ping_disconnect_delay() + rtt()     # must see a packet within rtt() seconds
    last_read_at = now - read_disconnect_delay() + rtt()
else (online → offline):
    last_pong_at = last_read_at = now
last_ping_at = 0 (ping immediately), forget the last ping ids
```
This is tdlib's fast dead-connection detection when the app comes to the foreground: an existing connection must
answer a ping within about 2 s or it is torn down and replaced. `Session::connection_online_update`
(`Session.cpp:353-367`) computes
`connection_online = (online || logging_out) && (has_queries || last_activity + 10 > now || is_primary)` and calls
`set_online(connection_online, is_primary)` on change, and also forcibly on every online/logging-out event.

### 4.12 Flush scheduling

`must_flush_packet` (`:644-700`) is evaluated in a loop from `before_write` (`:702-708`, called by `RawConnection`
between read and write):
- no auth key, or the transport cannot send (HTTP waiting for a response) → no;
- LongPoll: send only when `has_salt` (it always has an `http_wait` to send);
- `has_salt && force_send_at != 0`: send if `now > force_send_at`, else wake at `force_send_at`.
  `force_send_at` is set by `send_before(t)` = min of pending deadlines: query `now + 0.001`
  (`QUERY_DELAY`), resend/cancel `now + 0.001` (`RESEND_ANSWER_DELAY`), state request `now`, ack `now + 30`;
- `has_salt && must_ping` → yes, else wake at `last_ping_at + ping_must_delay`;
- `!has_salt`: send for get_future_salts (first time, or 60 s after the last one);
- destroy_auth_key pending and not sent → yes.

`QUERY_DELAY = 1 ms` batches queries issued within the same event-loop turn into one container.

---

## 5. Session layer: Session, SessionProxy, SessionMultiProxy, dispatcher, delayer, DC auth

### 5.1 Topology and counts

```
NetQueryDispatcher (one)                        td/telegram/net/NetQueryDispatcher.cpp
 └─ per DC (raw id 1..1000, lazily created in wait_dc_init :200-277)
     ├─ main_session_           SessionMultiProxy(session_count,  is_primary=true,  is_main=(dc==main_dc), media=false)
     ├─ upload_session_         SessionMultiProxy(8 or 4,         is_primary=false, allow_media_only=false, is_media=true)
     ├─ download_session_       SessionMultiProxy(8 or 2,         is_primary=false, allow_media_only=true,  is_media=true)
     └─ download_small_session_ SessionMultiProxy(8 or 2,         is_primary=false, allow_media_only=true,  is_media=true)
          └─ SessionProxy × N  (one per session; holds pending "needs auth" queries and the persisted temp key)
               └─ Session (actor; one MTProto session_id)
                    ├─ main_connection_      (SessionConnection over RawConnection; TCP or HTTP)
                    └─ long_poll_connection_ (HTTP mode only)
```
- `session_count` = option `session_count` (from `config.tmp_sessions`, default 1), clamped to 1..100
  (`NetQueryDispatcher.cpp:363-365`, `SessionMultiProxy.cpp:95`).
- Upload sessions: 8 if the DC is not 2 or 4, or if the user is premium; else 4. Download and download_small: 8 if
  premium, else 2 (`NetQueryDispatcher.cpp:246-249`).
- `use_pfs = option "use_pfs" || session_count > 1` (`:367-369`). PFS is never used for CDN
  (`SessionMultiProxy::get_pfs_flag`, `:132-134`). The temp key is persisted (`persist_tmp_auth_key`) only when
  `session_count > 1 && is_primary` (`SessionMultiProxy.cpp:164`).
- All Sessions of a DC (main, upload and download) share **one perm auth key** through `AuthDataShared` (persisted in
  the key-value store as `"auth<dc>"`, `AuthDataShared.cpp:96-98`). Each Session has its own random non-zero
  `session_id` (`Session.cpp:261-265`) and its own seq_no/msg_id counters.
- Query routing to sessions inside a multi-proxy (`SessionMultiProxy::send`, `:39-65`): authorized queries with
  `session_rand` go to `sessions[rand % n]`; others go to the session with the fewest in-flight queries (random
  tie-break). Unauthorized queries always go to session 0.
- `SessionProxy::send` (`:156-165`): a query that needs auth while the DC key is not authorized (`AuthKeyState != OK`)
  is parked until it is (`update_auth_key_state`, `:250-265`).
- Session creation is lazy: the main DC session opens eagerly; other sessions open when they have queries
  (`open_session`, `:199-248`). A non-main Session closes itself after **300 s** without activity or queries
  (`ACTIVITY_TIMEOUT`, `Session.h:180`, `Session.cpp:1511-1513`).

### 5.2 Session state

`Session.h:112-201`:
- `pending_queries_`: two FIFO queues, high-priority first (`Session.cpp:215-228`).
- `sent_queries_: map<msg_id, Query{container_message_id, net_query, is_acknowledged, is_unknown, connection_id,
  sent_at}>` plus an intrusive list in send order (used by the dead-query scan).
- `sent_containers_: map<container_msg_id, {ref_cnt, query_msg_ids}>`.
- `unknown_queries_`: msg_ids whose fate is unknown after a connection loss.
- `pending_invoke_after_queries_`: queries with dependencies waiting until `unknown_queries_` is empty.
- `MAX_INFLIGHT_QUERIES = 1024` (`Session.h:181`): at most 1024 entries in `sent_queries_`
  (`Session.cpp:1544`). If unknown queries exceed 1024 when a connection opens → `on_session_failed`
  (`:1295-1299`).

### 5.3 Query lifecycle

**Send** (`Session::loop` `:1537-1567`, `connection_send_query` `:1121-1179`). Only when
`auth_data_.is_ready(now)` (main key present, temp key valid if PFS, salt valid) and
`need_send_query()` = not closing, not checking the main key, bound (if PFS), not destroying the key:
1. Cancelled queries return immediately.
2. invokeAfter: every dependency must have been sent **in this same Session** (`ref->session_id() == our
   session_id`) and have a msg_id; otherwise fail with `ResendInvokeAfter` (204) so the SequenceDispatcher
   re-chains it. If there are dependencies and `unknown_queries_` is non-empty, park the query until the unknown set
   is empty (so the dependency state is known).
3. `msg_id = connection.send_query(bytes, gzip, msg_id, invoke_after_ids, quick_ack)`. A new msg_id is generated
   unless one is passed (bind).
4. Record `sent_queries_[msg_id]`, set `net_query.message_id`, hook up a cancellation event.

**Acknowledged** (`on_message_ack_impl`, `:767-798`): if the id is a known container, ack every query in it and drop
the container. Otherwise mark that query `is_acknowledged`, fire its quick-ack promise, drop its container entry, and
`mark_as_known`.

**Result OK** (`on_message_result_ok`, `:870-920`):
- Unknown req_msg_id (cancelled or already answered): drop it. If the dropped result is **>16 KB**, add it to
  `dropped_size_`; above **256 KB** total, return error code 2 → the connection closes (this stops the server
  streaming unwanted large results, e.g. cancelled file parts) and the counter resets.
- `auth_data.on_api_response()` (header removal, 5.12).
- "Steal authorization" hack: if the result constructor is `auth.authorization`, `auth.loginTokenSuccess` or
  `auth.sentCodeSuccess`, set the main DC to this DC (except for `auth.importAuthorization`), set `auth_flag` on the
  perm key and persist it (`:897-909`).
- Return the bytes to the caller and erase the entry.

**Result error** (`on_message_result_error`, `:922-1000`): see 5.7.

**Failed / resend** (`on_message_failed`, `:1002-1036`; triggered by bad_msg 16/20, bad_server_salt and state info
1/2/3): expand containers; for each query mark it known and `resend_query` → back into `pending_queries_` with
msg_id reset (**a new msg_id is generated**). Bind/check-key internal queries are failed with Resend instead.

**Message info** (`on_message_info`, `:1038-1091`), from msgs_state_info (source 1), msg_detailed_info (source 2) and
msg_new_detailed_info (source 0):
- If the query was cancelled meanwhile: return it.
- `state & 7`: `1, 2, 3` (unknown / not received / not received, id too high) → `on_message_failed` (resend).
  `4` (received) → ack. `0` → ack if `answer_msg_id != 0`, else treat as failed.
- If `answer_msg_id != 0` → `msg_resend_req` for the answer (`connection.resend_answer`). tdlib requests the
  re-delivery even if it already has the answer.

**Cancellation** (`raw_event`, `:532-554`): remove from `sent_queries_`, return it as cancelled, and send
`rpc_drop_answer#58e4a740 req_msg_id` now, or on the next connection (`to_cancel_message_ids_`) if none is ready.
Replies to `rpc_drop_answer` are ignored.

**Dead-query detection on pong** (`on_pong`, `:564-597`): only for the main connection and only after it has existed
for **60 s** (`MIN_CONNECTION_ACTIVE`):
- `unknown_queries_` still non-empty → error "No state info…" (closes the connection and opens a new one, which asks
  again);
- walking `sent_query_list_` from the newest: any query sent more than `60 + (server_now - ping_time)` seconds ago →
  `is_acknowledged = false` and error "No answer…". The connection closes and the query becomes unknown, so its state
  is asked on the next connection.

### 5.4 Connection lifecycle inside a Session

- `connection_open` (`:1181-1213`): needs the network flag and an auth key. Reuse `cached_connection_` (from the
  handshake, <10 s old) or `request_raw_connection(dc, allow_media_only, is_media, hash)` from ConnectionCreator.
  The main connection opens with `ask_info = true`.
- `connection_open_finish` (`:1231-1310`): ignore results from an older network generation. HTTP or TCP mode follows
  the transport type received. A TCP connection offered for the long-poll slot goes to the cache. Create the
  `SessionConnection`, `destroy_key()` if destroying, `set_online`, subscribe. If `ask_info`: send
  `msgs_state_req` for **all** `unknown_queries_` and `rpc_drop_answer` for all queued cancels.
- `on_closed(status)` (`:619-699`):
  - status `-404` (unknown auth key): see the cascade in 5.9;
  - for every `sent_queries_` entry on this connection that is **not acknowledged**:
    - status code **500** (e.g. transport `-429`) → return the query with error 500 "Session failed: …" (the
      dispatcher's delayer resends it after a backoff, on any session);
    - otherwise → `mark_as_unknown` (kept in `sent_queries_`; its fate is asked on the next connection with
      `msgs_state_req`; meanwhile invokeAfter dependents are parked).
  - Acknowledged-but-unanswered queries stay as they are and wait for the server to re-deliver the rpc_result on the
    new connection (the session survives the TCP reconnect, and the server keeps unacked results).
- Network change (`on_network`, `:320-337`): a new network generation closes both connections immediately.

### 5.5 new_session_created

`Session::on_new_session_created` (`:701-732`):
- On the main DC session: inject a fake `updatesTooLong#e317af7e` so the update layer runs `updates.getDifference`.
- Map `first_msg_id` to the container that carried it (if known).
- Every sent query whose `container_message_id < first_msg_id` is resent (`resend_query`, new msg_id).
- Without PFS: `last_success_timestamp_ = now`.

### 5.6 invokeAfter chains (SequenceDispatcher)

`td/telegram/SequenceDispatcher.cpp`. Queries with chain ids (e.g. sends within one chat) go through
`MultiSequenceDispatcher` (`:290-456`, a `ChainScheduler`). Each query gets `invoke_after = [parent query refs]`
(the previous in-flight queries of the same chains). The Session turns those into msg_ids (they must be in the
same session, see 5.3). Rules:
- Error `ResendInvokeAfter` (204), or 400 `MSG_WAIT_FAILED` / `MSG_WAIT_TIMEOUT` → resend the query and restart the
  chain from it (`:369-377`). `NetQuery::set_error` normalizes `MSG_WAIT_FAILED` with any code to 400
  (`NetQuery.cpp:137-139`).
- When a query is delayed by flood wait (`last_timeout_`), dependents with the same TL constructor have that time
  added to their `total_timeout`; if it exceeds the limit they fail with 429 (`:346-366`).
- `NetQueryDelayer`: when a delayed query that is part of an invokeAfter chain wakes up, it is failed with
  `ResendInvokeAfter` instead of re-sent, so the whole chain re-forms (`NetQueryDelayer.cpp:127-132`).
- Old single-chain implementation: at most 10 simultaneously waiting queries per chain (`MAX_SIMULTANEOUS_WAIT`).

### 5.7 Error handling by code

`Session::on_message_result_error` (`Session.cpp:922-1000`) first:
- An error message that is not valid UTF-8 becomes `INVALID_UTF8_ERROR_MESSAGE`.
- `error_code <= -10000 || >= 10000 || == 0` → treated as **500**.

| Code / message | Where | Behaviour |
|---|---|---|
| **401**, any message except `SESSION_PASSWORD_NEEDED` | Session `:933-967` | PFS + `AUTH_KEY_PERM_EMPTY` → drop the temp key (a new one is made and bound) and turn the error into 500 (retried). Otherwise: PFS on a non-main DC → drop the temp key, code → 500. If CDN, or a non-main session on a DC that is not the main DC → **drop the perm key** for that DC (re-imported via DcAuthManager), code → 500. Otherwise (main DC) → `auth_flag = false`, `G()->log_out(message)`, persist, `on_session_failed`. |
| 400 `CONNECTION_NOT_INITED` / `CONNECTION_LAYER_INVALID` | `:968-972` | `on_connection_not_inited()` (send the header again), code → 500 (retried) |
| **303** `PHONE_MIGRATE_X` / `NETWORK_MIGRATE_X` / `USER_MIGRATE_X` | Dispatcher `try_fix_migrate` `:390-407` | `set_main_dc_id(X)` (persisted as `"main_dc_id"`, flips the `is_main` flags, informs DcAuthManager), then resend to the main DC (or to `DcId(X)` if the query targeted an explicit DC) |
| 303 `FILE_MIGRATE_X`, `STATS_MIGRATE_X`, others | — | **not handled generically**: the 303 error is returned to the caller. File and stats code address DCs explicitly. |
| **420** `FLOOD_WAIT_N`, `SLOWMODE_WAIT_N`, `2FA_CONFIRM_WAIT_N`, `TAKEOUT_INIT_DELAY_N`, `FLOOD_PREMIUM_WAIT_N` | Delayer `:35-59` | `timeout = clamp(N, 1, 14 days)`, `next_timeout = 1`. `FLOOD_PREMIUM_WAIT` on upload/download also notifies "speed limited" |
| 420 `FLOOD_SKIP_FAILED_WAIT…` | Delayer `:60-64` | timeout 1 s |
| 420 `STORY_SEND_FLOOD_*`, `PREMIUM_SUB_ACTIVE_UNTIL_*` | Dispatcher `:102-104` | not delayed; returned to the caller |
| 420 `FROZEN_METHOD_INVALID` | Dispatcher `:100-101` | rewritten to 406 and returned |
| 420 other | Delayer | exponential backoff (below) |
| **500** `WORKER_BUSY_TOO_LONG_RETRY` | Delayer `:30-34` | timeout 1 s |
| 500 other (including "Session failed", internal 500s) | Delayer | exponential backoff |
| **negative** codes (`-503 Timeout` etc.) | Delayer | exponential backoff. `-503` on a query with `need_resend_on_503_ = false` → 502 "Bad Gateway" to the caller (`:86-91`) |
| 202 Resend (internal) | Dispatcher `:98-99` | resend immediately |
| 204 ResendInvokeAfter, 203 Canceled | — | returned to the caller or the SequenceDispatcher |
| 403 `RECAPTCHA_CHECK_*`, `APNS_VERIFY_CHECK_*` | Dispatcher (iOS/Android builds) | sent to the verifier |

NetQueryDelayer details (`NetQueryDelayer.cpp:22-112`):
```
if timeout == 0:                              # backoff case
    timeout = query.next_timeout              # starts at 1
    if timeout < 60: query.next_timeout *= 2  # sequence 1,2,4,8,16,32,64,64,...
else:
    query.next_timeout = 1
query.total_timeout += timeout
if query.total_timeout > query.total_timeout_limit:    # default 60 s; 8 s for bots; 86400 for export/import auth and getCdnConfig
    fail with 429 "Too Many Requests: retry after <timeout>"
else: resend after `timeout` seconds
```
So `FLOOD_WAIT_5` is retried transparently, while `FLOOD_WAIT_120` (or cumulative waits above 60 s) is surfaced
immediately as 429. **[MUST]** A query is retried only through this path: Session-level resends (5.3) do not count
toward `total_timeout`.

`dispatch_ttl_`: internal queries (bind, check key) are created with `dispatch_ttl_ = 0`, so any re-dispatch fails
them with "DispatchTtlError" instead of looping (`NetQueryDispatcher.cpp:150-154`). The Session then re-issues them.

### 5.8 Cross-DC authorization (DcAuthManager)

`DcAuthManager.cpp:107-245`. Runs only when the main DC key is authorized (`AuthKeyState::OK`). If the main DC is
known but not OK and `check_authorization_is_ok` was requested, it logs out. For every other internal DC whose key
is not OK:
```
Export:  auth.exportAuthorization#e5bfffcd(dc_id) on the MAIN DC (auth required, total_timeout_limit 86400)
Import:  auth.importAuthorization#a57a7dad(id, bytes) on the TARGET DC (AuthFlag::Off, limit 86400)
         success → the Session's "steal authorization" hook (5.3) sets auth_flag on that DC's perm key, persists it,
         and all listeners (SessionProxy, DcAuthManager) see AuthKeyState::OK
any error → back to Export
```
If a key is lost while in state Ok, the loop restarts at Export. The target DC's perm key is created on demand by its
Session handshake. Import runs on an unauthorized key, which is why the query is `AuthFlag::Off`.

### 5.9 PFS: temp keys, bind, checks, -404 cascade

**Temp key creation**: `Session::auth_loop` with `need_tmp_auth_key(now, margin)`: missing, or
`now > expires_at - margin` (margin 2 min if persisted, else 60 min). Lifetime 23..24 h random (1.6).

**Bind** (`connection_send_bind_key`, `Session.cpp:1362-1388`; `SessionConnection::encrypted_bind`,
`SessionConnection.cpp:856-878`):
```
nonce        = secure_int64
expires_at   = (int32) server_time(tmp_key.expires_at)       # local expiry converted to server unix time
msg_id       = next_message_id(now)                          # shared by inner and outer message
inner_obj    = bind_auth_key_inner#75a3f765 nonce temp_auth_key_id perm_auth_key_id temp_session_id=our session_id expires_at
inner_msg    = msg_id(8) | seq_no=0 (4) | len(4) | inner_obj                 # QueryImpl with empty header
encrypted_message = MTProto **v1** encrypt(inner_msg) with the PERM key:
                    salt = random int64, session_id = random int64, X = 0, v1 msg_key, v1 KDF, 0..15 random pad
outer query  = auth.bindTempAuthKey#cdd42a05 perm_auth_key_id nonce expires_at encrypted_message:bytes
               sent over the temp-key connection WITH THE SAME msg_id as the inner message
```
- `dispatch_ttl_ = 0`, sent with the normal header prefix if `need_header`.
- While unbound, **no other query is sent** (`need_send_query` requires `get_bind_flag()`), but pings and salts work.
- Result (`on_bind_result`, `:383-445`): `boolTrue` → `on_bind()` (temp key `auth_flag = true`), persist.
  `"DispatchTtlError"` → retry the bind. 400 `ENCRYPTED_MESSAGE_INVALID` → main-key suspicion (below). Other errors
  → close both connections (retry with a new connection).

**ENCRYPTED_MESSAGE_INVALID** handling:
```
has_immunity = !server_time_reliable || key_age < 60 s || (key_age > 1 day && last_success > now - 1 day)
   where key_age = server_time - main_key.created_at, last_success = last_bind_success (PFS) or last_success (non-PFS)
non-PFS session (use_pfs_ false, i.e. running a PFS check of the main key): no immunity → drop main key, log out
PFS session: no immunity → need_check_main_key = true, auth_data.use_pfs = false
             → send help.getNearestDc#1fb33026 encrypted directly with the MAIN key (dispatch_ttl 0)
               result OK or any error other than -404 → main key fine, back to PFS
               (the -404 case arrives as a transport close, handled below)
```

**-404 cascade** (`Session::on_closed`, `Session.cpp:627-662`; transport `-404` = "auth key not found"):
1. PFS active → drop the temp key, persist, regenerate (common after server restarts or long sleeps).
2. CDN session → drop the CDN key and fail the Session.
3. Destroying keys → treat as destroyed (drop the main key).
4. Non-PFS session (`use_pfs_` false) → switch `auth_data.use_pfs(true)`: create a temp key and try to bind it, which
   validates the perm key (bind failure goes to ENCRYPTED_MESSAGE_INVALID above).
5. `need_check_main_key_` (the main key was used directly for getNearestDc) → the main key is invalid: drop it; if
   this is not the main DC session and the DC is not the main DC, just fail the Session (the key is re-imported);
   otherwise **log out**.
6. Otherwise log only.
Handshake connections clear and restart on -404 (1.1). ConnectionCreator drops a client's cached `auth_data` if a
check ping gets -404 (`ConnectionCreator.cpp:1148-1153`).

**TempAuthKeyWatchdog** (`TempAuthKeyWatchdog.h:25-148`): the main-DC sessions register their temp key ids. When the
set changes, after a debounce of `min(sync_at, now + 0.1)` with `sync_at = now + 1.0` max, it sends
`auth.dropTempAuthKeys#8e48a188 except_auth_keys = [registered ids]` (unauthorized query, main DC). If more than one
key is registered, it re-syncs up to **6** more times every **5 s** (`RESYNC_DELAY`, `MAX_RESYNC_COUNT`). On error it
retries with the resync budget reset.

### 5.10 destroy_auth_key (log-out key wipe)

`NetQueryDispatcher::destroy_auth_keys` (`:315-332`) → each internal DC's main `SessionMultiProxy::destroy_auth_key`
→ `update_options(1, use_pfs = false, need_destroy = true)`: a single Session with `need_destroy_auth_key_`. That
Session never runs handshakes (`auth_loop` returns), never sends queries, and connects with the perm key;
`SessionConnection::destroy_key()` sends `destroy_auth_key#d1435160` once a salt is valid. Any
`destroy_auth_key_ok/none/fail` → drop the main key. If a pong arrives more than 60 s after sending without an
answer → close the connection and resend. `-404` while destroying → treat as destroyed. `DcAuthManager::destroy`
resolves when every DC key is Empty.

### 5.11 CDN DCs

- `DcId::external(id)` (the `is_external` flag) marks CDN; the options carry the `Cdn` flag (`DcOptions.h:53-58`).
- RSA keys come from `help.getCdnConfig` (1.13). No PFS. The "main" key is generated as a **temp-style** key
  (`p_q_inner_data_temp_dc`, lifetime 23-24 h, dc id positive) and never bound (`Session.cpp:1443`).
- The anonymous header is used (5.12). Updates on CDN sessions are errors. 401 or -404 → drop the key and recreate.

### 5.12 invokeWithLayer / initConnection header

`MtprotoHeader::gen_header` (`MtprotoHeader.cpp:23-113`), serialized once and prepended as raw bytes:
```
invokeWithLayer#da9b0d0d layer:int=203
initConnection#c1cd5ea9 flags:#
   flags.0 = MTProxy in use (non-anonymous only) → proxy:inputClientProxy#75588b3f address:string port:int
   flags.1 = !anonymous → params:JSONValue
   flags.10 = is_emulator                    (bit not in the public schema; tdlib sets it)
   api_id:int device_model system_version app_version system_lang_code lang_pack lang_code
   (anonymous: device_model = system_version = "n/a", lang_pack = lang_code = "")
   (lang_pack empty or custom language → both "", lang_code defaults to "en")
   params: the JSON object from the "connection_parameters" option with "tz_offset" (number) added or overwritten
query (follows)
```
- Default header for normal sessions, anonymous header for CDN (`Session.cpp:276-280`).
- **When it is attached** (`AuthData::get_header`, `AuthKey::need_header`, `AuthKey.h:42-53`): while
  `have_header_ || now < header_expires_at_`. `on_api_response()` (any successful rpc_result for a known query)
  calls `remove_header()`, which only acts if the key's `auth_flag` is set (main key authorized / temp key bound);
  it then stops sending the header **3 s later** (in-flight grace). The header is restored on
  `CONNECTION_NOT_INITED`/`CONNECTION_LAYER_INVALID`, on a new key or a new Session, and when the header changes
  (proxy or language change → `update_mtproto_header` → every Session is recreated).
- Consequence: an unauthorized connection (before login) sends initConnection with **every** query.

### 5.13 gzip policy

`NetQueryCreator::create` (`NetQueryCreator.cpp:64-102`), `gzencode`/`gzdecode` (`tdutils/td/utils/Gzip.cpp`):
- Compress requests of ≥ **128** bytes (≥1024 for bots). For requests ≥ **16384** bytes, first compress the middle
  1024 bytes; if that does not reach a ratio ≤0.9, skip compression (cheap entropy probe for already-compressed file
  parts).
- `gzencode(data, 0.9)`: output buffer = `0.9 × input`; if deflate does not finish within it, return empty (do not
  compress). Encoder: `deflateInit2(level 6, Z_DEFLATED, windowBits 15, memLevel 9 (MAX_MEM_LEVEL),
  Z_DEFAULT_STRATEGY)` (`Gzip.cpp:39`). **[quirk]** windowBits 15 produces a **zlib (RFC 1950)** stream, not gzip
  (RFC 1952). Telegram servers accept it inside `gzip_packed`.
- Decoder: `inflateInit2(MAX_WBITS + 32)` auto-detects gzip or zlib (`Gzip.cpp:50`). The output buffer grows
  ×2, then ×1.5 per step. **No decompression-size limit** (a hardening opportunity for the port). Any error → empty
  result.
- The compressed bytes replace the query body at creation; `QueryImpl` wraps them in `gzip_packed` (4.4).

---

## 6. ConnectionCreator: getting a socket to a DC

`td/telegram/net/ConnectionCreator.{h,cpp}`, `DcOptionsSet.{h,cpp}`, `DcOptions.h`.

### 6.1 Clients

Every Session asks for raw connections through `request_raw_connection(dc_id, allow_media_only, is_media, promise,
hash, auth_data)` (`ConnectionCreator.cpp:729-752`). `hash = Hash("Session<name> <raw_dc_id> <allow_media_only>")`
(`SessionProxy.cpp:229-230`) identifies a **client** (`ClientInfo`, `ConnectionCreator.h:106-155`). Each client keeps:
queued promises, `ready_connections` (`(conn, created_at)`, expire after **10 s**, `READY_CONNECTIONS_TIMEOUT`),
counters `pending_connections` and `checking_connections`, flood controls, a backoff, and an optional `AuthData` copy
for checks.

`client_loop` (`:934-1068`):
1. Exit if there is no network, the creator is closing, or a proxy is configured but its IP is not resolved yet.
2. Drop expired ready connections; hand ready connections to waiting promises (LIFO from `ready_connections`).
3. Loop: stop if no queries are waiting. In check mode stop at **3** concurrent checks; otherwise stop when
   `pending_connections >= queries.size()`.
4. Flood gate (6.2). When blocked → set a timer and stop.
5. `sanity_flood_control.add_event(now)`; when offline, also `backoff.add_event(now)`.
6. `find_connection` (6.3) → socket fd. On failure (no address, socket error): mark the option stat as error, retry
   in **0.1 s**.
7. `flood_control.add_event(now)` (failed socket creations are excluded on purpose).
8. `pending_connections++`; in check mode `stat.on_check()` and `checking_connections++`.
9. `prepare_connection` (proxy, TLS or direct, 6.5) → `client_create_raw_connection` → `RawConnection` with
   `extra.extra = network_generation` and `debug_str`. In check mode a **ping actor** verifies the connection first
   (6.6).
10. `client_add_connection`: success → `backoff.clear()`, push to `ready_connections`; failure → nothing extra
    (the flood controls already counted it). Then `client_loop` again.

### 6.2 Flood control and backoff constants

`FloodControlStrict::add_limit(duration_seconds, max_events)` means "no more than `max_events` events within any
`duration_seconds` window" (`tdutils/td/utils/FloodControlStrict.h:29-33`). From `ConnectionCreator.cpp:102-115`:

| Control | Limits | Applies |
|---|---|---|
| `sanity_flood_control` | ≤10 per 5 s | always |
| `flood_control` (offline) | ≤1 per 1 s, ≤2 per 4 s, ≤3 per 8 s | when not online and not logging out |
| `flood_control_online` | ≤4 per 1 s, ≤5 per 5 s | when online or logging out |
| `mtproto_error_flood_control` | ≤1 per 1 s, ≤2 per 4 s, ≤3 per 8 s | events = transport `-429` received (`on_mtproto_error`) |
| `backoff` (offline only) | delay 1, 2, 4, … s, capped at **16 s** on desktop and **300 s** on Android/iOS/watchOS/visionOS/Tizen | cleared on a successful connection |

`wakeup_at = max(active flood_control, mtproto_error_fc, sanity_fc[, backoff when offline])`
(`:997-1008`).

Reset events:
- `on_network(true)` → clear backoff and all three connection flood controls for every client, re-run `client_loop`;
  a new generation also re-resolves the proxy (`:659-681`);
- going online (or still offline, from offline) → clear backoff, sanity and online flood controls (`:683-695`);
- logging out → the same (`:696-709`).

### 6.3 DC address selection

**Option list.** `DcOptionsSet` holds the hard-coded defaults (6.8) and the config options. In
`add_dc_options(defaults)` followed by `add_dc_options(config)` (`ConnectionCreator.cpp:1197-1202`), each call puts
its options **first** in the order, so config options rank above defaults. Stats are shared per IP:port
(`init_option_stat`, `DcOptionsSet.cpp:189-199`).

**Config ordering** (`on_dc_options`, `ConnectionCreator.cpp:1164-1195`), a stable sort:
`dc_id` asc → IPv4 before IPv6 → non-media before media_only → `tcpo_only` (obfuscated-only) first → non-static before
static → for IPv4, `Hash<int64>(ipv4 + my_user_id)` asc (a per-user deterministic shuffle that spreads load).

**Candidate filter** (`find_all_connections`, `DcOptionsSet.cpp:53-137`):
- same `dc_id` (internal vs external matters), valid, and media_only options only when `allow_media_only`;
- TCP candidates (unless only_http), split into static and non-static; HTTP candidates (only_http) skip tcpo_only,
  static, and IPv6 unless `prefer_ipv6`;
- `use_static` (true only when a SOCKS5 proxy is used): use only static options if any exist, else drop IPv6 when any
  IPv4 exists. Without use_static: fall back to static options only if no others exist. `prefer_ipv6` disables
  use_static;
- `prefer_ipv6`: keep only IPv6 if any exist;
- if any media_only candidate exists, keep only media_only ones.

**Choice** (`find_connection`, `:139-174`), with `Stat{ok_at, error_at, check_at}` and
`state = Ok if ok_at is the latest, Checking if check_at is the latest, else Error`:
- pick the minimum by `(state: Ok < Error < Checking)`; among Ok, lower `order` first (TCP before HTTP on a tie);
  among Error, the **oldest** `error_at` first (round-robin away from recent failures); among Checking, `order`;
- `should_check = !chosen.is_ok() || chosen.use_http || (latest error_at among candidates) > now - 10`;
- no candidates → error and `ConfigManager::lazy_request_config`.

Stat updates (`detail::StatsCallback`, `ConnectionCreator.cpp:55-98`): `on_pong` → `ok_at = now` (a decrypted packet
with a key, a check ping, a successful handshake); `on_error` → `error_at = now` (RawConnection errors except code 2,
ping/read timeout, failed handshake, failed proxy handshake after TCP connect); `on_check` when a check starts.

### 6.4 Transport type per connection

`get_transport_type(proxy, info)` (`:780-807`):
- MTProxy → `ObfuscatedTcp(dc_id_obf, proxy.secret)` and the socket goes to the **proxy IP**;
- HTTP caching proxy → `Http` with secret `"<dc_ip>|basic <b64(user:pass)>"`;
- HTTP option → `Http`;
- otherwise → `ObfuscatedTcp(dc_id_obf, option.secret)`; option.secret is usually empty.

`dc_id_obf = (int16)(media_only_option ? -(raw + test?10000:0) : (raw + test?10000:0))`.

`prefer_ipv6 = option "prefer_ipv6" || (proxy in use && proxy IP is IPv6)` (`:812`).

### 6.5 Proxies

`Proxy` types: None, Socks5, HttpTcp (CONNECT), HttpCaching (plain HTTP to the proxy), Mtproto.
`prepare_connection` (`:847-932`):
- SOCKS5 → `Socks5` actor (3.7) targeting the chosen DC IP;
- HttpTcp → `HttpProxy` CONNECT to the DC IP;
- any connection whose transport secret is fake-TLS (`ee`) → `TlsInit` (3.5) using the secret's domain and its
  16-byte key;
- otherwise direct: the socket goes to RawConnection at once (no handshake step and **no connect timeout here**;
  liveness is enforced later by SessionConnection read/ping timeouts and, in check mode, the 10 s ping actor).
- All TransparentProxy flows have a **10 s** timeout.
- With MTProxy active, initConnection gets `inputClientProxy(server, port)` (5.12) and the session is recreated on
  any proxy change (`update_mtproto_header`, `:1217-1224`).
- Proxy DNS (`loop`/`on_proxy_resolved`, `:1419-1478`): resolve the proxy host; success is cached **5 min**, failure
  retries after **1 min**. When `expect_blocking` is set (the default), a resolver chain of Google DoH then native
  is used.

### 6.6 Connection check ("check mode") and the ping actor

When `DcOptionsSet` says `should_check` (and no proxy is used), new connections are verified before use
(`client_create_raw_connection`, `:1070-1121`): `create_ping_actor` (`td/mtproto/Ping.cpp`) with a **10 s** timeout
(`Ping.cpp:40`):
- without auth data: `PingConnectionReqPQ` sends `req_pq_multi` (unencrypted, msg_id 1) **twice** and measures the
  RTT of the second round trip (`PingConnection.cpp:31-91`, ping_count 2 at `Ping.cpp:29`);
- with PFS auth data (copied from the client, with a fresh session id taken from a pool; currently disabled at the
  Session side, `Session.cpp:1206-1208`): a full `SessionConnection` that waits for **2 pongs**; rtt = time between
  them (`PingConnection.cpp:93-203`).
The measured RTT is stored in `raw_connection.extra().rtt` and feeds `SessionConnection::rtt()`. Failure →
`stats.on_error()`.

### 6.7 Network change and online state

- `StateManager` increments `network_generation` on every network-type report (`StateManager.cpp:34-49`). Session and
  ConnectionCreator compare it: Sessions close their connections, ConnectionCreator clears flood state, and stale
  connections and handshakes are discarded.
- `online` (app in foreground / user active) shortens all keep-alive timeouts (4.10), triggers a fast liveness check
  (4.11), and relaxes reconnect flood control (6.2).
- `ConnectionManager` tokens count connected main sessions and proxies for the "Connecting / Updating / Ready" UI
  state (`ConnectionManager.{h,cpp}`); purely informational.

### 6.8 Default DC addresses

`get_default_dc_options` (`ConnectionCreator.cpp:1356-1417`), ports **443, 80, 5222** for every address (one option
per port × address; IPs within a DC are shuffled):

| DC | production IPv4 | production IPv6 | test IPv4 | test IPv6 |
|---|---|---|---|---|
| 1 | 149.154.175.50 | 2001:b28:f23d:f001::a | 149.154.175.10 | 2001:b28:f23d:f001::e |
| 2 | 149.154.167.51, 95.161.76.100 | 2001:67c:4e8:f002::a | 149.154.167.40 | 2001:67c:4e8:f002::e |
| 3 | 149.154.175.100 | 2001:b28:f23d:f003::a | 149.154.175.117 | 2001:b28:f23d:f003::e |
| 4 | 149.154.167.91 | 2001:67c:4e8:f004::a | — | — |
| 5 | 149.154.171.5 | 2001:b28:f23f:f005::a | — | — |

The default main DC is **1** (`NetQueryDispatcher.h:83`); the persisted `"main_dc_id"` overrides it.

### 6.9 DcOption flags

`DcOption::Flags` (`DcOptions.h:26`): `IPv6=1, MediaOnly=2, ObfuscatedTcpOnly=4, Cdn=8, Static=16, HasSecret=32`,
mapped from `dcOption#18b7a10d` flags `ipv6(0) media_only(1) tcpo_only(2) cdn(3) static(4) this_port_only(5,
ignored) secret(10)`. Options from `help.configSimple` access-point rules (`ipPort`/`ipPortSecret`) are always
`ObfuscatedTcpOnly` (`DcOptions.h:82-105`).

---

## 7. Cryptography helpers (tdutils)

### 7.1 AES-256-IGE (exact)

`AesIgeStateImpl` (`crypto.cpp:465-555`). The 32-byte IV is `iv[0..16] = "encrypted_iv"` (the previous ciphertext
block, c₋₁) and `iv[16..32] = "plaintext_iv"` (the previous plaintext block, p₋₁).
```
encrypt: for each 16-byte block p:  c = AES_ENC(key, p XOR c_prev) XOR p_prev;  c_prev = c; p_prev = p
decrypt: for each 16-byte block c:  p = AES_DEC(key, c XOR p_prev) XOR c_prev;  c_prev = c; p_prev = p
```
- tdlib's encrypt batches 31 blocks through AES-CBC (`data_xored[i] = data[i-2] ^ data[i]`, a CBC run over the IGE
  chain); the result is identical to the definition above (verified, 9.2).
- `aes_ige_encrypt/decrypt(key, iv, from, to)` **write the final `(c_prev || p_prev)` back into `iv`**
  (`crypto.cpp:578-590`). Callers that reuse the IV must copy it first (the handshake does, 1.8). Lengths must be
  multiples of 16 (CHECKed). In-place operation is allowed.
- Keys must be 32 bytes (AES-256 only).

### 7.2 AES-256-CTR

`AesCtrState` (`crypto.cpp:665-721`): `EVP_aes_256_ctr` with a 16-byte IV used as a **128-bit big-endian counter**
(the fallback code increments `counter[15]` with carry towards `counter[0]`). Streaming: any chunk sizes, state
persists. `decrypt == encrypt`. Used for obfuscated2 (3.3). (`AesCbcState` and `aes_cbc_*` exist and are used
elsewhere, e.g. passport and file encryption; not in MTProto.)

### 7.3 Hashes, HMAC, PBKDF2

- `sha1`, `sha256`, `sha512`, `md5` are plain OpenSSL digests (`crypto.cpp:773-938`); `Sha256State` is incremental.
- `hmac_sha256`, `hmac_sha512` (`:1020-1036`).
- `pbkdf2_sha256(password, salt, iterations, dest32)` / `pbkdf2_sha512` = `PKCS5_PBKDF2_HMAC` with output length equal
  to the hash size (`:940-983`). 2FA (SRP) uses `pbkdf2_sha512` with 100000 iterations in the password KDF (that
  layer is outside `net/`: `PasswordManager.cpp:52`).
- `crc32` = zlib CRC-32; also `crc32c`, a table-driven `crc64` (init and xorout `~0`), and `crc16` (polynomial
  0x1021, init 0) (`:1234-1395`). None are used by MTProto 2.0 itself.

### 7.4 BigNum

`BigNum.cpp`: `from_binary`/`to_binary(exact_size)` big-endian (to_binary left-pads to `exact_size`, CHECK
`exact_size >= num_bytes`); `to_le_binary`; `random(bits, top, bottom)` = `BN_rand`; `mod_exp` = `BN_mod_exp`;
`is_prime` (1.9); `gcd`, `mod_mul`, `mod_add`, `mod_sub`, `mod_inverse` used by pq and fake-TLS key generation.
Constant-time behaviour is not a goal there. For the Rust port: `num-bigint`, or `crypto-bigint` for `g_b`/RSA.

### 7.5 Random sources

`Random::secure_bytes`/`secure_int32/64`/`secure_uint32/64` = OpenSSL RAND (CSPRNG). These are used for nonces,
new_nonce, b, padding, session_id, salt-before-known, obfuscation header, TLS hello randomness and msg_id low bits.
`Random::fast` (non-crypto) is used only for the pq rho constants, the temp key lifetime, the 0..5 s ping jitter and
the session tie-break. GREASE uses `secure_bytes`; the ClientHello extension permutation uses `Random::shuffle`.

---

## 8. Things tdlib does that typical clients get wrong (port checklist)

1. **Constant-time msg_key comparison**, done **before** trusting any length field; then the four length checks
   (`len % 4`, `len <= tail - 16`, `12 <= pad <= 1024`) (`Transport.cpp:264-290`).
2. **X = 8 for incoming, X = 0 for outgoing** in both msg_key and KDF2. The msg_key input starts at
   `auth_key[88 + X]`, the KDF2 inputs at `auth_key[X]` and `auth_key[40 + X]`.
3. **Session checks on every packet**: session_id equality, odd msg_id, a 1000-entry duplicate window with
   "too old ⇒ new session", and a server-time window of (-300 s, +30 s) once time is synced (`AuthData.cpp:139-167`).
4. **Duplicates are acked, not just dropped** (`SessionConnection.cpp:728-731`); otherwise the server keeps resending.
5. **Ack before processing**, for every odd seq_no message including each container element; batch acks (≤30 s, flush
   at 100).
6. **Updates have their own duplicate filter on the inner msg_id** (1000 entries); a too-old update fails the
   session.
7. **Monotone time difference**: only ever increase it from received msg_ids, but force a reset when a response's
   msg_id is more than 15 s older than its request (`SessionConnection.cpp:251`, `416`), and on bad_msg 17.
8. **msg_id generation**: server time, random low 22 bits, `& ~3`, strictly increasing by `+8*k`.
9. **The container id is generated after all inner ids**; a single query whose msg_id has gone stale (older than
   150 s) is wrapped in a fresh container instead of being re-sent bare.
10. **Resend means a new msg_id** (bad_msg 16/20, bad_server_salt, state 1-3). Re-sending the same msg_id causes
    error 16/20 again.
11. **Don't blindly resend after a disconnect**: unacked queries become "unknown" and are resolved with
    `msgs_state_req` on the next connection of the same session; resend only if the server says 1/2/3. Acked
    queries just wait for the server to re-deliver the rpc_result. This avoids double execution of non-idempotent
    calls.
12. **invokeAfter dependents wait while any query state is unknown**, and dependencies must belong to the same
    session_id (else the chain is rebuilt).
13. **new_session_created ⇒ resend queries with ids below first_msg_id, and run getDifference**.
14. **Salt**: valid for 10 min after a bad_server_salt; require 60 s of remaining validity; fetch 64 future salts at
    most once per 60 s; switch to the newest started salt; hold queries (not pings) until a salt is valid.
15. **ping_delay_disconnect, not ping**, with `disconnect_delay = local_timeout + 2`, so the server closes
    half-open TCP connections.
16. **Any decrypted packet counts as a pong** (big downloads must not trip the ping timeout).
17. **Foreground fast check**: on going online, require a packet within `rtt()` (≥2 s) on existing connections.
18. **Dead-query detector**: after a connection has lived 60 s, a pong with unknown-state queries outstanding, or a
    query unanswered for 60 s + ping RTT, forces a reconnect.
19. **Drop runaway results**: more than 256 KB of results for unknown (cancelled) queries closes the connection.
20. **DH checks**: exactly 2048-bit prime, g ∈ {2..7} with the residue table, a safe prime (cached; built-in known
    prime), and `g_a, g_b ∈ [2^1984, p - 2^1984]`. Check `new_nonce_hash1`. Check the SHA1 of `answer_with_hash` and
    the `< 16` padding.
21. **RSA_PAD retry loop** when `key_aes_encrypted >= n`. `data` ≤ 144 bytes; the IGE IV is 32 zero bytes; only the
    first 192 bytes are reversed.
22. **Temp keys**: random 23-24 h lifetime, regenerate 1 h before expiry (2 min if persisted), bind with
    MTProto **1.0** inner encryption using the **same msg_id** inner and outer and a random salt and session_id
    inside, `expires_at` in server time, and send nothing else until bound.
23. **-404 ladder** (5.9) instead of instantly wiping the perm key; immunity rules for ENCRYPTED_MESSAGE_INVALID.
24. **AUTH_KEY_PERM_EMPTY** (401 under PFS) ⇒ drop only the temp key and retry.
25. **401 on a non-main DC ⇒ drop that DC's key and re-import**, not log out.
26. **CONNECTION_NOT_INITED / CONNECTION_LAYER_INVALID ⇒ re-send initConnection and retry**; send initConnection on
    every query until the first successful response with an authorized/bound key, then for 3 s more.
27. **Flood wait**: transparent retry up to a cumulative 60 s per query (configurable per query), else surface 429;
    backoff 1→64 s for 5xx/negative codes.
28. **Error code sanity**: |code| ≥ 10000 or 0 ⇒ 500; non-UTF-8 message ⇒ placeholder.
29. **Obfuscation header**: reject `0xef` first byte, the 7 forbidden first words, and a zero second word; the dc_id
    is a signed int16 with +10000 for test and a negative sign for media; keys are derived from the forward header
    and from the reversed header.
30. **Fake-TLS**: a fixed 517-byte ClientHello, GREASE pairs, a real-looking X25519 key, the HMAC-ed random with the
    timestamp XORed into the last 4 bytes, server-side HMAC verification, ≤2878-byte records, and a single CCS
    before the first data record.
31. **Quick-ack tokens are per raw connection** and are the first 4 bytes of msg_key_large (LE) with the top bit
    set; an unknown or invalid quick ack is ignored, never an error.
32. **Bucketed padding** (64…1280, then 448 steps) hides message sizes on plain obfuscated connections; random
    padding (0..255 + 12) for `dd`/`ee` MTProxy secrets.
33. **Unknown bad_msg codes and seq_no errors close the connection, not the session**; bad_msg 17 recreates the
    session.
34. **The server_salt in new_session_created is ignored** by tdlib; nothing breaks because bad_server_salt corrects
    it. (Using it is harmless and saves a round trip.)
35. **The gzip encoder emits zlib**; the decoder must auto-detect gzip or zlib; compress only if it saves ≥10 %.
36. **Max inbound frame of 4 MB + 1 KB**; outbound frames < 16 MB.
37. **The handshake parses with trailing bytes allowed** (transport padding) and uses its own deadlines (6 s / 8 s /
    10 s).
38. **Reconnect flood control** differs online and offline, plus a separate limiter for `-429`.

Things tdlib does **not** do that the Rust engine could add without breaking interop: check the incoming salt; use
the salt from new_session_created; send a non-zero msg_id in the handshake; bound gzip decompression; dedupe
`unique_id` of new_session_created; check `msg_id % 4 ∈ {1,3}` for server messages.

---

## 9. Test vectors

### 9.1 Vectors taken verbatim from tdlib tests

**Hash and MAC vectors** (`tdutils/test/crypto.cpp:19, 273-331`). Inputs:
`strings = {"", "1", "short test string", "a" × 1000000}`. HMAC key = `"cucumber"`. tdlib stores the expected
values as base64; the hex was decoded and checked with Python `hashlib`/`hmac`:

| # | SHA1 (b64 / hex) | SHA256 (b64 / hex) | HMAC-SHA256("cucumber", s) (b64 / hex) |
|---|---|---|---|
| 0 | `2jmj7l5rSw0yVb/vlWAYkK/YBwk=` / `da39a3ee5e6b4b0d3255bfef95601890afd80709` | `47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=` / `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `t33rfT85UOe6N00BhsNwobE+f2TnW331HhdvQ4GdJp8=` / `b77deb7d3f3950e7ba374d0186c370a1b13e7f64e75b7df51e176f43819d269f` |
| 1 | `NWoZK3kTsExUV00Ywo1G5jlUKKs=` / `356a192b7913b04c54574d18c28d46e6395428ab` | `a4ayc/80/OGda4BO/1o/V0etpOqiLx1JwB5S3beHW0s=` / `6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b` | `BQl5HF2jqhCz4JTqhAs+H364oxboh7QlluOMHuuRVh8=` / `0509791c5da3aa10b3e094ea840b3e1f7eb8a316e887b42596e38c1eeb91561f` |
| 2 | `uRysQwoax0pNJeBC3+zpQzJy1rA=` / `b91cac430a1ac74a4d25e042dfece9433272d6b0` | `yPMaY7Q8PKPwCsw64UnDD5mhRcituEJgzLZMvr0O8pY=` / `c8f31a63b43c3ca3f00acc3ae149c30f99a145c8adb84260ccb64cbebd0ef296` | `NCCPuZBsAPBd/qr3SyeYE+e1RNgzkKJCS/+eXDBw8zU=` / `34208fb9906c00f05dfeaaf74b279813e7b544d83390a2424bff9e5c3070f335` |
| 3 | `NKqXPNTE2qT2Husr260nMWU0AW8=` / `34aa973cd4c4daa4f61eeb2bdbad27316534016f` | `zcduXJkU+5KBocfihNc+Z/GAmkiklyAOBG05zMcRLNA=` / `cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0` | `mo3ahTkyLKfoQoYA0s7vRZULuH++vqwFJD0U5n9HHw0=` / `9a8dda8539322ca7e8428600d2ceef45950bb87fbebeac05243d14e67f471f0d` |

- MD5 (b64): `1B2M2Y8AsgTpgAmY7PhCfg==`, `xMpCOKC5I4INzFCab3WEmw==`, `vwBninYbDRkgk+uA7GMiIQ==`, `dwfWrk4CfHDuoqk1wilvIQ==`.
- HMAC-SHA512("cucumber", s) (b64):
  `o28hTN1m/TGlm/VYxDIzOdUE4wMpQzO8hVcTkiP2ezEJXtrOvCjRnl20aOV1S8axA5Te0TzIjfIoEAtpzamIsA==`,
  `32X3GslSz0HDznSrCNt++ePRcFVSUSD+tfOVannyxS+yLt/om11qILCE64RFTS8/B84gByMzC3FuAlfcIam/KA==`,
  `BVqe5rK1Fg1i+C7xXTAzT9vDPcf3kQQpTtse6rT/EVDzKo9AUo4ZwyUyJ0KcLHoffIjul/TuJoBg+wLz7Z7r7g==`,
  `WASmeku5Pcfz7N0Kp4Q3I9sxtO2MiaBXA418CY0HvjdtmAo7QY+K3E0o9UemgGzz41KqeypzRC92MwOAOnXJLA==`.
- CRC32 (zlib): `0, 2212294583, 3013144151, 3693461436`. CRC32C: `0, 2432014819, 1077264849, 1131405888`.
  CRC64: `0, 3039664240384658157, 17549519902062861804, 8794730974279819706`. CRC16: `0, 9842, 25046, 37023`.

**PBKDF2-HMAC-SHA256, 32-byte output** (`tdutils/test/crypto.cpp:240-271`). Loop order: password ∈
{"", "qwerty", "a"×1000} (outer), salt ∈ {"", "qwerty", "a"×1000}, iterations ∈ {1, 2, 1000} (inner). All 27 were
re-verified with Python `hashlib.pbkdf2_hmac`:
```
984LZT0tcqQQjPWr6RL/3Xd2Ftu7J6cOggTzri0Pb60=  lzmEEdaupDp3rO+SImq4J41NsGaL0denanJfdoCsRcU=  T8WKIcEAzhg1uPmZHXOLVpZdFLJOF2H73/xprF4LZno=
NHxAnMhPOATsb1wV0cGDlAIs+ofzI6I4I8eGJeWN9Qw=  fjYi7waEPjbVYEuZ61/Nm2hbk/vRdShoJoXg4Ygnqe4=  GhW6e95hGJSf+ID5IrSbvzWyBZ1l35A+UoL55Uh/njk=
BueLDpqSCEc0GWk83WgMwz3UsWwfvVKcvllETSB/Yq8=  hgHgJZNWRh78PyPdVJsK8whgHOHQbNQiyaTuGDX2IFo=  T2xdyNT1GlcA4+MVNzOe7NCgSAAzNkanNsmuoSr+4xQ=
/f6t++GUPE+e63+0TrlInL+UsmzRSAAFopa8BBBmb2w=  8Zn98QEAKS9wPOUlN09+pfm0SWs1IGeQxQkNMT/1k48=  sURLQ/6UX/KVYedyQB21oAtMJ+STZ4iwpxfQtqmWkLw=
T9t/EJXFpPs2Lhca7IVGphTC/OdEloPMHw1UhDnXcyQ=  TIrtN05E9KQL6Lp/wjtbsFS+KkWZ8jlGK0ErtaoitOg=  +1KcMBjyUNz5VMaIfE5wkGwS6I+IQ5FhK+Ou2HgtVoQ=
h36ci1T0vGllCl/xJxq6vI7n28Bg40dilzWOKg6Jt8k=  9uwsHJsotTiTqqCYftN729Dg7QI2BijIjV2MvSEUAeE=  /l+vd/XYgbioh1SfLMaGRr13udmY6TLSlG4OYmytwGU=
7qfZZBbMRLtgjqq7GHgWa/UfXPajW8NXpJ6/T3P1rxI=  ufwz94p28WnoOFdbrb1oyQEzm/v0CV2b0xBVxeEPJGA=  T/PUUBX2vGMUsI6httlhbMHlGPMvqFBNzayU5voVlaw=
viMvsvTg9GfQymF3AXZ8uFYTDa3qLrqJJk9w/74iZfg=  HQF+rOZMW4DAdgZz8kAMe28eyIi0rs3a3u/mUeGPNfs=  7lBVA+GnSxWF/eOo+tyyTB7niMDl1MqP8yzo+xnHTyw=
aTWb7HQAxaTKhSiRPY3GuM1GVmq/FPuwWBU/TUpdy70=  fbg8M/+Ht/oU+UAZ4dQcGPo+wgCCHaA+GM4tm5jnWcY=  DJbCGFMIR/5neAlpda8Td5zftK4NGekVrg2xjrKW/4c=
```
For example, `("", "", 1)` = `f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad` and
`("qwerty", "qwerty", 1000)` = `fb529c3018f250dcf954c6887c4e70906c12e88f884391612be3aed8782d5684`.

**AES-IGE, AES-CTR, AES-CBC with deterministic inputs** (`tdutils/test/crypto.cpp:45-217`). The generator is a
32-bit LCG, reproducible in any language:
```
seed = length (u32)
next_byte(): seed = seed * 123457567 + 987651241  (mod 2^32); return (seed >> 23) & 255
plaintext = next_byte() × length; then key = next_byte() × 32; then iv = next_byte() × (32 for IGE, 16 for CTR/CBC)
expected = zlib_crc32(ciphertext)
```
- **IGE** (one IV of 32 bytes), lengths `{0, 16, 32, 256, 1024, 65536}` → crc32 `{0, 2045698207, 2423540300, 525522475,
  1545267325, 724143417}`. Decrypting must give back the plaintext. Chunked processing must match one-shot
  processing (the IV is carried over).
- **CTR**, lengths `{0, 1, 31, 32, 33, 9999, 10000, 10001, 999999, 1000001}` → crc32 `{0, 1141589763, 596296607,
  3673001485, 2302125528, 330967191, 2047392231, 3537459563, 307747798, 2149598133}`. The same plaintext and key with
  `iv = ff × 16` (exercises the 128-bit counter wrap) → `{0, 2053451992, 1384063362, 3266188502, 2893295118,
  780356167, 1904947434, 2043402406, 472080809, 1807109488}`. Encryption is streamed in random chunk sizes.
- **CBC** (16-byte IV), lengths `{0, 16, 32, 256, 1024, 65536}` → `{0, 3617355989, 3449188102, 186999968, 4244808847,
  2626031206}`.
- All three sets were re-verified with an independent Python implementation (CommonCrypto AES-ECB plus hand-written
  modes). Concrete small cases from the same generator:
  ```
  IGE len=16: key=d48738a34a08cf4f4675a41f19d7cf52a7a7fc9962cf66174ea7d85bfdf8ad67
              iv =92fcd0adc15bbb0dcb3079d88402a5d04ecc6b261ef6847a74593cdf653f6ed4
              pt =6153cb81c0c03e6ffa5422dc1f595247
              ct =11f422b6abcd37a927c1a8ebdbccdd5f
  IGE len=32: key=3ef36a602c7c290e9f61268b6ea7ff16fec2e55b47989477d17d5df8b1381eda
              iv =8efd468ba172d4e8aeaa573d0e2ced49a7ed4639f052a1a8ef30cba53dcb25ad
              pt =4c7b4aeccf62f232603b211f558bf57195491f5397d8db64620efab08c30dab5
              ct =c7dc97b92ae0375496947e56678e2bf4b1b5f178a91dfa2ddeb69d9d5db2361c   (crc32 2423540300)
              iv after encrypt (tdlib writes it back) = ct[16..32] || pt[16..32]
              = b1b5f178a91dfa2ddeb69d9d5db2361c95491f5397d8db64620efab08c30dab5
  CTR len=33: key=88a1fdb96755bdf47dab6e656225f1453eb6b640cbc2bd71521b9964ac056a12
              iv =4034e1e909c93ec28f5853e8ebe58118
              pt =5b1d9203f04c2d5e562911e4d8ce40f331e52d7e8ca5bc0583d73f9a24d57bdce7
              ct =469e0b6ec02cc1d0f5d4e6ce9391404668ec56e7aee6be91bb77c09ff8eacdf79c   (crc32 2302125528)
  ```
- `TEST(Crypto, Aes)` (single-block AES with tdlib's Xorshift128plus(123) RNG, crc32 of the ciphertext =
  178892237) depends on tdlib's RNG and is not portable as a vector.

**pq factorization** (`tdutils/test/pq.cpp:120-162`):
- u64 function: `pq_factorize(0)=1, (1)=1, (2)=1, (3)=1, (4)=2, (5)=1, (21)=3`,
  `pq_factorize(179424611 × 179424673 = 32193202156827203 = 0x725f8bfabd7243) = 179424611`.
- Big path (pq ≥ 2^63): `4294467311 × 4294467449 = 18442450077884059639 = 0xfff0bea230278ff7`, so
  `p = 4294467311 (0xfff0bdef)`, `q = 4294467449 (0xfff0be79)`.
- Generated suites: every prime pair from {primes < 100, 5 primes ≥ 2^31-500000, 2 primes ≥ 2^32-500000, 1 prime ≥
  2^39-500000}, and "server-like" pairs with one prime from each [i×10^8, (i+1)×10^8), i = 10..19. Outputs are
  minimal big-endian byte strings with `p ≤ q`.
- Well-known spec sample (not in tdlib tests; product checked): `pq = 0x17ED48941A08F981` →
  `p = 0x494C553B (1229739323)`, `q = 0x53911073 (1402015859)`.

**RSA** (`test/mtproto.cpp:725-742`): unit-test key (Appendix B.3), `RSA::get_fingerprint() == -7596991558377038078`
(`0x9692106da14b9f02`), `size == 256`; `rsa.encrypt(pem_text[0..256])` (the first 256 bytes of the PEM string,
including `-----BEGIN RSA PUBLIC KEY-----\n`, taken as a big-endian integer) → `base64(SHA256(ciphertext)) ==
"U2nJEtB2AgpHrm3HB0yhpTQgb0wbesi9Pv/W1v/vULU="`. Re-verified in Python with textbook RSA.

**GREASE** (`test/mtproto.cpp:663-672`): for 10000 generated bytes, every byte has low nibble `0xA`, and
`s[i] != s[i-1]` for every odd i.

**Fake-TLS negative test** (`test/mtproto.cpp:674-723`): a TlsInit against `www.google.com:443` with secret
`"0123456789secret"` must fail with exactly `"Response hash mismatch"` (a real TLS server answers but cannot produce
the HMAC). A useful smoke test for the ServerHello parser.

**Live handshake tests** (`test/mtproto.cpp:257-439`): a handshake against test DC `149.154.167.40:80` with
`dc_id = 10002`, `expires_in = 3600`, plain `TransportType::Tcp` (intermediate, no obfuscation), the test RSA key,
`DhCallback = nullptr` (full primality test each time). Also `Mtproto_ping` (3 × req_pq) and `FastPing`. These need
the network; they are useful as integration tests for the Rust engine.

### 9.2 Derived vectors (computed for this digest; not from tdlib)

Computed with a Python reimplementation that follows the tdlib code above. That implementation reproduces every
tdlib vector in 9.1 (IGE/CTR/CBC crc32s, PBKDF2, the RSA fingerprint and RSA output), so these values check the
*composition* of primitives. They are not a second authority: if a Rust result differs, re-read the tdlib reference
first.

Common inputs: `auth_key = bytes(i % 256 for i in 0..255)` (00 01 02 … ff), `msg_key = 00 01 … 0f`.
```
SHA1(auth_key)       = 4916d6bdb7f78e6803698cab32d1586ea457dfc8
auth_key_id          = LE64(SHA1[12..20]) = 0xc8df57a46e58d132   (wire bytes 32d1586ea457dfc8)

KDF2 X=0: aes_key = 704ed09c8b41668ae8f99d244738f71dbddc44469b6bbd4aa8573dd042bd059e
          aes_iv  = 4d266000a550edabbf4c7ce40fd0043cc92230184cd317a5cc9c2482fd3b9318
KDF2 X=8: aes_key = 217725799b245806458174a1fcfbc883906807b15033fdd0ea2b4d69cf9c364e
          aes_iv  = 669a6538917a4fa56ca32360a431c9160be4ad887140980dab91ce7bdc47ffbc
KDF1 X=0: aes_key = 17d7295ca9213d1ab656acdb1ad48b2ea7f3a8f7095098d5508b900bbd5fccfc
          aes_iv  = 2d7d16a65a84108e9805656caa474501cc580aa2edc33abfd0bfad785464d1c6
KDF1 X=8: aes_key = bb17b07eb91110647098b069bd1a9b6fe5c4bcc3c31f8e67e831d07a61085f68
          aes_iv  = 5197fc1e25b41fe36f18b5a3a8b2b36cb2cb061f1f157b3514fe42e74fb58359
```
Handshake helpers with `server_nonce = 00 01 … 0f` and `new_nonce = 20 21 … 3f`:
```
tmp_aes_key = 867aae22fba1fba9ab6d4eb1e5f965bd036d84f3a867f358bbf91beae86c38e9
tmp_aes_iv  = a6d3105c0138f8b458b1c56a7fe8c6e6e1436b219d7f2c12af8f95b420212223
server_salt = LE64(new_nonce[0..8]) ^ LE64(server_nonce[0..8]) = 0x2020202020202020
with the auth_key above:
new_nonce_hash1 = SHA1(new_nonce || 01 || SHA1(auth_key)[0..8])[4..20] = a6d02fe60a733a741a2754b0b8e3f71b
new_nonce_hash2 (02)                                                  = acec5b07881b58ed91b679cd74817e07
new_nonce_hash3 (03)                                                  = f1ca00681b954ee0eaeace382a5acd3d
```
A complete client→server MTProto 2.0 packet (basic padding policy; **zero** padding bytes instead of random, for
determinism): `salt = 0x1122334455667788`, `session_id = 0x0102030405060708`, `msg_id = 0x5f00000000000004`,
`seq_no = 1`, body = `ping_delay_disconnect#f3427b8c ping_id = 0x0123456789abcdef disconnect_delay = 75` (16 bytes),
so `data_size = 32`, `align16(16+32+12) = 64`, bucket 64, 16 padding bytes:
```
to_encrypt (64 B)  = 8877665544332211 0807060504030201 040000000000005f 01000000 10000000
                     8c7b42f3 efcdab8967452301 4b000000 00000000000000000000000000000000
msg_key_large      = eaa46ef1c7862ef184982f7a64ace3c03551c5f45353d75d7605637002f9b074
msg_key            = 84982f7a64ace3c03551c5f45353d75d
quick_ack token    = 0xf16ea4ea   (LE32(eaa46ef1) | 0x80000000)
wire packet        = 32d1586ea457dfc8 84982f7a64ace3c03551c5f45353d75d
                     e86c851d3bafee1d8e6939974dba095e6c5bec6bbb69ffe1bfcfcaadcee15cb8
                     612d882cf909c407ae83bb4d9d976d10b270463f32cafdd347281cde9ec80cc1
```
Obfuscated2 header with `random part = 00 01 02 … 3f` (so bytes 0..55 are 00..37), dc_id = 2:
```
no secret, intermediate (ee):
  header_plain = 000102…3637 eeeeeeee 0200 3e3f
  enc_key = 08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627  enc_iv = 28292a2b2c2d2e2f3031323334353637
  dec_key = 37363534333231302f2e2d2c2b2a292827262524232221201f1e1d1c1b1a1918  dec_iv = 17161514131211100f0e0d0c0b0a0908
  sent      = 000102…3637 || 4618255e1c00fd5d
  then intermediate frame "04000000 00000000" (len 4, payload 00000000) encrypts to 36a9c12838f16541
secret = 00 01 … 0f, padded intermediate (dd):
  header_plain = 000102…3637 dddddddd 0200 3e3f
  enc_key = SHA256(header[8..40] || secret) = 58e43c97ffd7f8263296692cd28695bc3e29e03707aa98faa3be518061df6e67
  dec_key = SHA256(rev[8..40]   || secret) = f4effaeae14a397813a60bc9ff0da4a25a01c756fe62eeed037a5841d3cadcee
  (ivs as above)
  sent      = 000102…3637 || 7fb7a7adbb08ade4
  next frame "04000000 00000000" → 52decc6a1a716c4d
```
(`header_plain` here ignores the forbidden-prefix rule: first word `0x03020100` and second word `0x07060504` are both
allowed, so this header is also a legal tdlib output.)

Recommended additional Rust unit tests, with the expected behaviour taken from tdlib's code: the duplicate checker
(insert/duplicate/too-old at N=1000), `next_message_id` monotonicity with a frozen clock (`+8k` bumps), the padding
size function in basic mode (message_data_length → total packet bytes incl. auth_key_id+msg_key: 0→88, 4→88, 8→88, 12→88, 16→88, 20→88, 36→152, 100→216, 1236→1304, 1240→1752, 1700→2200),
the container decision, and the bad_msg code table.


---

## Appendix A. `td/generate/scheme/mtproto_api.tl` (verbatim, 87 lines)

Copied byte-for-byte from the tdlib checkout. Notes for implementers (not part of the file):
- `rpc_result#f35c6d01`, `msg_container#73f1f8dc`, `message`, `msg_copy`, `ping#7abe77ec`, `destroy_session*` are
  commented out here; tdlib handles `rpc_result` and `msg_container` by hand (`SessionConnection.cpp:44-47`,
  `CryptoStorer.h:26-29`) and never uses the others.
- `server_DH_params_fail` is absent, so tdlib treats it as a parse error (1.8).
- The client uses `req_pq_multi` only (never the legacy `req_pq#60469778`).
- Vectors are boxed (`vector#1cb5c415`) when written as `Vector<...>`. `future_salts.salts` is a **bare**
  `vector<future_salt>`: the count is followed directly by bare `future_salt` bodies (no `0x1cb5c415`, no
  per-item constructor id).

```tl
int ? = Int;
long ? = Long;
double ? = Double;
string ? = String;

dummyHttpWait = HttpWait;

vector {t:Type} # [ t ] = Vector t;

int128 4*[ int ] = Int128;
int256 8*[ int ] = Int256;

resPQ#05162463 nonce:int128 server_nonce:int128 pq:string server_public_key_fingerprints:Vector<long> = ResPQ;

p_q_inner_data_dc#a9f55f95 pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 dc:int = P_Q_inner_data;
p_q_inner_data_temp_dc#56fddf88 pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 dc:int expires_in:int = P_Q_inner_data;

server_DH_params_ok#d0e8075c nonce:int128 server_nonce:int128 encrypted_answer:string = Server_DH_Params;

server_DH_inner_data#b5890dba nonce:int128 server_nonce:int128 g:int dh_prime:string g_a:string server_time:int = Server_DH_inner_data;

client_DH_inner_data#6643b654 nonce:int128 server_nonce:int128 retry_id:long g_b:string = Client_DH_Inner_Data;

dh_gen_ok#3bcbf734 nonce:int128 server_nonce:int128 new_nonce_hash1:int128 = Set_client_DH_params_answer;
dh_gen_retry#46dc1fb9 nonce:int128 server_nonce:int128 new_nonce_hash2:int128 = Set_client_DH_params_answer;
dh_gen_fail#a69dae02 nonce:int128 server_nonce:int128 new_nonce_hash3:int128 = Set_client_DH_params_answer;

bind_auth_key_inner#75a3f765 nonce:long temp_auth_key_id:long perm_auth_key_id:long temp_session_id:long expires_at:int = BindAuthKeyInner;

//rpc_result#f35c6d01 req_msg_id:long result:string = RpcResult;
rpc_error#2144ca19 error_code:int error_message:string = RpcError;

rpc_answer_unknown#5e2ad36e = RpcDropAnswer;
rpc_answer_dropped_running#cd78e586 = RpcDropAnswer;
rpc_answer_dropped#a43ad8b7 msg_id:long seq_no:int bytes:int = RpcDropAnswer;

future_salt#0949d9dc valid_since:int valid_until:int salt:long = FutureSalt;
future_salts#ae500895 req_msg_id:long now:int salts:vector<future_salt> = FutureSalts;

pong#347773c5 msg_id:long ping_id:long = Pong;

//destroy_session_ok#e22045fc session_id:long = DestroySessionRes;
//destroy_session_none#62d350c9 session_id:long = DestroySessionRes;

new_session_created#9ec20908 first_msg_id:long unique_id:long server_salt:long = NewSession;

//msg_container#73f1f8dc messages:vector<%Message> = MessageContainer;
//message msg_id:long seqno:int bytes:int body:string = Message;
//msg_copy#e06046b2 orig_message:Message = MessageCopy;

gzip_packed#3072cfa1 packed_data:string = GzipPacked;

msgs_ack#62d6b459 msg_ids:Vector<long> = MsgsAck;

bad_msg_notification#a7eff811 bad_msg_id:long bad_msg_seqno:int error_code:int = BadMsgNotification;
bad_server_salt#edab447b bad_msg_id:long bad_msg_seqno:int error_code:int new_server_salt:long = BadMsgNotification;

msg_resend_req#7d861a08 msg_ids:Vector<long> = MsgResendReq;
msgs_state_req#da69fb52 msg_ids:Vector<long> = MsgsStateReq;
msgs_state_info#04deb57d req_msg_id:long info:string = MsgsStateInfo;
msgs_all_info#8cc0d131 msg_ids:Vector<long> info:string = MsgsAllInfo;
msg_detailed_info#276d3ec6 msg_id:long answer_msg_id:long bytes:int status:int = MsgDetailedInfo;
msg_new_detailed_info#809db6df answer_msg_id:long bytes:int status:int = MsgDetailedInfo;

rsa_public_key n:string e:string = RSAPublicKey;

destroy_auth_key_ok#f660e1d4 = DestroyAuthKeyRes;
destroy_auth_key_none#0a9f2259 = DestroyAuthKeyRes;
destroy_auth_key_fail#ea109b13 = DestroyAuthKeyRes;

---functions---

req_pq_multi#be7e8ef1 nonce:int128 = ResPQ;

req_DH_params#d712e4be nonce:int128 server_nonce:int128 p:string q:string public_key_fingerprint:long encrypted_data:string = Server_DH_Params;

set_client_DH_params#f5045f1f nonce:int128 server_nonce:int128 encrypted_data:string = Set_client_DH_params_answer;

rpc_drop_answer#58e4a740 req_msg_id:long = RpcDropAnswer;
get_future_salts#b921bd04 num:int = FutureSalts;
//ping#7abe77ec ping_id:long = Pong;
ping_delay_disconnect#f3427b8c ping_id:long disconnect_delay:int = Pong;
//destroy_session#e7512126 session_id:long = DestroySessionRes;

http_wait#9299359f max_delay:int wait_after:int max_wait:int = HttpWait;

destroy_auth_key#d1435160 = DestroyAuthKeyRes;
```

---

## Appendix B. Hard-coded RSA public keys and DH prime (verbatim)

### B.1 Production RSA key (`td/telegram/net/PublicRsaKeySharedMain.cpp:40-47`)

```
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB
-----END RSA PUBLIC KEY-----
```
- PKCS#1 `RSAPublicKey`, 2048-bit modulus, `e = 65537`.
- Fingerprint (1.4 formula) = **`0xd09d1d85de64fd85`** (as int64: `-3414540481677951611`).
- n (hex, big-endian):
  `e8bb3305c0b52c6cf2afdf7637313489e63e05268e5badb601af417786472e5f93b85438968e20e6729a301c0afc121bf7151f834436f7fda680847a66bf64accec78ee21c0b316f0edafe2f41908da7bd1f4a5107638eeb67040ace472a14f90d9f7c2b7def99688ba3073adb5750bb02964902a359fe745d8170e36876d4fd8a5d41b2a76cbff9a13267eb9580b2d06d10357448d20d9da2191cb5d8c93982961cdfdeda629e37f1fb09a0722027696032fe61ed663db7a37f6f263d370f69db53a0dc0a1748bdaaff6209d5645485e6e001d1953255757e4b8e42813347b11da6ab500fd0ace7e6dfa3736199ccaf9397ed0745a427dcfa6cd67bcb1acff3`

tdlib ships **only this one** production key and looks for its fingerprint in `server_public_key_fingerprints`.
If the server ever stopped listing it, the handshake would fail with "Unknown Main fingerprints".

### B.2 Test-DC RSA key (`PublicRsaKeySharedMain.cpp:24-32`)

```
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR
yy7mx66W0/sOFa7/1mAZtEoIokDP3ShoqF4fVNb6XeqgQfaUHd8wJpDWHcR2OFwv
plUUI1PLTktZ9uW2WE23b+ixNwJjJGwBDJPQEQFBE+vfmH0JP503wr5INS1poWg/
j25sIWeYPHYeOrFp/eXaqhISP6G+q2IeTaWTXpwZj4LzXq5YOpk4bYEQ6mvRq7D1
aHWfYmlEGepfaYR8Q0YqvvhYtMte3ITnuSJs171+GDqpdKcSwHnd6FudwGO4pcCO
j4WcDuXc2CTHgH8gFTNhp/Y8/SpDOhvn9QIDAQAB
-----END RSA PUBLIC KEY-----
```
- 2048-bit, `e = 65537`, fingerprint **`0xb25898df208d2603`** (int64 `-5595554452916591101`).
- n (hex):
  `c8c11d635691fac091dd9489aedced2932aa8a0bcefef05fa800892d9b52ed03200865c9e97211cb2ee6c7ae96d3fb0e15aeffd66019b44a08a240cfdd2868a85e1f54d6fa5deaa041f6941ddf302690d61dc476385c2fa655142353cb4e4b59f6e5b6584db76fe8b1370263246c010c93d011014113ebdf987d093f9d37c2be48352d69a1683f8f6e6c2167983c761e3ab169fde5daaa12123fa1beab621e4da5935e9c198f82f35eae583a99386d8110ea6bd1abb0f568759f62694419ea5f69847c43462abef858b4cb5edc84e7b9226cd7bd7e183aa974a712c079dde85b9dc063b8a5c08e8f859c0ee5dcd824c7807f20153361a7f63cfd2a433a1be7f5`

### B.3 Unit-test-only RSA key (`test/mtproto.cpp:726-734`; used by the 9.1 RSA vector, not a Telegram server key)

```
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAr4v4wxMDXIaMOh8bayF/NyoYdpcysn5EbjTIOZC0RkgzsRj3SGlu
52QSz+ysO41dQAjpFLgxPVJoOlxXokaOq827IfW0bGCm0doT5hxtedu9UCQKbE8j
lDOk+kWMXHPZFJKWRgKgTu9hcB3y3Vk+JFfLpq3d5ZB48B4bcwrRQnzkx5GhWOFX
x73ZgjO93eoQ2b/lDyXxK4B4IS+hZhjzezPZTI5upTRbs5ljlApsddsHrKk6jJNj
8Ygs/ps8e6ct82jLXbnndC9s8HjEvDvBPH9IPjv5JUlmHMBFZ5vFQIfbpo0u0+1P
n6bkEi5o7/ifoyVv2pAZTRwppTz0EuXD8QIDAQAB
-----END RSA PUBLIC KEY-----
```
Fingerprint `-7596991558377038078` (`0x9692106da14b9f02`).

### B.4 Built-in known-good DH prime (`td/telegram/DhCache.cpp:24-31`)

The standard Telegram 2048-bit safe prime, accepted without a primality test:
```
c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f48198a0aa7c14058229493d22530f4dbfa336f6e0ac9
25139543aed44cce7c3720fd51f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f642477fe96bb2a941d5bcd1d4a
c8cc49880708fa9b378e3c4f3a9060bee67cf9a4a4a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754fd17
ed950d5965b4b9dd46582db1178d169c6bc465b0d6ff9ca3928fef5b9ae4e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959
d956850ce929851f0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b
```
(Concatenate the lines; 256 bytes big-endian.) Any other prime goes through the full safe-prime check, and the
verdict is cached persistently.

---

## Appendix C. Constant quick-reference

| Constant | Value | Where |
|---|---|---|
| Handshake timeout / resPQ deadline / DH params deadline | 10 s / 0.6× / 0.8× | `Session.cpp:205`, `Handshake.cpp:87,164` |
| Concurrent handshakes per thread | 50 | `Session.cpp:157` |
| p_q_inner_data max size before RSA_PAD | 144 bytes | `Handshake.cpp:129` |
| Temp key lifetime | uniform 82800..86400 s | `Session.cpp:1443` |
| Temp key refresh margin | 3600 s (120 s if persisted) | `Session.cpp:1493` |
| DH g_a/g_b bounds | [2^1984, p − 2^1984] | `DhHandshake.cpp:100-123` |
| Outbound msg_id validity | (−150 s, +30 s) | `AuthData.cpp:127-131` |
| Inbound msg_id validity | (−300 s, +30 s) | `AuthData.cpp:133-137` |
| Duplicate window (packets / updates / update recheck) | 1000 / 1000 / 100 | `AuthData.h:301-303` |
| Salt validity after bad_server_salt / min remaining | 600 s / 60 s | `AuthData.h:225-235` |
| get_future_salts num / min interval | 64 / 60 s | `SessionConnection.cpp:937-945` |
| Ack delay / ack flush threshold | 30 s / 100 | `SessionConnection.h:129`, `.cpp:895` |
| Query batching delay | 1 ms | `SessionConnection.h:130` |
| Max queries per packet / bytes trigger | 1000 / 32768 | `SessionConnection.cpp:947-952` |
| Max ids per ack/resend/state message | 8192 | `SessionConnection.cpp:1004-1011` |
| Max in-flight queries per Session | 1024 | `Session.h:181` |
| Session idle close (non-main) | 300 s | `Session.h:180` |
| Dead-query scan start / threshold | connection age 60 s / 60 s + ping RTT | `Session.cpp:565-593` |
| Dropped-result kill threshold | >16 KB results summing >256 KB | `Session.cpp:881-889` |
| Ping/read timeouts | see table 4.10 | `SessionConnection.h:145-163` |
| Ping jitter | uniform 0..5 s | `SessionConnection.cpp:758` |
| http_wait | max_delay 30 ms, wait_after 10 ms, max_wait ≤ 25 s | `SessionConnection.h:165-169` |
| destroy_auth_key answer timeout | 60 s (checked on pong) | `SessionConnection.cpp:420` |
| MTProto 2.0 padding | 12..1024; buckets 64..1280 then +448 | `Transport.cpp:166-185` |
| Max inbound frame | 4 MiB + 1024 | `RawConnection.cpp:168` |
| Fake-TLS ClientHello size / record payload max | 517 / 2878 | `TlsInit.cpp:281-300`, `TcpTransport.h:162` |
| Max MTProxy TLS domain | 182 bytes | `ProxySecret.h:18` |
| TransparentProxy (SOCKS5/HTTP/TLS) timeout | 10 s | `TransparentProxy.cpp:57` |
| Check-ping timeout / pings | 10 s / 2 | `Ping.cpp:29,40` |
| Ready / cached connection TTL | 10 s / 10 s | `ConnectionCreator.h:145`, `Session.cpp:1508` |
| Reconnect backoff cap | 16 s desktop, 300 s mobile | `ConnectionCreator.h:107-112` |
| Proxy DNS cache / retry | 300 s / 60 s | `ConnectionCreator.cpp:1469-1474` |
| gzip threshold / ratio / probe | 128 B (1024 bots) / 0.9 / ≥16384 B probes middle 1 KiB | `NetQueryCreator.cpp:64-102` |
| Flood-wait auto-retry budget | 60 s per query (8 s bots) | `NetQuery.h:299`, `NetQueryCreator.cpp:66-76` |
| Backoff for 5xx/negative codes | 1,2,4,…,64 s | `NetQueryDelayer.cpp:70-77` |
| FLOOD_WAIT clamp | 1 s .. 14 days | `NetQueryDelayer.cpp:40` |
| Session count clamp | 1..100 | `SessionMultiProxy.cpp:95` |
| Upload/download sessions | 8 or 4 / 8 or 2 | `NetQueryDispatcher.cpp:246-249` |
| TempAuthKeyWatchdog | debounce 0.1 s (≤1 s), resync 6× every 5 s | `TempAuthKeyWatchdog.h:56-59` |
