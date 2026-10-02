# MTProto protocol coverage matrix

Every protocol condition the Rust engine can meet on the wire, how the two reference clients handle it, what
the engine does, and the test that pins the behaviour. Every row ends with at least one passing test.

Sources: `docs/research/tdlib.md` (tdlib 1.8.49), `docs/research/tdesktop-and-docs.md` (Part B checklist ids
`P-NNN`, gotchas `D-N`, error table §B4), `docs/research/mtprotokit.md` (§3.11–3.20 incoming handling, §4.9
error classification, §10 bug list `H*`/`M*`/`L*`), `docs/research/integration.md` §2.4 (what TelegramCore needs
surfaced).

Columns:

- **Spec**: checklist id or research section.
- **tdlib** / **MtProtoKit**: reference behaviour. MtProtoKit bugs carry their §10 id.
- **Rust engine**: current behaviour.
- **Tests**: test functions. Unqualified names live in `crates/mtproto-core/src/session/tests.rs`. Prefixes:
  `rpc::` = `crates/mtproto-core/src/rpc/tests.rs`, `hs::` = `crates/mtproto-core/tests/handshake.rs`,
  `engine::` = `crates/mtproto-engine/tests/engine.rs` (real sockets against `mtproto-testserver`),
  `tl::` = `src/tl/mtproto.rs` and `src/tl/reader.rs`, `msg::` = `src/message.rs`, `codec::` =
  `src/transport/codec.rs`, `transport::` = other files under `src/transport/`, `salts::`/`dedupe::` = files under
  `src/session/`, `msgid::` = `src/msg_id.rs`, `dh::` = `src/crypto/dh.rs`.
- **Δ**: `ok` = the engine already behaved correctly (a test may have been added), `fixed` = behaviour changed in
  this pass, `new` = the condition was not handled at all before, `better` = deliberately better than both
  reference clients (verified against production where the server's behaviour matters).

Fault injection used by the engine tests (`crates/mtproto-testserver`): `TAG_TRANSPORT_ERROR_ONCE`
(`transport_error_call(code)`), `TAG_BAD_MSG_ONCE` (`bad_msg_call(code, container)`), `TAG_SERVER_PING`,
`TAG_RESEND_REQ_ONCE`, `TAG_MSG_COPY`, `TAG_GARBAGE_SIBLINGS`, `TAG_GZIP`, `ServerOptions::handshake_faults`
(`HandshakeFault::TransportError`, `HandshakeFault::Stall`), `ServerOptions::clock_offset` with
`validate_msg_id_time`. Existing tags keep their behaviour.

## 1. Transport framing and transport errors

| ID | Condition | Spec | tdlib | MtProtoKit | Rust engine | Tests | Δ |
|---|---|---|---|---|---|---|---|
| T01 | Transport error `-404` on an encrypted session (auth key unknown, e.g. expired temp key) | P-048, P-049, P-241 | Close with status -404; PFS: drop temp key and regenerate (§5.9 ladder) | `handleMissingKey`, and the connection is reported as broken: scheme invalidation, backup discovery and proxy probing that never stops (H10) | `AuthKeyInvalid{-404}` to the host; in-flight requests are kept and replayed on the next key; the address is reported reachable (`AddressResult{success:true}`); failure backoff | `codec::intermediate_quick_ack_and_error`, `engine::unknown_key_reports_invalid_and_recovers_with_new_key` | fixed |
| T02 | `-404` while generating an auth key | P-049, P-100 | Handshake cleared and restarted | Restart at once, no limit, no delay (H7) | `AuthKeyCreationFailed("transport error -404")`, never `AuthKeyInvalid`; restart after the reconnect ladder | `engine::handshake_transport_error_restarts_key_generation_without_key_invalid` | fixed |
| T03 | Transport flood `-429` | P-050 | Close with status 500: unacknowledged queries fail with 500 and are re-sent by the delayer; separate flood control (≤1/1 s, 2/4 s, 3/8 s) | Sets a throttle flag whose 5 s clear timer is never started: the MTProto stops sending for good (H1, reproduced by `torture/transport-flood`) | `TransportFlood` event; plain close: messages of that packet may already have run, so in-flight queries are retransmitted under their original msg_id (exactly once); reconnect after 1, 2, 4, 8, 16, 30 s, reset by the first decrypted packet | `transport::transport_error_kinds`, `transport::flood_delay_grows_and_caps`, `engine::transport_flood_backs_off_and_retransmits_without_reexecution`, `torture/transport-flood` | better |
| T04 | `-429` during key generation | P-050 | As T03 | H7 loop | `AuthKeyCreationFailed` + `TransportFlood` + flood delay | `engine::handshake_transport_error_restarts_key_generation_without_key_invalid` | fixed |
| T05 | `-444` invalid DC (test/prod mismatch, MTProxy cannot route) | P-051 | Generic close; queries unknown | Connection problems path (H10) | Unacknowledged queries re-queued, next address, failure backoff, address reported reachable | `engine::other_transport_errors_reconnect_quickly`, `engine::handshake_transport_error_restarts_key_generation_without_key_invalid` | fixed |
| T06 | `-403` and any other negative code | P-052 | Generic close; queries become unknown | As T05 | Close with failure backoff (previously an immediate reconnect loop once a packet had been received); queries become unknown and are retransmitted under their original msg_id (A01) | `codec::short_frames_follow_tdlib_classification`, `engine::other_transport_errors_reconnect_quickly` | fixed |
| T07 | Non-negative non-zero code in a short frame (4..15 bytes) | §2.6 | Treated as an error code | 4..19 bytes are errors | `TransportError(code)` → close with backoff (previously handed to the decryptor) | `codec::short_frames_follow_tdlib_classification`, `engine::other_transport_errors_reconnect_quickly` | fixed |
| T08 | Zero first word in a short frame | §2.6 | `Nop` | — | Ignored | `codec::short_frames_follow_tdlib_classification`, `codec::abridged_nop_and_long_quick_ack` | ok |
| T09 | Quick ack: abridged (big-endian, top bit), intermediate/padded (little-endian, top bit), padded `0xffffffff` + token form; unknown tokens | P-034, P-037, P-040, §2.9 | Parsed; unknown ignored | Parsed | Parsed; unknown and repeated tokens ignored | `codec::abridged_quick_ack_is_big_endian`, `codec::intermediate_quick_ack_and_error`, `codec::padded_error_and_ffff_quick_ack`, `codec::abridged_nop_and_long_quick_ack`, `quick_ack_marks_query_acknowledged`, `rpc::quick_ack_events_only_for_requests_that_asked` | ok |
| T10 | A long frame whose first word is `0xffffffff` (an auth key id with that low word) | P-040 | Only short frames are quick acks | — | Treated as a packet; previously every packet for such a key was misread as a quick ack | `codec::long_frames_are_packets_even_with_suspicious_prefixes` | fixed |
| T11 | Invalid frame length (0, < 4, > 16 MiB, abridged marker 0) | P-031, P-036 | Close | Abridged ≤ 4 MiB, intermediate ≤ 16 MiB (L16) | Connection error → reconnect | `codec::rejects_bad_lengths` | ok |
| T12 | Frames split at arbitrary byte boundaries, several frames per read | — | Reassembled | Reassembled | Reassembled | `codec::decode_any_split` | ok |
| T13 | Garbage byte stream | — | — | — | Never panics | `codec::decoder_never_panics` | ok |
| T14 | Padded intermediate random padding | P-041 | Ignored by the decryptor | — | Trimmed using the inner structure | `codec::padded_trim_uses_inner_structure` | ok |
| T15 | Encrypted payload followed by 1..15 bytes of transport junk | P-041 | Decrypts the 16-byte-aligned prefix | Same (floor) | Same as tdlib (previously rejected as unaligned) | `msg::trailing_transport_junk_is_ignored_like_tdlib` | fixed |
| T16 | Fake-TLS ServerHello: wrong prefix, HMAC mismatch, byte-by-byte arrival | §3.5.2 | Error | Error | Error / waits for more | `transport::server_hello_roundtrip` | ok |
| T17 | Fake-TLS records: wrong record type, zero-length record, records split across reads | §3.5.3 | Close on wrong type | Zero-length record stalls the stream (M23); reassembly can reorder (M22) | Wrong type closes; zero-length and split records are handled | `transport::record_writer_and_reader`, `transport::zero_length_and_split_records_do_not_stall` | ok |
| T18 | SOCKS5 failures (version, method, credentials, CONNECT reply, address type) | §3.7 | Error | IPv4 only (M24) | Error → reconnect; IPv4, IPv6 and domain targets | `transport::failures`, `transport::no_auth_ipv4`, `transport::password_auth_ipv6_and_domain_reply`, `engine::socks5_proxy_without_and_with_credentials` | ok |
| T19 | Obfuscation header that starts with a forbidden word | P-061 | Regenerated | Checks the wrong (encrypted) bytes (M1) | Regenerated (plaintext header) | `transport::rejects_forbidden_prefixes` | ok |
| T20 | MTProxy secrets: 16 bytes, `dd`, `ee`+domain, too long, malformed | §3.4 | Same | Lenient parsing (L15) | Same as tdlib | `transport::rejections_and_truncation`, `transport::simple_and_padded_hex`, `transport::fake_tls_hex_and_base64`, `engine::mtproxy_simple_padded_and_fake_tls` | ok |
| T21 | Packets queued before the transport is ready (fake-TLS/SOCKS) and the connection dies | — | — | The request hangs until the transport is replaced (H4) | Sent-but-unacknowledged queries are retransmitted under their original msg_id on the next connection (A01) | `reconnect_without_ack_retransmits_with_original_msg_ids`, `engine::mtproxy_simple_padded_and_fake_tls` | ok |
| T22 | HTTP transport, `http_wait` | P-220 | HTTP and long poll | Not used | TCP only; a received `http_wait` is ignored | `tl::resend_answer_requests_and_http_wait_are_distinct`, `mtproto_service_constructors_are_never_forwarded_as_updates` | new |
| T23 | Fake-TLS ClientHello fingerprint | §3.5.1 | Fixed 517-byte template | Chrome-like template (`MTCreateSafariClientHello`): random choice of two cipher lists and two ALPN lists, X25519MLKEM768 + X25519 key shares, 8 GREASE values | Byte-identical port of MtProtoKit's template, including the ML-KEM-shaped key share (coefficients < 3329) and the squared-x fake X25519 keys; every length field checked by a full parser | `transport::hello_is_well_formed_and_chrome_shaped`, `transport::hello_choices_cover_every_alternative`, `transport::hello_hmac_encodes_time`, `engine::mtproxy_simple_padded_and_fake_tls` | fixed |

## 2. Decryption and per-packet header checks

| ID | Condition | Spec | tdlib | MtProtoKit | Rust engine | Tests | Δ |
|---|---|---|---|---|---|---|---|
| D01 | Packet shorter than header + 12-byte padding | P-130 | Error, close | Dropped | `Decrypt(TooShort)` → close | `msg::rejects_bad_shapes`, `msg::decrypt_never_panics` | ok |
| D02 | `auth_key_id` of another key | P-130 | Error, close | Undecryptable | `Decrypt(AuthKeyMismatch)` → close | `msg::wrong_side_or_key_is_rejected` | ok |
| D03 | `msg_key` mismatch (constant time, checked before any length field) | P-131, P-132 | Same | Same | Same | `msg::tampering_is_detected_everywhere`, `msg::rejects_forged_length_with_valid_msg_key`, `foreign_session_and_tampering_are_rejected` | ok |
| D04 | `message_data_length` negative, not a multiple of 4, or past the plaintext | P-133 | Error | Error | `Decrypt(InvalidLength)` | `msg::padding_bounds_are_enforced_after_authentication` | ok |
| D05 | Padding outside 12..1024 | P-133 | Error | Error | `Decrypt(InvalidPadding)` | `msg::padding_bounds_are_enforced_after_authentication` | ok |
| D06 | Wrong direction (`x = 0` instead of 8) | P-120 | Error | Error | `MsgKeyMismatch` | `msg::wrong_side_or_key_is_rejected` | ok |
| D07 | `session_id` of another session | P-134 | Error, close | Parse error: packet dropped and session reset | Packet ignored, connection kept (stragglers of a session we just reset are harmless) | `foreign_session_and_tampering_are_rejected` | ok |
| D08 | Even server `msg_id` | P-135 | Error, close | Not checked (M31) | Ignored, not acknowledged | `even_server_msg_id_is_ignored` | ok |
| D09 | Duplicate `msg_id` (outer packet or container child) | P-136 | Ack the outer id, skip | Ack again, skip | Not reprocessed; every content-related child of a duplicated container is acknowledged again so the server stops resending | `duplicate_container_reacks_every_content_child`, `gzip_rpc_errors_and_duplicates`, `updates_are_delivered_once_and_unknown_constructors_do_not_break_containers`, `dedupe::never_accepts_same_id_twice_within_window` | fixed |
| D10 | `msg_id` older than the 1000-id window (outer or child) | P-136 | Session failed: new session, everything re-sent | Processed-id set grows without bound (M2) | Acknowledged and processed in replay-safe mode: `rpc_result`s complete pending queries (idempotent by query map), verified service messages apply, updates and `new_session_created` are not trusted and the host is told to fetch the difference. Previously dropped silently and never acked, so the server re-sent it forever | `too_old_messages_are_acked_and_replayed_safely`, `rpc::lost_updates_ask_the_host_for_a_difference`, `dedupe::peek_predicts_check`, `dedupe::peek_does_not_record` | fixed |
| D11 | `msg_id` outside (−300 s, +30 s) after time sync, nothing in it refers to our messages | P-137 | Error, close | Not checked | Dropped without acknowledgement and without being recorded as received (a later fresh copy is still processed) | `messages_outside_time_window_are_ignored_after_sync` | fixed |
| D12 | Same, but the packet answers one of our in-flight messages (pong, `rpc_result`, `bad_msg_*`, state info, future salts, detailed info, new session) | P-138 | Error, close | — | That proves the packet is fresh and our clock is wrong: forced resync from the packet, then processed | `future_msg_id_glitch_is_recovered_through_a_freshness_proof` | new |
| D13 | Updates: duplicate filter on the inner `msg_id`; update older than its window | §4.6 | Duplicate skipped; too old → session failed | — | Duplicate skipped; too old → host told to fetch the difference (previously dropped silently) | `updates_are_delivered_once_and_unknown_constructors_do_not_break_containers`, `rpc::lost_updates_ask_the_host_for_a_difference` | fixed |
| D14 | Ack every odd-seqno message, before processing, including malformed ones; never ack even seqno | P-171, P-173 | Same | Same (no flush timer, M33) | Same; flushed within 30 s or at 100 pending | `only_odd_seqno_messages_are_acked`, `malformed_and_unknown_children_do_not_break_the_container`, `many_acks_flush_immediately`, `request_roundtrip_with_ping_and_acks` | ok |
| D15 | Incoming salt differs from ours | P-203 | Not checked | Not checked | Not checked; our salt only changes through `bad_server_salt`, `future_salts` and `new_session_created` | `incoming_salt_is_not_validated` | ok |
| D16 | Server `msg_id`s out of order within the window | P-136 | Accepted | Accepted | Accepted once each | `dedupe::detects_duplicates_and_out_of_order`, `dedupe::never_accepts_same_id_twice_within_window` | ok |

## 3. Service messages

| ID | Condition | Spec | tdlib | MtProtoKit | Rust engine | Tests | Δ |
|---|---|---|---|---|---|---|---|
| S01 | `rpc_result` for a pending query | P-210 | Result | Result | `Completed` | `request_roundtrip_with_ping_and_acks`, `engine::requests_complete_with_correct_payloads` | ok |
| S02 | `rpc_result` carrying `gzip_packed` value or `gzip_packed` `rpc_error` | P-015 | Unpacked | Unpacked | Unpacked | `gzip_rpc_errors_and_duplicates`, `tl::rpc_result_variants`, `engine::copied_gzipped_and_noisy_answers_complete_on_one_connection` | ok |
| S03 | `rpc_result` for an unknown, cancelled or zero `req_msg_id` | §4.7.1 | Dropped (0 closes the connection) | Dropped | Dropped and acknowledged | `rpc_result_for_unknown_or_zero_request_is_dropped_and_acked`, `cancellation` | ok |
| S04 | Unwanted answers: results for unknown (cancelled) queries | §5.3 | Close after 256 KB of > 16 KB results | — | Close only after 8 MB within 10 s; with `rpc_drop_answer` sent on every cancel the server rarely streams them. The tdlib limit reset the connection on every few cancelled 128 KiB FetchV2 parts (27 reconnects in one CDN download, measured through TelegramCore) | `dropped_answers_are_accounted` | better |
| S05 | `rpc_answer_unknown` / `rpc_answer_dropped_running` / `rpc_answer_dropped` (replies to our `rpc_drop_answer`) | P-212 | Dropped | `rpc_drop_answer` never sent (M14) | Silent, acknowledged; every cancelled in-flight request sends `rpc_drop_answer` and the connection is kept | `drop_answer_replies_are_silent_and_acked`, `rpc::cancelling_in_flight_requests_drops_answers_without_resetting_the_connection` | fixed |
| S06 | Response `msg_id` more than 15 s older than the request (`rpc_result`, `pong`) | §4.9 | Forced time reset | — | Forced time reset, now only for responses to our own messages | `responses_older_than_their_request_reset_the_clock` | fixed |
| S07 | `rpc_result` whose body cannot be unpacked (broken gzip, empty, over budget) | — | Empty result fails at the API layer | `500 TL_PARSING_ERROR`, retried every 2 s forever with initConnection (H8) | `500 RESPONSE_UNPACK_FAILED: …`, terminal: never retried, never delegated | `unparsable_results_fail_the_query_once`, `rpc::local_unpack_failures_are_terminal_and_never_retried` | fixed |
| S08 | `pong` for our ping | P-215 | RTT, liveness | Clears actualization ping | RTT, liveness | `request_roundtrip_with_ping_and_acks`, `responses_older_than_their_request_reset_the_clock` | ok |
| S09 | `pong` for a ping we never sent | — | Time check still applied | Ignored | Ignored: no RTT sample, no time reset | `pong_for_unknown_ping_is_ignored` | fixed |
| S10 | Server-initiated `ping` / `ping_delay_disconnect` | P-215 | Not in schema: handed to the update layer | Passed to services, never answered | Answered with `pong` (same `msg_id`/`ping_id`, non-content) | `server_pings_are_answered_with_pongs`, `tl::server_pings_parse_as_ping`, `engine::server_pings_are_answered` | new |
| S11 | `msgs_ack` (including a container id); acks never complete an RPC | P-170, P-176 | Same | Same | Same | `msgs_ack_on_container_acknowledges_children_once`, `acknowledged_queries_survive_reconnect_without_state_request` | ok |
| S12 | `bad_server_salt` | P-198 | New salt, resend with new msg_id | Synthetic 30 min salt (H2) | New salt (10 min), future salts refetched, resend with new msg_id, executed once | `bad_server_salt_updates_salt_and_resends`, `engine::bad_server_salt_rotates_salt_and_executes_once` | ok |
| S13 | `bad_server_salt` inside a container next to other results | — | Each processed | Each processed | Each processed | `bad_server_salt_inside_a_container_keeps_siblings` | ok |
| S14 | `bad_server_salt` / `bad_msg_notification` naming a message we never sent | P-146, P-191 | Not verified | Not verified | Ignored: no salt, time or session change | `notifications_about_messages_we_never_sent_are_ignored` | fixed |
| S15 | `new_session_created` | P-207, P-208 | Resend queries whose container is older than `first_msg_id`; fake `updatesTooLong` | Same; salt ignored | Same; acknowledged; `UpdatesReset` to the host | `new_session_created_resends_older_queries_and_reports_reset`, `rpc::updates_too_long_and_session_resets_emit_updates_reset`, `engine::updates_and_session_resets_are_delivered` | ok |
| S16 | `new_session_created` and an answer for an older query in the same packet (either order) | — | Resends, then drops the late answer: double execution | Same | Resends are deferred to the end of the packet, so an answered query is never re-sent | `new_session_created_never_resends_queries_answered_in_the_same_packet` | fixed |
| S17 | Duplicate `new_session_created` (same `unique_id`) | P-209 | Not deduplicated | Not deduplicated | Ignored | `duplicate_new_session_notifications_are_ignored` | new |
| S18 | `new_session_created.server_salt` | P-204 | Ignored | Ignored (H2) | Adopted when it differs or the current salt is invalid | `new_session_created_salt_is_adopted` | new |
| S19 | `msg_detailed_info`: status 1..3 → resend; otherwise ack the query and ask for an unseen answer with `msg_resend_req`; `answer_msg_id = 0` → resend | P-185, P-186 | Same | Asks for the answer while the request is pending | Same as tdlib (a zero answer id used to produce `msg_resend_req [0]`) | `msg_detailed_info_requests_lost_answer`, `detailed_info_without_answer_resends_the_query` | fixed |
| S20 | `msg_new_detailed_info`: seen answer → ack; unseen → `msg_resend_req` | P-185, P-186 | Same | Always requests | Same as tdlib | `msg_new_detailed_info_for_received_message_is_only_acked`, `msg_new_detailed_info_requests_an_unseen_answer` | ok |
| S21 | Our `msg_resend_req`: answer arrives / server replies `msgs_state_info` / no reply | P-184 | Fire and forget | No timeout: "Updating" forever (M34) | Answer clears the request and the "updating" flag; a `msgs_state_info` reply means the answer is gone → query re-sent; no reply → asked again every 20 s, after 3 requests the query is re-sent | `answer_resend_requests_resolve_or_fall_back_to_resending_the_query` | fixed |
| S22 | `msgs_state_info` for our `msgs_state_req` (status flags masked with `& 7`) | P-180, P-181 | 1..3 resend, 4 ack | — | Same | `reconnect_after_retransmit_window_asks_state_and_resends_only_unreceived` | ok |
| S23 | `msgs_state_info` whose `info` length differs from the request | — | Error | — | Ignored; the request is retried later | `state_info_with_mismatched_length_is_ignored` | ok |
| S24 | Our `msgs_state_req` never answered | — | Re-asked on the next connection | — | Re-asked after 20 s on the same connection (previously never, while the first request was outstanding) | `unanswered_state_request_is_retried` | fixed |
| S25 | `msgs_all_info` | P-183 | As state info | Not handled | 1..3 resend, 4 ack | `msgs_all_info_drives_resend_and_ack` | ok |
| S26 | Server `msgs_state_req` | P-180, P-181 | — | Never answered | `msgs_state_info` with 4 (received), 2 (in range, missing), 3 (newer than anything seen), 1 (older than the window) | `server_state_requests_get_precise_statuses`, `server_state_request_is_answered` | fixed |
| S27 | Server `msg_resend_req` for our messages | P-182, P-184 | Ignored | Cannot parse it (vector header): whole packet dropped and session reset (H3) | Pending queries are re-transmitted with their original `msg_id`, `seqno` and body inside a fresh container; ids we no longer have get `msgs_state_info` | `server_resend_request_retransmits_the_original_message_in_a_container`, `engine::server_resend_request_is_answered_with_the_original_message` | new |
| S28 | Server `msg_resend_ans_req` | P-184 | — | — | `msgs_state_info` (1 = nothing known; we never answer server queries) | `server_resend_answer_request_gets_state_info`, `tl::resend_answer_requests_and_http_wait_are_distinct` | new |
| S29 | `future_salts` for our request (bare or boxed items) | P-201 | Set future salts | Never requested (H2) | Set and rotate | `missing_salt_requests_future_salts_first`, `tl::future_salts_accepts_bare_and_boxed_items` | ok |
| S30 | `future_salts` with a foreign `req_msg_id`; salts with `valid_until ≤ valid_since` | P-201 | `req_msg_id` ignored | — | Foreign answers ignored; inverted ranges dropped | `future_salts_must_answer_our_request` | fixed |
| S31 | `destroy_session_ok` / `destroy_session_none` | P-218 | Not implemented | Ignored | Ignored | `destroy_responses_are_handled` | ok |
| S32 | `destroy_auth_key_ok/none/fail` | P-219 | Acted on only when requested | — | Outcome event only when requested | `destroy_responses_are_handled` | ok |
| S33 | `msg_copy` (boxed or bare `message`) | P-166 | Not in schema: handed to the update layer | Unwrapped | Inner message processed once; a copy of an already-received message is acknowledged again, not reprocessed (previously forwarded to the host as an update) | `msg_copy_is_unwrapped_and_deduplicated`, `tl::msg_copy_accepts_boxed_and_bare_messages`, `engine::copied_gzipped_and_noisy_answers_complete_on_one_connection` | new |
| S34 | Other MTProto-layer constructors from the server (`http_wait`, top-level `rpc_error`/`rpc_answer_*`, `future_salt`, `message`, `vector`, handshake objects, `get_future_salts`, `rpc_drop_answer`, `destroy_session`, …) | — | Handed to the update layer | Unknown to `Api.parse`: packet dropped and session reset (H3) | Ignored (acknowledged when content-related), never forwarded as updates | `mtproto_service_constructors_are_never_forwarded_as_updates`, `tl::mtproto_constructors_are_never_updates` | new |
| S35 | Unknown constructors (new API layer) inside containers | — | Passed as updates | Packet dropped and session reset (H3) | Passed as updates; siblings unaffected; no reconnect, no session reset | `updates_are_delivered_once_and_unknown_constructors_do_not_break_containers`, `malformed_and_unknown_children_do_not_break_the_container`, `tl::unknown_constructor_is_passed_through`, `engine::copied_gzipped_and_noisy_answers_complete_on_one_connection` | ok |
| S36 | `updatesTooLong` | P-320 | getDifference | `.reset` | `UpdatesReset` | `rpc::updates_too_long_and_session_resets_emit_updates_reset` | ok |

## 4. `bad_msg_notification` codes

All codes act only when `bad_msg_id` (or the container holding it) is one of our recent messages (S14). "Resend"
always means a fresh `msg_id`.

| ID | Code | Spec | tdlib | MtProtoKit | Rust engine | Tests | Δ |
|---|---|---|---|---|---|---|---|
| B16 | 16 msg_id too low | P-192 | Resend (time already raised) | Time sync, resend | Forced resync from the notification's `msg_id`, resend | `bad_msg_16_resyncs_time_and_resends`, `every_bad_msg_notification_code_recovers_the_message`, `engine::bad_msg_notifications_are_recovered_end_to_end`, `engine::clock_skew_in_either_direction_is_corrected` | ok |
| B17 | 17 msg_id too high | P-193 | Forced reset + new session | Time sync, resend | Forced resync + new session (ids must stay monotonic), resend | `bad_msg_17_resets_session`, `every_bad_msg_notification_code_recovers_the_message`, `engine::clock_skew_in_either_direction_is_corrected` | ok |
| B18 | 18 msg_id not divisible by 4 | P-194 | Close ("BUG") | Resend | Resend; after 3 such rejections of the same query it fails with terminal `500 PROTOCOL_ERROR_BAD_MSG_18` instead of looping | `every_bad_msg_notification_code_recovers_the_message`, `repeated_bug_class_rejections_fail_the_query_instead_of_looping` | fixed |
| B19 | 19 container id reused | P-195 | Close | Resend | Resend children; strikes as B18 | `every_bad_msg_notification_code_recovers_the_message`, `engine::bad_msg_notifications_are_recovered_end_to_end` | fixed |
| B20 | 20 message too old | P-196 | Resend | Resend | Resend | `every_bad_msg_notification_code_recovers_the_message`, `engine::bad_msg_notifications_are_recovered_end_to_end` | ok |
| B32 | 32 seqno too low | P-197, P-157 | Close | Session reset | New session, resend; the rest of the packet is still processed | `bad_msg_32_resets_session_and_keeps_processing_container`, `every_bad_msg_notification_code_recovers_the_message`, `engine::bad_msg_notifications_are_recovered_end_to_end` | ok |
| B33 | 33 seqno too high | P-197, P-157 | Close | Session reset | As B32 | `every_bad_msg_notification_code_recovers_the_message`, `engine::bad_msg_notifications_are_recovered_end_to_end` | ok |
| B34 | 34 even seqno expected | P-197 | Close | Resend | Resend; strikes as B18 (previously a full session reset, re-executing every in-flight query) | `every_bad_msg_notification_code_recovers_the_message`, `repeated_bug_class_rejections_fail_the_query_instead_of_looping`, `rpc::protocol_errors_after_repeated_rejections_are_terminal`, `engine::bad_msg_notifications_are_recovered_end_to_end` | fixed |
| B35 | 35 odd seqno expected | P-197 | Close | Resend | As B34 | `every_bad_msg_notification_code_recovers_the_message`, `rpc::protocol_errors_after_repeated_rejections_are_terminal` | fixed |
| B48 | 48 bad salt (as `bad_msg_notification`, no salt given) | P-198 | Unknown code: close | Time sync | Current salt invalidated, queries wait for `get_future_salts`, then resend (previously re-sent at once with the same bad salt) | `every_bad_msg_notification_code_recovers_the_message`, `engine::bad_msg_notifications_are_recovered_end_to_end` | fixed |
| B64 | 64 invalid container | P-199 | Close | Resend children | Every child re-sent, ping restarted (previously a full session reset) | `container_rejection_resends_every_child`, `every_bad_msg_notification_code_recovers_the_message`, `engine::bad_msg_notifications_are_recovered_end_to_end` | fixed |
| B?? | Unknown codes (0, 99, −1, …) | — | Close | Resend | Resend; strikes as B18 | `every_bad_msg_notification_code_recovers_the_message`, `engine::bad_msg_notifications_are_recovered_end_to_end` | fixed |

## 5. Containers, gzip, malformed and oversized input

| ID | Condition | Spec | tdlib | MtProtoKit | Rust engine | Tests | Δ |
|---|---|---|---|---|---|---|---|
| C01 | Container structure broken (count > 1024, child length negative/unaligned/past the end) | P-160, P-163 | Parse error, close | Packet dropped, session reset | Connection closed (no session reset); unacked children are re-sent by the server | `tl::container_parse_and_limits`, `broken_container_structure_is_reported`, `tl::container_parser_never_panics_on_any_layout` | ok |
| C02 | Nested container | P-162 | Processed recursively | Opaque body | Processed recursively, depth ≤ 8 (previously dropped silently) | `nested_containers_and_gzip_are_unwrapped` | fixed |
| C03 | Container child with an even `msg_id` | P-135 | Not checked | — | Skipped | `container_children_with_even_msg_ids_are_skipped` | ok |
| C04 | Malformed child (truncated known constructor), empty child, broken gzip child | — | Parse error, close | Packet dropped, session reset (H3) | Child acknowledged and skipped; siblings processed; no reconnect (previously the connection was closed and later siblings lost) | `malformed_and_unknown_children_do_not_break_the_container`, `engine::copied_gzipped_and_noisy_answers_complete_on_one_connection` | fixed |
| C05 | `gzip_packed` at top level, in containers, around containers, in `rpc_result` | P-015, P-322 | Unpacked | Unpacked | Unpacked | `nested_containers_and_gzip_are_unwrapped`, `gzip_rpc_errors_and_duplicates`, `engine::copied_gzipped_and_noisy_answers_complete_on_one_connection` | ok |
| C06 | Decompression bombs and deep gzip nesting | C2.15 | No limit (`gzdecode` grows until done) | 32 MiB per object; inflates the whole bomb (242 MB RSS in `hostile/x-gzip-bomb`) | The gzip trailer's declared size is checked first: more than 32 MiB is refused without inflating, an honest stream is unpacked into one exact allocation, a stream longer than it declares is cut off there; failures are charged to a per-packet budget shared with the freshness check (64 MiB); depth ≤ 8; at most 4096 messages per packet. Peak RSS under the bomb 42.8 MB (was 500 MB) | `unpacking_is_bounded_per_packet_and_by_depth`, `gzip_bombs_are_refused_without_unpacking_them`, `tl::declared_sizes_bound_allocation`, `tl::gunzip_budget_is_shared`, fuzz `gunzip`/`session` | better |
| C07 | TL limits: vector counts, byte lengths, booleans, truncation | P-006 | Checked | Partly | Checked | `tl::vector_count_limits`, `tl::rejects_truncated_bytes`, `tl::bool_roundtrip_and_rejection`, `tl::reader_never_panics_on_garbage` | ok |
| C08 | Arbitrary service-message bodies | — | — | — | Parser never panics | `tl::service_parser_never_panics`, `tl::container_parser_never_panics_on_any_layout` | ok |
| C09 | Arbitrary server packets with valid encryption: random service objects, ids (ours, stale, future, even, duplicate), nesting, gzip, copies, truncation | — | — | — | Never panics; all state bounded | `arbitrary_server_packets_never_panic_and_state_stays_bounded` | new |
| C10 | Memory bounds of per-session state | M2 | Bounded windows | Grows ~69 KB/h | Acks ≤ 16384, server replies ≤ 64 each, pending pings ≤ 16, recent outgoing ids ≤ 1024, service containers ≤ 64 (previously one entry per ping for the whole connection), container maps detached on resend (previously leaked), dedupe windows ≤ 2000 | `service_queues_are_bounded`, `arbitrary_server_packets_never_panic_and_state_stays_bounded` | fixed |
| C11 | Empty container, empty or sub-4-byte body | P-165 | Error for short bodies (session failed) | Parse error | Ignored (acked when content-related); no reset | `empty_containers_and_empty_bodies_are_harmless` | ok |

## 6. Outgoing msg_id and seq_no

| ID | Condition | Spec | tdlib | MtProtoKit | Rust engine | Tests | Δ |
|---|---|---|---|---|---|---|---|
| I01 | Client `msg_id`: server time, `% 4 == 0`, strictly increasing even when the clock moves back, low 32 bits never zero | P-140, P-141 | Same | Can go backwards (M32) | Same as tdlib, plus non-zero low bits | `outgoing_msg_ids_stay_monotonic_when_the_clock_moves_back`, `msgid::ids_are_divisible_by_four_and_monotonic`, `msgid::strictly_increasing_for_any_clock` | fixed |
| I02 | Container `msg_id` greater than every child | P-144, P-161 | Same | Can be lower (M32) | Same as tdlib | `request_roundtrip_with_ping_and_acks`, `server_resend_request_retransmits_the_original_message_in_a_container` | ok |
| I03 | seqno: queries odd, service messages and containers even, 0 on a new session | P-150..P-156 | Same | Same | Same | `queries_are_packed_into_one_container_in_order`, `bad_msg_32_resets_session_and_keeps_processing_container`, `server_pings_are_answered_with_pongs`, `msgid::seqno_rules` | ok |
| I04 | Container limits (1000 queries, 32 KiB) and oversized single queries | §4.3 | Same | 3 KiB groups | Same as tdlib | `container_limits_split_packets`, `single_large_query_is_sent_alone` | ok |

## 7. Salts

| ID | Condition | Spec | tdlib | MtProtoKit | Rust engine | Tests | Δ |
|---|---|---|---|---|---|---|---|
| SA1 | No valid salt: only `get_future_salts` until one arrives, retried every 60 s | §4.8 | Same | Time-fix ping (H2) | Same as tdlib | `missing_salt_requests_future_salts_first`, `salts::empty_state_needs_salts` | ok |
| SA2 | Rotation by `valid_since`, 60 s safety margin, restore from persisted salts | P-202 | Same | Last eligible entry wins (L3) | Same as tdlib | `salts::future_salts_rotate_in_order`, `salts::restore_picks_currently_valid_salt` | ok |
| SA3 | `bad_server_salt`: 10 min validity, future salts cleared | §4.8 | Same | 30 min synthetic window | Same as tdlib | `salts::bad_server_salt_gives_ten_minutes`, `bad_server_salt_updates_salt_and_resends` | ok |
| SA4 | Salt from `new_session_created`, foreign `future_salts`, bad_msg 48 | — | — | — | See S18, S30, B48 | `new_session_created_salt_is_adopted`, `future_salts_must_answer_our_request`, `every_bad_msg_notification_code_recovers_the_message` | fixed |

## 8. Time synchronisation and clock problems

| ID | Condition | Spec | tdlib | MtProtoKit | Rust engine | Tests | Δ |
|---|---|---|---|---|---|---|---|
| TI1 | First packet sets the offset; later packets only raise it | §4.9 | Same | Time-fix ping only | Same as tdlib | `bad_msg_16_resyncs_time_and_resends`, `messages_outside_time_window_are_ignored_after_sync` | ok |
| TI2 | Server clock 1000 s ahead or behind at start (server enforces the msg_id window) | P-143, P-192, P-193 | bad_msg 16/17 recovery | Time sync | Recovers through 16/17; the host is told the new difference | `engine::clock_skew_in_either_direction_is_corrected` | ok |
| TI3 | Local wall clock jumps ±1 h during a session | §4.9 | Unaffected (monotonic clock) | Wall clock based | Server time now runs on the monotonic clock, so a jump changes nothing on the wire; the host gets a forced `TimeDifferenceUpdated`. Previously a forward jump made every server packet look "too old": the session ignored everything, including the bad_msg 17 that would have fixed it | `wall_clock_jumps_do_not_move_server_time` | fixed |
| TI4 | One server packet with a far-future `msg_id` (raises our clock) | P-138 | Same raise; later packets rejected and the connection closed | — | Recovered by the first packet that answers one of our messages (D12) | `future_msg_id_glitch_is_recovered_through_a_freshness_proof` | new |
| TI5 | Host pushes a wrong time difference | — | — | — | Corrected by the 15 s response rule (S06) | `responses_older_than_their_request_reset_the_clock` | ok |

## 9. Delivery, acknowledgement and resend

| ID | Condition | Spec | tdlib | MtProtoKit | Rust engine | Tests | Δ |
|---|---|---|---|---|---|---|---|
| A01 | Disconnect with sent-but-unacknowledged queries | P-079, P-182, `msg_resend_req` semantics | Unknown → `msgs_state_req`, resend only not-received (two round trips) | Re-send everything with new msg_ids (H12) | Retransmit at once with the original msg_id and seqno; the server deduplicates and re-delivers a cached answer (production probe `examples/live_dedupe.rs`, cases B–H). One round trip, executed once | `reconnect_without_ack_retransmits_with_original_msg_ids`, `repeated_reconnects_keep_retransmitting_the_same_message`, `engine::dropped_connection_recovers_without_duplicate_execution`, `engine::stalled_timed_requests_reconnect_and_retransmit_without_reexecution` | better |
| A01a | Unacknowledged query older than `RETRANSMIT_WINDOW` (240 s) at reconnect | P-182 | As A01 | As A01 | tdlib's `msgs_state_req` path; resend only not-received | `reconnect_after_retransmit_window_asks_state_and_resends_only_unreceived`, `unanswered_state_request_is_retried` | ok |
| A01b | `bad_server_salt` / bad_msg 48 for a retransmission | — | Resend with a new msg_id (may execute twice) | Resend with a new msg_id | Retransmit again under the same msg_id with the new salt; the server checks the salt before deduplicating (probe cases I, J) | `retransmission_rejected_for_salt_is_retransmitted_again_with_the_same_msg_id`, `fresh_query_rejected_for_salt_still_gets_a_new_msg_id` | better |
| A01c | Any other `bad_msg_notification` for a retransmission | — | Resend with a new msg_id | Resend with a new msg_id | Back to unknown and `msgs_state_req`; never retransmitted blindly again; a new msg_id only after "not received" | `retransmission_rejected_by_bad_msg_falls_back_to_state_request` | better |
| A01d | Stale "not received" (`msgs_all_info`) for a query retransmitted since | — | Resend | — | Ignored; the retransmission is answered | `stale_not_received_info_does_not_duplicate_a_retransmitted_query` | better |
| A01e | Transport flood / invalid DC after a retransmission | — | — | — | Left for the next connection's same-msg_id retransmission instead of a new msg_id | `rejected_connection_does_not_resend_a_retransmission_under_a_new_msg_id` | better |
| A02 | Disconnect with acknowledged queries | P-079 | Wait for the server to re-deliver | Re-send | Same as tdlib | `acknowledged_queries_survive_reconnect_without_state_request` | ok |
| A03 | Unknown queries still unresolved 60 s after connecting | §5.3 | Close on pong | — | Close on pong, after the rest of that packet has been processed (previously the packet was abandoned at the pong) | `unknown_queries_stuck_for_a_minute_close_the_connection_after_processing` | fixed |
| A04 | Local session reset requeues every in-flight query in order | §5.3 | Same | Same | Same | `reset_requeues_everything_in_original_order` | ok |
| A05 | Cancellation (pending, in flight, large in flight) | P-212 | `rpc_drop_answer` | Session reset for ≥ 512 KiB (M14): every other in-flight part restarts | Removed; in-flight requests of any size send `rpc_drop_answer`; no reconnect (tdlib) | `cancellation`, `rpc::cancelling_in_flight_requests_drops_answers_without_resetting_the_connection`, `engine::cancelled_requests_never_complete` | fixed |
| A06 | `invokeAfterMsg` dependencies | P-256, P-257 | Same | Dynamic decorator (M38) | Wrapped with the dependency's msg_id; dropped once the dependency completed | `dependencies_wrap_invoke_after_msg`, `rpc::dependency_ordering_and_msg_wait_timeout` | ok |

## 10. Liveness and reconnection

| ID | Condition | Spec | tdlib | MtProtoKit | Rust engine | Tests | Δ |
|---|---|---|---|---|---|---|---|
| L01 | `ping_delay_disconnect` cadence, online/offline timing | P-216, §4.10 | rtt-based online, 60/135 s offline | No keepalive | Same as tdlib | `online_mode_pings_faster`, `ping_and_read_timeouts` | ok |
| L02 | Silently dead connection (blackhole, NAT timeout) while answers are awaited by an offline (worker) session | — | 135 s | 12 s response timer | rtt-grade ping and read timeouts whenever queries or state/resend requests are outstanding: detected after ~7 s (`max(2, 1.5·rtt + 1) · 3.5`), previously 135 s | `offline_session_with_a_pending_query_detects_a_dead_connection_fast` | fixed |
| L03 | Idle offline session | §4.10 | 135 s | — | 135 s kept | `offline_idle_session_keeps_the_long_timeout` | ok |
| L04 | Slow but alive link (a large response trickling in) | — | Main online session can time out mid-packet | Response timer reset by partial reads | Every received byte refreshes both the read and the ping deadline, so slow links are never cut | `slow_link_trickling_bytes_never_times_out` | fixed |
| L05 | Ping right after (re)connect | §4.11 | Same | Actualization ping | Same | `reconnect_sends_a_ping_immediately`, `request_roundtrip_with_ping_and_acks` | ok |
| L06 | Reconnect backoff | §6.2 | Flood controls | 1..64 s | Immediate, then 0.3, 1, 2, 4 s with ±20 % jitter; reset on network change and on any decrypted packet; `-429` keeps its own longer delay (previously 0, 1, 2, 4, 8 s) | `transport::reconnect_ladder_is_fast_and_jittered`, `engine::network_unavailable_blocks_connections`, `engine::idle_workers_disconnect_and_reconnect_on_demand` | fixed |
| L07 | Handshake that never answers | §1.1 | 10 s | No handshake timeout (M25) | 10 s timeout → `AuthKeyCreationFailed("handshake timeout")` → retry | `engine::stalled_handshake_times_out_and_retries` | new |
| L08 | Silent blackhole while a ping is unanswered (no RST, no FIN) | — | ~7 s (`max(2, 1.5·rtt + 1) · 3.5` read timeout) | 12 s response timer | Probe: dead when nothing was read since the ping, the ping left our buffer, and the kernel send queue (`SO_NWRITE`) has not drained for `clamp(3·srtt + 0.75, 1, 4) s × backoff`; a draining queue (slow upload) is progress and is never cut; each false alarm doubles the backoff, a timely pong halves it. The classic timeouts stay as a backstop | `silent_connection_is_cut_by_the_probe_long_before_the_read_timeout`, `draining_backlog_is_progress_and_never_trips_the_probe`, `without_backlog_information_only_the_classic_timeouts_apply`, `inbound_bytes_after_the_ping_cancel_the_probe`, `probe_backoff_grows_after_a_false_alarm_and_relaxes_after_fast_pongs` | better |
| L09 | Several busy sessions on one worker thread | — | One thread per DC | One global queue (M20) | Each socket reads at most 512 KiB per turn; sessions with more data are revisited round-robin with a zero poll timeout. media/perfect p99 27–32 ms → 13–14 ms (MtProtoKit 16–19 ms) | engine benchmarks | better |

## 11. RPC errors

| ID | Condition | Spec | tdlib | MtProtoKit | Rust engine | Tests | Δ |
|---|---|---|---|---|---|---|---|
| E01 | `303 PHONE_/NETWORK_/USER_/FILE_/STATS_MIGRATE_X`, and `FILE_MIGRATE_X` with code 400 | P-270, P-271, D2 | PHONE/NETWORK/USER handled internally | Surfaced | Surfaced verbatim (TelegramCore switches DC) | `rpc::migrate_errors_surface_verbatim`, `rpc::every_migrate_error_surfaces_verbatim` | ok |
| E02 | `400 CONNECTION_NOT_INITED` / `CONNECTION_LAYER_INVALID` | P-253 | Re-send header, retry | Clear hash, retry without limit (M15) | Clear init hash, retry wrapped, at most 5 times, then surface | `rpc::connection_not_inited_clears_hash_and_retries_wrapped`, `rpc::connection_initialization_errors_are_retried_a_bounded_number_of_times` | ok |
| E03 | `MSG_WAIT_TIMEOUT` (400 or −503) and `MSG_WAIT_FAILED` (400 or 500) | P-258, P-259 | Normalized for any code, chain restarted | 400 timeout only; 500 failed unreachable (M15) | Matched by text for any code: wait for the dependency to finish, then resend without the stale wrapper; without a dependency the code decides (no hot loop) | `rpc::dependency_ordering_and_msg_wait_timeout`, `rpc::msg_wait_errors_wait_for_the_dependency_with_any_code`, `rpc::msg_wait_errors_without_a_dependency_follow_their_code` | fixed |
| E04 | Other `400`s (`PEER_ID_INVALID`, `CONNECTION_API_ID_INVALID`, `INPUT_*`, `ENCRYPTED_MESSAGE_INVALID`, `TEMP_AUTH_KEY_*`, empty text) | B4.2 | Returned | Surfaced | Surfaced verbatim | `rpc::other_error_classes_surface_verbatim` | ok |
| E05 | Main session `401 AUTH_KEY_UNREGISTERED`, `AUTH_KEY_INVALID`, `USER_DEACTIVATED`, `USER_DEACTIVATED_BAN`, `SESSION_REVOKED`, `SESSION_EXPIRED` | integration §2.4 | Log out | `AuthorizationRequired` + surfaced | `AuthorizationRequired` + surfaced | `rpc::main_session_401_requires_authorization_and_surfaces`, `rpc::main_session_401_family_requires_authorization`, `engine::main_session_401_requests_authorization` | ok |
| E06 | `401 SESSION_PASSWORD_NEEDED` | B4.2 | Not a logout | Password flag | Surfaced only | `rpc::main_session_401_family_requires_authorization` | ok |
| E07 | `401 AUTH_KEY_PERM_EMPTY` | P-232, integration §2.4 | Drop temp key, retry as 500 | Intercepted; the whole packet is dropped (L10) | Never surfaced; `TemporaryKeyRejected` once per key (or every 30 s); the request waits for a new key or a 1..30 s backoff (previously re-sent at once: a hot loop until the host rebinds); other messages in the packet are processed | `rpc::auth_key_perm_empty_never_surfaces`, `rpc::temporary_key_rejection_does_not_drop_sibling_results` | fixed |
| E08 | `401` on a token worker | integration §2.9 | Drop key, re-import | Any 401 re-transfers the token; revoked/unregistered park | Any 401 except the password case → `AuthTokenRequired`; `SESSION_REVOKED`/`AUTH_KEY_UNREGISTERED` park until the token is back (previously other 401s did not ask for a token) | `rpc::worker_token_wait_parks_requests`, `rpc::token_workers_refresh_the_token_on_any_401_but_park_only_revocations` | fixed |
| E09 | `401`/`406` on plain workers and CDN | integration §2.9 | — | Never logs out | Surfaced only | `rpc::plain_workers_and_cdn_never_log_out` | ok |
| E10 | `403 APNS_VERIFY_CHECK_x`, `RECAPTCHA_CHECK_m__k`; other 403 | integration §2.4 | Verifier | Verification | Verification; other 403 (and RECAPTCHA without `__`) surfaced | `rpc::apns_and_recaptcha_verification_park_until_resolved`, `rpc::other_error_classes_surface_verbatim` | ok |
| E11 | `404 METHOD_INVALID` | B4.1 | Returned | Surfaced | Surfaced | `rpc::other_error_classes_surface_verbatim` | ok |
| E12 | `406` (incl. `AUTH_KEY_DUPLICATED`, `UPDATE_APP_TO_LOGIN`) | P-283, B4.2 | Returned (`FROZEN_METHOD_INVALID` rewritten) | Soft reset callback + surfaced | Main: `SoftAuthReset` + surfaced verbatim; workers: surfaced | `rpc::soft_auth_reset_is_reported_and_surfaced`, `rpc::other_error_classes_surface_verbatim`, `rpc::plain_workers_and_cdn_never_log_out` | ok |
| E13 | `420 FLOOD_WAIT_X` / `FLOOD_PREMIUM_WAIT_X` (any code containing the marker) | B4.2 | Wait clamp(X, 1 s, 14 d), surface above the budget | Wait X (0 = immediate, no cap) | Wait clamp(X, 1 s, 14 d) unless automatic waiting is off; reported or delegated on request; unparsable X surfaces | `rpc::flood_wait_is_waited_out_and_reported`, `rpc::flood_wait_surfaces_without_automatic_wait`, `rpc::flood_wait_delays_are_bounded`, `rpc::delegated_retry_decisions_for_flood_and_server_errors`, `engine::flood_wait_and_server_errors_are_retried_transparently` | fixed |
| E14 | `420 SLOWMODE_WAIT_X`, `2FA_CONFIRM_WAIT_X`, `TAKEOUT_INIT_DELAY_X`, `PREMIUM_SUB_ACTIVE_UNTIL_X`, `FROZEN_METHOD_INVALID` | B4.2 | Returned | Surfaced | Surfaced verbatim | `rpc::unparsable_flood_and_frozen_method_surface`, `rpc::other_error_classes_surface_verbatim` | ok |
| E15 | `500` (incl. `INTERDC_X_CALL_ERROR`, `WORKER_BUSY_TOO_LONG_RETRY`, `RANDOM_ID_DUPLICATE`, server-side `TL_PARSING_ERROR`, `AUTH_KEY_UNSYNCHRONIZED`) | B4.1 | Backoff 1..64 s | Retry every 2 s if the gate allows | Retry after 2, 4, 8, 16 s; surfaced when retries are disabled; delegated on request | `rpc::server_errors_retry_with_backoff_or_fail`, `rpc::negative_and_normalized_codes_are_retried_as_server_errors`, `engine::flood_wait_and_server_errors_are_retried_transparently` | ok |
| E16 | Negative codes (`-503 Timeout`, `-500`, any other negative) | B4.1 | Backoff | `-500` only | Server-error class (previously only −500 and −503) | `rpc::negative_and_normalized_codes_are_retried_as_server_errors` | fixed |
| E17 | Invalid codes: 0, ≥ 10000, ≤ −10000 | §5.7 | Treated as 500 | Verbatim | Normalized to 500 (retried as E15) | `rpc_errors_are_sanitized_like_tdlib`, `tl::rpc_errors_are_sanitized`, `rpc::negative_and_normalized_codes_are_retried_as_server_errors` | fixed |
| E18 | Error text that is not valid UTF-8 | §5.7 | `INVALID_UTF8_ERROR_MESSAGE` | Lossy | `INVALID_UTF8_ERROR_MESSAGE` (previously lossy replacement characters) | `rpc::invalid_utf8_error_messages_are_replaced`, `rpc_errors_are_sanitized_like_tdlib` | fixed |
| E19 | Other unknown codes (418, 502, …) | B4 | Returned | Surfaced | Surfaced verbatim | `rpc::other_error_classes_surface_verbatim` | ok |
| E20 | Engine-made errors (`RESPONSE_UNPACK_FAILED`, `PROTOCOL_ERROR_BAD_MSG_x`) | H8 | — | `TL_PARSING_ERROR` retried forever | Terminal: never retried or delegated | `rpc::local_unpack_failures_are_terminal_and_never_retried`, `rpc::protocol_errors_after_repeated_rejections_are_terminal` | fixed |

## 12. Auth key handshake

| ID | Condition | Spec | tdlib | MtProtoKit | Rust engine | Tests | Δ |
|---|---|---|---|---|---|---|---|
| H01 | `resPQ.nonce` mismatch | P-091 | Error | Reset | `NonceMismatch` | `hs::tampering_is_rejected` | ok |
| H02 | No known RSA fingerprint | P-092 | Error | Single-key fallback | `UnknownFingerprints` | `hs::tampering_is_rejected`, `hs::unknown_server_key_is_rejected` | ok |
| H03 | Hostile `pq`: empty, > 8 bytes, < 4, prime | P-091, M7 | Factorization fails | Divide by zero / truncation (M7) | Rejected before factorization; a prime `pq` no longer burns minutes of CPU in Pollard–Brent | `hs::hostile_pq_values_fail_fast_without_hanging` | fixed |
| H04 | `server_DH_params_fail` with valid / invalid `new_nonce_hash` | D5 | Parse error | Reset | `ServerDhParamsFail` / `NewNonceHashMismatch` | `hs::server_failures_are_reported`, `hs::server_dh_params_fail_with_bad_hash_is_reported_as_hash_mismatch` | ok |
| H05 | `server_nonce` mismatch in DH params; nonce mismatch inside `server_DH_inner_data`; nonce mismatch in `dh_gen_*` | P-332 | Error | Partly | Error | `hs::nonce_checks_cover_every_message` | ok |
| H06 | `encrypted_answer` not a multiple of 16; SHA1 mismatch; ≥ 16 bytes of padding | P-099, D4 | Error | Error | `BadEncryptedAnswer` | `hs::encrypted_answer_shape_is_validated`, `hs::tampering_is_rejected` | ok |
| H07 | `dh_prime` not 2048-bit or not safe; unsupported `g`; `g_a` out of range | P-101..P-104 | Error | Error | `Dh(..)` | `hs::non_safe_or_short_primes_are_rejected`, `hs::tampering_is_rejected`, `dh::generator_conditions_follow_documentation`, `dh::g_a_range_checks`, `dh::unknown_composite_is_rejected_and_cached`, `dh::rejects_wrong_prime_shapes` | ok |
| H08 | `dh_gen_ok` with a wrong `new_nonce_hash1` | P-110 | Error | Error | `NewNonceHashMismatch` | `hs::dh_gen_hash_mismatch_is_rejected` | ok |
| H09 | `dh_gen_retry` (with `retry_id`), too many retries, `dh_gen_fail` | P-111 | Restart | Restart (L17) | Retry with `retry_id` up to 5, then fail; `DhGenFail` | `hs::dh_gen_retry_is_followed`, `hs::too_many_retries_fail`, `hs::server_failures_are_reported` | ok |
| H10 | Trailing bytes after the TL object, declared length shorter than the frame | §1.2 | Allowed (`check_end = false`) | Body not truncated | Allowed (previously `TrailingData` failed the handshake) | `hs::trailing_bytes_after_handshake_answers_are_tolerated_like_tdlib`, `msg::plain_message_roundtrip` | fixed |
| H11 | Wrong constructor for the current state | — | Error | Reset | `Tl(UnexpectedConstructor)` | `hs::unexpected_constructor_in_state_fails` | ok |
| H12 | Garbage plain packets | — | — | — | Never panics | `hs::handshake_never_panics_on_garbage` | new |
| H13 | Transport errors and stalls during the handshake | P-100 | Restart, 10 s timeout | H7, M25 | See T02, T04, L07 | `engine::handshake_transport_error_restarts_key_generation_without_key_invalid`, `engine::stalled_handshake_times_out_and_retries` | fixed |
| H14 | Auth key with a leading zero byte | M6 | 256-byte encoding | Unpadded (M6) | 256-byte encoding | `dh::fixed_be_padding`, `hs::permanent_key_agreement` | ok |
| H15 | Temporary key (`p_q_inner_data_temp_dc`, `expires_at`) | P-230 | Same | Legacy constructor (L17) | Same as tdlib | `hs::temporary_key_agreement` | ok |

## 13. Temporary keys (PFS)

| ID | Condition | Spec | tdlib | MtProtoKit | Rust engine | Tests | Δ |
|---|---|---|---|---|---|---|---|
| P01 | Temp key unknown (`-404`) | P-241 | Regenerate and rebind | Recreate | `AuthKeyInvalid`; requests kept for the new key | `engine::unknown_key_reports_invalid_and_recovers_with_new_key` | ok |
| P02 | Unbound temp key (`AUTH_KEY_PERM_EMPTY`) | P-232 | Rebind | Intercept | See E07 | `rpc::auth_key_perm_empty_never_surfaces` | fixed |
| P03 | Bind errors (`ENCRYPTED_MESSAGE_INVALID`, `TEMP_AUTH_KEY_EMPTY`, `TEMP_AUTH_KEY_ALREADY_BOUND`, `EXPIRES_AT_INVALID`) | P-237, P-239 | 60 s rule | H5 | Surfaced verbatim to the host, which owns binding | `rpc::other_error_classes_surface_verbatim` | ok |
| P04 | Key replaced by the host | — | New session | — | Session reset; requests parked by E07 are released at once | `rpc::auth_key_perm_empty_never_surfaces` | fixed |

## 14. Hostile peers, amplification and long uptime

Found by the 2026-10 security pass (three independent audits, the `mtproto-fuzz` harness and the hostile fault
suite). "Hostile" means either an on-path attacker (everything before decryption: framing, obfuscation without a
proxy secret, transport error codes, the unencrypted handshake) or a server holding the key.

| ID | Condition | tdlib | MtProtoKit | Rust engine | Tests | Δ |
|---|---|---|---|---|---|---|
| X01 | `msg_new_detailed_info` / `msg_detailed_info` fan-out (one 16 MB packet = 460k answer ids) | Unbounded map | p50 ×60, CPU ×27 (`hostile/x-fan-out`) | Awaited answers capped at 1024, set-based requeue on reconnect, ≤ 4096 messages processed per packet (was 35 s per reconnect) | `hostile_detailed_info_fan_out_stays_bounded`, fuzz `session` amplification packets | fixed |
| X02 | Messages evicted from the dedupe window replayed (salt / clock rollback) | Dropped | — | Too-old messages act only on live client state (pending query, ping, service request); freshness proof needs a msg_id sent in the last 300 s | `replayed_old_salt_and_bad_msg_notifications_are_ignored`, `an_answer_redelivered_with_an_evicted_msg_id_still_completes_its_query` | fixed |
| X03 | Server rejects every send (`bad_server_salt` or `bad_msg_notification` loop) | Resends at RTT rate forever | 158k packets, 24 MB, 41 s CPU per minute for 2 stuck requests (`loop/x-salt-loop`, `loop/x-time-loop`) | After 12 consecutive rejections the query fails with 500 and the RPC backoff (2–16 s) applies: 283 packets, 0.5 s CPU | `a_server_rejecting_every_send_cannot_hold_a_query_in_a_resend_loop` | better |
| X04 | `msg_resend_req` loop for a large query (upload amplification) | Unbounded | 4366 connections, 10655 duplicate executions (`loop/x-resend-loop`) | ≤ 8 server-requested resends per query | `a_server_cannot_make_the_client_upload_a_query_forever` | better |
| X05 | Server or middlebox closes every connection right after it is accepted | ≤ ~1 attempt/s | — | Urgent ladder 0, 50, 100, 250, 500 ms then 1 s (was 250 ms forever) | `engine::a_server_that_closes_every_connection_is_retried_at_a_bounded_rate` | fixed |
| X06 | Path kills every connection after its first answer (DPI, flapping NAT) with keep-alive sessions | — | — | Connections that die within 10 s without delivering a result count as flaps; after 3, back off 0.5 → 16 s; productive connections never back off (was 31 reconnects/s) | `engine::a_path_that_cuts_every_connection_after_the_first_answer_does_not_cause_a_reconnect_storm`, `transport::flapping_paths_back_off_after_a_few_short_connections` | new |
| X07 | Racing connection fed endless garbage | — | — | Racer fails after 2 reads / 16 KB without a matching `res_pq`, any decode error fails it, failed races back off 1–8 s (was: unbounded buffering, the worker starved every session) | `engine::a_racer_fed_endless_garbage_is_dropped_without_starving_the_worker` | fixed |
| X08 | Proxy hostname that does not resolve, or resolves slowly | — | — | Lookups shared per host, waiting sessions leave the poll deadline, failures back off 1–8 s (was 100% of a core and a thread per spin) | `engine::unresolvable_proxy_host_backs_off_instead_of_spinning` | fixed |
| X09 | Attacker-chosen `pq` (prime, near 2^64) | Bounded iterations | — | Deterministic Miller–Rabin rejects primes, global step budget, overflow-free step | `crypto::factor` tests, fuzz `pq` | fixed |
| X10 | SOCKS5: proxy sends data before the TCP connect completes; bad auth reply version | — | — | The connect transition runs before the read, so the SOCKS handshake is never skipped; auth reply version checked | `socks5` tests, fuzz `socks5` | fixed |
| X11 | Garbage, tampered msg_key, oversized/truncated frames, transport codes, foreign session, even msg_id, huge vector counts, deep nesting, salts floods, salt storms, unknown results, replays, quick-ack noise | Varies | Hangs and 143–561 duplicate executions per scenario (`hostile/*`) | 0 hung, 0 duplicates, non-fatal faults never reconnect | `engine::hostile_server_faults_never_break_exactly_once_delivery`, bench `tc --suite hostile` | better |
| X12 | Secrets in memory | Partly | — | FFI copies of auth keys and key buffers zeroed, AES key schedules zeroed, no callbacks after `mt_engine_destroy`, test RNGs and helpers not compiled into the library | ffi tests | fixed |
| X13 | Months of uptime: counters, salts expiring during sleep, wall-clock changes, state growth | — | Grows ~69 KB/h (C10) | 30–90 simulated days per fuzz case: exactly-once on both sides, monotonic msg_ids, idle state ≤ 256 KB; real-time `mtproto-bench soak` keeps threads, descriptors and live heap flat | fuzz `soak`, `mtproto-bench soak` | new |

## 15. Documentation re-audit (2026-10-02)

Every normative statement on the core.telegram.org MTProto and invoking pages, checked against the code after the
hardening pass.

| ID | Condition | Spec | tdlib | MtProtoKit | Rust engine | Tests | Δ |
|---|---|---|---|---|---|---|---|
| I05 | Outgoing container: queries + `rpc_drop_answer` + every service message ≤ 1024 | service_messages#simple-container, mtproto-transports (-429) | queries+cancels ≤ 1000 | 3 KiB groups | One budget of 1024 per container (2 slots reserved for destroy/ack); overflow stays queued (was: drop answers, pongs and state replies unbounded) | `outgoing_containers_never_exceed_1024_messages` | fixed |
| I06 | Retransmission under the original msg_id never sent bare | service_messages_about_messages#request-for-message-status-information | — | — | Always wrapped in a fresh container | `reconnect_without_ack_retransmits_with_original_msg_ids` | ok |
| I07 | Padding length | description (12..1024) | Size buckets, +0..255 random with proxy secrets | Random ≤ 72 | 0–64 random extra bytes direct, 0–240 behind proxies or secrets (was minimal 12..27, a DPI length fingerprint) | `message::padding` tests | fixed |
| I08 | Request body size and alignment | mtproto (multiple of 4) | — | — | Bodies that are empty, unaligned or > 8 MiB fail locally with `REQUEST_INVALID_SIZE` (was: ≥ 16 MiB aborted the process) | `rpc::oversized_or_unaligned_requests_fail_locally_instead_of_reaching_the_wire` | fixed |
| S21 | Our `msg_resend_req` answered by `msgs_state_info` | service_messages_about_messages#explicit-request-to-re-send-messages | Closes the connection | M34 | A multi-id request that fails is retried one id at a time; only a query whose own single-id request fails is re-sent (was: every query in the batch re-sent, re-executing those whose answers still existed) | `a_failed_batched_answer_request_is_retried_one_by_one_before_any_query_is_resent`, `answer_resend_requests_resolve_or_fall_back_to_resending_the_query` | fixed |
| S28 | `msg_resend_ans_req` | Removed from the docs in 2024, never in the schema | — | — | Answered with state info, all 1; we send `msg_resend_req` with answer ids, as tdlib | (unchanged) | ok |
| S32 | `destroy_auth_key` on logout | service_messages#destruction-of-a-permanent-auth-key | Sent on logout | Never | `Engine::destroy_auth_key` / `mt_session_destroy_auth_key`, outcome reported as `RpcEvent::AuthKeyDestroyed` (TelegramCore does not call it yet) | `engine::destroying_the_auth_key_on_logout_reaches_the_server`, `destroy_responses_are_handled` | fixed |
| D11 | msg_id outside the window after sync | security_guidelines#checking-msg-id | Same | — | > 300 s in the past dropped; future ids adopted as the new server time (tdlib parity, deliberate) | `messages_outside_time_window_are_ignored_after_sync` | ok |
| E21 | `initConnection` after an app restart | invoking#saving-client-info ("must") | Re-sent per process | Skipped while the hash matches | The persisted hash is honoured only for keys initialised in this process, so the first request after a restart is wrapped again | engine tests | fixed |
| E22 | `MSG_WAIT_TIMEOUT` | invoking#sequential-requests | — | — | Waits for the dependency, re-sends unwrapped (deliberate: keeps order without a server-side wait) | `rpc::msg_wait_errors_wait_for_the_dependency_with_any_code` | ok |
| E23 | Outgoing `gzip_packed` | invoking#data-compression ("recommend") | Yes | No | The innermost query is gzipped when it is ≥ 256 bytes, not a file part and shrinks by ≥ 10 % | `rpc::wrap` tests | fixed |
| U01 | Updates from CDN sessions | cdn ("must not accept") | — | — | Dropped in the RPC layer for `SessionRole::Cdn` (was left to the host) | `rpc::cdn_sessions_never_forward_updates` | fixed |
| P05–P08 | Temp key binding (`bind_auth_key_inner`, gate until bound, `initConnection` after bind, `ENCRYPTED_MESSAGE_INVALID` rule) | api/pfs | Yes | Yes | Not in Rust yet; keys (including temporary ones) are created and bound by MTContext | — | gap |

## 16. Final hardening pass (2026-10-02)

Found by four parallel reviews (transport, runtime/FFI, crypto/handshake, Swift bridge), by profiling one
million requests through TelegramCore, and by a new stateful adversary in the test server. Every row was
checked against tdlib's source (`third-party/td`, 1.8.49).

| ID | Condition | tdlib | MtProtoKit | Rust engine | Tests | Δ |
|---|---|---|---|---|---|---|
| L10 | Bytes arrive but prove nothing: a frame header announcing 8 MiB then 1 byte per 300 ms, Nop frames, quick-ack noise, replayed server packets | Ping timeout fed only by pongs and decrypted packets (replays count); read timeout by any byte | Any byte resets its timers | Only packets with a new msg_id refresh liveness; raw bytes count only for a frame in progress that keeps ≥ 512 B/s after a 15 s grace (was: any byte, so the ping, read, probe and request timeouts never fired) | `engine::trickling_or_noisy_connections_are_abandoned_and_requests_complete` (all three modes) | fixed |
| L11 | Large uploads on a slow uplink: no byte comes back until a part is fully sent | Read timeout `rtt × 3.5` with no write progress | Response timeout 12 s + size / 12 KB/s | Every packet ≥ 4 KiB extends a transmit grace by size / 8 KiB/s during which no liveness timeout fires; bytes acknowledged by TCP count as progress while ≥ 16 KiB are queued (was: probe and read timeouts restarted the upload forever: 18 connections, never finished) | `engine::slow_uplink_uploads_complete_without_reconnect_loops` (netsim `slow-uplink` with backpressure) | fixed |
| L12 | Every connection answered with -444, -403, -1 or another non-flood transport error | `mtproto_error_flood_control`: at most 3 attempts per 8 s | Retries | Exponential 1 → 16 s backoff (tdlib desktop cap); from the second consecutive rejection the address counts as failed so others are tried (was: about one reconnect a second to the same address, forever) | `engine::persistent_transport_rejections_back_off`, `engine::other_transport_errors_reconnect_quickly` | fixed |
| L13 | DNS answers for proxy or DC host names | Cached 60–299 s, errors not cached | Resolved per connection | Cached 299 s, re-resolved once every cached address failed, cleared on reset and network change; answers for a host no longer targeted are ignored; a lookup stuck for 30 s may start again (was: cached for the session's lifetime, lookups never expired) | `session_runtime::tests::resolved_addresses_expire_and_are_refreshed_after_every_one_failed` | fixed |
| L14 | The OS says the network is unavailable | Hard gate on the app's network flag | Hint only | Gate, but a session with work still probes every 30 s, and a packet received while marked offline corrects the flag (false negatives under VPNs cannot strand the app) | `engine::network_unavailable_blocks_connections` | better |
| L15 | Engine idle | — | — | No wakeup without pending usage bytes (was every 2 s per connection); the connection race and racer timeouts are real deadlines now (they relied on that tick) | `engine::connect_race_reaches_a_live_address_when_the_first_one_swallows_syns` | fixed |
| L16 | Racing an `ee` (fake-TLS) address | — | — | A promoted racer starts its session at TCP connect, and the silent-race probe is sent once TLS completes (was: never sent, so the race always lost) | engine race tests | fixed |
| L17 | Write buffer under sustained backpressure | — | — | Compacted once the written prefix is ≥ 64 KiB and half the buffer (was: grew by every byte uploaded on the connection) | `connection::tests::a_never_empty_write_buffer_stays_bounded` | fixed |
| E24 | Negative error codes other than -500 (`-503 Timeout`) | Retried with 1 → 60 s backoff for at most 60 s, then 429; off for bot callbacks | Surfaced | Surfaced at once, like MtProtoKit, since TelegramCore and the wallet were written against it (was: retried every 2 s forever through the Swift retry decision) | `rpc::other_negative_codes_surface_like_mtprotokit` | fixed |
| E25 | Repeated 500 / -500 with a delegated retry decision | 1 → 60 s backoff | Fixed delay | 2 → 16 s backoff (was fixed 2 s) | `rpc::delegated_server_error_retries_back_off` | fixed |
| B10 | `bad_msg_notification` 17 while earlier queries are still being answered | Closes the session at once and resends everything: queries executed but not yet answered run twice | Resets the session | Stops sending and collects answers still in flight on the old session for up to RTT estimate (1–5 s), then resets and resends only what is left (removes the duplicate execution seen under server clock warps) | `bad_msg_17_drains_answers_in_flight_before_resetting`, `bad_msg_17_drain_gives_up_after_its_deadline` | better |
| K10 | Clock offset and salt events reaching MTContext (each one a keychain and Postbox write) | — | After time syncs only | Forwarded only when the offset moves by ≥ 1 s or the salt set changes (was: on every new maximum above 0.1 ms) | engine tests | fixed |
| K11 | `fail_request` / retry decision for a request queued before the session has a key | — | — | Removes it and reports `Failed` (was ignored, the request ran later anyway) | engine tests | fixed |
| H10 | `res_pq` with 65 536 fingerprints, none known | — | — | The error carries only the count (was: a 1.3 MB log line per attempt) | `hs::` tests | fixed |
| C10 | Per-packet CPU | — | — | `dispatch_ready` walks only parked requests, query state counters replace scans, randomness comes from a 256-byte pool refilled by the OS (one syscall per 256 bytes instead of several per packet), engine wakeups are coalesced, a 1 ms send delay batches bursts into containers (tdlib's `QUERY_DELAY`), AES-IGE builds one key schedule instead of two, gunzip reserves at most the deflate bound. One million requests through TelegramCore: CPU 11.8 → 8.8 s, packets 29 k → 8.9 k, p50 1.16 → 0.92 ms (MtProtoKit: 73.5 s, 7.46 ms) | all suites | fixed |
| S10 | Swift: the first `AuthKeyRequired` of a keyless session | — | — | The mailbox buffers events until the session attaches (was: dropped if delivered before `init` finished, and the session never asked for a key) | bench suites | fixed |
| S11 | Swift: per-event and per-request overhead | — | — | Events are coalesced into one queue hop per burst, the routing lock is an unfair lock, cancellation goes by request id instead of a weak reference (no side table per request) | million-request bench | fixed |
| S12 | Swift: connection watchdog | Config recoverer retries backup sources while connecting stays broken | Re-armed for every connection attempt | Re-armed with 20 → 320 s backoff while unhealthy, reset on resume, transport scheme revalidated on recovery (was: fired once per outage) | — | fixed |
| S13 | Swift: system wake | — | — | Connections are reset on `NSWorkspace.didWakeNotification` (kevent timeouts do not count sleep) | — | new |

Adversary added to `mtproto-testserver` (`Fault::ADAPTIVE` plus `Fault::AdaptiveTrickle`): `a-reconnect-ambush`
(bad salt, then bad_msg 16, then a cut on the first packets of a connection), `a-kill-on-retransmit` (cuts the
connection when the client retransmits or asks for state, three times per message), `a-time-warp` (the server
clock jumps ±10–60 minutes), `a-lazy-redelivery` (executes, cuts, and redelivers only when asked), `a-slow-drip`
(answers trickle out in 1–48 byte pieces), `a-trickle` (the connection is held with one of the L10 streams).
`torture/apocalypse` mixes all ordinary and adaptive faults on a flaky network; `torture/apocalypse-hostile` adds
every hostile fault. The cluster servers now validate client msg_id times like the real server.

Verification on the final code, through TelegramCore with both engines (`mtproto-bench tc`, suites `quick`,
`torture-quick` with 27 scenarios and `hostile-quick` with 20): the Rust engine completed every request of every
scenario with 0 wrong results and 0 duplicate executions (the `loop/*` scenarios keep their 2 doomed requests
pending by design, at 0.5 s CPU against MtProtoKit's 51 s). MtProtoKit stalled in 7 torture scenarios (rotate-salt,
transport-flood, all-faults, all-faults-flaky, a-time-warp, a-trickle, apocalypse-hostile) and executed requests
twice in 12 (up to 8,086). Fuzzing: 14 targets, 10.1 million cases (3,000 of them 30–90 simulated days of soak),
0 failures. `cargo test --workspace`: 371 tests; `MTProtoRustEngineTests`: 37.

`a-slow-drip` is the one scenario where MtProtoKit finishes sooner (167–250 against 116–123 requests/s). The test
server drips the whole reply to the client packet that drew the fault and reads nothing meanwhile, and the engine
batches up to 130 messages into one container (tdlib's 1 ms `QUERY_DELAY`), so its dripped batches averaged 43
replies against MtProtoKit's 23 (`TC_BENCH_STATS=1` prints the server's counts). A real server keeps reading while
a slow write drains, so batching was left as it is.

## Not covered (deliberately)

- **HTTP transport** (`http_wait`, long poll): the engine only speaks TCP transports (T22).
- **Answers lost after the server acknowledged a query** (the server says "received" but never answers):
  tdlib closes the connection after 60 s and asks again, which never resolves either; the engine relies on
  host request timeouts. Unacknowledged queries are fully covered (A01, A03).
- **`destroy_session` for old sessions** after a local reset: not sent (tdlib and MtProtoKit do not either);
  the responses are handled (S31).
- **Binding temp keys** (`auth.bindTempAuthKey`) is done by the host; the engine only reports and surfaces the
  conditions (P01..P04).
