//! Security requirements on the RPC layer that had no test of their own: outgoing gzip (B-19), the cap
//! on queries in flight (B-29), CDN updates (B-33), initConnection's conditional fields (L-05) and the
//! error texts the client hands to the host (L-10).

use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::XorShiftRandom;
use mtproto_core::rpc::{
    ApiEnvironment, ClientProxy, INIT_CONNECTION, INPUT_CLIENT_PROXY, RequestFlags, RequestId, RpcClient, RpcEvent,
    RpcRequest, SessionRole, wrap_request, wrapper_len,
};
use mtproto_core::session::{Now, ServerSalt, Session, SessionConfig};
use mtproto_core::test_support::server_peer::{
    DecodedPacket, Outgoing, ServerPeer, container, gzip_packed, msg_copy, new_session_created, rpc_error_raw,
    rpc_result, update,
};
use mtproto_core::tl::mtproto::{INVALID_UTF8_ERROR_MESSAGE, gunzip};
use mtproto_core::tl::{Reader, Writer, ids};

const START: f64 = 1_727_000_000.0;
const CALL: u32 = 0x5e57_0b01;
const UPLOAD_SAVE_FILE_PART: u32 = 0xb304_a621;
const UPLOAD_SAVE_BIG_FILE_PART: u32 = 0xde7b_673d;
const MAX_INFLIGHT_QUERIES: usize = 1024;

fn key() -> AuthKey {
    AuthKey::new(core::array::from_fn(|i| (i as u8).wrapping_mul(23).wrapping_add(5)))
}

fn environment() -> ApiEnvironment {
    ApiEnvironment {
        layer: 230,
        api_id: 4,
        device_model: "Mac".into(),
        system_version: "26".into(),
        app_version: "1".into(),
        system_lang_code: "en".into(),
        lang_pack: "macos".into(),
        lang_code: "en".into(),
        proxy: None,
        params: None,
        init_hash: "h1".into(),
        disable_updates: false,
    }
}

fn call(tag: u32) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(CALL);
    writer.write_u32(tag);
    writer.into_inner()
}

fn noise(length: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

fn compressible(constructor: u32, length: usize) -> Vec<u8> {
    let mut body = constructor.to_le_bytes().to_vec();
    body.resize(length, b'a');
    body
}

struct Harness {
    client: RpcClient,
    server: ServerPeer,
    rng: XorShiftRandom,
    now: Now,
}

impl Harness {
    fn new(role: SessionRole, stored_hash: Option<&str>) -> Self {
        let mut rng = XorShiftRandom::new(41);
        let now = Now { mono: 10.0, unix: START };
        let salts = [ServerSalt { salt: 7, valid_since: START - 10.0, valid_until: START + 100_000.0 }];
        let mut session = Session::new(SessionConfig::default(), key(), &salts, 0.0, now, &mut rng);
        session.connection_opened(now);
        let client = RpcClient::new(session, role, Some(environment()), stored_hash.map(str::to_string));
        let mut server = ServerPeer::new(key(), START);
        server.salt = 7;
        Self { client, server, rng, now }
    }

    fn advance(&mut self, seconds: f64) {
        self.now.mono += seconds;
        self.now.unix += seconds;
        self.server.server_time += seconds;
    }

    fn send_body(&mut self, id: u64, body: Vec<u8>) {
        self.client
            .send(RpcRequest { id: RequestId(id), body, flags: RequestFlags::default(), invoke_after: None }, self.now);
    }

    fn packets(&mut self) -> Vec<DecodedPacket> {
        let mut packets = Vec::new();
        let mut idle = 0;
        for _ in 0..60 {
            self.advance(0.002);
            let _ = self.client.handle_timeout(self.now);
            let Some(transmit) = self.client.poll_transmit(self.now, &mut self.rng) else {
                idle += 1;
                if idle > 3 {
                    break;
                }
                continue;
            };
            idle = 0;
            packets.push(self.server.decode(&transmit.data));
        }
        packets
    }

    fn query_bodies(&mut self) -> Vec<(i64, Vec<u8>)> {
        self.packets()
            .into_iter()
            .flat_map(|packet| packet.messages)
            .filter(|message| message.is_content_related())
            .map(|message| (message.msg_id, message.body))
            .collect()
    }

    fn reply(&mut self, items: Vec<Outgoing>) {
        let packet = self.server.encode(items);
        self.client.handle_packet(&packet, self.now, &mut self.rng).unwrap();
    }

    fn events(&mut self) -> Vec<RpcEvent> {
        self.client.drain_events()
    }
}

fn skip_init_connection(reader: &mut Reader<'_>) {
    assert_eq!(reader.read_u32().unwrap(), ids::INVOKE_WITH_LAYER);
    reader.read_i32().unwrap();
    assert_eq!(reader.read_u32().unwrap(), INIT_CONNECTION);
    let flags = reader.read_i32().unwrap();
    assert_eq!(flags, 0);
    reader.read_i32().unwrap();
    for _ in 0..6 {
        reader.read_bytes().unwrap();
    }
}

fn query_on_the_wire(role: SessionRole, stored_hash: Option<&str>, body: Vec<u8>) -> Vec<u8> {
    let mut h = Harness::new(role, stored_hash);
    h.send_body(1, body);
    let mut bodies = h.query_bodies();
    assert_eq!(bodies.len(), 1);
    bodies.remove(0).1
}

#[test]
fn outgoing_gzip_only_for_compressible_requests_above_255_bytes_and_never_for_file_parts() {
    for length in [8, 64, 128, 252] {
        let body = compressible(CALL, length);
        assert_eq!(wrap_request(&body, None, false, None), body, "{length} bytes are sent as they are");
        assert_eq!(query_on_the_wire(SessionRole::Main, Some("h1"), body.clone()), body, "{length} bytes on the wire");
    }
    for length in [256, 1024, 64 * 1024] {
        let body = compressible(CALL, length);
        let wire = query_on_the_wire(SessionRole::Main, Some("h1"), body.clone());
        assert_eq!(u32::from_le_bytes(wire[..4].try_into().unwrap()), ids::GZIP_PACKED, "{length} bytes are packed");
        assert!(wire.len() < body.len(), "{length}: packing made it {} bytes", wire.len());
        let mut reader = Reader::new(&wire[4..]);
        assert_eq!(gunzip(reader.read_bytes().unwrap(), 1 << 20).unwrap(), body);
        assert!(reader.finish().is_ok());
    }
    for constructor in [UPLOAD_SAVE_FILE_PART, UPLOAD_SAVE_BIG_FILE_PART] {
        let part = compressible(constructor, 4096);
        assert_eq!(
            query_on_the_wire(SessionRole::Worker { requires_auth_token: false }, Some("h1"), part.clone()),
            part
        );
    }
    for (length, seed) in [(256usize, 3u64), (300, 5), (4096, 7), (64 * 1024, 11)] {
        let mut random = noise(length, seed);
        random[..4].copy_from_slice(&CALL.to_le_bytes());
        assert_eq!(wrap_request(&random, None, false, None), random, "{length} incompressible bytes");
    }
    let body = compressible(CALL, 4096);
    let wire = query_on_the_wire(SessionRole::Main, None, body.clone());
    let mut reader = Reader::new(&wire);
    skip_init_connection(&mut reader);
    assert_eq!(reader.read_u32().unwrap(), ids::GZIP_PACKED, "the initConnection header stays outside the packing");
    assert_eq!(gunzip(reader.read_bytes().unwrap(), 1 << 20).unwrap(), body);
}

#[test]
#[ignore = "B-29: nothing caps the queries in flight; 1500 go out unanswered at once"]
fn no_more_than_1024_queries_are_in_flight_at_once() {
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    for id in 1..=1500u64 {
        h.send_body(id, call(id as u32));
    }
    let first = h.query_bodies();
    assert!(first.len() <= MAX_INFLIGHT_QUERIES, "{} queries in flight with none answered", first.len());
    let mut sent = first.len();
    let mut in_flight: Vec<i64> = first.iter().map(|(msg_id, _)| *msg_id).collect();
    for _ in 0..8 {
        if in_flight.is_empty() {
            break;
        }
        for chunk in in_flight.chunks(500) {
            let answers = chunk.iter().map(|msg_id| Outgoing::Content(rpc_result(*msg_id, &[1, 0, 0, 0]))).collect();
            h.reply(answers);
        }
        let next = h.query_bodies();
        assert!(next.len() <= MAX_INFLIGHT_QUERIES, "{} queries in flight", next.len());
        sent += next.len();
        in_flight = next.iter().map(|(msg_id, _)| *msg_id).collect();
    }
    assert_eq!(sent, 1500, "every query went out once a slot was free");
    let completed = h.events().iter().filter(|event| matches!(event, RpcEvent::Completed { .. })).count();
    assert_eq!(completed, 1500);
}

#[test]
fn updates_from_a_cdn_are_dropped_in_every_wrapping() {
    for role in [SessionRole::Cdn, SessionRole::Main] {
        let mut h = Harness::new(role, Some("h1"));
        h.send_body(1, call(1));
        let sent = h.query_bodies();
        let query = sent[0].0;
        let inner = h.server.next_msg_id(false);
        let child = h.server.next_msg_id(false);
        let too_long = update(0xe317_af7e, &[]);
        h.reply(vec![
            Outgoing::Content(update(0x1234_5678, &[1; 8])),
            Outgoing::Content(gzip_packed(&update(0x1234_5679, &[2; 8]))),
            Outgoing::Content(msg_copy(inner, 1, &update(0x1234_567a, &[3; 8]))),
            Outgoing::Content(container(&[(child, 1, update(0x1234_567b, &[4; 8]))])),
            Outgoing::Content(too_long),
            Outgoing::Service(new_session_created(query, 99, 7)),
            Outgoing::Content(rpc_result(query, &[9, 0, 0, 0])),
        ]);
        let events = h.events();
        let updates = events.iter().filter(|event| matches!(event, RpcEvent::Update { .. })).count();
        let resets = events.iter().filter(|event| matches!(event, RpcEvent::UpdatesReset)).count();
        let completed = events.iter().any(|event| matches!(event, RpcEvent::Completed { id: RequestId(1), .. }));
        assert!(completed, "{role:?}: the answer in the same packet still completes: {events:?}");
        if role == SessionRole::Cdn {
            assert_eq!((updates, resets), (0, 0), "a CDN pushed updates or a gap to the host: {events:?}");
        } else {
            assert_eq!(updates, 5, "the main session takes every update shape: {events:?}");
            assert!(resets >= 1);
        }
    }
}

#[test]
fn init_connection_conditional_fields_are_present_only_with_their_flag() {
    let payload = [0x11u8, 0x22, 0x33, 0x44];
    let params = vec![0x99u8, 0x71, 0xb5, 0x99, 0, 0, 0, 0];
    for (with_proxy, with_params) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut env = environment();
        env.proxy = with_proxy.then(|| ClientProxy { address: "198.51.100.7".into(), port: 8443 });
        env.params = with_params.then(|| params.clone());
        let wrapped = wrap_request(&payload, Some(&env), false, None);
        assert_eq!(
            wrapper_len(Some(&env), false, None),
            Some(wrapped.len() - payload.len()),
            "{with_proxy} {with_params}: the size check measures what is written"
        );
        let mut reader = Reader::new(&wrapped);
        assert_eq!(reader.read_u32().unwrap(), ids::INVOKE_WITH_LAYER);
        assert_eq!(reader.read_i32().unwrap(), 230);
        assert_eq!(reader.read_u32().unwrap(), INIT_CONNECTION);
        let flags = reader.read_i32().unwrap();
        assert_eq!(flags, i32::from(with_proxy) | (i32::from(with_params) << 1), "only bits 0 and 1 are defined");
        assert_eq!(reader.read_i32().unwrap(), 4);
        for expected in ["Mac", "26", "1", "en", "macos", "en"] {
            assert_eq!(reader.read_bytes().unwrap(), expected.as_bytes());
        }
        if flags & 1 != 0 {
            assert_eq!(reader.read_u32().unwrap(), INPUT_CLIENT_PROXY);
            assert_eq!(reader.read_bytes().unwrap(), b"198.51.100.7");
            assert_eq!(reader.read_i32().unwrap(), 8443);
        }
        if flags & 2 != 0 {
            assert_eq!(reader.read_array::<8>().unwrap(), params[..]);
        }
        assert_eq!(reader.read_array::<4>().unwrap(), payload, "absent fields take no bytes");
        assert!(reader.finish().is_ok());
    }
}

#[test]
fn error_texts_reach_the_host_as_the_server_sent_them_or_as_one_marker() {
    let invalid: [&[u8]; 6] = [
        &[0x46, 0x4c, 0x4f, 0x4f, 0x44, 0x80],
        &[0xc3],
        &[0x41, 0xe2, 0x82],
        &[0xc0, 0x80],
        &[0xed, 0xa0, 0x80],
        b"APNS_VERIFY_CHECK_\xff\xfe",
    ];
    for raw in invalid {
        for gzipped in [false, true] {
            let mut h = Harness::new(SessionRole::Main, Some("h1"));
            h.send_body(1, call(1));
            let sent = h.query_bodies();
            let error = rpc_error_raw(sent[0].0, 403, raw);
            let error = if gzipped {
                let mut inner = Writer::new();
                inner.write_u32(ids::RPC_ERROR);
                inner.write_i32(403);
                inner.write_bytes(raw);
                rpc_result(sent[0].0, &gzip_packed(inner.as_slice()))
            } else {
                error
            };
            h.reply(vec![Outgoing::Content(error)]);
            let events = h.events();
            assert!(
                events.iter().any(
                    |event| matches!(event, RpcEvent::Failed { message, .. } if message == INVALID_UTF8_ERROR_MESSAGE)
                ),
                "{raw:?} gzipped {gzipped}: {events:?}"
            );
            assert!(!events.iter().any(|event| matches!(event, RpcEvent::VerificationRequired { .. })));
        }
    }
    let mut h = Harness::new(SessionRole::Main, Some("h1"));
    h.send_body(1, call(1));
    let sent = h.query_bodies();
    let text = "PEER_ID_INVALID\0ignored \u{e9}";
    h.reply(vec![Outgoing::Content(rpc_error_raw(sent[0].0, 400, text.as_bytes()))]);
    let events = h.events();
    assert!(
        events.iter().any(|event| matches!(event, RpcEvent::Failed { code: 400, message, .. } if message == text)),
        "valid text is delivered whole, NUL included: {events:?}"
    );
}
