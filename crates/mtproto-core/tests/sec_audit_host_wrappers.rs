//! Host strings go into the request wrappers (initConnection, invokeWithReCaptcha, invokeWithApnsSecret).
//! One TL cannot carry, or a wrapper that would push the packet past the transport's frame limit, must
//! fail that request locally: the TL writer and the framer assert, and a release build aborts on a panic.

use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::XorShiftRandom;
use mtproto_core::rpc::{
    ApiEnvironment, ClientProxy, MAX_WRAPPER_BYTES, RequestFlags, RequestId, RpcClient, RpcEvent, RpcRequest,
    SessionRole, Verification, wrapper_len,
};
use mtproto_core::session::{Now, ServerSalt, Session, SessionConfig};
use mtproto_core::test_support::server_peer::{Outgoing, ServerPeer, rpc_error};
use mtproto_core::tl::ids;
use mtproto_core::transport::{Framing, encode_frame};

const START: f64 = 1_727_000_000.0;
const TOO_LONG: usize = 1 << 24;

fn key() -> AuthKey {
    AuthKey::new(core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(3)))
}

fn environment() -> ApiEnvironment {
    ApiEnvironment {
        layer: 230,
        api_id: 9,
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

struct Harness {
    client: RpcClient,
    server: ServerPeer,
    rng: XorShiftRandom,
    now: Now,
}

impl Harness {
    fn new(environment: ApiEnvironment) -> Self {
        let mut rng = XorShiftRandom::new(9);
        let now = Now { mono: 10.0, unix: START };
        let salts = [ServerSalt { salt: 5, valid_since: START - 10.0, valid_until: START + 100_000.0 }];
        let mut session = Session::new(SessionConfig::default(), key(), &salts, 0.0, now, &mut rng);
        session.connection_opened(now);
        let client = RpcClient::new(session, SessionRole::Main, Some(environment), None);
        let mut server = ServerPeer::new(key(), START);
        server.salt = 5;
        Self { client, server, rng, now }
    }

    fn send(&mut self, id: u64) {
        let body = [0x88u8, 0x77, 0x66, 0x55, id as u8, 0, 0, 0].to_vec();
        self.client
            .send(RpcRequest { id: RequestId(id), body, flags: RequestFlags::default(), invoke_after: None }, self.now);
    }

    /// Everything the client sends, framed as the TCP transport frames it.
    fn flush(&mut self) -> Vec<i64> {
        let mut msg_ids = Vec::new();
        for _ in 0..8 {
            self.now.mono += 0.01;
            self.now.unix += 0.01;
            let _ = self.client.handle_timeout(self.now);
            if let Some(transmit) = self.client.poll_transmit(self.now, &mut self.rng) {
                let mut framed = Vec::new();
                encode_frame(Framing::Intermediate, &transmit.data, false, &mut self.rng, &mut framed);
                let packet = self.server.decode(&transmit.data);
                let queries = packet.messages.iter().filter(|message| {
                    matches!(
                        message.constructor(),
                        0x5566_7788
                            | ids::INVOKE_WITH_LAYER
                            | ids::INVOKE_WITHOUT_UPDATES
                            | mtproto_core::rpc::INVOKE_WITH_RECAPTCHA
                            | mtproto_core::rpc::INVOKE_WITH_APNS_SECRET
                    )
                });
                msg_ids.extend(queries.map(|message| message.msg_id));
            }
        }
        msg_ids
    }

    fn failed_with_invalid_size(&mut self, id: u64) -> bool {
        self.client.drain_events().iter().any(|event| {
            matches!(event, RpcEvent::Failed { id: failed, code: 400, message, .. }
                if failed.0 == id && message == "REQUEST_INVALID_SIZE")
        })
    }
}

#[test]
fn an_environment_string_tl_cannot_carry_fails_the_request() {
    for field in 0..7 {
        let mut environment = environment();
        let huge = "x".repeat(TOO_LONG);
        match field {
            0 => environment.device_model = huge,
            1 => environment.system_version = huge,
            2 => environment.app_version = huge,
            3 => environment.system_lang_code = huge,
            4 => environment.lang_pack = huge,
            5 => environment.lang_code = huge,
            _ => environment.proxy = Some(ClientProxy { address: huge, port: 443 }),
        }
        let mut h = Harness::new(environment);
        h.send(1);
        assert!(h.flush().is_empty(), "field {field}: nothing goes out");
        assert!(h.failed_with_invalid_size(1), "field {field}: the request fails locally");
    }
}

#[test]
fn init_params_that_would_overflow_a_frame_fail_the_request() {
    let mut environment = environment();
    environment.params = Some(vec![0u8; 17 << 20]);
    let mut h = Harness::new(environment);
    h.send(1);
    assert!(h.flush().is_empty());
    assert!(h.failed_with_invalid_size(1));
}

#[test]
fn init_params_that_are_not_whole_words_fail_the_request() {
    for size in [1usize, 2, 3, 4097] {
        let mut environment = environment();
        environment.params = Some(vec![0x42; size]);
        let mut h = Harness::new(environment);
        h.send(1);
        assert!(h.flush().is_empty(), "{size}: an unaligned body never reaches the session");
        assert!(h.failed_with_invalid_size(1), "{size}");
    }
}

#[test]
fn a_verification_token_tl_cannot_carry_fails_the_request() {
    let mut h = Harness::new(environment());
    h.send(1);
    let sent = h.flush();
    assert_eq!(sent.len(), 1);
    let reply = h.server.encode(vec![Outgoing::Content(rpc_error(sent[0], 403, "RECAPTCHA_CHECK_login__key"))]);
    h.client.handle_packet(&reply, h.now, &mut h.rng).unwrap();
    assert!(h.client.drain_events().iter().any(|event| matches!(event, RpcEvent::VerificationRequired { .. })));
    h.client.resolve_verification(RequestId(1), Verification::Recaptcha { token: "t".repeat(TOO_LONG) }, h.now);
    assert!(h.flush().is_empty());
    assert!(h.failed_with_invalid_size(1));
}

#[test]
fn ordinary_wrappers_still_go_out() {
    let mut environment = environment();
    environment.device_model = "d".repeat(4096);
    environment.params = Some(vec![0u8; 64 * 1024]);
    environment.proxy = Some(ClientProxy { address: "p".repeat(255), port: 443 });
    let mut h = Harness::new(environment.clone());
    h.send(1);
    assert_eq!(h.flush().len(), 1);
    assert!(!h.failed_with_invalid_size(1));
    let length =
        wrapper_len(Some(&environment), true, Some(&Verification::Apns { nonce: "n".into(), secret: "s".into() }));
    let wrapped = mtproto_core::rpc::wrap_request(
        &[1, 2, 3, 4],
        Some(&environment),
        true,
        Some(&Verification::Apns { nonce: "n".into(), secret: "s".into() }),
    );
    assert_eq!(length, Some(wrapped.len() - 4), "the size check matches what wrap_request writes");
    assert!(length.unwrap() <= MAX_WRAPPER_BYTES);
}
