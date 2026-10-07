use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::XorShiftRandom;
use mtproto_core::rpc::{
    ApiEnvironment, INIT_CONNECTION, RequestFlags, RequestId, RpcClient, RpcEvent, RpcRequest, SessionRole,
};
use mtproto_core::session::{Now, ServerSalt, Session, SessionConfig};
use mtproto_core::test_support::server_peer::{ClientMessage, Outgoing, ServerPeer, rpc_error, rpc_result};
use mtproto_core::tl::{Reader, Writer, ids};

const START: f64 = 1_727_000_000.0;
const CALL: u32 = 0x5e57_0b01;
const BOOL_TRUE: u32 = 0x997275b5;
const BIND: u32 = 0xcdd42a05;

fn key(seed: u8) -> AuthKey {
    AuthKey::new(core::array::from_fn(|i| (i as u8).wrapping_mul(23).wrapping_add(seed)))
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

fn initializes(message: &ClientMessage) -> bool {
    let mut reader = Reader::new(&message.body);
    reader.read_u32().unwrap() == ids::INVOKE_WITH_LAYER && {
        reader.read_i32().unwrap();
        reader.read_u32().unwrap() == INIT_CONNECTION
    }
}

struct Harness {
    client: RpcClient,
    server: ServerPeer,
    rng: XorShiftRandom,
    now: Now,
}

impl Harness {
    fn new() -> Self {
        let mut rng = XorShiftRandom::new(41);
        let now = Now { mono: 10.0, unix: START };
        let salts = [ServerSalt { salt: 7, valid_since: START - 10.0, valid_until: START + 100_000.0 }];
        let mut session = Session::new(SessionConfig::default(), key(5), &salts, 0.0, now, &mut rng);
        session.connection_opened(now);
        let client = RpcClient::new(session, SessionRole::Main, Some(environment()), Some("h1".into()));
        let mut server = ServerPeer::new(key(5), START);
        server.salt = 7;
        Self { client, server, rng, now }
    }

    fn send(&mut self, id: u64) {
        self.client.send(
            RpcRequest { id: RequestId(id), body: call(id as u32), flags: RequestFlags::default(), invoke_after: None },
            self.now,
        );
    }

    fn advance(&mut self, seconds: f64) {
        self.now.mono += seconds;
        self.now.unix += seconds;
        self.server.server_time += seconds;
    }

    fn sent(&mut self, steps: usize) -> Vec<ClientMessage> {
        let mut out = Vec::new();
        for _ in 0..steps {
            self.advance(0.002);
            let _ = self.client.handle_timeout(self.now);
            if let Some(transmit) = self.client.poll_transmit(self.now, &mut self.rng) {
                out.extend(self.server.decode(&transmit.data).messages.into_iter().filter(|m| m.is_content_related()));
            }
        }
        out
    }

    fn reply(&mut self, items: Vec<Outgoing>) {
        let packet = self.server.encode(items);
        self.client.handle_packet(&packet, self.now, &mut self.rng).unwrap();
    }
}

/// B-70: after auth.bindTempAuthKey the first call carries initConnection. A call the host handed over
/// just before the rebind started already sits in the session, wrapped without it, and goes first.
#[test]
fn the_first_call_after_a_rebind_carries_init_connection() {
    let mut h = Harness::new();
    h.send(1);
    let first = h.sent(10);
    assert_eq!(first.len(), 1);
    assert!(!initializes(&first[0]), "an initialized key sends calls as they are");

    h.send(2);
    h.reply(vec![Outgoing::Content(rpc_error(first[0].msg_id, 401, "AUTH_KEY_PERM_EMPTY"))]);
    assert!(h.client.drain_events().iter().any(|event| matches!(event, RpcEvent::TemporaryKeyRejected)));

    h.client.hold_until_bound();
    h.client.set_stored_init_hash(None);
    h.client.bind_temporary_key(key(9), (START + 86_400.0) as i32, h.now, &mut h.rng);
    let bind = h.sent(10);
    assert_eq!(bind.len(), 1, "only the bind goes while the key is not bound");
    assert_eq!(bind[0].constructor(), BIND);
    h.reply(vec![Outgoing::Content(rpc_result(bind[0].msg_id, &BOOL_TRUE.to_le_bytes()))]);
    assert!(h.client.drain_events().iter().any(|event| matches!(event, RpcEvent::TemporaryKeyBound)));

    let after = h.sent(2000);
    assert!(!after.is_empty());
    let tags: Vec<(u32, bool)> = after
        .iter()
        .map(|message| {
            let body = &message.body;
            (u32::from_le_bytes(body[body.len() - 4..].try_into().unwrap()), initializes(message))
        })
        .collect();
    assert!(tags[0].1, "the first call after the bind went without initConnection: {tags:?}");
}
