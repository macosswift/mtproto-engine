use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::XorShiftRandom;
use mtproto_core::rpc::{ApiEnvironment, RequestFlags, RequestId, RpcClient, RpcRequest, SessionRole};
use mtproto_core::session::{Now, ServerSalt, Session, SessionConfig};
use mtproto_core::test_support::server_peer::{Outgoing, ServerPeer, bad_server_salt, rpc_result};
use mtproto_core::tl::{Reader, Writer, ids};

const START: f64 = 1_727_000_000.0;
const CALL: u32 = 0x5e57_0b01;
const SLOTS: u64 = 1024;

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

struct Sent {
    msg_id: i64,
    tag: u32,
    after: Option<i64>,
}

fn decode(msg_id: i64, body: &[u8]) -> Sent {
    let mut reader = Reader::new(body);
    let mut after = None;
    if reader.peek_u32().unwrap() == ids::INVOKE_AFTER_MSG {
        reader.read_u32().unwrap();
        after = Some(reader.read_i64().unwrap());
    }
    assert_eq!(reader.read_u32().unwrap(), CALL);
    Sent { msg_id, tag: reader.read_u32().unwrap(), after }
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
        let mut session = Session::new(SessionConfig::default(), key(), &salts, 0.0, now, &mut rng);
        session.connection_opened(now);
        let client = RpcClient::new(session, SessionRole::Main, Some(environment()), Some("h1".into()));
        let mut server = ServerPeer::new(key(), START);
        server.salt = 7;
        Self { client, server, rng, now }
    }

    fn send(&mut self, id: u64, invoke_after: Option<u64>) {
        self.client.send(
            RpcRequest {
                id: RequestId(id),
                body: call(id as u32),
                flags: RequestFlags::default(),
                invoke_after: invoke_after.map(RequestId),
            },
            self.now,
        );
    }

    fn sent(&mut self) -> Vec<Sent> {
        let mut out = Vec::new();
        let mut idle = 0;
        for _ in 0..60 {
            self.now.mono += 0.002;
            self.now.unix += 0.002;
            self.server.server_time += 0.002;
            let _ = self.client.handle_timeout(self.now);
            let Some(transmit) = self.client.poll_transmit(self.now, &mut self.rng) else {
                idle += 1;
                if idle > 3 {
                    break;
                }
                continue;
            };
            idle = 0;
            for message in self.server.decode(&transmit.data).messages {
                if message.is_content_related() {
                    out.push(decode(message.msg_id, &message.body));
                }
            }
        }
        out
    }

    fn reply(&mut self, items: Vec<Outgoing>) {
        let packet = self.server.encode(items);
        self.client.handle_packet(&packet, self.now, &mut self.rng).unwrap();
    }
}

/// A query the server sends back (bad_server_salt, a bad_msg_notification) keeps its turn: it goes before
/// the queries that never went out, so a call chained after it with invoke_after is not sent first and
/// without its invokeAfterMsg.
#[test]
fn a_resent_query_goes_before_the_queries_waiting_for_a_slot() {
    let mut h = Harness::new();
    for id in 1..SLOTS {
        h.send(id, None);
    }
    h.send(SLOTS, None);
    h.send(SLOTS + 1, Some(SLOTS));
    let first = h.sent();
    assert_eq!(first.len() as u64, SLOTS, "one slot per query in flight");
    let dependency = first.iter().find(|sent| u64::from(sent.tag) == SLOTS).expect("the dependency went").msg_id;
    assert!(first.iter().all(|sent| u64::from(sent.tag) != SLOTS + 1), "the chained call waits for a slot");

    h.reply(vec![Outgoing::Service(bad_server_salt(dependency, 1, 8))]);
    h.server.salt = 8;
    let second = h.sent();
    let resent = second.iter().position(|sent| u64::from(sent.tag) == SLOTS);
    let chained = second.iter().position(|sent| u64::from(sent.tag) == SLOTS + 1);
    assert!(resent.is_some(), "the query the server sent back goes again in the slot it freed");
    if let Some(chained) = chained {
        assert!(resent.unwrap() < chained, "the chained call went before the call it depends on");
        let resent_msg_id = second[resent.unwrap()].msg_id;
        assert_eq!(second[chained].after, Some(resent_msg_id), "the chained call lost its invokeAfterMsg");
    }

    let answers = first
        .iter()
        .filter(|sent| u64::from(sent.tag) != SLOTS)
        .take(8)
        .map(|sent| Outgoing::Content(rpc_result(sent.msg_id, &[1, 0, 0, 0])))
        .collect();
    h.reply(answers);
    let third = h.sent();
    let resent_msg_id = second.iter().chain(third.iter()).find(|sent| u64::from(sent.tag) == SLOTS).unwrap().msg_id;
    let chained = second.iter().chain(third.iter()).find(|sent| u64::from(sent.tag) == SLOTS + 1);
    let chained = chained.expect("the chained call goes once slots are free");
    assert_eq!(chained.after, Some(resent_msg_id), "the chained call goes after the call it depends on");
}
