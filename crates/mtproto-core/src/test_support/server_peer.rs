use crate::auth_key::AuthKey;
use crate::crypto::{SecureRandom, Side, XorShiftRandom};
use crate::message::{MessageHeader, PaddingPolicy, decrypt_message, encrypt_message};
use crate::msg_id::msg_id_for_time;
use crate::tl::mtproto::{ContainerMessage, ServiceMessage, gzip, write_container};
use crate::tl::{Writer, ids};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientMessage {
    pub msg_id: i64,
    pub seq_no: i32,
    pub body: Vec<u8>,
    pub container_id: Option<i64>,
}

impl ClientMessage {
    pub fn constructor(&self) -> u32 {
        u32::from_le_bytes(self.body[..4].try_into().expect("4"))
    }

    pub fn is_content_related(&self) -> bool {
        self.seq_no & 1 == 1
    }
}

pub struct DecodedPacket {
    pub header: MessageHeader,
    pub messages: Vec<ClientMessage>,
}

impl DecodedPacket {
    pub fn constructors(&self) -> Vec<u32> {
        self.messages.iter().map(ClientMessage::constructor).collect()
    }

    pub fn find(&self, constructor: u32) -> Option<&ClientMessage> {
        self.messages.iter().find(|message| message.constructor() == constructor)
    }

    pub fn queries(&self) -> Vec<&ClientMessage> {
        self.messages.iter().filter(|message| message.is_content_related()).collect()
    }
}

pub struct ServerPeer {
    pub auth_key: AuthKey,
    pub session_id: i64,
    pub salt: i64,
    pub server_time: f64,
    last_msg_id: i64,
    seq_no: i32,
    rng: XorShiftRandom,
}

pub enum Outgoing {
    Content(Vec<u8>),
    Service(Vec<u8>),
    Raw { body: Vec<u8>, seq_no: i32, msg_id: Option<i64> },
}

impl ServerPeer {
    pub fn new(auth_key: AuthKey, server_time: f64) -> Self {
        Self { auth_key, session_id: 0, salt: 0, server_time, last_msg_id: 0, seq_no: 0, rng: XorShiftRandom::new(777) }
    }

    pub fn decode(&mut self, packet: &[u8]) -> DecodedPacket {
        let decrypted = decrypt_message(&self.auth_key, packet, Side::Client).expect("client packet decrypts");
        let header = decrypted.header;
        self.session_id = header.session_id;
        let body = decrypted.body().to_vec();
        let mut messages = Vec::new();
        match ServiceMessage::parse(&body).expect("parse") {
            ServiceMessage::Container(children) => {
                for child in children {
                    messages.push(ClientMessage {
                        msg_id: child.msg_id,
                        seq_no: child.seqno,
                        body: child.body.to_vec(),
                        container_id: Some(header.msg_id),
                    });
                }
            }
            _ => {
                messages.push(ClientMessage { msg_id: header.msg_id, seq_no: header.seq_no, body, container_id: None })
            }
        }
        DecodedPacket { header, messages }
    }

    pub fn next_msg_id(&mut self, response: bool) -> i64 {
        let base = msg_id_for_time(self.server_time) | if response { 1 } else { 3 };
        let id = if base <= self.last_msg_id { self.last_msg_id + 4 } else { base };
        self.last_msg_id = id;
        id
    }

    fn next_seq(&mut self, content: bool) -> i32 {
        let seq = self.seq_no;
        if content {
            self.seq_no += 2;
            seq | 1
        } else {
            seq
        }
    }

    pub fn encode(&mut self, items: Vec<Outgoing>) -> Vec<u8> {
        let mut messages: Vec<(i64, i32, Vec<u8>)> = Vec::new();
        for item in items {
            match item {
                Outgoing::Content(body) => {
                    let msg_id = self.next_msg_id(true);
                    let seq = self.next_seq(true);
                    messages.push((msg_id, seq, body));
                }
                Outgoing::Service(body) => {
                    let msg_id = self.next_msg_id(true);
                    let seq = self.next_seq(false);
                    messages.push((msg_id, seq, body));
                }
                Outgoing::Raw { body, seq_no, msg_id } => {
                    let msg_id = msg_id.unwrap_or_else(|| self.next_msg_id(true));
                    messages.push((msg_id, seq_no, body));
                }
            }
        }
        let (msg_id, seq_no, body) = if messages.len() == 1 {
            messages.pop().expect("one")
        } else {
            let refs: Vec<ContainerMessage<'_>> = messages
                .iter()
                .map(|(msg_id, seq_no, body)| ContainerMessage { msg_id: *msg_id, seqno: *seq_no, body })
                .collect();
            let mut writer = Writer::new();
            write_container(&mut writer, &refs);
            let container_id = self.next_msg_id(true);
            let seq = self.next_seq(false);
            (container_id, seq, writer.into_inner())
        };
        self.seal(msg_id, seq_no, &body)
    }

    pub fn seal(&mut self, msg_id: i64, seq_no: i32, body: &[u8]) -> Vec<u8> {
        let header = MessageHeader { salt: self.salt, session_id: self.session_id, msg_id, seq_no };
        let mut rng = self.rng.clone();
        let packet = encrypt_message(&self.auth_key, &header, body, Side::Server, PaddingPolicy::default(), &mut rng);
        self.rng.next_u64();
        packet.data
    }
}

pub fn rpc_result(req_msg_id: i64, result: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::RPC_RESULT);
    writer.write_i64(req_msg_id);
    writer.write_raw(result);
    writer.into_inner()
}

pub fn rpc_result_gzipped(req_msg_id: i64, result: &[u8]) -> Vec<u8> {
    let mut inner = Writer::new();
    inner.write_u32(ids::GZIP_PACKED);
    inner.write_bytes(&gzip(result));
    rpc_result(req_msg_id, inner.as_slice())
}

pub fn rpc_error(req_msg_id: i64, code: i32, message: &str) -> Vec<u8> {
    let mut inner = Writer::new();
    inner.write_u32(ids::RPC_ERROR);
    inner.write_i32(code);
    inner.write_bytes(message.as_bytes());
    rpc_result(req_msg_id, inner.as_slice())
}

pub fn bad_server_salt(bad_msg_id: i64, bad_seq_no: i32, new_salt: i64) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::BAD_SERVER_SALT);
    writer.write_i64(bad_msg_id);
    writer.write_i32(bad_seq_no);
    writer.write_i32(48);
    writer.write_i64(new_salt);
    writer.into_inner()
}

pub fn bad_msg_notification(bad_msg_id: i64, bad_seq_no: i32, code: i32) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::BAD_MSG_NOTIFICATION);
    writer.write_i64(bad_msg_id);
    writer.write_i32(bad_seq_no);
    writer.write_i32(code);
    writer.into_inner()
}

pub fn new_session_created(first_msg_id: i64, unique_id: i64, salt: i64) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::NEW_SESSION_CREATED);
    writer.write_i64(first_msg_id);
    writer.write_i64(unique_id);
    writer.write_i64(salt);
    writer.into_inner()
}

pub fn msgs_ack(msg_ids: &[i64]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::MSGS_ACK);
    writer.write_i64_vector(msg_ids);
    writer.into_inner()
}

pub fn pong(msg_id: i64, ping_id: i64) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::PONG);
    writer.write_i64(msg_id);
    writer.write_i64(ping_id);
    writer.into_inner()
}

pub fn future_salts(req_msg_id: i64, now: i32, salts: &[(i32, i32, i64)]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::FUTURE_SALTS);
    writer.write_i64(req_msg_id);
    writer.write_i32(now);
    writer.write_i32(salts.len() as i32);
    for (since, until, salt) in salts {
        writer.write_i32(*since);
        writer.write_i32(*until);
        writer.write_i64(*salt);
    }
    writer.into_inner()
}

pub fn msgs_state_info(req_msg_id: i64, info: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::MSGS_STATE_INFO);
    writer.write_i64(req_msg_id);
    writer.write_bytes(info);
    writer.into_inner()
}

pub fn msg_detailed_info(msg_id: i64, answer_msg_id: i64, bytes: i32) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::MSG_DETAILED_INFO);
    writer.write_i64(msg_id);
    writer.write_i64(answer_msg_id);
    writer.write_i32(bytes);
    writer.write_i32(0);
    writer.into_inner()
}

pub fn msg_new_detailed_info(answer_msg_id: i64, bytes: i32) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::MSG_NEW_DETAILED_INFO);
    writer.write_i64(answer_msg_id);
    writer.write_i32(bytes);
    writer.write_i32(0);
    writer.into_inner()
}

pub fn msgs_state_req(msg_ids: &[i64]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::MSGS_STATE_REQ);
    writer.write_i64_vector(msg_ids);
    writer.into_inner()
}

pub fn update(constructor: u32, payload: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(constructor);
    writer.write_raw(payload);
    writer.into_inner()
}

pub fn read_vector_after_constructor(body: &[u8]) -> Vec<i64> {
    let mut reader = crate::tl::Reader::new(&body[4..]);
    reader.read_i64_vector(1 << 16).expect("vector")
}

pub fn server_ping(ping_id: i64) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::PING);
    writer.write_i64(ping_id);
    writer.into_inner()
}

pub fn server_ping_delay_disconnect(ping_id: i64, delay: i32) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::PING_DELAY_DISCONNECT);
    writer.write_i64(ping_id);
    writer.write_i32(delay);
    writer.into_inner()
}

pub fn msg_copy(msg_id: i64, seq_no: i32, body: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    crate::tl::mtproto::write_msg_copy(&mut writer, &ContainerMessage { msg_id, seqno: seq_no, body });
    writer.into_inner()
}

pub fn msg_resend_req(msg_ids: &[i64]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::MSG_RESEND_REQ);
    writer.write_i64_vector(msg_ids);
    writer.into_inner()
}

pub fn msg_resend_ans_req(msg_ids: &[i64]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::MSG_RESEND_ANS_REQ);
    writer.write_i64_vector(msg_ids);
    writer.into_inner()
}

pub fn msgs_all_info(msg_ids: &[i64], info: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::MSGS_ALL_INFO);
    writer.write_i64_vector(msg_ids);
    writer.write_bytes(info);
    writer.into_inner()
}

pub fn msg_detailed_info_status(msg_id: i64, answer_msg_id: i64, bytes: i32, status: i32) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::MSG_DETAILED_INFO);
    writer.write_i64(msg_id);
    writer.write_i64(answer_msg_id);
    writer.write_i32(bytes);
    writer.write_i32(status);
    writer.into_inner()
}

pub fn container(messages: &[(i64, i32, Vec<u8>)]) -> Vec<u8> {
    let refs: Vec<ContainerMessage<'_>> = messages
        .iter()
        .map(|(msg_id, seqno, body)| ContainerMessage { msg_id: *msg_id, seqno: *seqno, body })
        .collect();
    let mut writer = Writer::new();
    write_container(&mut writer, &refs);
    writer.into_inner()
}

pub fn gzip_packed(body: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(ids::GZIP_PACKED);
    writer.write_bytes(&gzip(body));
    writer.into_inner()
}

pub fn rpc_answer(req_msg_id: i64, constructor: u32, payload: &[u8]) -> Vec<u8> {
    rpc_result(req_msg_id, &update(constructor, payload))
}

pub fn rpc_error_raw(req_msg_id: i64, code: i32, message: &[u8]) -> Vec<u8> {
    let mut inner = Writer::new();
    inner.write_u32(ids::RPC_ERROR);
    inner.write_i32(code);
    inner.write_bytes(message);
    rpc_result(req_msg_id, inner.as_slice())
}

pub fn ping_id_of(message: &ClientMessage) -> Option<i64> {
    match message.constructor() {
        ids::PING | ids::PING_DELAY_DISCONNECT => Some(i64::from_le_bytes(message.body[4..12].try_into().ok()?)),
        _ => None,
    }
}
