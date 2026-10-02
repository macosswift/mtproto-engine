use std::sync::OnceLock;

use mtproto_core::crypto::{SecureRandom, XorShiftRandom};
use mtproto_core::msg_id::msg_id_for_time;
use mtproto_core::tl::mtproto::gzip;
use mtproto_core::tl::{Writer, ids};

pub const CONSTRUCTORS: &[u32] = &[
    ids::VECTOR,
    ids::BOOL_TRUE,
    ids::BOOL_FALSE,
    ids::RES_PQ,
    ids::SERVER_DH_PARAMS_OK,
    ids::SERVER_DH_PARAMS_FAIL,
    ids::SERVER_DH_INNER_DATA,
    ids::DH_GEN_OK,
    ids::DH_GEN_RETRY,
    ids::DH_GEN_FAIL,
    ids::RPC_RESULT,
    ids::RPC_ERROR,
    ids::RPC_ANSWER_UNKNOWN,
    ids::RPC_ANSWER_DROPPED_RUNNING,
    ids::RPC_ANSWER_DROPPED,
    ids::FUTURE_SALT,
    ids::FUTURE_SALTS,
    ids::PING,
    ids::PING_DELAY_DISCONNECT,
    ids::PONG,
    ids::DESTROY_SESSION_OK,
    ids::DESTROY_SESSION_NONE,
    ids::NEW_SESSION_CREATED,
    ids::MSG_CONTAINER,
    ids::MSG_COPY,
    ids::MESSAGE,
    ids::GZIP_PACKED,
    ids::MSGS_ACK,
    ids::BAD_MSG_NOTIFICATION,
    ids::BAD_SERVER_SALT,
    ids::MSG_RESEND_REQ,
    ids::MSG_RESEND_ANS_REQ,
    ids::MSGS_STATE_REQ,
    ids::MSGS_STATE_INFO,
    ids::MSGS_ALL_INFO,
    ids::MSG_DETAILED_INFO,
    ids::MSG_NEW_DETAILED_INFO,
    ids::HTTP_WAIT,
    ids::DESTROY_AUTH_KEY_OK,
    ids::DESTROY_AUTH_KEY_NONE,
    ids::DESTROY_AUTH_KEY_FAIL,
    ids::AUTH_EXPORTED_AUTHORIZATION,
    ids::NEAREST_DC,
];

const INTERESTING_I32: &[i32] = &[
    0,
    1,
    -1,
    2,
    3,
    4,
    16,
    17,
    18,
    19,
    20,
    32,
    33,
    34,
    35,
    48,
    64,
    127,
    128,
    253,
    254,
    255,
    256,
    1020,
    1024,
    4096,
    65535,
    65536,
    0x00ff_ffff,
    0x0100_0000,
    0x7fff_fffc,
    i32::MAX,
    i32::MIN,
    -4,
    -404,
    -429,
    -444,
    -500,
];

const RPC_ERROR_MESSAGES: &[&str] = &[
    "FLOOD_WAIT_",
    "FLOOD_PREMIUM_WAIT_",
    "SLOWMODE_WAIT_",
    "FILE_MIGRATE_",
    "PHONE_MIGRATE_",
    "NETWORK_MIGRATE_",
    "USER_MIGRATE_",
    "STATS_MIGRATE_",
    "AUTH_KEY_UNREGISTERED",
    "AUTH_KEY_PERM_EMPTY",
    "AUTH_KEY_DUPLICATED",
    "SESSION_REVOKED",
    "SESSION_PASSWORD_NEEDED",
    "CONNECTION_NOT_INITED",
    "CONNECTION_LAYER_INVALID",
    "MSG_WAIT_FAILED",
    "MSG_WAIT_TIMEOUT",
    "INPUT_METHOD_INVALID_",
    "APNS_VERIFY_CHECK_",
    "RECAPTCHA_CHECK_",
    "FILE_REFERENCE_EXPIRED",
    "INTERNAL",
    "TIMEOUT",
    "",
];

pub struct Gen {
    rng: XorShiftRandom,
}

impl Gen {
    pub fn new(seed: u64) -> Self {
        Self { rng: XorShiftRandom::new(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1B5_4A32_D192_ED03) }
    }

    pub fn rng(&mut self) -> &mut XorShiftRandom {
        &mut self.rng
    }

    pub fn u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    pub fn u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    pub fn below(&mut self, bound: usize) -> usize {
        if bound <= 1 { 0 } else { (self.rng.next_u64() % bound as u64) as usize }
    }

    pub fn range(&mut self, low: usize, high: usize) -> usize {
        low + self.below(high.saturating_sub(low) + 1)
    }

    pub fn one_in(&mut self, n: usize) -> bool {
        self.below(n) == 0
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut data = vec![0u8; len];
        self.rng.fill(&mut data);
        data
    }

    pub fn small_len(&mut self) -> usize {
        match self.below(10) {
            0 => 0,
            1..=5 => self.below(16),
            6..=8 => self.below(256),
            _ => self.below(4096),
        }
    }

    pub fn i32(&mut self) -> i32 {
        if self.one_in(2) { *self.pick(INTERESTING_I32) } else { self.u32() as i32 }
    }

    pub fn i64(&mut self) -> i64 {
        match self.below(6) {
            0 => 0,
            1 => -1,
            2 => i64::MAX,
            3 => i64::MIN,
            4 => self.i32() as i64,
            _ => self.u64() as i64,
        }
    }

    pub fn constructor(&mut self) -> u32 {
        if self.one_in(8) { self.u32() } else { *self.pick(CONSTRUCTORS) }
    }

    pub fn tl_bytes(&mut self, writer: &mut Writer, data: &[u8]) {
        match self.below(12) {
            0 => {
                writer.write_raw(&[254]);
                let declared = self.i32() as u32 & 0x00ff_ffff;
                writer.write_raw(&declared.to_le_bytes()[..3]);
                writer.write_raw(data);
            }
            1 => {
                writer.write_raw(&[self.u32() as u8]);
                writer.write_raw(data);
            }
            _ => writer.write_bytes(data),
        }
    }

    pub fn mutate(&mut self, data: &mut Vec<u8>) {
        let rounds = 1 + self.below(6);
        for _ in 0..rounds {
            match self.below(11) {
                0 if !data.is_empty() => {
                    let index = self.below(data.len());
                    data[index] ^= 1 << self.below(8);
                }
                1 if !data.is_empty() => {
                    let index = self.below(data.len());
                    data[index] = *self.pick(&[0u8, 0xff, 0x7f, 0x80, 0xfe, 0x01]);
                }
                2 if data.len() >= 4 => {
                    let index = self.below(data.len() - 3) & !3;
                    let value = self.i32();
                    data[index..index + 4].copy_from_slice(&value.to_le_bytes());
                }
                3 if data.len() >= 4 => {
                    let index = self.below(data.len() - 3) & !3;
                    let value = self.constructor();
                    data[index..index + 4].copy_from_slice(&value.to_le_bytes());
                }
                4 if !data.is_empty() => {
                    let keep = self.below(data.len());
                    data.truncate(keep);
                }
                5 => {
                    let index = self.below(data.len() + 1);
                    let insert = {
                        let len = self.small_len();
                        self.bytes(len)
                    };
                    data.splice(index..index, insert);
                }
                6 if !data.is_empty() => {
                    let start = self.below(data.len());
                    let end = (start + 1 + self.below(64)).min(data.len());
                    data.drain(start..end);
                }
                7 if !data.is_empty() => {
                    let start = self.below(data.len());
                    let end = (start + 1 + self.below(256)).min(data.len());
                    let copy = data[start..end].to_vec();
                    let at = self.below(data.len() + 1);
                    data.splice(at..at, copy);
                }
                8 => {
                    let extra = {
                        let len = self.small_len();
                        self.bytes(len)
                    };
                    data.extend_from_slice(&extra);
                }
                9 if data.len() >= 8 => {
                    let index = self.below(data.len() - 7) & !3;
                    let value = self.i64();
                    data[index..index + 8].copy_from_slice(&value.to_le_bytes());
                }
                _ => {}
            }
        }
    }

    pub fn split<'a>(&mut self, data: &'a [u8]) -> Vec<&'a [u8]> {
        let mut parts = Vec::new();
        let mut rest = data;
        while !rest.is_empty() {
            let take = match self.below(4) {
                0 => 1 + self.below(4),
                1 => 1 + self.below(64),
                2 => 1 + self.below(4096),
                _ => rest.len(),
            }
            .min(rest.len());
            let (head, tail) = rest.split_at(take);
            parts.push(head);
            rest = tail;
        }
        parts
    }
}

pub fn gzip_bomb() -> &'static [u8] {
    static BOMB: OnceLock<Vec<u8>> = OnceLock::new();
    BOMB.get_or_init(|| gzip(&vec![0u8; 80 * 1024 * 1024]))
}

pub fn gzip_small_bomb() -> &'static [u8] {
    static BOMB: OnceLock<Vec<u8>> = OnceLock::new();
    BOMB.get_or_init(|| gzip(&vec![0u8; 2 * 1024 * 1024]))
}

pub struct TlContext {
    pub client_msg_ids: Vec<i64>,
    pub server_time: f64,
    pub session_id: i64,
}

impl TlContext {
    pub fn msg_id(&self, g: &mut Gen) -> i64 {
        match g.below(8) {
            0..=3 if !self.client_msg_ids.is_empty() => *g.pick(&self.client_msg_ids),
            4 => msg_id_for_time(self.server_time) | 1,
            5 => msg_id_for_time(self.server_time + (g.below(1_000_000) as f64) - 500_000.0) & !3,
            _ => g.i64(),
        }
    }

    pub fn server_msg_id(&self, g: &mut Gen) -> i64 {
        match g.below(10) {
            0..=5 => msg_id_for_time(self.server_time) | 1 | ((g.below(1 << 20) as i64) << 2),
            6 => msg_id_for_time(self.server_time) & !3,
            7 => msg_id_for_time(self.server_time - 400.0) | 1,
            8 => msg_id_for_time(self.server_time + 100.0) | 1,
            _ => self.msg_id(g),
        }
    }
}

fn id_vector(g: &mut Gen, cx: &TlContext, writer: &mut Writer) {
    let count = match g.below(8) {
        0 => 0,
        1..=4 => g.below(8),
        5 => g.below(1024),
        6 => 70_000,
        _ => g.below(9000),
    };
    let lie = g.one_in(8);
    writer.write_u32(if g.one_in(16) { g.u32() } else { ids::VECTOR });
    writer.write_i32(if lie { g.i32() } else { count as i32 });
    for _ in 0..count {
        writer.write_i64(cx.msg_id(g));
    }
}

fn rpc_error(g: &mut Gen, writer: &mut Writer) {
    writer.write_u32(ids::RPC_ERROR);
    writer.write_i32(match g.below(6) {
        0 => 420,
        1 => 303,
        2 => 401,
        3 => 500,
        4 => -503,
        _ => g.i32(),
    });
    let mut message = g.pick(RPC_ERROR_MESSAGES).to_string();
    if message.ends_with('_') {
        match g.below(5) {
            0 => message.push_str(&g.u64().to_string()),
            1 => message.push_str("-1"),
            2 => message.push_str("99999999999999999999999"),
            3 => {}
            _ => message.push_str(&g.below(100_000).to_string()),
        }
    }
    if g.one_in(10) {
        let noise = {
            let len = g.small_len();
            g.bytes(len)
        };
        g.tl_bytes(writer, &noise);
    } else {
        writer.write_bytes(message.as_bytes());
    }
}

fn rpc_result_payload(g: &mut Gen, cx: &TlContext, depth: usize, writer: &mut Writer) {
    match g.below(9) {
        0..=1 => rpc_error(g, writer),
        2 => {
            writer.write_u32(ids::GZIP_PACKED);
            let mut inner = Writer::new();
            if g.one_in(2) {
                rpc_error(g, &mut inner);
            } else {
                inner.write_u32(g.constructor());
                inner.write_raw(&{
                    let len = g.small_len();
                    g.bytes(len)
                });
            }
            let mut packed = gzip(inner.as_slice());
            if g.one_in(4) {
                g.mutate(&mut packed);
            }
            g.tl_bytes(writer, &packed);
        }
        3 => {
            writer.write_u32(ids::GZIP_PACKED);
            let bomb = if g.one_in(8) { gzip_bomb() } else { gzip_small_bomb() };
            writer.write_bytes(bomb);
        }
        4 => writer.write_u32(*g.pick(&[ids::RPC_ANSWER_UNKNOWN, ids::RPC_ANSWER_DROPPED_RUNNING])),
        5 => {
            writer.write_u32(ids::RPC_ANSWER_DROPPED);
            writer.write_i64(cx.msg_id(g));
            writer.write_i32(g.i32());
            writer.write_i32(g.i32());
        }
        6 if depth < 12 => writer.write_raw(&service_body(g, cx, depth + 1)),
        _ => {
            writer.write_u32(g.constructor());
            writer.write_raw(&{
                let len = g.small_len();
                g.bytes(len)
            });
        }
    }
}

pub fn service_body(g: &mut Gen, cx: &TlContext, depth: usize) -> Vec<u8> {
    let mut writer = Writer::new();
    let choice = if depth > 10 { 30 + g.below(5) } else { g.below(35) };
    match choice {
        0..=4 => {
            writer.write_u32(ids::RPC_RESULT);
            writer.write_i64(cx.msg_id(g));
            rpc_result_payload(g, cx, depth, &mut writer);
        }
        5..=7 => {
            let count = match g.below(6) {
                0 => 0,
                1 => 1100,
                _ => g.below(12),
            };
            writer.write_u32(ids::MSG_CONTAINER);
            writer.write_i32(if g.one_in(10) { g.i32() } else { count as i32 });
            for _ in 0..count {
                let body = if count > 64 { vec![0; 4] } else { service_body(g, cx, depth + 1) };
                writer.write_i64(cx.server_msg_id(g));
                writer.write_i32(if g.one_in(2) { 2 * g.below(1000) as i32 + 1 } else { g.i32() });
                let declared = if g.one_in(12) { g.i32() } else { body.len() as i32 };
                writer.write_i32(declared);
                writer.write_raw(&body);
            }
        }
        8..=9 => {
            writer.write_u32(ids::GZIP_PACKED);
            let inner = service_body(g, cx, depth + 1);
            let mut packed = gzip(&inner);
            if g.one_in(6) {
                g.mutate(&mut packed);
            }
            g.tl_bytes(&mut writer, &packed);
        }
        10 => {
            writer.write_u32(ids::GZIP_PACKED);
            writer.write_bytes(if g.one_in(6) { gzip_bomb() } else { gzip_small_bomb() });
        }
        11 => {
            writer.write_u32(ids::MSG_COPY);
            if g.one_in(2) {
                writer.write_u32(ids::MESSAGE);
            }
            let body = service_body(g, cx, depth + 1);
            writer.write_i64(cx.server_msg_id(g));
            writer.write_i32(g.i32());
            writer.write_i32(if g.one_in(8) { g.i32() } else { body.len() as i32 });
            writer.write_raw(&body);
        }
        12 => {
            writer.write_u32(ids::PONG);
            writer.write_i64(cx.msg_id(g));
            writer.write_i64(g.i64());
        }
        13..=14 => {
            writer.write_u32(ids::BAD_MSG_NOTIFICATION);
            writer.write_i64(cx.msg_id(g));
            writer.write_i32(g.i32());
            writer.write_i32(*g.pick(&[16, 17, 18, 19, 20, 32, 33, 34, 35, 48, 64, 0, -1, i32::MAX]));
        }
        15..=16 => {
            writer.write_u32(ids::BAD_SERVER_SALT);
            writer.write_i64(cx.msg_id(g));
            writer.write_i32(g.i32());
            writer.write_i32(if g.one_in(2) { 48 } else { g.i32() });
            writer.write_i64(g.i64());
        }
        17 => {
            writer.write_u32(ids::NEW_SESSION_CREATED);
            writer.write_i64(cx.msg_id(g));
            writer.write_i64(g.i64());
            writer.write_i64(g.i64());
        }
        18 => {
            writer.write_u32(ids::MSGS_ACK);
            id_vector(g, cx, &mut writer);
        }
        19 => {
            writer.write_u32(ids::MSG_DETAILED_INFO);
            writer.write_i64(cx.msg_id(g));
            writer.write_i64(cx.server_msg_id(g));
            writer.write_i32(g.i32());
            writer.write_i32(g.i32());
        }
        20 => {
            writer.write_u32(ids::MSG_NEW_DETAILED_INFO);
            writer.write_i64(cx.server_msg_id(g));
            writer.write_i32(g.i32());
            writer.write_i32(g.i32());
        }
        21 => {
            writer.write_u32(*g.pick(&[ids::MSG_RESEND_REQ, ids::MSG_RESEND_ANS_REQ, ids::MSGS_STATE_REQ]));
            id_vector(g, cx, &mut writer);
        }
        22 => {
            writer.write_u32(ids::MSGS_STATE_INFO);
            writer.write_i64(cx.msg_id(g));
            let info = {
                let len = g.small_len();
                g.bytes(len)
            };
            g.tl_bytes(&mut writer, &info);
        }
        23 => {
            writer.write_u32(ids::MSGS_ALL_INFO);
            id_vector(g, cx, &mut writer);
            let info = {
                let len = g.small_len();
                g.bytes(len)
            };
            g.tl_bytes(&mut writer, &info);
        }
        24..=25 => {
            writer.write_u32(ids::FUTURE_SALTS);
            writer.write_i64(cx.msg_id(g));
            writer.write_i32(if g.one_in(2) { cx.server_time as i32 } else { g.i32() });
            let count = match g.below(5) {
                0 => 0,
                1 => 65_536,
                2 => 70_000,
                _ => g.below(64),
            };
            if g.one_in(2) {
                writer.write_u32(ids::VECTOR);
            }
            writer.write_i32(count as i32);
            for _ in 0..count {
                if g.one_in(2) {
                    writer.write_u32(ids::FUTURE_SALT);
                }
                let since = if g.one_in(2) { cx.server_time as i32 + g.below(7200) as i32 - 3600 } else { g.i32() };
                writer.write_i32(since);
                writer.write_i32(if g.one_in(2) { since.wrapping_add(1800) } else { g.i32() });
                writer.write_i64(g.i64());
            }
        }
        26 => {
            writer.write_u32(*g.pick(&[ids::DESTROY_SESSION_OK, ids::DESTROY_SESSION_NONE]));
            writer.write_i64(if g.one_in(2) { cx.session_id } else { g.i64() });
        }
        27 => writer.write_u32(*g.pick(&[
            ids::DESTROY_AUTH_KEY_OK,
            ids::DESTROY_AUTH_KEY_NONE,
            ids::DESTROY_AUTH_KEY_FAIL,
        ])),
        28 => {
            writer.write_u32(*g.pick(&[ids::PING, ids::PING_DELAY_DISCONNECT]));
            writer.write_i64(g.i64());
            writer.write_i32(g.i32());
        }
        29 => {
            writer.write_u32(ids::HTTP_WAIT);
            writer.write_i32(g.i32());
            writer.write_i32(g.i32());
            writer.write_i32(g.i32());
        }
        30..=31 => {
            writer.write_u32(g.constructor());
            writer.write_raw(&{
                let len = g.small_len() & !3;
                g.bytes(len)
            });
        }
        32 => {
            writer.write_u32(ids::RPC_RESULT);
            writer.write_i64(cx.msg_id(g));
            writer.write_u32(g.u32());
        }
        _ => {
            let raw = {
                let len = g.small_len();
                g.bytes(len)
            };
            writer.write_raw(&raw);
        }
    }
    let mut body = writer.into_inner();
    if g.one_in(25) {
        g.mutate(&mut body);
    }
    body
}

pub fn amplification_body(g: &mut Gen, cx: &TlContext) -> Vec<u8> {
    let mut outer = Vec::new();
    match g.below(4) {
        0 | 1 => {
            let (groups, per_group) = if g.one_in(8) { (1024, 300) } else { (g.range(8, 64), g.range(64, 400)) };
            for _ in 0..groups {
                let mut inner = Writer::new();
                inner.write_u32(ids::MSG_CONTAINER);
                inner.write_i32(per_group as i32);
                for _ in 0..per_group {
                    let mut child = Writer::new();
                    match g.below(5) {
                        0 => {
                            child.write_u32(ids::MSG_DETAILED_INFO);
                            child.write_i64(cx.msg_id(g));
                            child.write_i64(g.u64() as i64 | 1);
                            child.write_i32(128);
                            child.write_i32(0);
                        }
                        1 => {
                            child.write_u32(ids::BAD_SERVER_SALT);
                            child.write_i64(cx.msg_id(g));
                            child.write_i32(0);
                            child.write_i32(48);
                            child.write_i64(g.i64());
                        }
                        2 => {
                            child.write_u32(ids::MSG_RESEND_REQ);
                            child.write_u32(ids::VECTOR);
                            child.write_i32(8);
                            for _ in 0..8 {
                                child.write_i64(cx.msg_id(g));
                            }
                        }
                        _ => {
                            child.write_u32(ids::MSG_NEW_DETAILED_INFO);
                            child.write_i64(g.u64() as i64 | 1);
                            child.write_i32(128);
                            child.write_i32(0);
                        }
                    }
                    let child = child.into_inner();
                    inner.write_i64(cx.server_msg_id(g));
                    inner.write_i32(if g.one_in(2) { 1 } else { 0 });
                    inner.write_i32(child.len() as i32);
                    inner.write_raw(&child);
                }
                outer.push(inner.into_inner());
            }
        }
        2 => {
            for _ in 0..g.range(4, 24) {
                let mut child = Writer::new();
                child.write_u32(ids::GZIP_PACKED);
                child.write_bytes(if g.one_in(2) { gzip_bomb() } else { gzip_small_bomb() });
                outer.push(child.into_inner());
            }
        }
        _ => {
            for _ in 0..g.range(64, 1024) {
                let mut child = Writer::new();
                child.write_u32(ids::GZIP_PACKED);
                let inner = service_body(g, cx, 6);
                child.write_bytes(&gzip(&inner));
                outer.push(child.into_inner());
            }
        }
    }
    let mut writer = Writer::new();
    writer.write_u32(ids::MSG_CONTAINER);
    writer.write_i32(outer.len() as i32);
    for body in outer {
        writer.write_i64(cx.server_msg_id(g));
        writer.write_i32(if g.one_in(2) { 1 } else { 0 });
        writer.write_i32(body.len() as i32);
        writer.write_raw(&body);
    }
    writer.into_inner()
}
