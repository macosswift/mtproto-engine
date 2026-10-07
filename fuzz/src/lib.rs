//! Shared pieces of the cargo-fuzz targets: a byte cursor, the fake server peer that seals fuzzer bytes
//! with the session's key, and the placeholders that let a fuzzer name the client's own msg_ids.

pub mod peer;
pub mod seeds;

use mtproto_core::auth_key::AuthKey;

pub const START: f64 = 1_727_000_000.0;

/// Reads structured choices off the fuzzer's bytes; once they run out every read yields zero.
pub struct Cursor<'a> {
    data: &'a [u8],
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn u8(&mut self) -> u8 {
        match self.data.split_first() {
            Some((first, rest)) => {
                self.data = rest;
                *first
            }
            None => 0,
        }
    }

    pub fn bool(&mut self) -> bool {
        self.u8() & 1 == 1
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }

    pub fn u64(&mut self) -> u64 {
        u64::from(self.u32()) | (u64::from(self.u32()) << 32)
    }

    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 { 0 } else { usize::from(self.u16()) % bound }
    }

    pub fn bytes(&mut self, count: usize) -> &'a [u8] {
        let count = count.min(self.data.len());
        let (head, rest) = self.data.split_at(count);
        self.data = rest;
        head
    }

    /// A length-prefixed slice: two bytes of length, then up to that many bytes.
    pub fn chunk(&mut self) -> &'a [u8] {
        let length = usize::from(self.u16());
        self.bytes(length)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        self.bytes(self.data.len())
    }
}

/// Splits `data` at points the fuzzer picks, to exercise every parser's partial-input paths.
pub fn split_points(cursor: &mut Cursor<'_>, length: usize) -> Vec<usize> {
    let mut points = Vec::new();
    let mut at = 0usize;
    while at < length {
        let step = match cursor.u8() {
            0 => length - at,
            byte @ 1..=200 => usize::from(byte),
            byte => usize::from(byte) * 97,
        };
        at = (at + step).min(length);
        points.push(at);
    }
    points
}

pub fn test_key() -> AuthKey {
    AuthKey::new(core::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(7)))
}

/// 8-byte words in a fuzzed body that the harness replaces with live values before sealing it, so
/// the fuzzer can name what only exists at run time: `0x7fff_ffff_ffff_<kind><index>`.
pub const PLACEHOLDER: u64 = 0x7fff_ffff_ffff_0000;
pub const ANY_CLIENT_MSG: u8 = 0xff;
pub const SERVER_MSG: u8 = 0xfe;
pub const SESSION_ID: u8 = 0xfd;
pub const SALT: u8 = 0xfc;
pub const FRESH_SERVER_MSG: u8 = 0xfb;
pub const CLIENT_QUERY: u8 = 0xfa;
pub const PING_ID: u8 = 0xf9;
pub const PING_MSG: u8 = 0xf8;
pub const FUTURE_SALTS_MSG: u8 = 0xf7;
pub const STATE_REQUEST_MSG: u8 = 0xf6;
pub const CLIENT_PACKET: u8 = 0xf5;

#[derive(Debug, Default, Clone)]
pub struct Names {
    pub client_msg_ids: Vec<i64>,
    pub query_msg_ids: Vec<i64>,
    pub ping_ids: Vec<i64>,
    pub ping_msg_ids: Vec<i64>,
    pub future_salts_msg_ids: Vec<i64>,
    pub state_request_msg_ids: Vec<i64>,
    pub packet_msg_ids: Vec<i64>,
    pub server_msg_ids: Vec<i64>,
    pub session_id: i64,
    pub salt: i64,
    pub server_time: f64,
}

impl Names {
    pub fn trim(&mut self, keep: usize) {
        for ids in [
            &mut self.client_msg_ids,
            &mut self.query_msg_ids,
            &mut self.ping_ids,
            &mut self.ping_msg_ids,
            &mut self.future_salts_msg_ids,
            &mut self.state_request_msg_ids,
            &mut self.packet_msg_ids,
            &mut self.server_msg_ids,
        ] {
            let excess = ids.len().saturating_sub(keep);
            ids.drain(..excess);
        }
    }
}

pub fn substitute(body: &mut [u8], names: &Names) {
    let mut offset = 0;
    while offset + 8 <= body.len() {
        let word = u64::from_le_bytes(body[offset..offset + 8].try_into().expect("8"));
        if word & 0xffff_ffff_ffff_0000 == PLACEHOLDER {
            let kind = ((word >> 8) & 0xff) as u8;
            let index = (word & 0xff) as usize;
            let newest = |ids: &[i64]| ids.len().checked_sub(1 + index % ids.len().max(1)).map(|at| ids[at]);
            let value = match kind {
                ANY_CLIENT_MSG => newest(&names.client_msg_ids),
                SERVER_MSG => newest(&names.server_msg_ids),
                SESSION_ID => Some(names.session_id),
                SALT => Some(names.salt),
                FRESH_SERVER_MSG => Some(mtproto_core::msg_id::msg_id_for_time(names.server_time - index as f64) | 1),
                CLIENT_QUERY => newest(&names.query_msg_ids),
                PING_ID => newest(&names.ping_ids),
                PING_MSG => newest(&names.ping_msg_ids),
                FUTURE_SALTS_MSG => newest(&names.future_salts_msg_ids),
                STATE_REQUEST_MSG => newest(&names.state_request_msg_ids),
                CLIENT_PACKET => newest(&names.packet_msg_ids),
                _ => None,
            };
            if let Some(value) = value {
                body[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                offset += 8;
                continue;
            }
        }
        offset += 4;
    }
}

pub fn placeholder(kind: u8, index: u8) -> i64 {
    (PLACEHOLDER | (u64::from(kind) << 8) | u64::from(index)) as i64
}
