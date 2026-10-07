use crate::tl::mtproto as tlm;
use crate::tl::{Writer, ids};

pub const INIT_CONNECTION: u32 = 0xc1cd5ea9;
pub const INPUT_CLIENT_PROXY: u32 = 0x75588b3f;
pub const INVOKE_WITH_APNS_SECRET: u32 = 0x0dae54f8;
pub const INVOKE_WITH_RECAPTCHA: u32 = 0xadbb0f94;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientProxy {
    pub address: String,
    pub port: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiEnvironment {
    pub layer: i32,
    pub api_id: i32,
    pub device_model: String,
    pub system_version: String,
    pub app_version: String,
    pub system_lang_code: String,
    pub lang_pack: String,
    pub lang_code: String,
    pub proxy: Option<ClientProxy>,
    pub params: Option<Vec<u8>>,
    pub init_hash: String,
    pub disable_updates: bool,
}

impl ApiEnvironment {
    pub fn anonymous(&self) -> Self {
        Self {
            device_model: "n/a".into(),
            system_version: "n/a".into(),
            lang_pack: String::new(),
            lang_code: String::new(),
            proxy: None,
            params: None,
            ..self.clone()
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum Verification {
    Apns { nonce: String, secret: String },
    Recaptcha { token: String },
}

impl core::fmt::Debug for Verification {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Verification::Apns { .. } => f.write_str("Verification::Apns(<redacted>)"),
            Verification::Recaptcha { .. } => f.write_str("Verification::Recaptcha(<redacted>)"),
        }
    }
}

pub fn wrap_request(
    payload: &[u8],
    initialize: Option<&ApiEnvironment>,
    without_updates: bool,
    verification: Option<&Verification>,
) -> Vec<u8> {
    let mut writer = Writer::with_capacity(payload.len() + 256);
    match verification {
        Some(Verification::Recaptcha { token }) => {
            writer.write_u32(INVOKE_WITH_RECAPTCHA);
            writer.write_bytes(token.as_bytes());
        }
        Some(Verification::Apns { nonce, secret }) => {
            writer.write_u32(INVOKE_WITH_APNS_SECRET);
            writer.write_bytes(nonce.as_bytes());
            writer.write_bytes(secret.as_bytes());
        }
        None => {}
    }
    if without_updates {
        writer.write_u32(ids::INVOKE_WITHOUT_UPDATES);
    }
    if let Some(environment) = initialize {
        writer.write_u32(ids::INVOKE_WITH_LAYER);
        writer.write_i32(environment.layer);
        writer.write_u32(INIT_CONNECTION);
        let mut flags = 0i32;
        if environment.proxy.is_some() {
            flags |= 1;
        }
        if environment.params.is_some() {
            flags |= 2;
        }
        writer.write_i32(flags);
        writer.write_i32(environment.api_id);
        writer.write_bytes(environment.device_model.as_bytes());
        writer.write_bytes(environment.system_version.as_bytes());
        writer.write_bytes(environment.app_version.as_bytes());
        writer.write_bytes(environment.system_lang_code.as_bytes());
        writer.write_bytes(environment.lang_pack.as_bytes());
        writer.write_bytes(environment.lang_code.as_bytes());
        if let Some(proxy) = &environment.proxy {
            writer.write_u32(INPUT_CLIENT_PROXY);
            writer.write_bytes(proxy.address.as_bytes());
            writer.write_i32(proxy.port);
        }
        if let Some(params) = &environment.params {
            writer.write_raw(params);
        }
    }
    match compressed_payload(payload) {
        Some(packed) => writer.write_raw(&packed),
        None => writer.write_raw(payload),
    }
    writer.into_inner()
}

/// The most the wrappers around a request (verification, initConnection) may add. The host's strings
/// go into them: one TL cannot carry (16 MiB or more) or a wrapper this large fails the request
/// locally instead of aborting the process in the TL writer or the transport framer.
pub const MAX_WRAPPER_BYTES: usize = 1 << 20;

/// The bytes `wrap_request` puts around the payload, or None when a host string is too long for TL or
/// the init params (a serialized TL object) are not whole 4-byte words.
pub fn wrapper_len(
    initialize: Option<&ApiEnvironment>,
    without_updates: bool,
    verification: Option<&Verification>,
) -> Option<usize> {
    fn bytes_len(length: usize) -> Option<usize> {
        (length < 1 << 24).then(|| crate::tl::serialized_bytes_len(length))
    }
    let mut total = 0usize;
    match verification {
        Some(Verification::Recaptcha { token }) => total += 4 + bytes_len(token.len())?,
        Some(Verification::Apns { nonce, secret }) => {
            total += 4 + bytes_len(nonce.len())? + bytes_len(secret.len())?;
        }
        None => {}
    }
    if without_updates {
        total += 4;
    }
    if let Some(environment) = initialize {
        total += 20;
        for text in [
            &environment.device_model,
            &environment.system_version,
            &environment.app_version,
            &environment.system_lang_code,
            &environment.lang_pack,
            &environment.lang_code,
        ] {
            total += bytes_len(text.len())?;
        }
        if let Some(proxy) = &environment.proxy {
            total += 8 + bytes_len(proxy.address.len())?;
        }
        if let Some(params) = &environment.params {
            if !params.len().is_multiple_of(4) {
                return None;
            }
            total = total.checked_add(params.len())?;
        }
    }
    Some(total)
}

pub const GZIP_MIN_REQUEST_SIZE: usize = 256;
/// From this size on, a request is gzipped only if a sample from its middle compresses: random or
/// encrypted bytes (upload parts of media, secret chat payloads) would be packed for nothing.
pub const GZIP_SAMPLE_FROM: usize = 16 * 1024;
pub const GZIP_SAMPLE_SIZE: usize = 1024;
pub const UPLOAD_SAVE_FILE_PART: u32 = 0xb304_a621;
pub const UPLOAD_SAVE_BIG_FILE_PART: u32 = 0xde7b_673d;

pub fn compressed_payload(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() < GZIP_MIN_REQUEST_SIZE {
        return None;
    }
    let constructor = u32::from_le_bytes(payload[..4].try_into().ok()?);
    if matches!(constructor, UPLOAD_SAVE_FILE_PART | UPLOAD_SAVE_BIG_FILE_PART | ids::GZIP_PACKED) {
        return None;
    }
    if payload.len() >= GZIP_SAMPLE_FROM {
        let start = (payload.len() - GZIP_SAMPLE_SIZE) / 2;
        let sample = &payload[start..start + GZIP_SAMPLE_SIZE];
        if tlm::gzip(sample).len() * 10 >= GZIP_SAMPLE_SIZE * 9 {
            return None;
        }
    }
    let packed = tlm::gzip(payload);
    let mut writer = Writer::with_capacity(packed.len() + 8);
    tlm::write_gzip_packed(&mut writer, &packed);
    let body = writer.into_inner();
    (body.len() * 10 < payload.len() * 9).then_some(body)
}

pub fn flood_wait_seconds(message: &str) -> Option<i64> {
    for marker in ["FLOOD_PREMIUM_WAIT_", "FLOOD_WAIT_"] {
        if let Some(position) = message.find(marker) {
            let digits: String =
                message[position + marker.len()..].chars().take_while(|c| c.is_ascii_digit()).collect();
            return digits.parse::<i64>().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(length: usize) -> Vec<u8> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    fn text_with_noisy_middle(length: usize) -> Vec<u8> {
        let mut payload = vec![b'a'; length];
        let start = (length - GZIP_SAMPLE_SIZE) / 2;
        payload[start..start + GZIP_SAMPLE_SIZE].copy_from_slice(&noise(GZIP_SAMPLE_SIZE));
        payload[..4].copy_from_slice(&0x7e57_0001u32.to_le_bytes());
        payload
    }

    #[test]
    fn a_large_request_whose_middle_does_not_compress_is_sent_as_it_is() {
        assert_eq!(compressed_payload(&text_with_noisy_middle(64 * 1024)), None, "the sample decides alone");
        assert!(
            compressed_payload(&text_with_noisy_middle(GZIP_SAMPLE_FROM - 1)).is_some(),
            "below the sampling size the whole request is tried"
        );
        let mut noisy = noise(64 * 1024);
        noisy[..4].copy_from_slice(&0x7e57_0001u32.to_le_bytes());
        assert_eq!(compressed_payload(&noisy), None);
        let mut text = vec![b'a'; 64 * 1024];
        text[..4].copy_from_slice(&0x7e57_0001u32.to_le_bytes());
        assert!(compressed_payload(&text).is_some_and(|packed| packed.len() < 1024));
    }

    #[test]
    fn large_requests_are_gzipped_but_file_parts_and_small_ones_are_not() {
        let mut text = vec![0x11u8, 0x22, 0x33, 0x44];
        text.extend(std::iter::repeat_n(b'a', 4000));
        let wrapped = wrap_request(&text, None, false, None);
        assert_eq!(u32::from_le_bytes(wrapped[..4].try_into().unwrap()), ids::GZIP_PACKED);
        assert!(wrapped.len() < 200);
        let mut reader = crate::tl::Reader::new(&wrapped[4..]);
        assert_eq!(tlm::gunzip(reader.read_bytes().unwrap(), 1 << 20).unwrap(), text);
        let mut part = UPLOAD_SAVE_FILE_PART.to_le_bytes().to_vec();
        part.extend(std::iter::repeat_n(0u8, 4000));
        assert_eq!(wrap_request(&part, None, false, None), part);
        let small = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(wrap_request(&small, None, false, None), small);
        let mut random = vec![0x11u8, 0x22, 0x33, 0x44];
        let mut state = 7u64;
        random.extend((0..4000).map(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (state >> 33) as u8
        }));
        assert_eq!(wrap_request(&random, None, false, None), random, "incompressible bodies are sent as is");
    }
    use crate::tl::Reader;

    fn environment() -> ApiEnvironment {
        ApiEnvironment {
            layer: 230,
            api_id: 9,
            device_model: "MacBookPro18,3".into(),
            system_version: "macOS 26.4".into(),
            app_version: "12.6".into(),
            system_lang_code: "en".into(),
            lang_pack: "macos".into(),
            lang_code: "en".into(),
            proxy: None,
            params: None,
            init_hash: "hash".into(),
            disable_updates: false,
        }
    }

    #[test]
    fn plain_payload_is_unchanged() {
        assert_eq!(wrap_request(&[1, 2, 3, 4], None, false, None), vec![1, 2, 3, 4]);
    }

    #[test]
    fn init_connection_layout() {
        let mut env = environment();
        env.proxy = Some(ClientProxy { address: "1.2.3.4".into(), port: 443 });
        env.params = Some(vec![0xaa, 0xbb, 0xcc, 0xdd]);
        let wrapped = wrap_request(&[9, 9, 9, 9], Some(&env), true, None);
        let mut reader = Reader::new(&wrapped);
        assert_eq!(reader.read_u32().unwrap(), ids::INVOKE_WITHOUT_UPDATES);
        assert_eq!(reader.read_u32().unwrap(), ids::INVOKE_WITH_LAYER);
        assert_eq!(reader.read_i32().unwrap(), 230);
        assert_eq!(reader.read_u32().unwrap(), INIT_CONNECTION);
        assert_eq!(reader.read_i32().unwrap(), 3);
        assert_eq!(reader.read_i32().unwrap(), 9);
        assert_eq!(reader.read_bytes().unwrap(), b"MacBookPro18,3");
        assert_eq!(reader.read_bytes().unwrap(), b"macOS 26.4");
        assert_eq!(reader.read_bytes().unwrap(), b"12.6");
        assert_eq!(reader.read_bytes().unwrap(), b"en");
        assert_eq!(reader.read_bytes().unwrap(), b"macos");
        assert_eq!(reader.read_bytes().unwrap(), b"en");
        assert_eq!(reader.read_u32().unwrap(), INPUT_CLIENT_PROXY);
        assert_eq!(reader.read_bytes().unwrap(), b"1.2.3.4");
        assert_eq!(reader.read_i32().unwrap(), 443);
        assert_eq!(reader.read_array::<4>().unwrap(), [0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(reader.read_array::<4>().unwrap(), [9, 9, 9, 9]);
        assert!(reader.finish().is_ok());
    }

    #[test]
    fn verification_wrappers_are_outermost() {
        let apns = wrap_request(
            &[1, 1, 1, 1],
            None,
            true,
            Some(&Verification::Apns { nonce: "n".into(), secret: "s".into() }),
        );
        let mut reader = Reader::new(&apns);
        assert_eq!(reader.read_u32().unwrap(), INVOKE_WITH_APNS_SECRET);
        assert_eq!(reader.read_bytes().unwrap(), b"n");
        assert_eq!(reader.read_bytes().unwrap(), b"s");
        assert_eq!(reader.read_u32().unwrap(), ids::INVOKE_WITHOUT_UPDATES);
        let recaptcha = wrap_request(&[1, 1, 1, 1], None, false, Some(&Verification::Recaptcha { token: "t".into() }));
        assert_eq!(&recaptcha[..4], &INVOKE_WITH_RECAPTCHA.to_le_bytes());
    }

    #[test]
    fn flood_wait_parsing() {
        assert_eq!(flood_wait_seconds("FLOOD_WAIT_17"), Some(17));
        assert_eq!(flood_wait_seconds("FLOOD_PREMIUM_WAIT_3"), Some(3));
        assert_eq!(flood_wait_seconds("FLOOD_WAIT_0"), Some(0));
        assert_eq!(flood_wait_seconds("SLOWMODE_WAIT_10"), None);
        assert_eq!(flood_wait_seconds("FLOOD_WAIT_"), None);
        assert_eq!(flood_wait_seconds("2FA_CONFIRM_WAIT_100"), None);
    }
}
