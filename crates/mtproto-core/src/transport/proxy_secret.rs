use base64::Engine;

pub const MAX_DOMAIN_LENGTH: usize = 182;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProxySecretError {
    #[error("wrong proxy secret")]
    Wrong,
    #[error("too long secret")]
    TooLong,
    #[error("unsupported proxy secret")]
    Unsupported,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProxySecret {
    raw: Vec<u8>,
}

impl core::fmt::Debug for ProxySecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let kind = if self.emulate_tls() {
            "fake-tls"
        } else if self.use_random_padding() {
            "padded"
        } else {
            "simple"
        };
        write!(f, "ProxySecret({kind})")
    }
}

impl ProxySecret {
    pub fn from_link(encoded: &str, truncate_if_needed: bool) -> Result<Self, ProxySecretError> {
        let decoded = decode_hex(encoded)
            .or_else(|| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded.trim_end_matches('=')).ok())
            .or_else(|| base64::engine::general_purpose::STANDARD.decode(encoded).ok())
            .or_else(|| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded).ok())
            .ok_or(ProxySecretError::Wrong)?;
        Self::from_binary(&decoded, truncate_if_needed)
    }

    pub fn from_binary(raw: &[u8], truncate_if_needed: bool) -> Result<Self, ProxySecretError> {
        let mut raw = raw;
        if raw.len() > 17 + MAX_DOMAIN_LENGTH {
            if truncate_if_needed {
                raw = &raw[..17 + MAX_DOMAIN_LENGTH];
            } else {
                return Err(ProxySecretError::TooLong);
            }
        }
        let valid = raw.len() == 16 || (raw.len() == 17 && raw[0] == 0xdd) || (raw.len() >= 18 && raw[0] == 0xee);
        if valid {
            return Ok(Self { raw: raw.to_vec() });
        }
        if raw.len() < 16 { Err(ProxySecretError::Wrong) } else { Err(ProxySecretError::Unsupported) }
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn proxy_key(&self) -> [u8; 16] {
        let slice = if self.raw.len() >= 17 { &self.raw[1..17] } else { &self.raw[..16] };
        slice.try_into().expect("16 bytes")
    }

    pub fn use_random_padding(&self) -> bool {
        self.raw.len() >= 17
    }

    pub fn emulate_tls(&self) -> bool {
        self.raw.len() >= 17 && self.raw[0] == 0xee
    }

    pub fn domain(&self) -> Option<&[u8]> {
        self.emulate_tls().then(|| &self.raw[17..])
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || text.is_empty() {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_and_padded_hex() {
        let simple = ProxySecret::from_link("00112233445566778899aabbccddeeff", false).unwrap();
        assert!(!simple.use_random_padding());
        assert!(!simple.emulate_tls());
        assert_eq!(simple.proxy_key()[0], 0x00);
        let padded = ProxySecret::from_link("dd00112233445566778899aabbccddeeff", false).unwrap();
        assert!(padded.use_random_padding());
        assert!(!padded.emulate_tls());
        assert_eq!(padded.proxy_key(), simple.proxy_key());
    }

    #[test]
    fn fake_tls_hex_and_base64() {
        let mut raw = vec![0xee];
        raw.extend_from_slice(&[0x42; 16]);
        raw.extend_from_slice(b"example.com");
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let from_hex = ProxySecret::from_link(&hex, false).unwrap();
        assert!(from_hex.emulate_tls());
        assert_eq!(from_hex.domain(), Some(&b"example.com"[..]));
        let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw);
        assert_eq!(ProxySecret::from_link(&b64url, false).unwrap(), from_hex);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
        assert_eq!(ProxySecret::from_link(&b64, false).unwrap(), from_hex);
    }

    #[test]
    fn rejections_and_truncation() {
        assert_eq!(ProxySecret::from_binary(&[1; 15], false), Err(ProxySecretError::Wrong));
        assert_eq!(ProxySecret::from_binary(&[1; 17], false), Err(ProxySecretError::Unsupported));
        assert_eq!(ProxySecret::from_link("zz", false), Err(ProxySecretError::Wrong));
        let mut long = vec![0xee];
        long.extend(vec![b'a'; 16 + MAX_DOMAIN_LENGTH + 5]);
        assert_eq!(ProxySecret::from_binary(&long, false), Err(ProxySecretError::TooLong));
        let truncated = ProxySecret::from_binary(&long, true).unwrap();
        assert_eq!(truncated.domain().unwrap().len(), MAX_DOMAIN_LENGTH);
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let secret = ProxySecret::from_link("00112233445566778899aabbccddeeff", false).unwrap();
        assert_eq!(format!("{secret:?}"), "ProxySecret(simple)");
    }
}
