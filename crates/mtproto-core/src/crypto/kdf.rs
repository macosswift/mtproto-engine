use zeroize::Zeroize;

use super::hash::{sha1, sha1_parts, sha256_parts};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

impl Side {
    fn offset(self) -> usize {
        match self {
            Side::Client => 0,
            Side::Server => 8,
        }
    }
}

pub struct MessageKeyMaterial {
    pub key: [u8; 32],
    pub iv: [u8; 32],
}

impl Drop for MessageKeyMaterial {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

pub fn message_key_v2(auth_key: &[u8; 256], msg_key: &[u8; 16], side: Side) -> MessageKeyMaterial {
    let x = side.offset();
    let a = sha256_parts(&[msg_key, &auth_key[x..x + 36]]);
    let b = sha256_parts(&[&auth_key[40 + x..40 + x + 36], msg_key]);
    let mut key = [0u8; 32];
    key[..8].copy_from_slice(&a[..8]);
    key[8..24].copy_from_slice(&b[8..24]);
    key[24..].copy_from_slice(&a[24..32]);
    let mut iv = [0u8; 32];
    iv[..8].copy_from_slice(&b[..8]);
    iv[8..24].copy_from_slice(&a[8..24]);
    iv[24..].copy_from_slice(&b[24..32]);
    MessageKeyMaterial { key, iv }
}

pub fn message_key_v1(auth_key: &[u8; 256], msg_key: &[u8; 16], side: Side) -> MessageKeyMaterial {
    let x = side.offset();
    let a = sha1_parts(&[msg_key, &auth_key[x..x + 32]]);
    let b = sha1_parts(&[&auth_key[32 + x..48 + x], msg_key, &auth_key[48 + x..64 + x]]);
    let c = sha1_parts(&[&auth_key[64 + x..96 + x], msg_key]);
    let d = sha1_parts(&[msg_key, &auth_key[96 + x..128 + x]]);
    let mut key = [0u8; 32];
    key[..8].copy_from_slice(&a[..8]);
    key[8..20].copy_from_slice(&b[8..20]);
    key[20..].copy_from_slice(&c[4..16]);
    let mut iv = [0u8; 32];
    iv[..12].copy_from_slice(&a[8..20]);
    iv[12..20].copy_from_slice(&b[..8]);
    iv[20..24].copy_from_slice(&c[16..20]);
    iv[24..].copy_from_slice(&d[..8]);
    MessageKeyMaterial { key, iv }
}

pub fn handshake_tmp_aes(new_nonce: &[u8; 32], server_nonce: &[u8; 16]) -> MessageKeyMaterial {
    let new_server = sha1_parts(&[new_nonce, server_nonce]);
    let server_new = sha1_parts(&[server_nonce, new_nonce]);
    let new_new = sha1_parts(&[new_nonce, new_nonce]);
    let mut key = [0u8; 32];
    key[..20].copy_from_slice(&new_server);
    key[20..].copy_from_slice(&server_new[..12]);
    let mut iv = [0u8; 32];
    iv[..8].copy_from_slice(&server_new[12..20]);
    iv[8..28].copy_from_slice(&new_new);
    iv[28..].copy_from_slice(&new_nonce[..4]);
    MessageKeyMaterial { key, iv }
}

pub fn auth_key_id(auth_key: &[u8; 256]) -> u64 {
    let hash = sha1(auth_key);
    u64::from_le_bytes(hash[12..20].try_into().expect("8 bytes"))
}

pub fn auth_key_aux_hash(auth_key: &[u8; 256]) -> u64 {
    let hash = sha1(auth_key);
    u64::from_le_bytes(hash[..8].try_into().expect("8 bytes"))
}

pub fn msg_key_v2(auth_key: &[u8; 256], plaintext_with_padding: &[u8], side: Side) -> [u8; 16] {
    let x = side.offset();
    let large = sha256_parts(&[&auth_key[88 + x..88 + x + 32], plaintext_with_padding]);
    large[8..24].try_into().expect("16 bytes")
}

pub fn msg_key_v1(plaintext_without_padding: &[u8]) -> [u8; 16] {
    let hash = sha1(plaintext_without_padding);
    hash[4..20].try_into().expect("16 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_auth_key() -> [u8; 256] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3))
    }

    #[test]
    fn v2_sides_differ() {
        let key = sample_auth_key();
        let msg_key = [9u8; 16];
        let client = message_key_v2(&key, &msg_key, Side::Client);
        let server = message_key_v2(&key, &msg_key, Side::Server);
        assert_ne!(client.key, server.key);
        assert_ne!(client.iv, server.iv);
    }

    #[test]
    fn v2_layout_matches_spec_definition() {
        let key = sample_auth_key();
        let msg_key = [0x5au8; 16];
        let material = message_key_v2(&key, &msg_key, Side::Server);
        let a = sha256_parts(&[&msg_key, &key[8..44]]);
        let b = sha256_parts(&[&key[48..84], &msg_key]);
        let expected_key = [&a[0..8], &b[8..24], &a[24..32]].concat();
        let expected_iv = [&b[0..8], &a[8..24], &b[24..32]].concat();
        assert_eq!(material.key.to_vec(), expected_key);
        assert_eq!(material.iv.to_vec(), expected_iv);
    }

    #[test]
    fn v1_layout_matches_spec_definition() {
        let key = sample_auth_key();
        let msg_key = [0x11u8; 16];
        let material = message_key_v1(&key, &msg_key, Side::Client);
        let a = sha1_parts(&[&msg_key, &key[0..32]]);
        let b = sha1_parts(&[&key[32..48], &msg_key, &key[48..64]]);
        let c = sha1_parts(&[&key[64..96], &msg_key]);
        let d = sha1_parts(&[&msg_key, &key[96..128]]);
        assert_eq!(material.key.to_vec(), [&a[0..8], &b[8..20], &c[4..16]].concat());
        assert_eq!(material.iv.to_vec(), [&a[8..20], &b[0..8], &c[16..20], &d[0..8]].concat());
    }

    #[test]
    fn auth_key_id_is_low_64_bits_of_sha1() {
        let key = sample_auth_key();
        let hash = sha1(&key);
        assert_eq!(auth_key_id(&key).to_le_bytes(), hash[12..20]);
        assert_eq!(auth_key_aux_hash(&key).to_le_bytes(), hash[0..8]);
    }

    #[test]
    fn msg_key_v2_uses_auth_key_slice_88() {
        let key = sample_auth_key();
        let payload = b"payload-with-padding-0123456789abcdef";
        let full = sha256_parts(&[&key[96..128], payload]);
        assert_eq!(msg_key_v2(&key, payload, Side::Server), full[8..24]);
    }
}
