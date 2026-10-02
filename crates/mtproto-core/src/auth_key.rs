use zeroize::Zeroize;

use crate::crypto::{auth_key_aux_hash, auth_key_id};

#[derive(Clone, PartialEq, Eq)]
pub struct AuthKey {
    key: Box<[u8; 256]>,
    id: u64,
    aux_hash: u64,
}

impl AuthKey {
    pub fn new(key: [u8; 256]) -> Self {
        let id = auth_key_id(&key);
        let aux_hash = auth_key_aux_hash(&key);
        Self { key: Box::new(key), id, aux_hash }
    }

    pub fn from_slice(key: &[u8]) -> Option<Self> {
        let array: [u8; 256] = key.try_into().ok()?;
        Some(Self::new(array))
    }

    pub fn bytes(&self) -> &[u8; 256] {
        &self.key
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn aux_hash(&self) -> u64 {
        self.aux_hash
    }
}

impl core::fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AuthKey({:#018x})", self.id)
    }
}

impl Drop for AuthKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
