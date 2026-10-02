use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes::{Aes256, Aes256Dec, Aes256Enc};
use zeroize::Zeroize;

use super::CryptoError;

pub struct AesIge {
    cipher: Aes256,
    iv: [u8; 32],
}

impl AesIge {
    pub fn new(key: &[u8; 32], iv: &[u8; 32]) -> Self {
        Self { cipher: Aes256::new(GenericArray::from_slice(key)), iv: *iv }
    }

    pub fn iv(&self) -> &[u8; 32] {
        &self.iv
    }

    pub fn encrypt(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        if !data.len().is_multiple_of(16) {
            return Err(CryptoError::UnalignedLength(data.len()));
        }
        let mut c_prev = block_from(&self.iv[..16]);
        let mut p_prev = block_from(&self.iv[16..]);
        for chunk in data.chunks_exact_mut(16) {
            let plain = block_from(chunk);
            let mut x = GenericArray::from(xor_block(&plain, &c_prev));
            self.cipher.encrypt_block(&mut x);
            let cipher_block = xor_block(&x.into(), &p_prev);
            chunk.copy_from_slice(&cipher_block);
            c_prev = cipher_block;
            p_prev = plain;
        }
        self.iv[..16].copy_from_slice(&c_prev);
        self.iv[16..].copy_from_slice(&p_prev);
        Ok(())
    }

    pub fn decrypt(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        if !data.len().is_multiple_of(16) {
            return Err(CryptoError::UnalignedLength(data.len()));
        }
        let mut c_prev = block_from(&self.iv[..16]);
        let mut p_prev = block_from(&self.iv[16..]);
        for chunk in data.chunks_exact_mut(16) {
            let cipher_block = block_from(chunk);
            let mut x = GenericArray::from(xor_block(&cipher_block, &p_prev));
            self.cipher.decrypt_block(&mut x);
            let plain = xor_block(&x.into(), &c_prev);
            chunk.copy_from_slice(&plain);
            c_prev = cipher_block;
            p_prev = plain;
        }
        self.iv[..16].copy_from_slice(&c_prev);
        self.iv[16..].copy_from_slice(&p_prev);
        Ok(())
    }
}

impl Drop for AesIge {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

pub fn aes_ige_encrypt(key: &[u8; 32], iv: &[u8; 32], data: &mut [u8]) -> Result<(), CryptoError> {
    if !data.len().is_multiple_of(16) {
        return Err(CryptoError::UnalignedLength(data.len()));
    }
    let cipher = Aes256Enc::new(GenericArray::from_slice(key));
    let mut c_prev = block_from(&iv[..16]);
    let mut p_prev = block_from(&iv[16..]);
    for chunk in data.chunks_exact_mut(16) {
        let plain = block_from(chunk);
        let mut x = GenericArray::from(xor_block(&plain, &c_prev));
        cipher.encrypt_block(&mut x);
        let cipher_block = xor_block(&x.into(), &p_prev);
        chunk.copy_from_slice(&cipher_block);
        c_prev = cipher_block;
        p_prev = plain;
    }
    Ok(())
}

pub fn aes_ige_decrypt(key: &[u8; 32], iv: &[u8; 32], data: &mut [u8]) -> Result<(), CryptoError> {
    if !data.len().is_multiple_of(16) {
        return Err(CryptoError::UnalignedLength(data.len()));
    }
    let cipher = Aes256Dec::new(GenericArray::from_slice(key));
    let mut c_prev = block_from(&iv[..16]);
    let mut p_prev = block_from(&iv[16..]);
    for chunk in data.chunks_exact_mut(16) {
        let cipher_block = block_from(chunk);
        let mut x = GenericArray::from(xor_block(&cipher_block, &p_prev));
        cipher.decrypt_block(&mut x);
        let plain = xor_block(&x.into(), &c_prev);
        chunk.copy_from_slice(&plain);
        c_prev = cipher_block;
        p_prev = plain;
    }
    Ok(())
}

#[inline(always)]
fn block_from(slice: &[u8]) -> [u8; 16] {
    let mut block = [0u8; 16];
    block.copy_from_slice(slice);
    block
}

#[inline(always)]
fn xor_block(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    (u128::from_ne_bytes(*a) ^ u128::from_ne_bytes(*b)).to_ne_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn reference_ige_encrypt(key: &[u8; 32], iv: &[u8; 32], data: &[u8]) -> Vec<u8> {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut out = Vec::with_capacity(data.len());
        let mut c_prev = iv[..16].to_vec();
        let mut p_prev = iv[16..].to_vec();
        for chunk in data.chunks(16) {
            let mut x: Vec<u8> = chunk.iter().zip(&c_prev).map(|(a, b)| a ^ b).collect();
            let block = GenericArray::from_mut_slice(&mut x);
            cipher.encrypt_block(block);
            let c: Vec<u8> = x.iter().zip(&p_prev).map(|(a, b)| a ^ b).collect();
            out.extend_from_slice(&c);
            c_prev = c;
            p_prev = chunk.to_vec();
        }
        out
    }

    #[test]
    fn rejects_unaligned_input() {
        let mut data = [0u8; 15];
        assert_eq!(aes_ige_encrypt(&[0; 32], &[0; 32], &mut data), Err(CryptoError::UnalignedLength(15)));
        assert_eq!(aes_ige_decrypt(&[0; 32], &[0; 32], &mut data), Err(CryptoError::UnalignedLength(15)));
    }

    #[test]
    fn empty_input_is_noop() {
        let mut data: [u8; 0] = [];
        aes_ige_encrypt(&[1; 32], &[2; 32], &mut data).unwrap();
    }

    #[test]
    fn streaming_matches_one_shot() {
        let key = [7u8; 32];
        let iv: [u8; 32] = core::array::from_fn(|i| i as u8);
        let mut whole: Vec<u8> = (0..96u8).collect();
        let mut split = whole.clone();
        aes_ige_encrypt(&key, &iv, &mut whole).unwrap();
        let mut ige = AesIge::new(&key, &iv);
        ige.encrypt(&mut split[..32]).unwrap();
        ige.encrypt(&mut split[32..]).unwrap();
        assert_eq!(whole, split);
    }

    proptest! {
        #[test]
        fn roundtrip(key in any::<[u8; 32]>(), iv in any::<[u8; 32]>(), blocks in 0usize..64, seed in any::<u8>()) {
            let plain: Vec<u8> = (0..blocks * 16).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect();
            let mut data = plain.clone();
            aes_ige_encrypt(&key, &iv, &mut data).unwrap();
            prop_assert_eq!(&data, &reference_ige_encrypt(&key, &iv, &plain));
            if blocks > 0 {
                prop_assert_ne!(&data, &plain);
            }
            aes_ige_decrypt(&key, &iv, &mut data).unwrap();
            prop_assert_eq!(data, plain);
        }
    }
}
