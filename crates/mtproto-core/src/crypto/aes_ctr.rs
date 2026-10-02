use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use zeroize::Zeroize;

const PARALLEL_BLOCKS: usize = 8;
const KEYSTREAM_LEN: usize = PARALLEL_BLOCKS * 16;

pub struct AesCtr {
    cipher: Aes256,
    counter: u128,
    keystream: [u8; KEYSTREAM_LEN],
    offset: usize,
}

impl AesCtr {
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self {
            cipher: Aes256::new(GenericArray::from_slice(key)),
            counter: u128::from_be_bytes(*iv),
            keystream: [0; KEYSTREAM_LEN],
            offset: KEYSTREAM_LEN,
        }
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        let mut position = 0;
        while position < data.len() {
            if self.offset == KEYSTREAM_LEN {
                self.refill();
            }
            let take = (KEYSTREAM_LEN - self.offset).min(data.len() - position);
            let keystream = &self.keystream[self.offset..self.offset + take];
            for (byte, key) in data[position..position + take].iter_mut().zip(keystream) {
                *byte ^= key;
            }
            self.offset += take;
            position += take;
        }
    }

    fn refill(&mut self) {
        let mut blocks = [GenericArray::default(); PARALLEL_BLOCKS];
        for block in blocks.iter_mut() {
            block.copy_from_slice(&self.counter.to_be_bytes());
            self.counter = self.counter.wrapping_add(1);
        }
        self.cipher.encrypt_blocks(&mut blocks);
        for (index, block) in blocks.iter().enumerate() {
            self.keystream[index * 16..index * 16 + 16].copy_from_slice(block);
        }
        self.offset = 0;
    }
}

impl Drop for AesCtr {
    fn drop(&mut self) {
        self.keystream.zeroize();
        self.counter = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn nist_sp800_38a_ctr_aes256() {
        let key: [u8; 32] = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .unwrap()
            .try_into()
            .unwrap();
        let iv: [u8; 16] = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap().try_into().unwrap();
        let mut data = hex::decode(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710"
        ))
        .unwrap();
        AesCtr::new(&key, &iv).apply(&mut data);
        assert_eq!(
            hex::encode(data),
            concat!(
                "601ec313775789a5b7a7f504bbf3d228",
                "f443e3ca4d62b59aca84e990cacaf5c5",
                "2b0930daa23de94ce87017ba2d84988d",
                "dfc9c58db67aada613c2dd08457941a6"
            )
        );
    }

    #[test]
    fn counter_wraps_around_128_bits() {
        let key = [3u8; 32];
        let iv = [0xffu8; 16];
        let mut a = vec![0u8; 48];
        AesCtr::new(&key, &iv).apply(&mut a);
        let mut b = vec![0u8; 32];
        AesCtr::new(&key, &[0u8; 16]).apply(&mut b);
        assert_eq!(&a[16..], &b[..]);
    }

    proptest! {
        #[test]
        fn chunked_equals_one_shot(key in any::<[u8; 32]>(), iv in any::<[u8; 16]>(), len in 0usize..1000, cuts in proptest::collection::vec(0usize..1000, 0..8)) {
            let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut whole = plain.clone();
            AesCtr::new(&key, &iv).apply(&mut whole);
            let mut chunked = plain.clone();
            let mut points: Vec<usize> = cuts.into_iter().map(|c| c.min(len)).collect();
            points.push(0);
            points.push(len);
            points.sort_unstable();
            let mut ctr = AesCtr::new(&key, &iv);
            for window in points.windows(2) {
                ctr.apply(&mut chunked[window[0]..window[1]]);
            }
            prop_assert_eq!(&whole, &chunked);
            AesCtr::new(&key, &iv).apply(&mut whole);
            prop_assert_eq!(whole, plain);
        }
    }
}
