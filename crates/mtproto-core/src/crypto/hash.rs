use sha1::Sha1;
use sha2::{Digest, Sha256};

pub fn sha1(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data).into()
}

pub fn sha1_parts(parts: &[&[u8]]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_known_vectors() {
        assert_eq!(hex::encode(sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex::encode(sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(hex::encode(sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn parts_equal_concatenation() {
        let a = b"hello ";
        let b = b"world";
        assert_eq!(sha1_parts(&[a, b]), sha1(b"hello world"));
        assert_eq!(sha256_parts(&[a, b, b""]), sha256(b"hello world"));
    }
}
