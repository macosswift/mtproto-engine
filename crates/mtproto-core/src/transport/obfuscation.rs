use super::codec::Framing;
use crate::crypto::{AesCtr, SecureRandom, sha256_parts};

pub const OBFUSCATED_HEADER_LEN: usize = 64;

const FORBIDDEN_FIRST_WORDS: [u32; 7] =
    [0x44414548, 0x54534f50, 0x20544547, 0x4954504f, 0xdddddddd, 0xeeeeeeee, 0x02010316];

pub struct ObfuscatedInit {
    pub header: [u8; OBFUSCATED_HEADER_LEN],
    pub encryptor: AesCtr,
    pub decryptor: AesCtr,
}

pub fn obfuscated_init(
    framing: Framing,
    dc_id: i16,
    proxy_secret: Option<&[u8; 16]>,
    emulate_tls: bool,
    rng: &mut impl SecureRandom,
) -> ObfuscatedInit {
    let mut header = [0u8; OBFUSCATED_HEADER_LEN];
    loop {
        rng.fill(&mut header);
        if emulate_tls {
            break;
        }
        if header[0] == 0xef {
            continue;
        }
        let first = u32::from_le_bytes(header[..4].try_into().expect("4"));
        if FORBIDDEN_FIRST_WORDS.contains(&first) {
            continue;
        }
        if u32::from_le_bytes(header[4..8].try_into().expect("4")) == 0 {
            continue;
        }
        break;
    }
    header[56..60].copy_from_slice(&framing.tag().to_le_bytes());
    header[60..62].copy_from_slice(&dc_id.to_le_bytes());

    let mut reversed = header;
    reversed.reverse();

    let derive = |key: &[u8]| -> [u8; 32] {
        match proxy_secret {
            Some(secret) => sha256_parts(&[key, secret]),
            None => key.try_into().expect("32 bytes"),
        }
    };
    let encrypt_key = derive(&header[8..40]);
    let encrypt_iv: [u8; 16] = header[40..56].try_into().expect("16");
    let decrypt_key = derive(&reversed[8..40]);
    let decrypt_iv: [u8; 16] = reversed[40..56].try_into().expect("16");

    let mut encryptor = AesCtr::new(&encrypt_key, &encrypt_iv);
    let decryptor = AesCtr::new(&decrypt_key, &decrypt_iv);
    let mut encrypted = header;
    encryptor.apply(&mut encrypted);
    header[56..].copy_from_slice(&encrypted[56..]);
    ObfuscatedInit { header, encryptor, decryptor }
}

pub struct ServerObfuscation {
    pub framing: Framing,
    pub dc_id: i16,
    pub decryptor: AesCtr,
    pub encryptor: AesCtr,
}

pub fn accept_obfuscated_header(
    header: &[u8; OBFUSCATED_HEADER_LEN],
    proxy_secret: Option<&[u8; 16]>,
) -> Option<ServerObfuscation> {
    let mut reversed = *header;
    reversed.reverse();
    let derive = |key: &[u8]| -> [u8; 32] {
        match proxy_secret {
            Some(secret) => sha256_parts(&[key, secret]),
            None => key.try_into().expect("32 bytes"),
        }
    };
    let mut decryptor = AesCtr::new(&derive(&header[8..40]), &header[40..56].try_into().expect("16"));
    let encryptor = AesCtr::new(&derive(&reversed[8..40]), &reversed[40..56].try_into().expect("16"));
    let mut plain = *header;
    decryptor.apply(&mut plain);
    let tag = u32::from_le_bytes(plain[56..60].try_into().expect("4"));
    let framing = match tag {
        0xefefefef => Framing::Abridged,
        0xeeeeeeee => Framing::Intermediate,
        0xdddddddd => Framing::PaddedIntermediate,
        _ => return None,
    };
    Some(ServerObfuscation {
        framing,
        dc_id: i16::from_le_bytes(plain[60..62].try_into().expect("2")),
        decryptor,
        encryptor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{SequenceRandom, XorShiftRandom};

    #[test]
    fn header_layout_and_symmetry() {
        for (framing, secret) in [
            (Framing::Abridged, None),
            (Framing::Intermediate, Some([7u8; 16])),
            (Framing::PaddedIntermediate, Some([9u8; 16])),
        ] {
            let mut rng = XorShiftRandom::new(11);
            let mut client = obfuscated_init(framing, -2, secret.as_ref(), false, &mut rng);
            let mut server = accept_obfuscated_header(&client.header, secret.as_ref()).expect("valid header");
            assert_eq!(server.framing, framing);
            assert_eq!(server.dc_id, -2);

            let mut up = b"client says hello".to_vec();
            client.encryptor.apply(&mut up);
            server.decryptor.apply(&mut up);
            assert_eq!(up, b"client says hello");

            let mut down = b"server answers".to_vec();
            server.encryptor.apply(&mut down);
            client.decryptor.apply(&mut down);
            assert_eq!(down, b"server answers");
        }
    }

    #[test]
    fn wrong_secret_fails_to_parse_tag() {
        let mut rng = XorShiftRandom::new(12);
        let client = obfuscated_init(Framing::Intermediate, 2, Some(&[1u8; 16]), false, &mut rng);
        assert!(accept_obfuscated_header(&client.header, Some(&[2u8; 16])).is_none());
    }

    #[test]
    fn rejects_forbidden_prefixes() {
        let mut bad = vec![0xefu8; 64];
        let mut head = vec![0u8; 64];
        head[..4].copy_from_slice(&0x44414548u32.to_le_bytes());
        bad.extend(head);
        let mut zero_second = vec![1u8; 64];
        zero_second[4..8].copy_from_slice(&[0; 4]);
        bad.extend(zero_second);
        let mut good = vec![0x11u8; 64];
        good[0] = 0x12;
        bad.extend(good.clone());
        let mut rng = SequenceRandom::new(bad);
        let init = obfuscated_init(Framing::Abridged, 1, None, false, &mut rng);
        assert_eq!(&init.header[..56], &good[..56]);
        assert_eq!(rng.remaining(), 0);
    }

    #[test]
    fn plaintext_prefix_is_sent_verbatim() {
        let mut rng = XorShiftRandom::new(13);
        let init = obfuscated_init(Framing::Abridged, 4, None, false, &mut rng);
        let mut again = XorShiftRandom::new(13);
        let mut raw = [0u8; 64];
        again.fill(&mut raw);
        assert_eq!(&init.header[..56], &raw[..56]);
        assert_ne!(&init.header[56..60], &Framing::Abridged.tag().to_le_bytes());
    }
}
