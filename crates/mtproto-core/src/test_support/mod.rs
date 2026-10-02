use num_bigint::BigUint;

use crate::crypto::RsaPublicKey;

pub const TEST_RSA_N_HEX: &str = "d8d234881042d0f269bdeb7f4f317ceaf991e904e28e8a974c582e8797dbadf811bdeb45ddf43c529dc0aa4c38bb0ea176099944e6d9b5d07b3abdda711a685972137ba7c1c451e586faed1e45fa15647e938f4f016b190ac0661a0e6b16a3cd8bc1873495c40fc773bbed4d41a4c00a016dce2f0d4fcf7f65a4f00cebe853ddc20d4848beee20bca65aad2dee79976bb1d110d00ddb0dee76b0580d66c3ef53ca1749aef9896498aae7a302e12e31b1a695641a8f0a070e266ef65a1e49da19efe07f740ea04f9430657dceb5ced2037d9cae3da04383c966a9e161386310fef3bfaa1c3247d5728a95a151387d4920380363e635883d4a536532851773abd1";
pub const TEST_RSA_D_HEX: &str = "123231ee694ef23225e5a669dcbf8e7839d1a0f8a3faca6ec01d766a32b860f53ca7efa2c169c9d6351f022bbb6717673d7cb8bc2b9381caa94cd8ba085beafdf6b0e3e3c443318c4db3a94aad1cbbc6df488af25a701e7de47fad1820ac99ba9a4bf788d638ca0a3710426e05604a2d8cc9265094916a1c8aef38a61cf636737241217824119dd19324b9522c1801678705020df9a880252b44daf2f702adc31f396ee2ff1cc26acd62545b751307c67792768d66b5dd0bfd9f64970973425e7cfd35ea3b8196d4566cc2b390f014ae891bc7e48dde873c54ce0cb7e27de05c70ccca9731eca28c546c4c4faf3f004eeacb45ff34b99fc8064163a3d2778241";

pub struct TestRsaKeyPair {
    pub public: RsaPublicKey,
    pub d: BigUint,
}

pub fn test_rsa_key_pair() -> TestRsaKeyPair {
    let n = hex_to_bytes(TEST_RSA_N_HEX);
    TestRsaKeyPair {
        public: RsaPublicKey::from_components(&n, &[1, 0, 1]).expect("valid test key"),
        d: BigUint::from_bytes_be(&hex_to_bytes(TEST_RSA_D_HEX)),
    }
}

impl TestRsaKeyPair {
    pub fn decrypt(&self, data: &[u8]) -> [u8; 256] {
        let raw = self.public.decrypt_with_private_exponent(&self.d, data);
        let mut out = [0u8; 256];
        out[256 - raw.len()..].copy_from_slice(&raw);
        out
    }
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex")).collect()
}

mod server_handshake;
pub mod server_peer;

pub use server_handshake::{ServerHandshake, ServerHandshakeBehavior, ServerHandshakeOutcome};
