//! Differential testing against the RustCrypto `aes` crate: with the standard
//! S-Box both implementations must agree on every block, in both directions.
#[cfg(test)]
mod tests {
    #![expect(
        clippy::cast_possible_truncation,
        clippy::min_ident_chars,
        clippy::unwrap_used,
        reason = "differential tests drive random data through both implementations"
    )]

    use aes::{
        Aes128 as RefAes128,
        Aes192 as RefAes192,
        Aes256 as RefAes256,
        cipher::{
            Array,
            BlockCipherDecrypt as _,
            BlockCipherEncrypt as _,
            KeyInit as _,
        },
    };
    use aes_custom_sbox::{
        Aes128,
        Aes192,
        Aes256,
    };

    /// Deterministic PRNG (SplitMix64) shared by the differential tests.
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut mixed = self.0;
            mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            mixed ^ (mixed >> 31)
        }

        fn bytes<const SIZE: usize>(&mut self) -> [u8; SIZE] {
            let mut buffer = [0_u8; SIZE];
            for slot in &mut buffer {
                *slot = self.next() as u8;
            }
            buffer
        }
    }

    const ITERATIONS: usize = 2_000;

    /// Cross-checks AES-128 against the reference for random keys and
    /// plaintexts.
    #[test]
    fn differential_aes128() {
        let mut rng = SplitMix64(0x0123_4567_89AB_CDEF);
        for _ in 0 .. ITERATIONS {
            let key = rng.bytes::<16>();
            let plaintext = rng.bytes::<16>();

            let ours = Aes128::new(&key);
            let mut block = plaintext;
            ours.encrypt_block(&mut block);

            let reference = RefAes128::new(&Array::try_from(&key[..]).unwrap());
            let mut expected = Array::from(plaintext);
            reference.encrypt_block(&mut expected);
            assert_eq!(block, <[u8; 16]>::from(expected), "AES-128 encryption mismatch");

            ours.decrypt_block(&mut block);
            let mut recovered = Array::from(<[u8; 16]>::from(expected));
            reference.decrypt_block(&mut recovered);
            assert_eq!(block, plaintext, "our AES-128 decryption must recover the plaintext");
            assert_eq!(<[u8; 16]>::from(recovered), plaintext, "reference decryption sanity");
        }
    }

    /// Cross-checks AES-192 against the reference for random keys and
    /// plaintexts.
    #[test]
    fn differential_aes192() {
        let mut rng = SplitMix64(0xFEDC_BA98_7654_3210);
        for _ in 0 .. ITERATIONS {
            let key = rng.bytes::<24>();
            let plaintext = rng.bytes::<16>();

            let ours = Aes192::new(&key);
            let mut block = plaintext;
            ours.encrypt_block(&mut block);

            let reference = RefAes192::new(&Array::try_from(&key[..]).unwrap());
            let mut expected = Array::from(plaintext);
            reference.encrypt_block(&mut expected);
            assert_eq!(block, <[u8; 16]>::from(expected), "AES-192 encryption mismatch");

            ours.decrypt_block(&mut block);
            let mut recovered = Array::from(<[u8; 16]>::from(expected));
            reference.decrypt_block(&mut recovered);
            assert_eq!(block, plaintext, "our AES-192 decryption must recover the plaintext");
            assert_eq!(<[u8; 16]>::from(recovered), plaintext, "reference decryption sanity");
        }
    }

    /// Cross-checks AES-256 against the reference for random keys and
    /// plaintexts.
    #[test]
    fn differential_aes256() {
        let mut rng = SplitMix64(0x0011_2233_4455_6677);
        for _ in 0 .. ITERATIONS {
            let key = rng.bytes::<32>();
            let plaintext = rng.bytes::<16>();

            let ours = Aes256::new(&key);
            let mut block = plaintext;
            ours.encrypt_block(&mut block);

            let reference = RefAes256::new(&Array::try_from(&key[..]).unwrap());
            let mut expected = Array::from(plaintext);
            reference.encrypt_block(&mut expected);
            assert_eq!(block, <[u8; 16]>::from(expected), "AES-256 encryption mismatch");

            ours.decrypt_block(&mut block);
            let mut recovered = Array::from(<[u8; 16]>::from(expected));
            reference.decrypt_block(&mut recovered);
            assert_eq!(block, plaintext, "our AES-256 decryption must recover the plaintext");
            assert_eq!(<[u8; 16]>::from(recovered), plaintext, "reference decryption sanity");
        }
    }
}
