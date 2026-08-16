#![no_main]

use aes_custom_sbox::{
    Aes128,
    Aes192,
    Aes256,
    compute_inv_sbox,
    is_valid_sbox,
};
use libfuzzer_sys::fuzz_target;

// Deterministically derives a byte permutation from the fuzz input via a
// Fisher-Yates shuffle driven by a SplitMix64 PRNG seeded from the data.
fn permutation_from(data: &[u8]) -> [u8; 256] {
    let mut state = [0_u8; 8];
    for (slot, byte) in state.iter_mut().zip(data.iter().cycle()) {
        *slot = *byte;
    }
    let mut rng = u64::from_le_bytes(state);
    let mut next = move || {
        rng = rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = rng;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    };
    let mut sbox = core::array::from_fn(|index| index as u8);
    for index in (1 .. 256).rev() {
        let other = (next() % (index as u64 + 1)) as usize;
        sbox.swap(index, other);
    }
    sbox
}

// Roundtrip property for arbitrary permutation S-Boxes across all key sizes.
fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let sbox = permutation_from(data);
    assert!(is_valid_sbox(&sbox));
    let inv_sbox = compute_inv_sbox(&sbox);
    for (input, substituted) in sbox.iter().enumerate() {
        assert_eq!(inv_sbox[usize::from(*substituted)], input as u8);
    }

    if data.len() >= 32 {
        let Ok(key) = <[u8; 16]>::try_from(&data[.. 16]) else { return };
        let Ok(mut block) = <[u8; 16]>::try_from(&data[16 .. 32]) else { return };
        let Ok(cipher) = Aes128::new_with_sbox(&key, &sbox) else { return };
        let plaintext = block;
        cipher.encrypt_block(&mut block);
        cipher.decrypt_block(&mut block);
        assert_eq!(block, plaintext);
    }
    if data.len() >= 48 {
        let Ok(key) = <[u8; 24]>::try_from(&data[8 .. 32]) else { return };
        let Ok(mut block) = <[u8; 16]>::try_from(&data[32 .. 48]) else { return };
        let Ok(cipher) = Aes192::new_with_sbox(&key, &sbox) else { return };
        let plaintext = block;
        cipher.encrypt_block(&mut block);
        cipher.decrypt_block(&mut block);
        assert_eq!(block, plaintext);
    }
    if data.len() >= 64 {
        let Ok(key) = <[u8; 32]>::try_from(&data[16 .. 48]) else { return };
        let Ok(mut block) = <[u8; 16]>::try_from(&data[48 .. 64]) else { return };
        let Ok(cipher) = Aes256::new_with_sbox(&key, &sbox) else { return };
        let plaintext = block;
        cipher.encrypt_block(&mut block);
        cipher.decrypt_block(&mut block);
        assert_eq!(block, plaintext);
    }
});
