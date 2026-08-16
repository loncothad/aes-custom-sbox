#![no_main]

use aes_custom_sbox::Aes192;
use libfuzzer_sys::fuzz_target;

// Roundtrip property: decrypt(encrypt(x)) == x for arbitrary keys and blocks.
fuzz_target!(|data: &[u8]| {
    if data.len() < 40 {
        return;
    }
    let (key_material, block_material) = data.split_at(24);
    let Ok(key) = <[u8; 24]>::try_from(key_material) else {
        return;
    };
    let cipher = Aes192::new(&key);
    for block_bytes in block_material.chunks_exact(16) {
        let Ok(mut block) = <[u8; 16]>::try_from(block_bytes) else {
            return;
        };
        let plaintext = block;
        cipher.encrypt_block(&mut block);
        cipher.decrypt_block(&mut block);
        assert_eq!(block, plaintext);
    }
});
