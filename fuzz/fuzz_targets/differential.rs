#![no_main]

use aes::{
    Aes128 as RefAes128,
    Aes192 as RefAes192,
    Aes256 as RefAes256,
    cipher::{
        Array,
        BlockCipherDecrypt as _,
        BlockCipherEncrypt as _,
        KeyInit,
    },
};
use aes_custom_sbox::{
    Aes128,
    Aes192,
    Aes256,
};
use libfuzzer_sys::fuzz_target;

// Differential fuzzing against the RustCrypto `aes` reference: with the
// standard S-Box our implementation must produce bit-identical blocks.
fuzz_target!(|data: &[u8]| {
    if data.len() < 49 {
        return;
    }
    let variant = data[0] % 3;
    let mut block = <[u8; 16]>::try_from(&data[33 .. 49]).unwrap();
    let plaintext = block;
    match variant {
        0 => {
            let key = <[u8; 16]>::try_from(&data[1 .. 17]).unwrap();
            Aes128::new(&key).encrypt_block(&mut block);
            let mut expected = Array::from(plaintext);
            RefAes128::new(&Array::try_from(&key[..]).unwrap()).encrypt_block(&mut expected);
            assert_eq!(block, <[u8; 16]>::from(expected));
            Aes128::new(&key).decrypt_block(&mut block);
            let mut recovered = Array::from(<[u8; 16]>::from(expected));
            RefAes128::new(&Array::try_from(&key[..]).unwrap()).decrypt_block(&mut recovered);
            assert_eq!(block, <[u8; 16]>::from(recovered));
        }
        1 => {
            let key = <[u8; 24]>::try_from(&data[1 .. 25]).unwrap();
            Aes192::new(&key).encrypt_block(&mut block);
            let mut expected = Array::from(plaintext);
            RefAes192::new(&Array::try_from(&key[..]).unwrap()).encrypt_block(&mut expected);
            assert_eq!(block, <[u8; 16]>::from(expected));
            Aes192::new(&key).decrypt_block(&mut block);
            let mut recovered = Array::from(<[u8; 16]>::from(expected));
            RefAes192::new(&Array::try_from(&key[..]).unwrap()).decrypt_block(&mut recovered);
            assert_eq!(block, <[u8; 16]>::from(recovered));
        }
        _ => {
            let key = <[u8; 32]>::try_from(&data[1 .. 33]).unwrap();
            Aes256::new(&key).encrypt_block(&mut block);
            let mut expected = Array::from(plaintext);
            RefAes256::new(&Array::try_from(&key[..]).unwrap()).encrypt_block(&mut expected);
            assert_eq!(block, <[u8; 16]>::from(expected));
            Aes256::new(&key).decrypt_block(&mut block);
            let mut recovered = Array::from(<[u8; 16]>::from(expected));
            RefAes256::new(&Array::try_from(&key[..]).unwrap()).decrypt_block(&mut recovered);
            assert_eq!(block, <[u8; 16]>::from(recovered));
        }
    }
});
