#![no_main]

use aes_custom_sbox::{
    compute_inv_sbox,
    generate_custom_sbox,
    is_irreducible_poly8,
    is_valid_sbox,
};
use libfuzzer_sys::fuzz_target;

// Generated S-Boxes from irreducible polynomials must be permutations whose
// computed inverse actually inverts them.
fuzz_target!(|data: &[u8]| {
    let Some(affine_const) = data.first().copied() else { return };
    let Some(poly) = data.get(1).copied() else { return };

    let sbox = generate_custom_sbox(affine_const, poly);
    if is_irreducible_poly8(poly) {
        assert!(is_valid_sbox(&sbox), "irreducible poly must yield a permutation");
        let inv_sbox = compute_inv_sbox(&sbox);
        for (input, substituted) in sbox.iter().enumerate() {
            assert_eq!(inv_sbox[usize::from(*substituted)], input as u8);
        }
    }
});
