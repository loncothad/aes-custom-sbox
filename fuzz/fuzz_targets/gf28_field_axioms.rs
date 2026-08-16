#![no_main]

use aes_custom_sbox::{
    IRREDUCIBLE_POLYNOMIALS,
    gf28_inv_poly,
    gf28_mul,
    gf28_mul_poly,
    is_irreducible_poly8,
};
use libfuzzer_sys::fuzz_target;

// GF(2^8) field axioms for arbitrary inputs: multiplication must be
// commutative and distributive for any polynomial, and every non-zero
// element must have an inverse when the polynomial is irreducible.
fuzz_target!(|data: &[u8]| {
    let Some(left) = data.first().copied() else { return };
    let Some(right) = data.get(1).copied() else { return };
    let Some(poly) = data.get(2).copied() else { return };

    // Commutativity and distributivity hold for any reduction polynomial,
    // even reducible ones.
    assert_eq!(gf28_mul_poly(left, right, poly), gf28_mul_poly(right, left, poly));
    assert_eq!(gf28_mul_poly(left, right ^ 0x39, poly), gf28_mul_poly(left, right, poly) ^ gf28_mul_poly(left, 0x39, poly));

    // Standard AES field sanity.
    assert_eq!(gf28_mul(left, 1), left);
    if left != 0 {
        assert_eq!(gf28_mul(left, aes_custom_sbox::gf28_inv(left)), 1);
    }

    // Inverses exist exactly when the polynomial is irreducible.
    if is_irreducible_poly8(poly) {
        if left != 0 {
            assert_eq!(gf28_mul_poly(left, gf28_inv_poly(left, poly), poly), 1);
        }
    }
    // Every polynomial in the published list must be irreducible.
    for &known in &IRREDUCIBLE_POLYNOMIALS {
        assert!(is_irreducible_poly8(known));
    }
});
