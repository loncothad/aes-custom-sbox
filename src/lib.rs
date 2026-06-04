//! AES implementation with support for custom S-Box.
//!
//! This crate provides AES-128, AES-192, and AES-256.
//! All variants allow you to configure a custom S-Box
//! via the `new_with_sbox` methods.
//! It also provides utility methods for generating
//! the standard AES S-Box or custom affine variations
//! using any of the 30 irreducible polynomials of degree 8
//! over GF(2).

#![no_std]

use core::{
    hint::assert_unchecked,
    ptr,
};

/// Polynomial modulo operation for GF(2)
pub const fn poly_mod(mut a: u16, b: u16) -> u16 {
    if b == 0 {
        return a;
    }
    let b_deg = 15 - (b.leading_zeros() as u16);
    while a != 0 {
        let a_deg = 15 - (a.leading_zeros() as u16);
        if a_deg < b_deg {
            break;
        }
        a ^= b << (a_deg - b_deg);
    }
    a
}

/// Generates the 30 characteristic irreducible polynomials of degree 8 over
/// GF(2). Returns an array of the 30 polynomials, represented by their lower 8
/// bits.
///
/// The standard AES irreducible polynomial is `x^8 + x^4 + x^3 + x + 1`,
/// which corresponds to `0x1B` in this list.
pub const fn find_irreducible_polynomials() -> [u8; 30] {
    let mut polys = [0u8; 30];
    let mut count = 0;
    let mut p: u16 = 256;
    while p < 512 {
        let mut is_irreducible = true;
        let mut d: u16 = 2;
        // Test divisibility by all polynomials up to degree 4.
        while d < 32 {
            if poly_mod(p, d) == 0 {
                is_irreducible = false;
                break;
            }
            d += 1;
        }
        if is_irreducible {
            polys[count] = (p & 0xFF) as u8;
            count += 1;
        }
        p += 1;
    }
    polys
}

/// The pre-calculated 30 irreducible polynomials of degree 8 over GF(2).
pub const IRREDUCIBLE_POLYNOMIALS: [u8; 30] = find_irreducible_polynomials();

/// Multiply by x in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 (Standard AES poly
/// 0x1B)
#[inline(always)]
const fn xtime(x: u8) -> u8 {
    (x << 1)
        ^ (if x & 0x80 != 0 {
            0x1B
        } else {
            0
        })
}

/// Generic GF(2^8) multiplication parameterized by an irreducible polynomial
/// (lower 8 bits).
#[inline]
pub const fn gf28_mul_poly(mut a: u8, mut b: u8, poly: u8) -> u8 {
    let mut p = 0;
    let mut i = 0;
    while i < 8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi_bit_set = a & 0x80 != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= poly;
        }
        b >>= 1;
        i += 1;
    }
    p
}

/// Standard AES GF(2^8) multiplication
#[inline]
pub const fn gf28_mul(a: u8, b: u8) -> u8 {
    gf28_mul_poly(a, b, 0x1B)
}

/// Computes the multiplicative inverse in GF(2^8) parameterized by an
/// irreducible polynomial.
pub const fn gf28_inv_poly(a: u8, poly: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    // a^254 = a^-1
    let mut res = 1;
    let mut i = 0;
    while i < 254 {
        res = gf28_mul_poly(res, a, poly);
        i += 1;
    }
    res
}

/// Computes the standard multiplicative inverse in GF(2^8).
pub const fn gf28_inv(a: u8) -> u8 {
    gf28_inv_poly(a, 0x1B)
}

/// Computes the inverse S-Box based on a provided S-Box.
pub const fn compute_inv_sbox(sbox: &[u8; 256]) -> [u8; 256] {
    let mut inv = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        inv[sbox[i] as usize] = i as u8;
        i += 1;
    }
    inv
}

/// Utility method to generate an AES S-Box with a custom affine constant and a
/// specific irreducible polynomial (provided as its lower 8 bits).
/// For the standard AES S-box, `affine_const` is `0x63` and `poly` is `0x1B`.
pub const fn generate_custom_sbox(affine_const: u8, poly: u8) -> [u8; 256] {
    let mut sbox = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        let inv = gf28_inv_poly(i as u8, poly);
        let mut out = 0;
        let mut j = 0;
        while j < 8 {
            let bit = (inv >> j) & 1;
            let bit4 = (inv >> ((j + 4) % 8)) & 1;
            let bit5 = (inv >> ((j + 5) % 8)) & 1;
            let bit6 = (inv >> ((j + 6) % 8)) & 1;
            let bit7 = (inv >> ((j + 7) % 8)) & 1;
            let c_bit = (affine_const >> j) & 1;
            let out_bit = bit ^ bit4 ^ bit5 ^ bit6 ^ bit7 ^ c_bit;
            out |= out_bit << j;
            j += 1;
        }
        sbox[i] = out;
        i += 1;
    }
    sbox
}

/// Utility method to generate the standard AES S-Box.
pub const fn generate_sbox() -> [u8; 256] {
    generate_custom_sbox(0x63, 0x1B)
}

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

#[inline]
fn add_round_key(state: &mut [u8; 16], w: &[u8], round: usize) {
    let offset = round * 16;
    unsafe {
        // SAFETY: The `encrypt_block_generic` / `decrypt_block_generic` loops pass a
        // round index that guarantees `offset + 16` is within the
        // pre-calculated size of the key schedule `w`.
        // By using `assert_unchecked`, we give the compiler hard boundaries to safely
        // eliminate bounds checks.
        assert_unchecked(w.len() >= offset + 16);

        // SAFETY: `state` is guaranteed to be a valid `&mut [u8; 16]`, which guarantees
        // 16 byte allocation. It is fully safe to cast a 16-byte array to a
        // `u128` pointer. The `w_ptr` is similarly validated by the above
        // unchecked assertion. `read_unaligned` and `write_unaligned` are used
        // so that we do not violate architectural alignment rules.
        let state_ptr = state.as_mut_ptr() as *mut u128;
        let w_ptr = w.as_ptr().add(offset) as *const u128;
        state_ptr.write_unaligned(state_ptr.read_unaligned() ^ w_ptr.read_unaligned());
    }
}

#[inline]
fn sub_bytes(state: &mut [u8; 16], sbox: &[u8; 256]) {
    for i in 0 .. 16 {
        unsafe {
            // SAFETY: The loop is bounded 0..16, so `i < 16` is always true.
            assert_unchecked(i < 16);
            let val = *state.get_unchecked(i);

            // SAFETY: `val` is a `u8`, which has a max value of 255. `sbox` is an array of
            // size 256. Casting `u8` to `usize` will always yield a number
            // within 0..=255.
            assert_unchecked((val as usize) < 256);
            *state.get_unchecked_mut(i) = *sbox.get_unchecked(val as usize);
        }
    }
}

#[inline]
fn shift_rows(s: &mut [u8; 16]) {
    let temp = *s;
    // Row 0 unchanged
    // Row 1
    s[1] = temp[5];
    s[5] = temp[9];
    s[9] = temp[13];
    s[13] = temp[1];
    // Row 2
    s[2] = temp[10];
    s[6] = temp[14];
    s[10] = temp[2];
    s[14] = temp[6];
    // Row 3
    s[3] = temp[15];
    s[7] = temp[3];
    s[11] = temp[7];
    s[15] = temp[11];
}

#[inline]
fn inv_shift_rows(s: &mut [u8; 16]) {
    let temp = *s;
    // Row 0 unchanged
    // Row 1
    s[1] = temp[13];
    s[5] = temp[1];
    s[9] = temp[5];
    s[13] = temp[9];
    // Row 2
    s[2] = temp[10];
    s[6] = temp[14];
    s[10] = temp[2];
    s[14] = temp[6];
    // Row 3
    s[3] = temp[7];
    s[7] = temp[11];
    s[11] = temp[15];
    s[15] = temp[3];
}

#[inline]
fn mix_columns(s: &mut [u8; 16]) {
    for c in 0 .. 4 {
        unsafe {
            let i = c * 4;
            // SAFETY: `c` runs from 0 to 3. The maximum value of `i` is 12.
            // Therefore, `i + 3 = 15`, which is `< 16`.
            // This guarantees all unchecked array accesses map directly into the fixed
            // 16-byte state.
            assert_unchecked(i + 3 < 16);

            let s0 = *s.get_unchecked(i);
            let s1 = *s.get_unchecked(i + 1);
            let s2 = *s.get_unchecked(i + 2);
            let s3 = *s.get_unchecked(i + 3);

            let t = s0 ^ s1 ^ s2 ^ s3;
            *s.get_unchecked_mut(i) = s0 ^ t ^ xtime(s0 ^ s1);
            *s.get_unchecked_mut(i + 1) = s1 ^ t ^ xtime(s1 ^ s2);
            *s.get_unchecked_mut(i + 2) = s2 ^ t ^ xtime(s2 ^ s3);
            *s.get_unchecked_mut(i + 3) = s3 ^ t ^ xtime(s3 ^ s0);
        }
    }
}

#[inline]
fn inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0 .. 4 {
        unsafe {
            let i = c * 4;
            // SAFETY: `c` runs from 0 to 3. The maximum value of `i` is 12.
            // Therefore, `i + 3 = 15`, which is `< 16`.
            assert_unchecked(i + 3 < 16);

            let s0 = *s.get_unchecked(i);
            let s1 = *s.get_unchecked(i + 1);
            let s2 = *s.get_unchecked(i + 2);
            let s3 = *s.get_unchecked(i + 3);

            *s.get_unchecked_mut(i) = gf28_mul(0x0E, s0) ^ gf28_mul(0x0B, s1) ^ gf28_mul(0x0D, s2) ^ gf28_mul(0x09, s3);
            *s.get_unchecked_mut(i + 1) =
                gf28_mul(0x09, s0) ^ gf28_mul(0x0E, s1) ^ gf28_mul(0x0B, s2) ^ gf28_mul(0x0D, s3);
            *s.get_unchecked_mut(i + 2) =
                gf28_mul(0x0D, s0) ^ gf28_mul(0x09, s1) ^ gf28_mul(0x0E, s2) ^ gf28_mul(0x0B, s3);
            *s.get_unchecked_mut(i + 3) =
                gf28_mul(0x0B, s0) ^ gf28_mul(0x0D, s1) ^ gf28_mul(0x09, s2) ^ gf28_mul(0x0E, s3);
        }
    }
}

unsafe fn expand_key_generic(key: &[u8], w: *mut u8, w_len: usize, sbox: &[u8; 256], nk: usize, rounds: usize) {
    unsafe {
        let words = (rounds + 1) * 4;

        // SAFETY: The caller passes the exact layout and sizes via the `impl_aes!`
        // macro instantiation. `w_len` is explicitly checked here against
        // `words * 4` to inform LLVM it will not OOB.
        assert_unchecked(w_len >= words * 4);
        assert_unchecked(key.len() >= nk * 4);

        // SAFETY: Both `key` and `w` buffers are guaranteed to hold `nk * 4` bytes.
        // Copying raw prevents loops from generating redundant bounds checks and
        // simplifies elision.
        ptr::copy_nonoverlapping(key.as_ptr(), w, nk * 4);

        let mut i = nk;
        while i < words {
            // SAFETY: The pointer math relies strictly on mathematical loops where
            // `i` steps from `nk` to `words - 1`. Because `prev_idx` is `(i - 1) * 4`,
            // and `w` has length `words * 4`, `prev_idx + 3 < words * 4`.
            let prev_idx = (i - 1) * 4;
            let mut temp = [
                *w.add(prev_idx),
                *w.add(prev_idx + 1),
                *w.add(prev_idx + 2),
                *w.add(prev_idx + 3),
            ];

            if i % nk == 0 {
                let t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;

                // SAFETY: `temp` holds `u8`, bounded naturally between 0-255.
                // The `sbox` array holds 256 entries. Therefore, `get_unchecked` is inherently
                // safe.
                temp[0] = *sbox.get_unchecked(temp[0] as usize);
                temp[1] = *sbox.get_unchecked(temp[1] as usize);
                temp[2] = *sbox.get_unchecked(temp[2] as usize);
                temp[3] = *sbox.get_unchecked(temp[3] as usize);

                // SAFETY: `RCON` is sized 10. `(i / nk) - 1` calculates exactly to the round
                // number minus 1. Max rounds configured are 14. For AES-256
                // (Nk=8), max i=60, (60/8)-1=6 < 10. Thus it always remains
                // within the 10 element boundary.
                assert_unchecked(((i / nk) - 1) < 10);
                temp[0] ^= *RCON.get_unchecked((i / nk) - 1);
            } else if nk > 6 && i % nk == 4 {
                temp[0] = *sbox.get_unchecked(temp[0] as usize);
                temp[1] = *sbox.get_unchecked(temp[1] as usize);
                temp[2] = *sbox.get_unchecked(temp[2] as usize);
                temp[3] = *sbox.get_unchecked(temp[3] as usize);
            }

            let nk_idx = (i - nk) * 4;
            let curr_idx = i * 4;
            *w.add(curr_idx) = *w.add(nk_idx) ^ temp[0];
            *w.add(curr_idx + 1) = *w.add(nk_idx + 1) ^ temp[1];
            *w.add(curr_idx + 2) = *w.add(nk_idx + 2) ^ temp[2];
            *w.add(curr_idx + 3) = *w.add(nk_idx + 3) ^ temp[3];

            i += 1;
        }
    }
}

#[inline]
fn encrypt_block_generic(block: &mut [u8; 16], w: &[u8], sbox: &[u8; 256], rounds: usize) {
    add_round_key(block, w, 0);
    for round in 1 .. rounds {
        sub_bytes(block, sbox);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, w, round);
    }
    sub_bytes(block, sbox);
    shift_rows(block);
    add_round_key(block, w, rounds);
}

#[inline]
fn decrypt_block_generic(block: &mut [u8; 16], w: &[u8], inv_sbox: &[u8; 256], rounds: usize) {
    add_round_key(block, w, rounds);
    for round in (1 .. rounds).rev() {
        inv_shift_rows(block);
        sub_bytes(block, inv_sbox);
        add_round_key(block, w, round);
        inv_mix_columns(block);
    }
    inv_shift_rows(block);
    sub_bytes(block, inv_sbox);
    add_round_key(block, w, 0);
}

macro_rules! impl_aes {
    ($name:ident, $key_len:expr, $rounds:expr, $round_keys_len:expr) => {
        #[derive(Clone, Copy)]
        pub struct $name {
            round_keys: [u8; $round_keys_len],
            sbox:       [u8; 256],
            inv_sbox:   [u8; 256],
        }

        impl $name {
            /// Initializes the AES variant using the standard AES S-Box.
            pub fn new(key: &[u8; $key_len]) -> Self {
                Self::new_with_sbox(key, &generate_sbox())
            }

            /// Initializes the AES variant using a fully custom provided S-Box.
            /// The inverse S-Box will be automatically calculated.
            pub fn new_with_sbox(key: &[u8; $key_len], sbox: &[u8; 256]) -> Self {
                // Skips expensive zero-initialization padding using `MaybeUninit`.
                // This mimics C/C++ memory allocation speed allowing LLVM to omit `memset`.
                let mut round_keys = core::mem::MaybeUninit::<[u8; $round_keys_len]>::uninit();

                unsafe {
                    // SAFETY: `expand_key_generic` expects a mutable pointer to the raw byte
                    // buffer. It operates purely on pointer arithmetic up to
                    // `$round_keys_len` bytes. We execute this immediately, populating
                    // the entirety of the uninitialized buffer.
                    expand_key_generic(
                        key,
                        round_keys.as_mut_ptr() as *mut u8,
                        $round_keys_len,
                        sbox,
                        $key_len / 4,
                        $rounds,
                    );

                    Self {
                        // SAFETY: Following the execution of `expand_key_generic`, `round_keys` is
                        // fully populated with mathematical cipher round keys. It is safe to `assume_init()`.
                        round_keys: round_keys.assume_init(),
                        sbox:       *sbox,
                        inv_sbox:   compute_inv_sbox(sbox),
                    }
                }
            }

            /// Encrypts a single 16-byte block in-place.
            pub fn encrypt_block(&self, block: &mut [u8; 16]) {
                encrypt_block_generic(block, &self.round_keys, &self.sbox, $rounds);
            }

            /// Decrypts a single 16-byte block in-place.
            pub fn decrypt_block(&self, block: &mut [u8; 16]) {
                decrypt_block_generic(block, &self.round_keys, &self.inv_sbox, $rounds);
            }
        }
    };
}

impl_aes!(Aes128, 16, 10, 176);
impl_aes!(Aes192, 24, 12, 208);
impl_aes!(Aes256, 32, 14, 240);

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that our generator successfully locates the 30 defined
    /// degree 8 irreducible polynomials over GF(2).
    #[test]
    fn test_find_irreducible_polynomials() {
        let polys = find_irreducible_polynomials();
        assert_eq!(polys.len(), 30);
        // Ensure standard AES polynomial 0x1B is correctly discovered in the
        // characteristic list.
        assert!(polys.contains(&0x1B));
    }

    /// Verifies that generating the substitution box constructs the
    /// mathematically proven standard AES S-Box.
    #[test]
    fn sbox_generation() {
        let sbox = generate_sbox();
        assert_eq!(sbox[0x00], 0x63);
        assert_eq!(sbox[0x01], 0x7C);
        assert_eq!(sbox[0x02], 0x77);
        assert_eq!(sbox[0x03], 0x7B);
        assert_eq!(sbox[0xFF], 0x16);
    }

    /// Verifies AES-128 encryption and decryption correctness using standard
    /// NIST Known Answer Tests (KAT)
    ///
    /// Source: FIPS-197 Appendix C.1.
    #[test]
    fn aes128_nist_vector() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ];
        let expected_ciphertext = [
            0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A,
        ];
        let plaintext_original = block;

        let aes = Aes128::new(&key);

        aes.encrypt_block(&mut block);
        assert_eq!(block, expected_ciphertext);

        aes.decrypt_block(&mut block);
        assert_eq!(block, plaintext_original);
    }

    /// Verifies AES-192 encryption and decryption correctness using standard
    /// NIST Known Answer Tests (KAT)
    ///
    /// Source: FIPS-197 Appendix C.2.
    #[test]
    fn aes192_nist_vector() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ];
        let expected_ciphertext = [
            0xDD, 0xA9, 0x7C, 0xA4, 0x86, 0x4C, 0xDF, 0xE0, 0x6E, 0xAF, 0x70, 0xA0, 0xEC, 0x0D, 0x71, 0x91,
        ];
        let plaintext_original = block;

        let aes = Aes192::new(&key);

        aes.encrypt_block(&mut block);
        assert_eq!(block, expected_ciphertext);

        aes.decrypt_block(&mut block);
        assert_eq!(block, plaintext_original);
    }

    /// Verifies AES-256 encryption and decryption correctness using standard
    /// NIST Known Answer Tests (KAT) Extracted directly from FIPS-197
    /// Appendix C.3.
    #[test]
    fn aes256_nist_vector() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ];
        let expected_ciphertext = [
            0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF, 0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89,
        ];
        let plaintext_original = block;

        let aes = Aes256::new(&key);

        aes.encrypt_block(&mut block);
        assert_eq!(block, expected_ciphertext);

        aes.decrypt_block(&mut block);
        assert_eq!(block, plaintext_original);
    }

    /// Verifies that supplying a mathematically valid but alternate irreducible
    /// polynomial from the characteristic set results in a completely
    /// different but fully reversible cipher behavior.
    #[test]
    fn custom_sbox_with_different_polynomial() {
        // Grab the 5th polynomial out of the 30 available characteristic polynomials
        let custom_poly = IRREDUCIBLE_POLYNOMIALS[4];

        let custom_sbox = generate_custom_sbox(0x63, custom_poly);
        let key = [0u8; 16];
        let aes = Aes128::new_with_sbox(&key, &custom_sbox);

        let mut block = [0x55; 16];
        let plaintext_original = block;

        aes.encrypt_block(&mut block);

        // Verify it actually changed and operated successfully with the injected
        // polynomials.
        assert_ne!(block, plaintext_original);

        aes.decrypt_block(&mut block);

        // Verify perfect reversibility under the non-standard affine system.
        assert_eq!(block, plaintext_original);
    }
}
