//! AES-128, AES-192 and AES-256 with pluggable S-Boxes.
//!
//! This crate provides the three AES block ciphers and allows replacing the
//! substitution box (S-Box) with a custom one via the `new_with_sbox`
//! constructors. It also provides utilities to generate the standard AES
//! S-Box or affine variations of it over any of the 30 irreducible
//! polynomials of degree 8 over GF(2).
//!
//! Only the S-Box layer is customizable; the MixColumns step always uses the
//! AES polynomial `x^8 + x^4 + x^3 + x + 1`, so any bijective S-Box produces
//! a fully invertible cipher. Constructors validate bijectivity and reject
//! non-permutation S-Boxes with [`InvalidSbox`].
//!
//! Round keys are zeroed when a cipher is dropped, and the [`fmt::Debug`]
//! implementations never expose key material.
//!
//! # Examples
//!
//! Standard AES-128:
//!
//! ```
//! let key = [
//!     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
//!     0x0F,
//! ];
//! let mut block = [
//!     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
//!     0xFF,
//! ];
//!
//! let cipher = aes_custom_sbox::Aes128::new(&key);
//! cipher.encrypt_block(&mut block);
//! assert_eq!(block, [
//!     0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5,
//!     0x5A,
//! ]);
//! ```
//!
//! AES-128 with a custom S-Box generated from a different irreducible
//! polynomial:
//!
//! ```
//! use aes_custom_sbox::{
//!     Aes128,
//!     IRREDUCIBLE_POLYNOMIALS,
//!     generate_custom_sbox,
//! };
//!
//! let sbox = generate_custom_sbox(0x63, IRREDUCIBLE_POLYNOMIALS[1]);
//! let key = [0x00_u8; 16];
//! let mut block = [0x55_u8; 16];
//! let plaintext = block;
//!
//! let cipher =
//!     Aes128::new_with_sbox(&key, &sbox).expect("generated S-Boxes are valid permutations");
//! cipher.encrypt_block(&mut block);
//! cipher.decrypt_block(&mut block);
//! assert_eq!(block, plaintext);
//! ```

#![no_std]

#[cfg(test)]
extern crate std;

use core::{
    fmt,
    hint::assert_unchecked,
    ptr,
};

/// Computes the degree (index of the highest set bit) of a non-zero binary
/// polynomial.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "`value >> 1` halves the operand each iteration, so the loop runs at most 15 times over `u16` values \
              that cannot overflow"
)]
const fn poly_degree(value: u16) -> u16 {
    let mut degree = 0_u16;
    let mut rest = value >> 1;
    while rest != 0 {
        degree += 1;
        rest >>= 1;
    }
    degree
}

/// Computes the remainder of the polynomial division of `dividend` by
/// `divisor` over GF(2), where bit `i` of a value is the coefficient of
/// `x^i`.
///
/// If `divisor` is zero, `dividend` is returned unchanged.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "both operands are `u16` polynomials whose degrees are bounded by 15, so the shift amount never exceeds \
              the bit width"
)]
pub const fn poly_mod(mut dividend: u16, divisor: u16) -> u16 {
    if divisor == 0 {
        return dividend;
    }
    let divisor_degree = poly_degree(divisor);
    while dividend != 0 {
        let dividend_degree = poly_degree(dividend);
        if dividend_degree < divisor_degree {
            break;
        }
        dividend ^= divisor << (dividend_degree - divisor_degree);
    }
    dividend
}

/// Finds all 30 irreducible polynomials of degree 8 over GF(2).
///
/// The polynomials are represented by their lower 8 bits (the coefficient of
/// `x^8` is implicitly 1). The standard AES polynomial `x^8 + x^4 + x^3 + x
/// + 1` corresponds to `0x1B` in the result.
#[expect(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    reason = "`candidate` stays within 0x100..0x200 so its low byte always fits into `u8`, `count` cannot exceed 29 \
              because exactly 30 such polynomials exist, and every index is bounded by those two facts"
)]
pub const fn find_irreducible_polynomials() -> [u8; 30] {
    let mut polys = [0_u8; 30];
    let mut count = 0;
    let mut candidate = 0x100_u16;
    while candidate < 0x200 {
        let mut is_irreducible = true;
        // A degree 8 polynomial is irreducible iff it has no irreducible
        // factors of degree 1 to 4, so trial division up to degree 4 (values
        // below 32) is sufficient.
        let mut divisor = 2_u16;
        while divisor < 32 {
            if poly_mod(candidate, divisor) == 0 {
                is_irreducible = false;
                break;
            }
            divisor += 1;
        }
        if is_irreducible {
            polys[count] = candidate as u8;
            count += 1;
        }
        candidate += 1;
    }
    polys
}

/// The pre-calculated 30 irreducible polynomials of degree 8 over GF(2),
/// represented by their lower 8 bits.
pub const IRREDUCIBLE_POLYNOMIALS: [u8; 30] = find_irreducible_polynomials();

/// Returns `true` if `poly` (the lower 8 bits) forms one of the 30
/// irreducible polynomials of degree 8 over GF(2).
#[expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "`index` is bounded by the fixed length of `IRREDUCIBLE_POLYNOMIALS`"
)]
pub const fn is_irreducible_poly8(poly: u8) -> bool {
    let mut index = 0;
    while index < IRREDUCIBLE_POLYNOMIALS.len() {
        if IRREDUCIBLE_POLYNOMIALS[index] == poly {
            return true;
        }
        index += 1;
    }
    false
}

/// Multiply by `x` in GF(2^8) modulo `x^8 + x^4 + x^3 + x + 1`, the standard
/// AES polynomial (`0x11B`).
#[inline]
const fn xtime(value: u8) -> u8 {
    (value << 1)
        ^ if value & 0x80 != 0 {
            0x1B
        } else {
            0
        }
}

/// Multiplies two elements of GF(2^8) reduced modulo `poly`, the lower 8
/// bits of an irreducible degree-8 polynomial (see
/// [`IRREDUCIBLE_POLYNOMIALS`]).
#[expect(
    clippy::arithmetic_side_effects,
    reason = "the loop runs exactly 8 times over `u8` shift, XOR and increment operations which cannot overflow"
)]
pub const fn gf28_mul_poly(left: u8, right: u8, poly: u8) -> u8 {
    let mut product = 0;
    let mut multiplicand = left;
    let mut multiplier = right;
    let mut round = 0;
    while round < 8 {
        if multiplier & 1 != 0 {
            product ^= multiplicand;
        }
        let high_bit = multiplicand & 0x80 != 0;
        multiplicand <<= 1;
        if high_bit {
            multiplicand ^= poly;
        }
        multiplier >>= 1;
        round += 1;
    }
    product
}

/// Multiplies two elements of GF(2^8) modulo the standard AES polynomial
/// `x^8 + x^4 + x^3 + x + 1` (`0x11B`).
#[inline]
pub const fn gf28_mul(left: u8, right: u8) -> u8 {
    gf28_mul_poly(left, right, 0x1B)
}

/// Computes the multiplicative inverse in GF(2^8) reduced modulo `poly`, the
/// lower 8 bits of an irreducible degree-8 polynomial.
///
/// The inverse of `0` is defined as `0`. If `poly` is reducible the result is
/// unspecified.
pub const fn gf28_inv_poly(value: u8, poly: u8) -> u8 {
    if value == 0 {
        return 0;
    }
    // a^254 = a^-1 in GF(2^8), computed by square-and-multiply with the
    // binary representation 254 = 0b1111_1110 (13 multiplications).
    let mut power = value;
    power = gf28_mul_poly(power, power, poly); // a^2
    power = gf28_mul_poly(power, value, poly); // a^3
    power = gf28_mul_poly(power, power, poly); // a^6
    power = gf28_mul_poly(power, value, poly); // a^7
    power = gf28_mul_poly(power, power, poly); // a^14
    power = gf28_mul_poly(power, value, poly); // a^15
    power = gf28_mul_poly(power, power, poly); // a^30
    power = gf28_mul_poly(power, value, poly); // a^31
    power = gf28_mul_poly(power, power, poly); // a^62
    power = gf28_mul_poly(power, value, poly); // a^63
    power = gf28_mul_poly(power, power, poly); // a^126
    power = gf28_mul_poly(power, value, poly); // a^127
    power = gf28_mul_poly(power, power, poly); // a^254
    power
}

/// Computes the multiplicative inverse in GF(2^8) modulo the standard AES
/// polynomial `x^8 + x^4 + x^3 + x + 1` (`0x11B`).
pub const fn gf28_inv(value: u8) -> u8 {
    gf28_inv_poly(value, 0x1B)
}

/// Returns `true` if `sbox` is a permutation of all 256 byte values.
///
/// This is the requirement custom S-Boxes must fulfill for decryption to be
/// the inverse of encryption; see [`InvalidSbox`].
#[expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "`index` is bounded to 0..256 and S-Box entries are `u8` values, so every access stays within the fixed \
              array bounds"
)]
pub const fn is_valid_sbox(sbox: &[u8; 256]) -> bool {
    let mut seen = [false; 256];
    let mut index = 0;
    while index < 256 {
        let slot = sbox[index] as usize;
        if seen[slot] {
            return false;
        }
        seen[slot] = true;
        index += 1;
    }
    true
}

/// Computes the inverse S-Box of a bijective `sbox`.
///
/// If `sbox` is not a permutation of all 256 byte values the result is
/// unspecified; verify custom tables with [`is_valid_sbox`] first.
#[expect(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    reason = "`index` is bounded to 0..256 so the `u8` cast is lossless, and all accesses stay within the fixed array \
              bounds"
)]
pub const fn compute_inv_sbox(sbox: &[u8; 256]) -> [u8; 256] {
    let mut inverse = [0_u8; 256];
    let mut index = 0;
    while index < 256 {
        inverse[sbox[index] as usize] = index as u8;
        index += 1;
    }
    inverse
}

/// Generates an S-Box from the multiplicative inversion in GF(2^8) defined
/// by `poly` followed by the AES affine transformation with constant
/// `affine_const`.
///
/// `poly` must be the lower 8 bits of an irreducible degree-8 polynomial,
/// e.g. one of [`IRREDUCIBLE_POLYNOMIALS`]; for reducible polynomials the
/// result is not a permutation. For the standard AES S-Box use
/// [`generate_sbox`].
#[expect(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    reason = "`index` is bounded to 0..256 so the `u8` cast is lossless, and the S-Box accesses stay within the fixed \
              array bounds"
)]
pub const fn generate_custom_sbox(affine_const: u8, poly: u8) -> [u8; 256] {
    let mut sbox = [0_u8; 256];
    let mut index = 0;
    while index < 256 {
        let inverted = gf28_inv_poly(index as u8, poly);
        // Affine transformation: b ^ rot_l(b, 1) ^ rot_l(b, 2) ^ rot_l(b, 3) ^ rot_l(b,
        // 4) ^ c, where bit i of rot_l(b, k) is bit (i - k) mod 8 of b. This is
        // the standard formulation of b_i ^ b_(i+4) ^ b_(i+5) ^ b_(i+6) ^
        // b_(i+7) ^ c_i.
        sbox[index] = inverted
            ^ inverted.rotate_left(1)
            ^ inverted.rotate_left(2)
            ^ inverted.rotate_left(3)
            ^ inverted.rotate_left(4)
            ^ affine_const;
        index += 1;
    }
    sbox
}

/// Generates the standard AES S-Box (`0x63` affine constant over the field
/// defined by `0x11B`).
pub const fn generate_sbox() -> [u8; 256] {
    generate_custom_sbox(0x63, 0x1B)
}

/// The pre-calculated standard AES S-Box.
pub const STANDARD_SBOX: [u8; 256] = generate_sbox();

/// The pre-calculated inverse of the standard AES S-Box.
pub const STANDARD_INV_SBOX: [u8; 256] = compute_inv_sbox(&STANDARD_SBOX);

/// The error returned by `new_with_sbox` when the provided S-Box is not a
/// permutation of all 256 byte values.
///
/// A non-bijective S-Box makes `decrypt_block` unable to invert
/// `encrypt_block`, so such tables are rejected up front instead of failing
/// silently during decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSbox;

impl fmt::Display for InvalidSbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the provided S-Box is not a permutation: every byte value must occur exactly once")
    }
}

impl core::error::Error for InvalidSbox {}

/// Round constants for the key schedule (`Rcon[i - 1]` belongs to round `i`).
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

/// XORs the 16 bytes of the round key for `round` into `state` as a single
/// wide 128-bit operation.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "`round` is at most 14 for the supported key sizes, so `offset` stays far below the key schedule length"
)]
const fn add_round_key(state: &mut [u8; 16], round_keys: &[u8], round: usize) {
    let offset = round * 16;
    // SAFETY: the callers pass round indices bounded by the key schedule
    // size, so `offset + 16` is always within `round_keys`. The assertion
    // hands LLVM the bound it needs to eliminate the slice length check.
    unsafe {
        assert_unchecked(round_keys.len() >= offset + 16);
    }

    let state_ptr = state.as_mut_ptr();
    // SAFETY: `state` is a valid 16-byte array and `read_unaligned` permits
    // any alignment, so reading a `u128` through this pointer is sound.
    let state_word = unsafe { (state_ptr as *const u128).read_unaligned() };
    // SAFETY: the assertion above proves `round_keys` holds at least
    // `offset + 16` bytes, so the offset stays in bounds.
    let key_ptr = unsafe { round_keys.as_ptr().add(offset) };
    // SAFETY: `read_unaligned` permits any alignment.
    let key_word = unsafe { (key_ptr as *const u128).read_unaligned() };
    // SAFETY: same 16-byte validity as the read above; `write_unaligned`
    // permits any alignment.
    unsafe {
        (state_ptr as *mut u128).write_unaligned(state_word ^ key_word);
    }
}

/// Applies the S-Box to every byte of `state`.
#[expect(
    clippy::indexing_slicing,
    reason = "a `u8` widened to `usize` is always a valid index into the 256-entry S-Box array"
)]
fn sub_bytes(state: &mut [u8; 16], sbox: &[u8; 256]) {
    for byte in state.iter_mut() {
        *byte = sbox[usize::from(*byte)];
    }
}

/// Rotates rows 1, 2 and 3 of the column-major state matrix left by 1, 2 and
/// 3 positions respectively.
const fn shift_rows(state: &mut [u8; 16]) {
    let previous = *state;
    // Row 0 is unchanged.
    state[1] = previous[5];
    state[5] = previous[9];
    state[9] = previous[13];
    state[13] = previous[1];
    state[2] = previous[10];
    state[6] = previous[14];
    state[10] = previous[2];
    state[14] = previous[6];
    state[3] = previous[15];
    state[7] = previous[3];
    state[11] = previous[7];
    state[15] = previous[11];
}

/// Rotates rows 1, 2 and 3 of the column-major state matrix right by 1, 2
/// and 3 positions respectively.
const fn inv_shift_rows(state: &mut [u8; 16]) {
    let previous = *state;
    // Row 0 is unchanged.
    state[1] = previous[13];
    state[5] = previous[1];
    state[9] = previous[5];
    state[13] = previous[9];
    state[2] = previous[10];
    state[6] = previous[14];
    state[10] = previous[2];
    state[14] = previous[6];
    state[3] = previous[7];
    state[7] = previous[11];
    state[11] = previous[15];
    state[15] = previous[3];
}

/// Multiplies every column of `state` by the MDS matrix of `MixColumns`
/// (`{02, 03, 01, 01}` circulated over the AES polynomial).
#[expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "the loop bounds keep every index within 0..16 of the fixed 16-byte state"
)]
fn mix_columns(state: &mut [u8; 16]) {
    for column in 0 .. 4 {
        let index = column * 4;
        let (first_value, second_value, third_value, fourth_value) =
            (state[index], state[index + 1], state[index + 2], state[index + 3]);
        let total = first_value ^ second_value ^ third_value ^ fourth_value;
        state[index] = first_value ^ total ^ xtime(first_value ^ second_value);
        state[index + 1] = second_value ^ total ^ xtime(second_value ^ third_value);
        state[index + 2] = third_value ^ total ^ xtime(third_value ^ fourth_value);
        state[index + 3] = fourth_value ^ total ^ xtime(fourth_value ^ first_value);
    }
}

/// Multiplies every column of `state` by the MDS matrix of `InvMixColumns`
/// (`{0e, 0b, 0d, 09}` circulated over the AES polynomial).
#[expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "the loop bounds keep every index within 0..16 of the fixed 16-byte state"
)]
fn inv_mix_columns(state: &mut [u8; 16]) {
    for column in 0 .. 4 {
        let index = column * 4;
        let (first_value, second_value, third_value, fourth_value) =
            (state[index], state[index + 1], state[index + 2], state[index + 3]);
        state[index] = gf28_mul(0x0E, first_value)
            ^ gf28_mul(0x0B, second_value)
            ^ gf28_mul(0x0D, third_value)
            ^ gf28_mul(0x09, fourth_value);
        state[index + 1] = gf28_mul(0x09, first_value)
            ^ gf28_mul(0x0E, second_value)
            ^ gf28_mul(0x0B, third_value)
            ^ gf28_mul(0x0D, fourth_value);
        state[index + 2] = gf28_mul(0x0D, first_value)
            ^ gf28_mul(0x09, second_value)
            ^ gf28_mul(0x0E, third_value)
            ^ gf28_mul(0x0B, fourth_value);
        state[index + 3] = gf28_mul(0x0B, first_value)
            ^ gf28_mul(0x0D, second_value)
            ^ gf28_mul(0x09, third_value)
            ^ gf28_mul(0x0E, fourth_value);
    }
}

/// Expands `key_bytes` into the `4 * (rounds + 1)` round key words stored in
/// `round_keys`, applying `sbox` for SubWord during the schedule.
///
/// The caller must pass `round_keys` with exactly `4 * (rounds + 1)` bytes
/// and `key_bytes` with exactly `4 * key_words` bytes, which the `impl_aes!`
/// instantiations guarantee by construction.
#[expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "the `impl_aes!` callers pass buffers sized exactly for the schedule, so every computed index stays in \
              bounds; `RCON` is indexed by at most 9 for the largest supported key size"
)]
fn expand_key_generic(key_bytes: &[u8], round_keys: &mut [u8], sbox: &[u8; 256], key_words: usize, rounds: usize) {
    let words = (rounds + 1) * 4;
    let key_len = key_words * 4;
    round_keys[.. key_len].copy_from_slice(&key_bytes[.. key_len]);

    // `position` tracks `word_idx % key_words` incrementally, avoiding the
    // modulo operator on the hot path.
    let mut position = 0;
    let mut word_idx = key_words;
    while word_idx < words {
        let previous = (word_idx - 1) * 4;
        let mut temp = [
            round_keys[previous],
            round_keys[previous + 1],
            round_keys[previous + 2],
            round_keys[previous + 3],
        ];

        if position == 0 {
            // RotWord, SubWord and the round constant.
            temp.rotate_left(1);
            for temp_byte in &mut temp {
                *temp_byte = sbox[usize::from(*temp_byte)];
            }
            temp[0] ^= RCON[(word_idx / key_words) - 1];
        } else if key_words > 6 && position == 4 {
            // SubWord for AES-256 key schedules.
            for temp_byte in &mut temp {
                *temp_byte = sbox[usize::from(*temp_byte)];
            }
        } else {
            // Regular round: `temp` is used unmodified.
        }

        let older = (word_idx - key_words) * 4;
        let current = word_idx * 4;
        for (byte_idx, temp_byte) in temp.iter().enumerate() {
            round_keys[current + byte_idx] = round_keys[older + byte_idx] ^ temp_byte;
        }

        position += 1;
        if position == key_words {
            position = 0;
        }
        word_idx += 1;
    }
}

/// Encrypts a single block in place with the standard AES round sequence,
/// applying `sbox` for SubBytes.
fn encrypt_block_generic(block: &mut [u8; 16], round_keys: &[u8], sbox: &[u8; 256], rounds: usize) {
    add_round_key(block, round_keys, 0);
    for round in 1 .. rounds {
        sub_bytes(block, sbox);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, round_keys, round);
    }
    sub_bytes(block, sbox);
    shift_rows(block);
    add_round_key(block, round_keys, rounds);
}

/// Decrypts a single block in place with the standard AES inverse round
/// sequence, applying `inv_sbox` for InvSubBytes.
fn decrypt_block_generic(block: &mut [u8; 16], round_keys: &[u8], inv_sbox: &[u8; 256], rounds: usize) {
    add_round_key(block, round_keys, rounds);
    for round in (1 .. rounds).rev() {
        inv_shift_rows(block);
        sub_bytes(block, inv_sbox);
        add_round_key(block, round_keys, round);
        inv_mix_columns(block);
    }
    inv_shift_rows(block);
    sub_bytes(block, inv_sbox);
    add_round_key(block, round_keys, 0);
}

macro_rules! impl_aes {
    ($name:ident, $key_len:literal, $rounds:literal, $round_keys_len:literal) => {
        #[doc = concat!(
                            "AES-", $key_len, " with a configurable S-Box.\n\n",
                            "The S-Box is applied for SubBytes in both the block cipher rounds and the key ",
                            "schedule; MixColumns always uses the AES polynomial. See the ",
                            "[crate documentation](crate) for details."
                        )]
        #[derive(Clone)]
        pub struct $name {
            round_keys: [u8; $round_keys_len],
            sbox:       [u8; 256],
            inv_sbox:   [u8; 256],
        }

        impl $name {
            /// Creates a cipher for `key_bytes` using the standard AES S-Box.
            pub fn new(key_bytes: &[u8; $key_len]) -> Self {
                let mut round_keys = [0_u8; $round_keys_len];
                expand_key_generic(key_bytes, &mut round_keys, &STANDARD_SBOX, $key_len / 4, $rounds);
                Self {
                    round_keys,
                    sbox: STANDARD_SBOX,
                    inv_sbox: STANDARD_INV_SBOX,
                }
            }

            /// Creates a cipher for `key_bytes` using a fully custom S-Box.
            /// The inverse S-Box is computed automatically.
            ///
            /// # Errors
            ///
            /// Returns [`InvalidSbox`] if `sbox` is not a permutation of all
            /// 256 byte values, because decryption could not invert
            /// encryption with such a table.
            pub fn new_with_sbox(key_bytes: &[u8; $key_len], sbox: &[u8; 256]) -> Result<Self, InvalidSbox> {
                if !is_valid_sbox(sbox) {
                    return Err(InvalidSbox);
                }
                let mut round_keys = [0_u8; $round_keys_len];
                expand_key_generic(key_bytes, &mut round_keys, sbox, $key_len / 4, $rounds);
                Ok(Self {
                    round_keys,
                    sbox: *sbox,
                    inv_sbox: compute_inv_sbox(sbox),
                })
            }

            /// Encrypts a single 16-byte block in place.
            pub fn encrypt_block(&self, block: &mut [u8; 16]) {
                encrypt_block_generic(block, &self.round_keys, &self.sbox, $rounds);
            }

            /// Decrypts a single 16-byte block in place.
            pub fn decrypt_block(&self, block: &mut [u8; 16]) {
                decrypt_block_generic(block, &self.round_keys, &self.inv_sbox, $rounds);
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Key material is deliberately never exposed.
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                // Best-effort scrubbing of the expanded key material. The
                // volatile stores cannot be elided by the optimizer.
                for byte in self.round_keys.iter_mut() {
                    // SAFETY: `byte` is a valid `&mut u8` derived from
                    // `self.round_keys`, so the pointer is writable and
                    // aligned.
                    unsafe { ptr::write_volatile(ptr::from_mut(byte), 0) };
                }
            }
        }
    };
}

impl_aes!(Aes128, 16, 10, 176);
impl_aes!(Aes192, 24, 12, 208);
impl_aes!(Aes256, 32, 14, 240);

#[cfg(test)]
mod tests {
    #![expect(
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        clippy::min_ident_chars,
        clippy::unwrap_used,
        reason = "tests use PRNG arithmetic, bounded indexing and unwrapping on purpose; identifiers such as `key` \
                  keep their natural names"
    )]

    use std::format;

    use super::*;

    /// Verifies that our generator locates exactly the 30 known irreducible
    /// degree-8 polynomials over GF(2).
    #[test]
    fn find_irreducible_polynomials_matches_known_table() {
        let expected = [
            0x1B, 0x1D, 0x2B, 0x2D, 0x39, 0x3F, 0x4D, 0x5F, 0x63, 0x65, 0x69, 0x71, 0x77, 0x7B, 0x87, 0x8B, 0x8D, 0x9F,
            0xA3, 0xA9, 0xB1, 0xBD, 0xC3, 0xCF, 0xD7, 0xDD, 0xE7, 0xF3, 0xF5, 0xF9,
        ];
        assert_eq!(find_irreducible_polynomials(), expected);
        assert!(is_irreducible_poly8(0x1B));
        assert!(!is_irreducible_poly8(0x1A));
    }

    /// Verifies the generated S-Box against entries of the standard AES
    /// S-Box table.
    #[test]
    fn sbox_generation_matches_known_table() {
        let sbox = generate_sbox();
        assert_eq!(&sbox[.. 16], &[
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76
        ]);
        assert_eq!(&sbox[240 ..], &[
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        ]);
        assert_eq!(sbox, STANDARD_SBOX);
        assert!(is_valid_sbox(&sbox));
    }

    /// Verifies the inverse S-Box table and the roundtrip property
    /// `sbox[inv[i]] == i` for every byte value.
    #[test]
    fn inverse_sbox_matches_known_table() {
        let inv_sbox = compute_inv_sbox(&generate_sbox());
        assert_eq!(&inv_sbox[.. 16], &[
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB
        ]);
        assert_eq!(inv_sbox, STANDARD_INV_SBOX);

        let sbox = generate_sbox();
        for (input, substituted) in sbox.iter().enumerate() {
            assert_eq!(sbox[usize::from(inv_sbox[usize::from(*substituted)])], *substituted);
            assert_eq!(inv_sbox[usize::from(sbox[input])], input as u8);
        }
    }

    /// Verifies the GF(2^8) field axioms for the standard AES polynomial.
    #[test]
    fn gf28_field_axioms_hold() {
        for left in 0 ..= u8::MAX {
            assert_eq!(gf28_mul(left, 0), 0);
            assert_eq!(gf28_mul(left, 1), left);
            assert_eq!(xtime(left), gf28_mul(left, 2));
            for right in [1_u8, 0x53, 0x80, 0xF0, 0xFF] {
                assert_eq!(gf28_mul(left, right), gf28_mul(right, left));
                assert_eq!(
                    gf28_mul(left, gf28_mul(right, 0x07)),
                    gf28_mul(gf28_mul(left, right), 0x07)
                );
                assert_eq!(
                    gf28_mul(left, right ^ 0x39),
                    gf28_mul(left, right) ^ gf28_mul(left, 0x39),
                    "distributivity failed for {left:#04X}"
                );
            }
            if left != 0 {
                assert_eq!(gf28_mul(left, gf28_inv(left)), 1, "inverse failed for {left:#04X}");
            }
        }
        // Known values.
        assert_eq!(gf28_inv(1), 1);
        assert_eq!(gf28_inv(3), 0xF6);
        assert_eq!(gf28_mul(0x57, 0x83), 0xC1);
    }

    /// Verifies that all 30 irreducible polynomials define fields in which
    /// every non-zero element has a multiplicative inverse.
    #[test]
    fn gf28_inverse_works_for_all_irreducible_polynomials() {
        for &poly in &IRREDUCIBLE_POLYNOMIALS {
            for value in 1 ..= u8::MAX {
                let inverse = gf28_inv_poly(value, poly);
                assert_eq!(
                    gf28_mul_poly(value, inverse, poly),
                    1,
                    "poly {poly:#04X} failed for {value:#04X}"
                );
            }
        }
    }

    /// Verifies that S-Boxes generated from irreducible polynomials are
    /// always permutations, for a spread of affine constants.
    #[test]
    fn generated_sboxes_are_permutations() {
        for &poly in &IRREDUCIBLE_POLYNOMIALS {
            for affine_const in [0x00_u8, 0x63, 0xA5, 0xFF] {
                let sbox = generate_custom_sbox(affine_const, poly);
                assert!(
                    is_valid_sbox(&sbox),
                    "poly {poly:#04X} affine {affine_const:#04X} not a permutation"
                );
                let inv_sbox = compute_inv_sbox(&sbox);
                for (input, substituted) in sbox.iter().enumerate() {
                    assert_eq!(inv_sbox[usize::from(*substituted)], input as u8);
                }
            }
        }
    }

    /// Verifies the key schedule against FIPS-197 Appendix A expansion
    /// examples.
    #[test]
    fn key_expansion_matches_fips197_appendix_a() {
        let cipher128 = Aes128::new(&[
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
        ]);
        assert_eq!(&cipher128.round_keys[16 .. 32], &[
            0xA0, 0xFA, 0xFE, 0x17, 0x88, 0x54, 0x2C, 0xB1, 0x23, 0xA3, 0x39, 0x39, 0x2A, 0x6C, 0x76, 0x05
        ]);

        let cipher256 = Aes256::new(&[
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81, 0x1F, 0x35,
            0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4,
        ]);
        assert_eq!(&cipher256.round_keys[32 .. 48], &[
            0x9B, 0xA3, 0x54, 0x11, 0x8E, 0x69, 0x25, 0xAF, 0xA5, 0x1A, 0x8B, 0x5F, 0x20, 0x67, 0xFC, 0xDE
        ]);
    }

    /// Verifies AES-128 against the FIPS-197 Appendix C.1 known answer test.
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

    /// Verifies AES-192 against the FIPS-197 Appendix C.2 known answer test.
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

    /// Verifies AES-256 against the FIPS-197 Appendix C.3 known answer test.
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

    /// Verifies the all-zero key and plaintext known answers for every key
    /// size (cross-checked against OpenSSL).
    #[test]
    fn all_zero_vectors() {
        let mut block = [0_u8; 16];
        Aes128::new(&[0_u8; 16]).encrypt_block(&mut block);
        assert_eq!(block, [
            0x66, 0xE9, 0x4B, 0xD4, 0xEF, 0x8A, 0x2C, 0x3B, 0x88, 0x4C, 0xFA, 0x59, 0xCA, 0x34, 0x2B, 0x2E
        ]);
        block = [0_u8; 16];
        Aes192::new(&[0_u8; 24]).encrypt_block(&mut block);
        assert_eq!(block, [
            0xAA, 0xE0, 0x69, 0x92, 0xAC, 0xBF, 0x52, 0xA3, 0xE8, 0xF4, 0xA9, 0x6E, 0xC9, 0x30, 0x0B, 0xD7
        ]);
        block = [0_u8; 16];
        Aes256::new(&[0_u8; 32]).encrypt_block(&mut block);
        assert_eq!(block, [
            0xDC, 0x95, 0xC0, 0x78, 0xA2, 0x40, 0x89, 0x89, 0xAD, 0x48, 0xA2, 0x14, 0x92, 0x84, 0x20, 0x87
        ]);
    }

    /// Verifies custom S-Box encryption against vectors produced by an
    /// independent reference implementation (identity S-Box, alternate
    /// affine constants and alternate polynomials).
    #[test]
    fn custom_sbox_golden_vectors() {
        let key128 = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let key192 = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let key256 = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ];
        let identity_sbox: [u8; 256] = core::array::from_fn(|index| index as u8);
        let poly_11d = generate_custom_sbox(0x63, 0x1D);
        let affine_zero = generate_custom_sbox(0x00, 0x1B);

        let cases: [(usize, &[u8; 256], [u8; 16]); 7] = [
            (16, &identity_sbox, [
                0x01, 0x6D, 0xC0, 0x16, 0x37, 0xD8, 0xB2, 0x84, 0x47, 0xAC, 0x50, 0xC5, 0x3C, 0x20, 0x3F, 0x6D,
            ]),
            (24, &identity_sbox, [
                0x7A, 0x4A, 0xDB, 0xDD, 0xCC, 0x22, 0x5D, 0x41, 0x63, 0x87, 0x61, 0xB5, 0xA0, 0xCA, 0xEF, 0x41,
            ]),
            (32, &identity_sbox, [
                0x56, 0xA3, 0x79, 0xF8, 0x5E, 0xBD, 0x78, 0xC7, 0xFC, 0x0C, 0xDB, 0x47, 0xE3, 0x00, 0xCD, 0x65,
            ]),
            (16, &poly_11d, [
                0x6B, 0x88, 0x4D, 0xE5, 0x38, 0xC4, 0x7C, 0x39, 0x05, 0x3B, 0xBA, 0xE9, 0x18, 0xA3, 0x6E, 0x3A,
            ]),
            (24, &poly_11d, [
                0x7B, 0x82, 0x6E, 0xE8, 0xAB, 0x78, 0xB4, 0x40, 0x44, 0xCF, 0x7F, 0xF9, 0xE3, 0x73, 0xB9, 0x98,
            ]),
            (32, &poly_11d, [
                0x5D, 0xF6, 0x6F, 0xD9, 0xB2, 0xC4, 0x6C, 0x56, 0xC8, 0x6C, 0x65, 0xB7, 0x9D, 0xA8, 0x23, 0x4C,
            ]),
            (16, &affine_zero, [
                0x59, 0x95, 0x8E, 0xEC, 0xA9, 0x7F, 0x58, 0xC9, 0x32, 0x4E, 0x9C, 0xEC, 0xAF, 0x57, 0x0F, 0x8A,
            ]),
        ];

        for (key_len, sbox, expected) in cases {
            let mut block = plaintext;
            match key_len {
                | 16 => Aes128::new_with_sbox(&key128, sbox).unwrap().encrypt_block(&mut block),
                | 24 => Aes192::new_with_sbox(&key192, sbox).unwrap().encrypt_block(&mut block),
                | _ => Aes256::new_with_sbox(&key256, sbox).unwrap().encrypt_block(&mut block),
            }
            assert_eq!(block, expected, "case failed for key length {key_len}");
        }
    }

    /// Verifies roundtrip encryption for every key size with custom S-Boxes
    /// derived from every supported irreducible polynomial.
    #[test]
    fn custom_sbox_roundtrip_all_polynomials() {
        let key128 = [0x42_u8; 16];
        let key192 = [0x42_u8; 24];
        let key256 = [0x42_u8; 32];
        let plaintext = [0x55_u8; 16];
        for &poly in &IRREDUCIBLE_POLYNOMIALS {
            let sbox = generate_custom_sbox(0x63, poly);

            let mut block128 = plaintext;
            let aes128 = Aes128::new_with_sbox(&key128, &sbox).unwrap();
            aes128.encrypt_block(&mut block128);
            assert_ne!(block128, plaintext);
            aes128.decrypt_block(&mut block128);
            assert_eq!(block128, plaintext);

            let mut block192 = plaintext;
            let aes192 = Aes192::new_with_sbox(&key192, &sbox).unwrap();
            aes192.encrypt_block(&mut block192);
            aes192.decrypt_block(&mut block192);
            assert_eq!(block192, plaintext);

            let mut block256 = plaintext;
            let aes256 = Aes256::new_with_sbox(&key256, &sbox).unwrap();
            aes256.encrypt_block(&mut block256);
            aes256.decrypt_block(&mut block256);
            assert_eq!(block256, plaintext);
        }
    }

    /// Verifies that non-permutation S-Boxes are rejected while swapped
    /// (still bijective) tables are accepted.
    #[test]
    fn invalid_sboxes_are_rejected() {
        let key = [0_u8; 16];

        let zeros_sbox = [0_u8; 256];
        assert!(!is_valid_sbox(&zeros_sbox));
        assert_eq!(Aes128::new_with_sbox(&key, &zeros_sbox).err(), Some(InvalidSbox));

        let mut duplicates = generate_sbox();
        duplicates[0] = duplicates[1];
        assert!(!is_valid_sbox(&duplicates));
        assert_eq!(Aes192::new_with_sbox(&[0_u8; 24], &duplicates).err(), Some(InvalidSbox));

        let mut swapped = generate_sbox();
        swapped.swap(0, 1);
        assert!(is_valid_sbox(&swapped));
        Aes128::new_with_sbox(&key, &swapped).unwrap();
        Aes256::new_with_sbox(&[0_u8; 32], &identity_sbox()).unwrap();
    }

    /// Verifies the `InvalidSbox` error rendering and trait implementation.
    #[test]
    fn invalid_sbox_error_display() {
        let error = InvalidSbox;
        assert!(!format!("{error}").is_empty());
        let _: &dyn core::error::Error = &error;
        assert_eq!(format!("{error:?}"), "InvalidSbox");
    }

    /// Verifies that `Debug` never leaks key material.
    #[test]
    fn debug_impl_is_redacted() {
        let key = [
            0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        ];
        let aes = Aes128::new(&key);
        let rendered = format!("{aes:?}");
        assert_eq!(rendered, "Aes128 { .. }");
        assert!(!rendered.contains("AB"));
    }

    /// Verifies that encryption is deterministic across instances and that a
    /// single flipped plaintext bit diffuses into roughly half of the
    /// ciphertext bits.
    #[test]
    fn avalanche_and_determinism() {
        let key = [0x33_u8; 16];
        let plaintext = [0x55_u8; 16];

        let mut first = plaintext;
        let mut second = plaintext;
        Aes128::new(&key).encrypt_block(&mut first);
        Aes128::new(&key).encrypt_block(&mut second);
        assert_eq!(first, second);

        let mut flipped = plaintext;
        flipped[7] ^= 0x01;
        Aes128::new(&key).encrypt_block(&mut flipped);
        let changed_bits = first
            .iter()
            .zip(flipped.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum::<u32>();
        assert!(
            (32 ..= 96).contains(&changed_bits),
            "avalanche out of the expected range: {changed_bits} bits changed"
        );
    }

    /// Deterministic PRNG for the randomized stress tests.
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut mixed = self.0;
            mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            mixed ^ (mixed >> 31)
        }

        fn byte(&mut self) -> u8 {
            self.next() as u8
        }

        fn bytes<const SIZE: usize>(&mut self) -> [u8; SIZE] {
            let mut buffer = [0_u8; SIZE];
            for slot in &mut buffer {
                *slot = self.byte();
            }
            buffer
        }

        /// Derives a permutation of all 256 byte values via Fisher-Yates.
        fn sbox(&mut self) -> [u8; 256] {
            let mut sbox = core::array::from_fn(|index| index as u8);
            for index in (1 .. 256).rev() {
                let other = (self.next() % (index as u64 + 1)) as usize;
                sbox.swap(index, other);
            }
            sbox
        }
    }

    /// The identity S-Box, a trivially valid custom table.
    fn identity_sbox() -> [u8; 256] {
        core::array::from_fn(|index| index as u8)
    }

    /// Randomized roundtrip testing across all key sizes and random
    /// permutation S-Boxes. Iterations increase in release builds.
    #[test]
    fn randomized_roundtrip_stress() {
        let mut rng = SplitMix64(0xDEAD_BEEF_CAFE_BABE);
        let iterations = if cfg!(debug_assertions) {
            300
        } else {
            20_000
        };
        for _ in 0 .. iterations {
            let sbox = rng.sbox();
            assert!(is_valid_sbox(&sbox));

            let inv_sbox = compute_inv_sbox(&sbox);
            for (input, substituted) in sbox.iter().enumerate() {
                assert_eq!(inv_sbox[usize::from(*substituted)], input as u8);
            }

            let mut block128 = rng.bytes::<16>();
            let plaintext128 = block128;
            let aes128 = Aes128::new_with_sbox(&rng.bytes::<16>(), &sbox).unwrap();
            aes128.encrypt_block(&mut block128);
            aes128.decrypt_block(&mut block128);
            assert_eq!(block128, plaintext128);

            let mut block192 = rng.bytes::<16>();
            let plaintext192 = block192;
            let aes192 = Aes192::new_with_sbox(&rng.bytes::<24>(), &sbox).unwrap();
            aes192.encrypt_block(&mut block192);
            aes192.decrypt_block(&mut block192);
            assert_eq!(block192, plaintext192);

            let mut block256 = rng.bytes::<16>();
            let plaintext256 = block256;
            let aes256 = Aes256::new_with_sbox(&rng.bytes::<32>(), &sbox).unwrap();
            aes256.encrypt_block(&mut block256);
            aes256.decrypt_block(&mut block256);
            assert_eq!(block256, plaintext256);
        }
    }
}
