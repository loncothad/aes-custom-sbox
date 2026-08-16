# aes-custom-sbox

[AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
implementation with support for custom S-Box.

This crate provides AES-128, AES-192, and AES-256.
All variants allow you to configure a custom S-Box
via the `new_with_sbox` methods.
It also provides utility methods for generating
the standard AES S-Box or custom affine variations
using any of the 30 irreducible polynomials of degree 8
over GF(2).

Custom S-Boxes must be permutations of all 256 byte
values; otherwise decryption could not invert encryption.
`new_with_sbox` validates this and rejects invalid
tables with [`InvalidSbox`], and `is_valid_sbox` can be
used to check a table up front.

Round keys are zeroed on drop and the `Debug`
implementations never expose key material.

## Example

```rust
use aes_custom_sbox::{generate_custom_sbox, Aes128, IRREDUCIBLE_POLYNOMIALS};

let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
let mut block = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

// Standard AES-128:
let cipher = aes_custom_sbox::Aes128::new(&key);
cipher.encrypt_block(&mut block);

// AES-128 with a custom S-Box (poly 0x11D, standard affine constant):
let sbox = generate_custom_sbox(0x63, IRREDUCIBLE_POLYNOMIALS[1]);
let cipher = Aes128::new_with_sbox(&key, &sbox)
    .expect("generated S-Boxes are valid permutations");
cipher.decrypt_block(&mut block);
```

## Testing and fuzzing

The crate is tested against NIST known-answer vectors
(FIPS-197 Appendices A and C, SP 800-38A ECB), zero
key/plaintext vectors cross-checked against OpenSSL, and
a differential test suite against the RustCrypto `aes`
crate.

Coverage-guided fuzz targets live in `fuzz/` and cover
encrypt/decrypt roundtrips for all key sizes, arbitrary
permutation S-Boxes, differential testing against
RustCrypto, GF(2^8) field axioms and S-Box generation.
Run them with:

```sh
cargo +nightly fuzz run <target>
```

## License

This project is licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) of
  <http://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
