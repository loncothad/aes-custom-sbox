# aes-sbox

[AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
implementation with support for custom S-Box.

This crate provides AES-128, AES-192, and AES-256.
All variants allow you to configure a custom S-Box
via the `new_with_sbox` methods.
It also provides utility methods for generating
the standard AES S-Box or custom affine variations
using any of the 30 irreducible polynomials of degree 8
over GF(2).

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
