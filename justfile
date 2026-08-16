fmt:
    taplo fmt
    cargo +nightly fmt

check:
    cargo +nightly check

test:
    cargo +nightly test
    cargo +nightly test --release

clippy:
    cargo +nightly clippy --all-targets -- -D warnings

fuzz:
    cargo +nightly fuzz build
