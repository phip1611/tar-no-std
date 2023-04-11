#!/usr/bin/env bash

cargo build --all-targets --verbose --features alloc
# use some random no_std target
rustup target add thumbv7em-none-eabihf
cargo build --verbose --target thumbv7em-none-eabihf --features alloc
cargo test --verbose --features alloc

cargo fmt -- --check
cargo +1.60.0 clippy --features alloc
cargo +1.60.0 doc --no-deps --document-private-items --features alloc
