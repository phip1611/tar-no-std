#!/usr/bin/bash

cargo build --all-targets --verbose --features all
# use some random no_std target
rustup target add thumbv7em-none-eabihf
cargo build --verbose --target thumbv7em-none-eabihf --features all
cargo test --verbose --features all

cargo fmt -- --check
cargo clippy --features all
cargo doc --features all
