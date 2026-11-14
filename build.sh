#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

# Runs the same checks as the CI. Keep in sync with .github/workflows/.

set -euo pipefail

# Build and test
cargo build --all-targets --verbose --features alloc
# use some arbitrary no_std target
rustup target add thumbv7em-none-eabihf
cargo build --verbose --target thumbv7em-none-eabihf --features alloc
cargo test --verbose --features alloc

# Style checks
cargo fmt --all -- --check
cargo clippy --features alloc --all-targets
cargo doc --no-deps --document-private-items --features alloc
typos .

# Miri
rustup +nightly component add miri
cargo +nightly miri test --tests

# Fuzzing (requires cargo-fuzz)
cargo +nightly fuzz build
mkdir -p fuzz/corpus/parse_archive
cargo +nightly fuzz run parse_archive fuzz/corpus/parse_archive tests -- -max_total_time=30
cargo +nightly fuzz run parse_valid_archive -- -max_total_time=30
