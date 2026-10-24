#!/bin/bash -eu
# Builds every target in fuzz/fuzz_targets and copies it to $OUT, with the
# seed corpus and dictionary named the way ClusterFuzzLite looks for them

cd "$SRC/gpg-import"

# The builder image pins an older nightly (nightly-2025-09-05) than the
# crate's rust-version allows. Use the nightly `nix develop .#fuzz` provides,
# from the locked rust-overlay, and update both together
export RUSTUP_TOOLCHAIN=nightly-2026-08-02
rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal

# Debug assertions turn integer overflow and debug_assert! into panics the
# fuzzer can find
cargo fuzz build -O --debug-assertions

for target in fuzz/fuzz_targets/*.rs; do
  name=$(basename "${target%.rs}")
  cp "fuzz/target/x86_64-unknown-linux-gnu/release/$name" "$OUT/"
done

zip -jq "$OUT/colon_records_seed_corpus.zip" fuzz/seeds/colon_records/*
zip -jq "$OUT/key_input_seed_corpus.zip" tests/testdata/*
cp fuzz/colon_records.dict "$OUT/"
