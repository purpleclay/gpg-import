# Pinned by digest, which also pins the nightly Rust and cargo-fuzz it ships
FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:3428d0a90b1e7efbe2ba947bd1d0c9a70594986b4b6553804547f1fb24cfc92f
COPY . $SRC/gpg-import
WORKDIR $SRC/gpg-import
COPY .clusterfuzzlite/build.sh $SRC/
