#!/bin/sh

set -e

MODULES="crypto digest kdf mac"

for crate in $MODULES
do
  travis-cargo test -- --manifest-path "$crate/Cargo.toml" && \
  travis-cargo --only stable coveralls --no-sudo --manifest-path "$crate/Cargo.toml"
done
