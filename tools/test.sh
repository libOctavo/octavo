#!/bin/bash

pushd "$1"
travis-cargo test && \
  travis-cargo --only stable coveralls --no-sudo
popd
