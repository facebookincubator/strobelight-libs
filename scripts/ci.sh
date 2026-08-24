#!/bin/sh
# Copyright (c) Meta Platforms, Inc. and affiliates.

sudo apt-get install -y linux-tools-common libelf-dev linux-libc-dev \
    clang libbpf-dev make pkg-config libfmt-dev libre2-dev libcap-dev \
    --no-install-recommends

if ! git submodule update --init --recursive
then
  echo "submodule update failed"
  exit 1
fi

if ! make -C strobelight/bpf_lib/python
then
  echo "library build failed"
  exit 1
fi

if ! make INSTALL_DIR="$(pwd)/foo" -C strobelight/bpf_lib/python install
then
  echo "library install failed"
  exit 1
fi

if ! find foo/pystacks.bpf.o || ! find foo/libpystacks.a
then
  echo "install did not place files where expected"
  exit 1
fi


if ! make -C strobelight/bpf_lib/samples/pystacks/
then
  echo "sample build failed"
  exit 1
fi

if [ "`strobelight/bpf_lib/samples/pystacks/.output/pystacks_sample`" != "Usage: strobelight/bpf_lib/samples/pystacks/.output/pystacks_sample <PID>" ]
then
  echo "sample run failed"
  exit 1
fi
