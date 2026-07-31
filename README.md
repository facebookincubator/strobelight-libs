# strobelight-libs

> [!CAUTION]
> This set of libraries is currently experimental. APIs are subject to change.\
Libraries are for use in applications leveraging libbpf.

## Requirements
BPF application leveraging libbpf.
The development versions of following libraries are needed on the system:
* libelf
* fmt
* re2
* libcap

## Building
To build python related libraries:
```
make -C strobelight/bpf_lib/python
```

## Installing
To install python related libraries:
```
make INSTALL_DIR=<path to install to> -C strobelight/bpf_lib/python install
```

## Usage
See blocks of code surrounded by "Stack Reader" comments in:\
[pystacks_sample.cpp](strobelight/bpf_lib/samples/pystacks/pystacks_sample.cpp)\
[pystacks_sample.bpf.c](strobelight/bpf_lib/samples/pystacks/pystacks_sample.bpf.c)

See the [CONTRIBUTING](CONTRIBUTING.md) file for how to help out.

## License
This work is dual-licensed under GNU LGPL v2.1 license and BSD-2-Clause license, as found in the LICENSE file. You can choose between one of them if you use this work.

SPDX-License-Identifier: BSD-2-Clause OR LGPL-2.1-only
