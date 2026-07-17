// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_PYTHON_DISCOVERY_PYPIDDATA_H__
#define __BPF_LIB_PYTHON_DISCOVERY_PYPIDDATA_H__

#ifdef __cplusplus
// @oss-disable: #include <bpf/uapi/linux/bpf.h>
#include <linux/bpf.h> // @oss-enable
#include <cstdint>
#endif

#include "strobelight/bpf_lib/python/include/OffsetConfig.h"

struct PyPidData {
  OffsetConfig offsets;
  bool use_tls;

  uintptr_t py_runtime_addr; // virtual address of _PyRuntime

  uintptr_t current_state_addr; // virtual address of
                                // _PyRuntime.gilstate.tstate_current
  uintptr_t tls_key_addr; // virtual address of autoTLSkey for pthreads TLS
  uintptr_t gil_locked_addr; // virtual address of gil_locked
  uintptr_t gil_last_holder_addr; // virtual address of gil_last_holder
};

#endif
