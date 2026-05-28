// Copyright (c) Meta Platforms, Inc. and affiliates.

// @oss-disable: #include <bpf/vmlinux/vmlinux.h>
#include <vmlinux.h> // @oss-enable

#include "strobelight/bpf_lib/common/bpf_read_helpers.bpf.h"
#include "strobelight/bpf_lib/common/task_helpers.bpf.h"

#define bpf_printk_debug(fmt, ...)    \
  ({                                  \
    if (0)                            \
      bpf_printk(fmt, ##__VA_ARGS__); \
  })

struct pthread_offset_config {
  uint32_t pthread_key_data_offset;
  uint32_t pthread_specific_1stblock_offset;
  uint32_t pthread_specific_offset;
  uint32_t pthread_size;
  uint32_t pthread_key_size;
};

// clang-format off
//
// To obtain these values, run:
//
// $ lldb -p <pid>
// (lldb) command script import ~/fbsource/fbcode/strobelight/scripts/pyperf_lldb.py
// (lldb) dump_pthread_offsets
//
// clang-format on

static struct pthread_offset_config get_pthread_offsets() {
  struct pthread_offset_config config = {};
#if __x86_64__
  config.pthread_key_data_offset = 8; // offsetof(pthread_key_data, data)
  config.pthread_specific_1stblock_offset =
      784; // offsetof(pthread, specific_1stblock)
  config.pthread_specific_offset = 1296; // offsetof(pthread, specific)
  config.pthread_size = 2496; // sizeof(pthread)
  config.pthread_key_size = 16; // sizeof(pthread_key_data)
#elif __aarch64__
  config.pthread_key_data_offset = 8; // offsetof(pthread_key_data, data)
  config.pthread_specific_1stblock_offset =
      272; // offsetof(pthread, specific_1stblock)
  config.pthread_specific_offset = 784; // offsetof(pthread, specific)
  config.pthread_size = 1856; // sizeof(pthread)
  config.pthread_key_size = 16; // sizeof(pthread_key_data)
#else
#error "Unsupported platform"
#endif
  return config;
}

static void* get_pthread_task(
    struct pthread_offset_config* offsets,
    struct task_struct* task) {
#if __x86_64__
  void* tls = (void*)BPF_PROBE_READ(get_current_task(task), thread.fsbase);
  void* pthread = tls;
#elif __aarch64__
  void* tls = (void*)BPF_PROBE_READ(get_current_task(task), thread.uw.tp_value);
  // tpidr_el0 points to after pthread
  void* pthread = tls - offsets->pthread_size;
#else
#error "Unsupported platform"
#endif
  return pthread;
}

// Read pthread specific data, mirroring the logic of pthread_getspecific
// function.
__hidden void* get_pthread_specific_data_task(
    uint32_t key,
    struct task_struct* task) {
  if (key >= 1024) {
    bpf_printk_debug("invalid pthread_key");
    return NULL;
  }

  struct pthread_offset_config offsets = get_pthread_offsets();

  bpf_printk_debug("pthread_key=%u", key);
  bpf_printk_debug("pthread_key_size=%u", offsets.pthread_key_size);
  bpf_printk_debug(
      "pthread_key_data_offset=%u", offsets.pthread_key_data_offset);
  bpf_printk_debug("pthread_size=%u", offsets.pthread_size);
  bpf_printk_debug(
      "pthread_specific_1stblock_offset=%u",
      offsets.pthread_specific_1stblock_offset);
  bpf_printk_debug(
      "pthread_specific_offset=%u", offsets.pthread_specific_offset);

  long ret;
  void* pthread = get_pthread_task(&offsets, task);
  void* data_addr = NULL;
  void* data = NULL;

  if (key < 32) {
    // key is located in 1st block, access via specific_1stblock[key]
    uint32_t i = key;
    void* specific_1stblock_addr =
        pthread + offsets.pthread_specific_1stblock_offset;
    specific_1stblock_addr +=
        offsets.pthread_key_size * i + offsets.pthread_key_data_offset;
    bpf_printk_debug(
        "pthread_specific_1stblock=0x%llx", specific_1stblock_addr);
    data_addr = specific_1stblock_addr;
  } else {
    // key is located in 2-level block, access via specific[key/32][key%32]
    uint32_t i = key / 32;
    uint32_t j = key % 32;
    void* specific_1stblock_addr = pthread + offsets.pthread_specific_offset;
    specific_1stblock_addr += sizeof(void*) * i;
    void* specific_2ndblock_addr = NULL;
    ret = bpf_probe_read_user_task(
        &specific_2ndblock_addr,
        sizeof(specific_2ndblock_addr),
        specific_1stblock_addr,
        task);
    if (ret != 0 || !specific_2ndblock_addr) {
      bpf_printk_debug("failed to read pthread_specific_2ndblock, ret=%d", ret);
      return NULL;
    }
    specific_2ndblock_addr +=
        offsets.pthread_key_size * j + offsets.pthread_key_data_offset;
    bpf_printk_debug(
        "pthread_specific_1stblock=0x%llx", specific_1stblock_addr);
    bpf_printk_debug(
        "pthread_specific_2ndblock=0x%llx", specific_2ndblock_addr);
    data_addr = specific_2ndblock_addr;
  }

  ret = bpf_probe_read_user_task(&data, sizeof(data), data_addr, task);
  if (ret != 0) {
    bpf_printk_debug("failed to read pthread_specific_data, ret=%d", ret);
    return NULL;
  }
  bpf_printk_debug("pthread_specific_data=0x%llx", data);

  return data;
}
