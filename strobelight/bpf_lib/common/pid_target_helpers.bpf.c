// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/common/pid_target_helpers.bpf.h"
#include "strobelight/bpf_lib/common/task_helpers.bpf.h"

#ifndef BPF_LIB_MAX_PID_TARGETS
#define BPF_LIB_MAX_PID_TARGETS 1024
#endif // BPF_LIB_MAX_PID_TARGETS

// Length of task->comm in the kernel (TASK_COMM_LEN from <linux/sched.h>).
// Kept local to avoid clashing with other strobelight definitions of the same
// name.
#ifndef BPF_LIB_TASK_COMM_LEN
#define BPF_LIB_TASK_COMM_LEN 16
#endif // BPF_LIB_TASK_COMM_LEN

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, BPF_LIB_MAX_PID_TARGETS);
  __type(key, pid_t);
  __type(value, bool);
} targeted_pids SEC(".maps");

volatile struct {
  pid_t targeted_pid; // if targeting 1 pid, this is cheaper than map lookup
  bool has_targeted_pids; // use the map for lookup vs target all pids
  int self_pid;
  bool filter_self;

  bool filter_kernel_threads;

  // Comm-name target programmed from ProfilerConfig.tid_targets /
  // MonitorConfig.tid_targets. BPF performs a bounded prefix match against
  // task->comm (max BPF_LIB_TASK_COMM_LEN bytes). The user-space string is
  // null-terminated; the prefix stops at the first NUL.
  bool has_include_comm;
  bool has_exclude_comm;
  char include_comm[BPF_LIB_TASK_COMM_LEN];
  char exclude_comm[BPF_LIB_TASK_COMM_LEN];
} pid_target_helpers_prog_cfg = {};

// Verifier-friendly bounded prefix compare. Returns true if `comm` starts with
// the null-terminated `prefix` (or if `prefix` is empty / length >=
// BPF_LIB_TASK_COMM_LEN and matches every byte read from `comm`).
//
// We can't use `bpf_strncmp` here because its `s2` argument must be
// `ARG_PTR_TO_CONST_STR` (i.e. live in `.rodata`), and `prefix` lives in
// `.bss` (it's written from userspace after the skeleton is opened).
//
// Uses a fully-unrolled loop with a compile-time constant bound so the
// verifier can statically validate the prefix walk on older kernels (5.12
// and below) that don't support `bpf_for()` / `bpf_loop()`.
static __always_inline bool comm_starts_with(
    const char* comm,
    const volatile char* prefix) {
#pragma unroll
  for (int i = 0; i < BPF_LIB_TASK_COMM_LEN; i++) {
    char p = prefix[i];
    if (p == '\0') {
      return true;
    }
    if (comm[i] != p) {
      return false;
    }
  }
  return true;
}

__hidden bool does_tid_match_targets_comm(const char* comm) {
  if (!pid_target_helpers_prog_cfg.has_include_comm &&
      !pid_target_helpers_prog_cfg.has_exclude_comm) {
    return true;
  }
  if (pid_target_helpers_prog_cfg.has_exclude_comm &&
      comm_starts_with(comm, pid_target_helpers_prog_cfg.exclude_comm)) {
    return false;
  }
  if (pid_target_helpers_prog_cfg.has_include_comm) {
    return comm_starts_with(comm, pid_target_helpers_prog_cfg.include_comm);
  }
  return true;
}

__hidden bool does_tid_match_targets(struct task_struct* task) {
  if (!pid_target_helpers_prog_cfg.has_include_comm &&
      !pid_target_helpers_prog_cfg.has_exclude_comm) {
    return true;
  }
  char comm[BPF_LIB_TASK_COMM_LEN] = {};
  bpf_probe_read_kernel_str(comm, sizeof(comm), task->comm);
  return does_tid_match_targets_comm(comm);
}

__hidden bool
profile_pid_task(pid_t pid, struct task_struct* task, bool check_comm) {
  // For profilers that only target a single process (e.g. Crochet,
  // FunctionTracer) we can avoid the map lookup below, which is
  // beneficial for high-frequency events
  if (pid_target_helpers_prog_cfg.targeted_pid > 0) {
    if (pid != pid_target_helpers_prog_cfg.targeted_pid) {
      return false;
    }
    return !check_comm || does_tid_match_targets(task);
  }
  if (pid_target_helpers_prog_cfg.has_targeted_pids) {
    if (bpf_map_lookup_elem(&targeted_pids, &pid) == NULL) {
      return false;
    }
    return !check_comm || does_tid_match_targets(task);
  }

  // ignore samples from strobelight itself
  if (pid_target_helpers_prog_cfg.filter_self &&
      pid == pid_target_helpers_prog_cfg.self_pid) {
    return false;
  }
  // ignore samples from kernel threads
  if (pid_target_helpers_prog_cfg.filter_kernel_threads &&
      is_kernel_thread(task)) {
    return false;
  }

  return !check_comm || does_tid_match_targets(task);
}

bool profile_pid(pid_t pid) {
  return profile_pid_task(pid, bpf_get_current_task_btf(), true);
};
