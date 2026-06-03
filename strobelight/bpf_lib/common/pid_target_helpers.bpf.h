// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_PID_TARGET_HELPERS_H__
#define __BPF_LIB_PID_TARGET_HELPERS_H__

// @oss-disable: #include <bpf/vmlinux/vmlinux.h>
#include <vmlinux.h> // @oss-enable

// Each Strobelight BPF program can target a subset of processes
// (`targeted_pid` / `targeted_pids` / kernel-thread filter) AND optionally
// a subset of threads within those processes by comm-name prefix
// (`tid_targets`). The helpers below apply those filters together.
//
//   profile_pid_task(pid, task, check_comm)
//     Returns true iff `pid` (and `task` for the kernel-thread filter)
//     passes the pid + kernel-thread filter. When `check_comm` is true,
//     the tid_targets (comm-name) filter is ALSO applied to `task`.
//     Pass `check_comm=false` when you want to apply the comm filter
//     yourself against a different task struct (e.g. sched_waking, which
//     OR-matches the comm of both the wakee and the waker).
//
//   profile_pid(pid)
//     Convenience wrapper:
//       profile_pid_task(pid, bpf_get_current_task_btf(), /*check_comm=*/true)
//     Use this only when the *current* task is the one whose pid is being
//     checked. In context-switch / sched_waking / iter.s/task contexts
//     `current` is NOT the task whose pid you are filtering — call
//     profile_pid_task(pid, the_correct_task_struct, true) directly
//     instead.
bool profile_pid(pid_t pid);
bool profile_pid_task(pid_t pid, struct task_struct* task, bool check_comm);

// Apply the `tid_targets` (comm-name) filter, if configured. Profilers that
// don't go through `profile_pid_task` can call this directly to honor the
// generic filter.
bool does_tid_match_targets(struct task_struct* task);

// Same as `does_tid_match_targets`, but accepts the `comm` string directly so
// callers that have already read it can avoid a redundant
// `bpf_probe_read_kernel_str`.
bool does_tid_match_targets_comm(const char* comm);

#endif // __BPF_LIB_PID_TARGET_HELPERS_H__
