// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_PID_TARGET_HELPERS_H__
#define __BPF_LIB_PID_TARGET_HELPERS_H__

// @oss-disable: #include <bpf/vmlinux/vmlinux.h>
#include <vmlinux.h> // @oss-enable

bool profile_pid(pid_t pid);
bool profile_pid_task(pid_t pid, struct task_struct* task);

// Apply the `tid_targets` (comm-name) filter, if configured. Profilers that
// don't go through `profile_pid_task` can call this directly to honor the
// generic filter.
bool does_tid_match_targets(struct task_struct* task);

// Same as `does_tid_match_targets`, but accepts the `comm` string directly so
// callers that have already read it can avoid a redundant
// `bpf_probe_read_kernel_str`.
bool does_tid_match_targets_comm(const char* comm);

#endif // __BPF_LIB_PID_TARGET_HELPERS_H__
