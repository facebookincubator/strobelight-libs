// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_PID_TARGET_HELPERS_H__
#define __BPF_LIB_PID_TARGET_HELPERS_H__

// @oss-disable: #include <bpf/vmlinux/vmlinux.h>
#include <vmlinux.h> // @oss-enable

bool profile_pid(pid_t pid);
bool profile_pid_task(pid_t pid, struct task_struct* task);

#endif // __BPF_LIB_PID_TARGET_HELPERS_H__
