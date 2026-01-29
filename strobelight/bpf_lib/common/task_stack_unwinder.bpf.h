// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_TASK_STACK_UNWINDER_H__
#define __BPF_LIB_TASK_STACK_UNWINDER_H__

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct task_stack_frame {
  struct task_stack_frame* next_frame;
  unsigned long return_address;
};

// Unwind user stack for a task by following frame pointers.
// This is a workaround for bpf_get_task_stack() not supporting
// user stack collection for non-current tasks.
// Returns number of frames collected.
static __always_inline size_t unwind_user_stack_task(
    struct task_struct* task,
    uint64_t* stack_buf,
    size_t max_frames) {
  struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
  struct task_stack_frame frame;
  int err;
  size_t idx = 0;

  uint64_t ip = PT_REGS_IP(regs);
  uint64_t fp = PT_REGS_FP(regs);

  if (idx < max_frames) {
    stack_buf[idx++] = ip;
  }

  void* next_frame = (void*)fp;

  while (next_frame != NULL && idx < max_frames) {
    err = bpf_copy_from_user_task(&frame, sizeof(frame), next_frame, task, 0);
    if (err != 0 || frame.return_address == 0) {
      break;
    }

    stack_buf[idx++] = frame.return_address;
    next_frame = frame.next_frame;
  }

  return idx;
}

#endif // __BPF_LIB_TASK_STACK_UNWINDER_H__
