// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/samples/pystacks/pystacks_sample.bpf.h"
#include "strobelight/bpf_lib/common/common.h"
#include "strobelight/bpf_lib/python/pystacks/pystacks.bpf.h"

struct event_heap_map event_heap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __type(key, u32);
  __type(value, u32);
} samples SEC(".maps");

SEC("perf_event")
int on_py_event(struct bpf_perf_event_data* ctx) {
  struct Event* const event = get_event();
  if (!event) {
    return 0;
  }

  event->buff_size = 0;

  event->pid = (pid_t)(bpf_get_current_pid_tgid() >> 32);
  event->tid = (pid_t)(bpf_get_current_pid_tgid());
  bpf_get_current_comm(&event->comm, sizeof(event->comm));
  event->ktime = bpf_ktime_get_ns();

  /////////////////////////////////////////////////////////////////////////////
  // { Stack Reader Logic /////////////////////////////////////////////////////
  /////////////////////////////////////////////////////////////////////////////
  int py_stack_size = pystacks_read_stacks(ctx, NULL, &event->py_msg_buffer);

  event->buff_size += py_stack_size;

  if (event->py_msg_buffer.stack_len <= 0) {
    return 0;
  }

  /////////////////////////////////////////////////////////////////////////////
  // } Stack Reader Logic /////////////////////////////////////////////////////
  /////////////////////////////////////////////////////////////////////////////

  size_t header_len = offsetof(struct Event, py_msg_buffer);
  unsigned sample_size = header_len + event->buff_size;
  if (sample_size < sizeof(struct Event)) {
    bpf_perf_event_output(ctx, &samples, BPF_F_CURRENT_CPU, event, sample_size);
  }

  return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
