// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <fmt/core.h>
#include <array>
#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <vector>

#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include "strobelight/bpf_lib/include/logging.h"
#include "strobelight/bpf_lib/python/pystacks/pystacks.h"
#include "strobelight/bpf_lib/samples/pystacks/pystacks_sample.skel.h"
#include "strobelight/bpf_lib/samples/pystacks/structs.h"

#include <syscall.h> // __NR_perf_event_open
#include <unistd.h> // syscall, close

namespace {

constexpr size_t stack_len = 512;
constexpr size_t perfBufSizePages = 32;

} // namespace

std::vector<int> get_online_cpus() {
  std::string path = "/sys/devices/system/cpu/online";
  std::ifstream cpus_range_stream{path};
  std::vector<int> cpus;
  std::string cpu_range;

  while (std::getline(cpus_range_stream, cpu_range, ',')) {
    auto rangeop = cpu_range.find('-');
    if (rangeop == std::string::npos) {
      cpus.push_back(std::stoi(cpu_range));
    } else {
      int start = std::stoi(cpu_range.substr(0, rangeop));
      int end = std::stoi(cpu_range.substr(rangeop + 1));
      for (int i = start; i <= end; i++) {
        cpus.push_back(i);
      }
    }
  }
  return cpus;
}

bool attachEvent(
    struct bpf_program* prog,
    std::vector<bpf_link*>& links,
    int pid) {
  perf_event_attr attr{
      .type = PERF_TYPE_HARDWARE,
      .size = sizeof(struct perf_event_attr),
      .config = PERF_COUNT_HW_CPU_CYCLES,
      .sample_period = 100000};

  struct bpf_link* bl;
  std::vector<int> cpus;

  cpus = get_online_cpus();

  if (pid > 0) {
    int pfd = syscall(
        __NR_perf_event_open,
        &attr,
        pid /* pid */,
        -1 /* cpu */,
        -1 /* group id */,
        0 /* flags */);
    if (pfd < 0) {
      std::cerr << "Failed to open perf event on pid: " << pid
                << " error: " << errno << "\n";
      return false;
    }
    bl = bpf_program__attach_perf_event(prog, pfd);
    if (libbpf_get_error(bl)) {
      close(pfd);
      std::cerr << "Failed to attach perf event on pid: " << pid << "\n";
      return false;
    }
    links.push_back(bl);
  } else {
    for (int i : cpus) {
      int pfd = syscall(
          __NR_perf_event_open,
          &attr,
          -1 /* pid */,
          i /* cpu */,
          -1 /* group id */,
          0 /* flags */);
      if (pfd < 0) {
        std::cerr << "Failed to open perf event on cpu: " << i
                  << " error: " << errno << "\n";
        return false;
      }
      bl = bpf_program__attach_perf_event(prog, pfd);
      if (libbpf_get_error(bl)) {
        close(pfd);
        std::cerr << "Failed to attach perf event on cpu: " << i << "\n";
        return false;
      }
      links.push_back(bl);
    }
  }
  return true;
}

void detachEvent(std::vector<bpf_link*>& links) {
  for (bpf_link* link : links) {
    bpf_link__destroy(link);
  }

  links.clear();
}

namespace {
class PyStacksSample {
 public:
  static void
  handleSampleCallback(void* ctx, int cpu, void* data, __u32 /*size*/) {
    struct Event* event = (struct Event*)data;

    std::cout << fmt::format(
        "SAMPLE cpu: {} pid: {} tid: {} comm: {} ktime: {}\n",
        cpu,
        event->pid,
        event->tid,
        event->comm,
        event->ktime);

    ///////////////////////////////////////////////////////////////////////////
    // { Stack Reader Processing //////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////

    if (ctx == nullptr) {
      std::cout << "ctx pointer is null\n";
      return;
    }

    PyStacksSample* self = static_cast<PyStacksSample*>(ctx);

    auto& pystacksMessage = event->py_msg_buffer;

    // do something more interesting than just printing the stack
    std::cout << "Py Stack:\n";

    char function_name[stack_len];
    char filename[stack_len];
    size_t line = 0;
    for (uint64_t idx = 0; idx < pystacksMessage.stack_len; ++idx) {
      pystacks_symbolize_function(
          self->psr_, pystacksMessage.buffer[idx], function_name, stack_len);
      pystacks_symbolize_filename_line(
          self->psr_, pystacksMessage.buffer[idx], filename, stack_len, line);
      std::cout << fmt::format(
          "    {} ({}:{})\n", function_name, filename, line);
    }
    std::cout << "\n";

    ///////////////////////////////////////////////////////////////////////////
    // } Stack Reader Processing //////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////
  }

  static void handleLostSamplesCallback(void* /*ctx*/, int cpu, __u64 cnt) {
    std::cout << "LOST SAMPLE " << cpu << " " << cnt << "\n";
  }

  int run(pid_t pid) {
    std::cout << "Profile PID: " << pid << "\n";
    std::vector<bpf_link*> links;

    auto bpfSkel = pystacks_sample__open_and_load();

    if (!bpfSkel) {
      std::cerr << "Failed to create skeleton\n";
      return 1;
    }

    //////////////////////////////////////////////////////////////////////////
    // { Stack Reader Init ///////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////
    struct stack_walker_opts opts {};

    if (pid >= 0) {
      opts.pidCount = 1;
      opts.pids = &pid;
    }

    psr_ = pystacks_init(bpfSkel->obj, opts);

    /////////////////////////////////////////////////////////////////////////
    // } Stack Reader Init //////////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////

    auto samplesFd = bpf_map__fd(bpfSkel->maps.samples);
    if (samplesFd < 0) {
      std::cerr << "Failed to load samples map\n";
      return 1;
    }

    auto samplesBuf = perf_buffer__new(
        samplesFd,
        perfBufSizePages,
        handleSampleCallback,
        handleLostSamplesCallback,
        this,
        nullptr);

    if (!samplesBuf) {
      std::cerr << "Failed to open 'samplesBuf' perf buffer: " << errno << "\n";
      return 1;
    }

    std::cout << "Opened 'samplesBuf' perf buffer with " << perfBufSizePages
              << " pages per CPU\n";

    if (!attachEvent(bpfSkel->progs.on_py_event, links, pid)) {
      std::cerr << "Init fail: failed to attach perf event\n";
      return 1;
    }

    auto wait = std::chrono::milliseconds(500);
    auto startedAt = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - startedAt < wait) {
      perf_buffer__poll(samplesBuf, 5);
    }

    detachEvent(links);

    perf_buffer__free(samplesBuf);
    pystacks_sample__destroy(bpfSkel);

    pystacks_free(psr_);

    return 0;
  }

  struct stack_walker_run* psr_;
};
} // namespace

extern "C" {
int strobelight_lib_printer(
    enum strobelight_lib_print_level level,
    const char* msg) {
  switch (level) {
    case STROBELIGHT_LIB_DEBUG:
      std::cout << "DEBUG: " << msg << "\n";
      break;
    case STROBELIGHT_LIB_INFO:
      std::cout << "INFO: " << msg << "\n";
      break;
    case STROBELIGHT_LIB_WARN:
      std::cout << "WARN: " << msg << "\n";
      break;
  }
  return 0;
}
}

int main(int argc, char** argv) {
  PyStacksSample pss;

  strobelight_lib_set_print(strobelight_lib_printer);

  if (argc < 2) {
    std::cout << "Usage: " << argv[0] << " <PID>\n";
    return 1;
  }

  pid_t target;
  sscanf(argv[1], "%d", &target);
  return pss.run(target);
}
