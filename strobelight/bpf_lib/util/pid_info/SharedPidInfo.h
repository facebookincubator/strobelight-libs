// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <utility>

#include "strobelight/bpf_lib/util/pid_info/ProcPidInfo.h" // @manual

namespace facebook::strobelight::bpf_lib::pid_info {

// this is the bpf_lib specific implementation of SharedPidInfo
// and can have all the types specified. The only thing that needs be generic
// is the interface, which can be kept minimal
// All SharedPidInfo APIs needed in bpf_lib should have a method here.

class SharedPidInfo {
 private:
  // Disable direct creation of SharedPidInfo. Always use SharedPidInfoCache for
  // consistency and so that procfs doesn't need to be parsed more than once for
  // the same process.
  explicit SharedPidInfo(pid_t pid, const std::string& rootDir = "")
      : internalPidInfo_(pid, rootDir) {}

  friend class SharedPidInfoCache;

 public:
  /*
   * Overrides for setting values.
   */
  friend std::ostream& operator<<(
      std::ostream& out,
      const SharedPidInfo& pidInfo) {
    return out << pidInfo.getName() << " [" << pidInfo.getPid() << "]";
  }

  // getPid
  pid_t getPid() const {
    return internalPidInfo_.getPid();
  }

  // getName
  const std::string& getName() const {
    return internalPidInfo_.getName();
  }

  // readMemory
  ssize_t readMemory(void* dest, const void* src, size_t len) {
    // mutex?
    return internalPidInfo_.readMemory(dest, src, len);
  }

  bool iterateAllMemoryMappings(const MemoryMappingCallback& callback) const {
    // mutex?
    return internalPidInfo_.iterateAllMemoryMappings(callback);
  }

  bool iterateAllMemoryMappings(
      // mutex?
      const MemoryMappingWithBaseLoadAddressCallback& callback) const {
    return internalPidInfo_.iterateAllMemoryMappings(callback);
  }

  static std::vector<pid_t> getRunningPids(const std::string& rootDir = "") {
    return ProcPidInfo::getRunningPids(rootDir);
  }

  std::filesystem::path getProcfsRoot(const std::filesystem::path& path) const {
    return internalPidInfo_.getProcfsRoot(path);
  }

  bool isAlive() const {
    return internalPidInfo_.isAlive();
  }

  bool isKernelProcess() const {
    return internalPidInfo_.isKernelProcess();
  }

  std::chrono::seconds getStartTimeAfterBoot() const {
    return internalPidInfo_.getStartTimeAfterBoot();
  }

  bool hasValidInfo() const {
    return internalPidInfo_.hasValidInfo();
  }

 private:
  pid_info::ProcPidInfo internalPidInfo_;
};

} // namespace facebook::strobelight::bpf_lib::pid_info
