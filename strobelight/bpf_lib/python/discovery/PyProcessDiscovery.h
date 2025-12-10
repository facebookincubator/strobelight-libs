// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <elf.h>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

#include "strobelight/bpf_lib/include/binary_id.h"
#include "strobelight/bpf_lib/util/ElfFile.h"
#include "strobelight/bpf_lib/util/pid_info/SharedPidInfo.h"
#include "strobelight/bpf_lib/util/pid_info/SharedPidInfoCache.h"

#include "strobelight/bpf_lib/python/discovery/IPyProcessDiscovery.h"
#include "strobelight/bpf_lib/python/include/PyPidData.h"

#include "strobelight/bpf_lib/python/discovery/OffsetResolver.h"

namespace facebook::strobelight::bpf_lib::python {

class PyProcessDiscovery : public facebook::strobelight::IPyProcessDiscovery {
 public:
  // Type aliases for interface types to maintain backward compatibility
  using PyInterpreter = IPyProcessDiscovery::PyInterpreter;
  using PyRuntimeInfo = IPyProcessDiscovery::PyRuntimeInfo;

  // default c-tor to allow creation outside of intializer list
  explicit PyProcessDiscovery() : processOffsetResolution_(true) {}

  void findPythonPids(const std::set<pid_t>& pids);

  std::optional<bool> isPyProcess(const pid_t pid) const;

  bool checkPyProcess(
      std::shared_ptr<facebook::strobelight::bpf_lib::pid_info::SharedPidInfo>&
          pidInfo,
      bool forceUpdate = false);

  bool updatePidConfigTable(int mapFd) const override;
  bool updatePidConfigTableForPid(int mapFd, pid_t pid) const override;

  void updateBinaryIdConfigTable(int mapFd) const override;

  std::set<pid_t> getPythonPids() const override {
    std::set<pid_t> ret;
    std::shared_lock<std::shared_mutex> rlock(pythonPidsMutex_);
    ret.insert(pythonPids_.begin(), pythonPids_.end());
    return ret;
  }

  std::optional<PyPidData> getPythonPidData(pid_t pid) const;

  std::optional<PyRuntimeInfo> getPyRuntimeInfo(pid_t pid) const override;

  std::unordered_map<std::string, uint32_t> getOffsetResolutionCounts() const {
    std::unordered_map<std::string, uint32_t> res;

    std::shared_lock<std::shared_mutex> rlock(offsetResolutionCountsMutex_);
    res.insert(offsetResolutionCounts_.begin(), offsetResolutionCounts_.end());

    return res;
  }

 private:
  mutable std::shared_mutex pythonPidsMutex_;
  std::set<pid_t> pythonPids_;

  struct PyProcessInfo {
    struct binary_id binaryId;
    PyPidData pidData; // memory addresses
  };
  mutable std::shared_mutex pythonProcessInfoCacheMutex_;
  std::unordered_map<pid_t, std::optional<PyProcessInfo>>
      pythonProcessInfoCache_;

  struct PyBinaryInfo {
    std::string path;
    GElf_Half elfType;
    PyPidData pidData; // file addresses
    PyInterpreter interpreter;
  };

  struct PyModuleInfo {
    std::optional<PyBinaryInfo> pyBinaryInfo;
    OffsetResolver offsetResolver;
  };

  mutable std::shared_mutex pythonModuleInfoCacheMutex_;
  std::unordered_map<struct binary_id, PyModuleInfo> pythonModuleInfoCache_;

  mutable std::shared_mutex offsetResolutionCountsMutex_;
  bool processOffsetResolution_;
  std::unordered_map<std::string, uint32_t> offsetResolutionCounts_;

  std::shared_ptr<facebook::strobelight::bpf_lib::pid_info::SharedPidInfoCache>
      pidInfoCache_ =
          facebook::strobelight::bpf_lib::pid_info::getSharedPidInfoCache();

  bool checkPyProcessImpl(
      facebook::strobelight::bpf_lib::pid_info::SharedPidInfo& pidInfo);

  bool clearPythonPidData(const pid_t pid);

  std::optional<PyBinaryInfo> getPyModuleInfo(
      strobelight::ElfFile& elf,
      const std::string& path,
      struct binary_id binaryId,
      facebook::strobelight::bpf_lib::OffsetResolver& offsetResolver);

  OffsetResolution resolveOffsets(
      const OffsetResolver& offsetResolver,
      const std::string& elfPath);

  static uintptr_t getElfSymbolAddress(
      const strobelight::ElfFile& elf,
      const std::string& elfPath,
      std::optional<strobelight::ElfFile::Symbol>& symbol);

  static const char* getElfSymbolStringValue(
      const strobelight::ElfFile& elf,
      const std::string& elfPath,
      const std::optional<strobelight::ElfFile::Symbol>& symbol);

  static PyPidData computePyPidData(
      const PyBinaryInfo& pyBinaryInfo,
      uintptr_t baseLoadAddr,
      uintptr_t exePyRuntimeAddr);
};

} // namespace facebook::strobelight::bpf_lib::python
