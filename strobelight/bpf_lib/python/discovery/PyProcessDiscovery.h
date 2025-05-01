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

#include "strobelight/bpf_lib/python/include/PyPidData.h"

#include "strobelight/bpf_lib/python/discovery/OffsetResolver.h"

namespace facebook::strobelight::bpf_lib::python {

class PyProcessDiscovery {
 public:
  // default c-tor to allow creation outside of intializer list
  explicit PyProcessDiscovery() : processOffsetResolution_(true) {}

  void findPythonPids(const std::set<pid_t>& pids);

  // Long term we should make these maps sharable between the different bpf
  // modules.
  void discoverAndConfigure(
      std::set<pid_t> pids,
      int pidMapFd,
      int exeMapFd,
      int pidTargetMapFd);

  std::optional<bool> isPyProcess(const pid_t pid) const;

  bool checkPyProcess(
      facebook::pid_info::SharedPidInfo& pidInfo,
      bool forceUpdate = false);

  bool updatePidConfigTable(int mapFd) const;
  bool updatePidConfigTableForPid(int mapFd, pid_t pid) const;

  void updateBinaryIdConfigTable(int mapFd) const;

  std::set<pid_t> getPythonPids() const {
    std::set<pid_t> ret;
    std::shared_lock<std::shared_mutex> rlock(pythonPidsMutex_);
    ret.insert(pythonPids_.begin(), pythonPids_.end());
    return ret;
  }

  std::optional<PyPidData> getPythonPidData(pid_t pid) const;

  enum PyInterpreter {
    PY_INTERPRETER_NONE = 0,
    PY_INTERPRETER_CPYTHON = 1,
    PY_INTERPRETER_CINDER = 2,
  };

  struct PyRuntimeInfo {
    PyInterpreter interpreter;
    std::string path;
    int versionMajor;
    int versionMinor;
    int versionMicro;

    std::string version() {
      return fmt::format("{}.{}.{}", versionMajor, versionMinor, versionMicro);
    }
  };
  std::optional<PyRuntimeInfo> getPyRuntimeInfo(pid_t pid) const;

  std::unordered_map<std::string, uint32_t> getOffsetResolutionCounts() const {
    std::unordered_map<std::string, uint32_t> res;

    std::shared_lock<std::shared_mutex> rlock(offsetResolutionCountsMutex_);
    res.insert(offsetResolutionCounts_.begin(), offsetResolutionCounts_.end());

    return res;
  }

  static const char* getPyInterpreterName(PyInterpreter interpreter);

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

  std::shared_ptr<facebook::pid_info::SharedPidInfoCache> pidInfoCache_ =
      facebook::pid_info::getSharedPidInfoCache();

  bool checkPyProcessImpl(facebook::pid_info::SharedPidInfo& pidInfo);

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
