// Copyright (c) Meta Platforms, Inc. and affiliates.

// @oss-disable: #include <bpf/uapi/linux/bpf.h>
#include <linux/bpf.h> // @oss-enable
#include <fmt/format.h>

extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
}

#include "strobelight/bpf_lib/python/discovery/PyProcessDiscovery.h"
#include "strobelight/bpf_lib/util/BpfLibLogger.h"
#include "strobelight/bpf_lib/util/ProcessDiscovery.h"
#include "strobelight/bpf_lib/util/pid_info/SharedPidInfo.h"

#include <elf.h>
#include <fmt/core.h>
#include <fmt/ostream.h> // needed for PidInfo in formatter
#include <re2/re2.h>
#include <strobelight/bpf_lib/util/ElfFile.h>
#include <memory>

#include "strobelight/bpf_lib/python/discovery/OffsetResolver.h"
#include "strobelight/bpf_lib/python/discovery/PyOffsets.h"

// Grabbed from kernel's kdev_t.h as these macros are redefined
// differently in uapi/kdev_t.h and we want the kernel definition here
#define BPF_LIB_KMINORBITS 20
#define BPF_LIB_KMKDEV(ma, mi) (((ma) << BPF_LIB_KMINORBITS) | (mi))

namespace facebook::strobelight::bpf_lib::python {

static const std::string kPyRuntimeSymbolName("_PyRuntime");
static const std::string kPySysImplCacheTagSymbolName("_PySys_ImplCacheTag");

static const std::string kAutoTLSKeySymbolName("autoTLSKey");
static const std::string kGilLockedSymbolName("gil_locked");
static const std::string kGilLastHolderSymbolName("gil_last_holder");
static const RE2 kPyProcessPatternRegex("python(\\d+)\\.(\\d+)?");
static const std::string kStrobeCodeRTPyCodeSymblName(
    "__strobe_CodeRuntime_py_code");
static const std::string kCPython312("cpython-312");

static const std::unordered_set<std::string> kPythonSymbolNames = [] {
  std::unordered_set<std::string> pySymbolNames = {
      kPyRuntimeSymbolName,
      kPySysImplCacheTagSymbolName,
      kAutoTLSKeySymbolName,
      kGilLockedSymbolName,
      kGilLastHolderSymbolName};
  auto processOffsetSymbols = facebook::strobelight::bpf_lib::OffsetResolver::
      getProcessOffsetSymbolNames();
  pySymbolNames.insert(
      processOffsetSymbols.begin(), processOffsetSymbols.end());
  return pySymbolNames;
}();

namespace fs = std::filesystem;

void PyProcessDiscovery::findPythonPids(const std::set<pid_t>& pids) {
  strobelight_lib_print(
      STROBELIGHT_LIB_INFO, "Discovering Python processes...");
  auto discoveryStart = std::chrono::steady_clock::now();

  std::atomic_int pidCount = 0;

  std::vector<VoidPidCallback> discoveryCbs;
  discoveryCbs.emplace_back(
      [&](std::shared_ptr<
          facebook::strobelight::bpf_lib::pid_info::SharedPidInfo>& pidInfo)
          -> void {
        checkPyProcess(pidInfo);
        ++pidCount;
      });

  // iterate pids and populate pythonPids_ member variable.
  facebook::strobelight::bpf_lib::iteratePids(
      chainDiscoveryCallbacks(discoveryCbs), pids);

  const auto& pythonPids = getPythonPids();

  auto const discoveryLatencyMs =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - discoveryStart)
          .count();

  strobelight_lib_print(
      STROBELIGHT_LIB_INFO,
      fmt::format(
          "Python process discovery took {}ms - found {} Python processes out of {} examined.",
          discoveryLatencyMs,
          pythonPids.size(),
          pidCount.load())
          .c_str());
}

bool PyProcessDiscovery::checkPyProcess(
    std::shared_ptr<facebook::strobelight::bpf_lib::pid_info::SharedPidInfo>&
        pidInfo,
    bool forceUpdate) {
  if (forceUpdate) {
    clearPythonPidData(pidInfo->getPid());
  } else {
    auto result = isPyProcess(pidInfo->getPid());
    if (result.has_value()) {
      return *result;
    }
  }
  return checkPyProcessImpl(*pidInfo);
}

bool PyProcessDiscovery::updatePidConfigTable(int mapFd) const {
  if (mapFd <= 0) {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format("Invalid map fd for pystacks_pid_config map: {}", mapFd)
            .c_str());
    return false;
  }
  size_t pyConfigCount = 0;
  { // pythonPidsMutex_ rlock
    std::shared_lock<std::shared_mutex> rlock(pythonPidsMutex_);
    for (pid_t pid : pythonPids_) {
      std::optional<PyPidData> pidData = getPythonPidData(pid);
      if (pidData.has_value()) {
        bpf_map_update_elem(mapFd, &pid, &(*pidData), 0);
        pyConfigCount++;
      }
    }
  } // pythonPidsMutex_ rlock
  strobelight_lib_print(
      STROBELIGHT_LIB_INFO,
      fmt::format("Updated Python pid configs for {} processes.", pyConfigCount)
          .c_str());
  return true;
}

bool PyProcessDiscovery::updatePidConfigTableForPid(int mapFd, pid_t pid)
    const {
  if (mapFd <= 0) {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format("Invalid map fd for pystacks_pid_config map: {}", mapFd)
            .c_str());
    return false;
  }

  auto pidData = getPythonPidData(pid);
  if (pidData) {
    if (bpf_map_update_elem(mapFd, &pid, &(*pidData), 0) != 0) {
      return false;
    }
    return true;
  } else {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format("No Python pid config for process {}.", pid).c_str());
    return false;
  }
}

void PyProcessDiscovery::updateBinaryIdConfigTable(int mapFd) const {
  if (mapFd <= 0) {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format("invalid map fd for binary_id_config map: {}", mapFd)
            .c_str());
    return;
  }

  { // pythonModuleInfoCache_ rlock
    std::shared_lock<std::shared_mutex> rlock(pythonModuleInfoCacheMutex_);
    for (const auto& item : pythonModuleInfoCache_) {
      auto& binaryInfo = item.second.pyBinaryInfo;
      if (binaryInfo && binaryInfo->elfType == ET_EXEC &&
          binaryInfo->interpreter != PY_INTERPRETER_NONE) {
        bpf_map_update_elem(mapFd, &item.first, &(binaryInfo->pidData), 0);
      }
    }
  } // pythonModuleInfoCache_ rlock
}

std::optional<PyPidData> PyProcessDiscovery::getPythonPidData(pid_t pid) const {
  std::shared_lock<std::shared_mutex> rlock(pythonProcessInfoCacheMutex_);
  auto procItr = pythonProcessInfoCache_.find(pid);
  if (procItr != pythonProcessInfoCache_.end() && procItr->second.has_value()) {
    return procItr->second->pidData;
  }
  return std::nullopt;
}

bool PyProcessDiscovery::clearPythonPidData(const pid_t pid) {
  bool res;
  { // pythonProcessInfoCacheMutex_ wlock
    std::unique_lock<std::shared_mutex> wlock(pythonProcessInfoCacheMutex_);
    res = pythonProcessInfoCache_.erase(pid) != 0;
  } // pythonProcessInfoCacheMutex_ wlock

  { // pythonPidsMutex_ wlock
    std::unique_lock<std::shared_mutex> wlock(pythonPidsMutex_);
    pythonPids_.erase(pid);
  } // pythonPidsMutex_ wlock
  return res;
}

std::optional<bool> PyProcessDiscovery::isPyProcess(const pid_t pid) const {
  std::shared_lock<std::shared_mutex> rlock(pythonProcessInfoCacheMutex_);
  auto procItr = pythonProcessInfoCache_.find(pid);
  if (procItr != pythonProcessInfoCache_.end()) {
    return procItr->second.has_value();
  }
  return std::nullopt; // unknown
}

std::optional<PyProcessDiscovery::PyRuntimeInfo>
PyProcessDiscovery::getPyRuntimeInfo(pid_t pid) const {
  // Get pid info to return process root-relative path to Python binary in order
  // to support containerized services.
  auto pidInfo = pidInfoCache_->get(pid);
  if (!pidInfo) {
    return std::nullopt;
  }

  struct binary_id binaryId;
  { // pythonProcessInfoCacheMutex_ rlock
    std::shared_lock<std::shared_mutex> rlock(pythonProcessInfoCacheMutex_);
    auto procItr = pythonProcessInfoCache_.find(pid);
    if (procItr == pythonProcessInfoCache_.end() || !procItr->second) {
      return std::nullopt;
    }
    binaryId = procItr->second->binaryId;
  } // pythonProcessInfoCacheMutex_ rlock

  std::shared_lock<std::shared_mutex> rlock(pythonModuleInfoCacheMutex_);
  auto modItr = pythonModuleInfoCache_.find(binaryId);
  if (modItr == pythonModuleInfoCache_.end()) {
    return std::nullopt;
  }

  auto& pyBinaryInfo = modItr->second.pyBinaryInfo;
  if (!pyBinaryInfo || pyBinaryInfo->interpreter == PY_INTERPRETER_NONE) {
    return std::nullopt;
  }

  return PyProcessDiscovery::PyRuntimeInfo{
      .interpreter = pyBinaryInfo->interpreter,
      .path = pidInfo->getProcfsRoot(pyBinaryInfo->path).string(),
      .versionMajor = pyBinaryInfo->pidData.offsets.PyVersion_major,
      .versionMinor = pyBinaryInfo->pidData.offsets.PyVersion_minor,
      .versionMicro = pyBinaryInfo->pidData.offsets.PyVersion_micro,
  };
}

// Check if the given process is a Python process.
// For any Python process, save off the address of Python runtime state and the
// appropriate offsets into runtime datastructures that will be needed to walk
// Python stacks at profile time from bpf.
bool PyProcessDiscovery::checkPyProcessImpl(
    facebook::strobelight::bpf_lib::pid_info::SharedPidInfo& pidInfo) {
  const auto pid = pidInfo.getPid();

  // Iterate over all memory mappings in the process to find the Python runtime
  // (normally the module containing _PyRuntime) and compute offsets.
  // **NOTE** we cheat with the locking here. We're not hodling the (write) lock
  // while iterating process memory mappings because it would be rather
  // expensive. Since we're just updating the various caches and the common use
  // case is updating separate processes concurrently this should be fine.
  std::unordered_set<std::string> checkedModules;
  uintptr_t exePyRuntimeAddr = 0;
  bool found = false;
  facebook::strobelight::bpf_lib::OffsetResolver offsetResolver;
  PyPidData pidData;
  binary_id pyModuleBinaryId;
  try {
    pidInfo.iterateAllMemoryMappings([&](const facebook::strobelight::bpf_lib::
                                             pid_info::MemoryMapping& mm,
                                         std::optional<uintptr_t> baseLoadAddr,
                                         const std::shared_ptr<
                                             strobelight::ElfFile>& elf) {
      if (!baseLoadAddr || !elf) {
        return facebook::strobelight::bpf_lib::pid_info::IterControl::CONTINUE;
      }

      // Only check each module once. In the /proc/<pid>/maps listing there
      // are typically multiple mappings for each module, each with
      // different memory protections.
      const bool checked = !checkedModules.insert(mm.name).second;
      if (checked) {
        return facebook::strobelight::bpf_lib::pid_info::IterControl::CONTINUE;
      }

      const bool isPie = elf->isPie();
      const bool isExe = isPie || elf->eType() == ET_EXEC;
      const auto binaryId =
          binary_id(BPF_LIB_KMKDEV(mm.devMajor, mm.devMinor), mm.inode);
      // Get BinaryInfo + OffsetResolver for the module
      auto pyBinaryInfo =
          getPyModuleInfo(*elf, mm.name, binaryId, offsetResolver);
      if (!pyBinaryInfo) {
        strobelight_lib_print(
            STROBELIGHT_LIB_INFO,
            fmt::format("Not a Python module: {}", mm.name).c_str());
      }
      // Check if the executable contains the _PyRuntime symbol but is not
      // an actual Python runtime.
      else if (isExe && pyBinaryInfo->interpreter == PY_INTERPRETER_NONE) {
        exePyRuntimeAddr = pyBinaryInfo->pidData.py_runtime_addr;
        if (exePyRuntimeAddr != 0) {
          strobelight_lib_print(
              STROBELIGHT_LIB_INFO,
              fmt::format(
                  "Discovered orphaned _PyRuntime symbol in process {} executable {} @ {:#x}",
                  pidInfo.getPid(),
                  mm.name,
                  exePyRuntimeAddr)
                  .c_str());
        }
      } else {
        if (isExe) {
          if (isPie) {
            // PIE executables are special because they can be loaded into a
            // random position in memory (similar to shared libraries), so we
            // need to adjust by baseLoadAddr to convert file to memory
            // addresses.
            exePyRuntimeAddr =
                *baseLoadAddr + pyBinaryInfo->pidData.py_runtime_addr;
          } else {
            exePyRuntimeAddr = pyBinaryInfo->pidData.py_runtime_addr;
          }
        }

        strobelight_lib_print(
            STROBELIGHT_LIB_INFO,
            fmt::format("Found Python module {}", mm.name).c_str());

        { // pythonPidsMutex_ wlock
          std::unique_lock<std::shared_mutex> wlock(pythonPidsMutex_);
          pythonPids_.insert(pid);
        } // pythonPidsMutex_ wlock

        pidData =
            computePyPidData(*pyBinaryInfo, *baseLoadAddr, exePyRuntimeAddr);
        strobelight_lib_print(
            STROBELIGHT_LIB_INFO,
            fmt::format(
                "Process {} uses Python - {} {}.{}.{} runtime at {} - current_state_addr:{:#x} tls_key_addr:{:#x}",
                pidInfo.getPid(),
                getPyInterpreterName(pyBinaryInfo->interpreter),
                pidData.offsets.PyVersion_major,
                pidData.offsets.PyVersion_minor,
                pidData.offsets.PyVersion_micro,
                pyBinaryInfo->path,
                pidData.current_state_addr,
                pidData.tls_key_addr)
                .c_str());

        pyModuleBinaryId = binaryId;
        found = true;
      }
      if (offsetResolver.allProcessOffsetsFound()) {
        return facebook::strobelight::bpf_lib::pid_info::IterControl::BREAK;
      }
      return facebook::strobelight::bpf_lib::pid_info::IterControl::CONTINUE;
    });
  } catch (const std::exception& e) {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format(
            "Exception when checking process {} for Python: {}",
            pidInfo.getPid(),
            e.what())
            .c_str());
  }
  if (found) {
    pidData.offsets = resolveOffsets(offsetResolver, pidInfo.getName()).offsets;
    { // pythonProcessInfoCacheMutex_ wlock
      std::unique_lock<std::shared_mutex> wlock(pythonProcessInfoCacheMutex_);
      pythonProcessInfoCache_.emplace(
          pid, PyProcessInfo{pyModuleBinaryId, pidData});
    } // pythonProcessInfoCacheMutex_ wlock
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format(
            "All offsets: {} {}", pid, pidInfo.getName() /*, pidData.offsets */)
            .c_str());
  } else {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format("Process {} does not use Python.", pidInfo.getPid())
            .c_str());
    { // pythonProcessInfoCacheMutex_ wlock
      std::unique_lock<std::shared_mutex> wlock(pythonProcessInfoCacheMutex_);
      pythonProcessInfoCache_.emplace(pid, std::nullopt);
    } // pythonProcessInfoCacheMutex_ wlock

    { // pythonPidsMutex_ wlock
      std::unique_lock<std::shared_mutex> wlock(pythonPidsMutex_);
      pythonPids_.erase(pid);
    } // pythonPidsMutex_ wlock
  }

  return found;
}

// Merge offsets with callers offset resolver because process offsets
// can be spread across multiple modules (shared objects)
// return PyBinaryInfo if the process is python, otherwise nullopt
std::optional<PyProcessDiscovery::PyBinaryInfo>
PyProcessDiscovery::getPyModuleInfo(
    strobelight::ElfFile& elf,
    const std::string& elfPath,
    struct binary_id binaryId,
    facebook::strobelight::bpf_lib::OffsetResolver& destOffsetResolver) {
  { // pythonModuleInfoCache_ rlock
    std::shared_lock<std::shared_mutex> rlock(pythonModuleInfoCacheMutex_);
    auto modItr = pythonModuleInfoCache_.find(binaryId);
    if (modItr != pythonModuleInfoCache_.end()) {
      destOffsetResolver.mergeOffsetResolver(modItr->second.offsetResolver);
      return modItr->second.pyBinaryInfo;
    }
  } // pythonModuleInfoCache_ rlock

  // Check for all of the possible symbols (Cinder, CPython; any version) in a
  // single pass.
  // **NOTE** We cheat with the locking again not holding the write lock until
  // updating to not hold the write lock whild checking Python runtime info.
  // This is mostly safe because we assume tht fetching the same binary id not a
  // common pattern. If this changes then this code may need to be refactored to
  // hold the lock.
  auto pySymbols = elf.getSymbolsByName(kPythonSymbolNames);

  // - CPython (or Cinder) 3.7 or newer will have the globals runtime state in
  // _PyRuntime.

  std::optional<std::string> pyVersion;
  const char* pyVersionElf = getElfSymbolStringValue(
      elf, elfPath, pySymbols.at(kPySysImplCacheTagSymbolName));
  if (pyVersionElf) {
    pyVersion = pyVersionElf;
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format(
            "Read python version from elf file {}: {}", elfPath, *pyVersion)
            .c_str());
  } else {
    // Edge case for some binaries where the symbols have been stripped
    // We try to find the python binary name itself, e.g. python3.10
    // And guess the runtime version based on it.
    auto filename = std::filesystem::path(elfPath).filename();

    // Perform the regex match and replacement
    int major, minor;
    if (RE2::PartialMatch(
            filename.string(), kPyProcessPatternRegex, &major, &minor)) {
      pyVersion = fmt::format("cpython-{}{}", major, minor);
      strobelight_lib_print(
          STROBELIGHT_LIB_INFO,
          fmt::format(
              "Failed to read Python runtime version from binary. Using file name {} => '{}' as best guess.",
              filename.string(),
              *pyVersion)
              .c_str());
    } else {
      strobelight_lib_print(
          STROBELIGHT_LIB_INFO,
          fmt::format(
              "Could not infer python version from filename {}", elfPath)
              .c_str());
    }
  }

  const uintptr_t pyRuntimeAddr =
      getElfSymbolAddress(elf, elfPath, pySymbols.at(kPyRuntimeSymbolName));

  // This symbols existence is used to determine the Py Interpreter type
  const uintptr_t strobeCodeRTPyCodeAddr = getElfSymbolAddress(
      elf, elfPath, pySymbols.at(kStrobeCodeRTPyCodeSymblName));

  { // pythonModuleInfoCache_ wlock
    std::unique_lock<std::shared_mutex> wlock(pythonModuleInfoCacheMutex_);
    auto& moduleInfo = pythonModuleInfoCache_[binaryId];
    auto& offsetResolver = moduleInfo.offsetResolver;

    // Set the default (headers) offsets, if we're able to determine the
    // pyVersion.
    if (pyVersion) {
      offsetResolver.setHeaderOffsets(*pyVersion);
    }
    // Some modules PyPerf symbols are stored outside of the main python binary
    // So we want to try and resolve offsets regardless of if the pyruntime is
    // found. Add symbols to the offset resolver.
    for (const auto& [name, sym] : pySymbols) {
      if (sym.has_value()) {
        offsetResolver.maybeAddProcessOffsetSymbol(elf, *sym);
      }
    }
    auto resolved = offsetResolver.resolveOffsets();

    if (!pyRuntimeAddr) {
      strobelight_lib_print(
          STROBELIGHT_LIB_INFO,
          fmt::format("No Python runtime state found in {}.", elfPath).c_str());
      // no runtime state found - not a Python binary
      destOffsetResolver.mergeOffsetResolver(moduleInfo.offsetResolver);
      return moduleInfo.pyBinaryInfo;
    }
    if (!pyVersion) {
      strobelight_lib_print(
          STROBELIGHT_LIB_INFO,
          fmt::format("No Python version string found in {}.", elfPath)
              .c_str());
      // No version string found - not an actual Python runtime even though this
      // binary contains the runtime state structure - e.g. _PyRuntime. See
      // T151754482.

      moduleInfo.pyBinaryInfo = PyBinaryInfo{
          elfPath,
          elf.eType(),
          PyPidData{.py_runtime_addr = pyRuntimeAddr},
          PY_INTERPRETER_NONE};
      destOffsetResolver.mergeOffsetResolver(moduleInfo.offsetResolver);
      return moduleInfo.pyBinaryInfo;
    }

    if (pyVersion && pyVersion->find(kCPython312) != std::string::npos) {
      strobelight_lib_print(
          STROBELIGHT_LIB_INFO,
          fmt::format(
              "CPython 3.12 detected. Support for 3.12 is currently experimental. Elf binary: {}",
              elfPath)
              .c_str());
    }

    PyPidData data = {};
    data.offsets = resolved.offsets;
    if (data.offsets.PyVersion_major == 3 &&
        data.offsets.PyVersion_minor >= 7) {
      data.py_runtime_addr = pyRuntimeAddr;
      // For modern Python (>= 3.7) we use offsets computed from _PyRuntime:
      // TLSKey_offset: offsetof(_PyRuntimeState, gilstate.autoTSSkey._key)
      data.tls_key_addr = pyRuntimeAddr + data.offsets.TLSKey_offset;
      // TCurrentState_offset: offsetof(_PyRuntimeState,
      // gilstate.tstate_current)
      data.current_state_addr =
          pyRuntimeAddr + data.offsets.TCurrentState_offset;
      // The GIL locked address/last holder is calculated as an offset after
      // Python3.7
      data.gil_locked_addr = pyRuntimeAddr + data.offsets.PyGIL_offset;
      data.gil_last_holder_addr =
          pyRuntimeAddr + data.offsets.PyGIL_last_holder;
    }
    data.use_tls = (data.tls_key_addr > 0);

    moduleInfo.pyBinaryInfo = PyBinaryInfo{
        elfPath,
        elf.eType(),
        data,
        strobeCodeRTPyCodeAddr ? PY_INTERPRETER_CINDER
                               : PY_INTERPRETER_CPYTHON};
    destOffsetResolver.mergeOffsetResolver(moduleInfo.offsetResolver);
    return moduleInfo.pyBinaryInfo;
  } // pythonModuleInfoCache_ wlock
}

OffsetResolution PyProcessDiscovery::resolveOffsets(
    const OffsetResolver& offsetResolver,
    const std::string& elfPath) {
  auto foundAllRequiredSymbols = offsetResolver.allProcessOffsetsFound();
  const bool forceHeaders =
      foundAllRequiredSymbols && !processOffsetResolution_;
  auto resolvedOffsets = offsetResolver.resolveOffsets(forceHeaders);
  const char* resolutionKey;
  if (forceHeaders) {
    resolutionKey = "forced_headers";
  } else if (foundAllRequiredSymbols) {
    resolutionKey = "process";
  } else {
    resolutionKey = "headers";
  }

  { // offsetResolutionCountsMutex_ wlock
    std::unique_lock<std::shared_mutex> wlock(offsetResolutionCountsMutex_);
    ++offsetResolutionCounts_[resolutionKey];
  } // offsetResolutionCountsMutex_ wlock

  // Fix up any missing (non-required) process offsets
  if (foundAllRequiredSymbols) {
    if (resolvedOffsets.offsets.PyVersion_major == 3 &&
        resolvedOffsets.offsets.PyVersion_minor == 10) {
      if (resolvedOffsets.offsets.PyGIL_offset ==
          BPF_LIB_DEFAULT_FIELD_OFFSET) {
        resolvedOffsets.offsets.PyGIL_offset =
            kCinder310OffsetConfig.PyGIL_offset;
        strobelight_lib_print(
            STROBELIGHT_LIB_INFO,
            fmt::format(
                "Patched 'PyGIL_offset' for cinder runtime {}: {}",
                elfPath,
                resolvedOffsets.offsets.PyGIL_offset)
                .c_str());
      }
      if (resolvedOffsets.offsets.PyGIL_last_holder ==
          BPF_LIB_DEFAULT_FIELD_OFFSET) {
        resolvedOffsets.offsets.PyGIL_last_holder =
            kCinder310OffsetConfig.PyGIL_last_holder;
        strobelight_lib_print(
            STROBELIGHT_LIB_INFO,
            fmt::format(
                "Patched 'PyGIL_last_holder' for cinder runtime {}: {}",
                elfPath,
                resolvedOffsets.offsets.PyGIL_last_holder)
                .c_str());
      }
      if (resolvedOffsets.offsets.PyFrameObject_lasti ==
          BPF_LIB_DEFAULT_FIELD_OFFSET) {
        resolvedOffsets.offsets.PyFrameObject_lasti =
            kCinder310OffsetConfig.PyFrameObject_lasti;
        strobelight_lib_print(
            STROBELIGHT_LIB_INFO,
            fmt::format(
                "Patched 'PyFrameObject_lasti' for cinder runtime {}: {}",
                elfPath,
                resolvedOffsets.offsets.PyFrameObject_lasti)
                .c_str());
      }
      if (resolvedOffsets.offsets.PyThreadState_interp ==
          BPF_LIB_DEFAULT_FIELD_OFFSET) {
        resolvedOffsets.offsets.PyThreadState_interp =
            kCinder310OffsetConfig.PyThreadState_interp;
        strobelight_lib_print(
            STROBELIGHT_LIB_INFO,
            fmt::format(
                "Patched 'PyThreadState_interp' for cinder runtime {}: {}",
                elfPath,
                resolvedOffsets.offsets.PyThreadState_interp)
                .c_str());
      }
      if (resolvedOffsets.offsets.PyInterpreterState_modules ==
          BPF_LIB_DEFAULT_FIELD_OFFSET) {
        resolvedOffsets.offsets.PyInterpreterState_modules =
            kCinder310OffsetConfig.PyInterpreterState_modules;
        strobelight_lib_print(
            STROBELIGHT_LIB_INFO,
            fmt::format(
                "Patched 'PyInterpreterState_modules' for cinder runtime {}: {}",
                elfPath,
                resolvedOffsets.offsets.PyInterpreterState_modules)
                .c_str());
      }
      if (resolvedOffsets.offsets.PyCodeObject_firstlineno ==
          BPF_LIB_DEFAULT_FIELD_OFFSET) {
        resolvedOffsets.offsets.PyCodeObject_firstlineno =
            kCinder310OffsetConfig.PyCodeObject_firstlineno;
        strobelight_lib_print(
            STROBELIGHT_LIB_INFO,
            fmt::format(
                "Patched 'PyCodeObject_firstlineno' for cinder runtime {}: {}",
                elfPath,
                resolvedOffsets.offsets.PyCodeObject_firstlineno)
                .c_str());
      }
      if (resolvedOffsets.offsets.PyCodeObject_linetable ==
          BPF_LIB_DEFAULT_FIELD_OFFSET) {
        resolvedOffsets.offsets.PyCodeObject_linetable =
            kCinder310OffsetConfig.PyCodeObject_linetable;
        strobelight_lib_print(
            STROBELIGHT_LIB_INFO,
            fmt::format(
                "Patched 'PyCodeObject_linetable' for cinder runtime {}: {}",
                elfPath,
                resolvedOffsets.offsets.PyCodeObject_linetable)
                .c_str());
      }
      if (resolvedOffsets.offsets.PyBytesObject_data ==
          BPF_LIB_DEFAULT_FIELD_OFFSET) {
        resolvedOffsets.offsets.PyBytesObject_data =
            kCinder310OffsetConfig.PyBytesObject_data;
        strobelight_lib_print(
            STROBELIGHT_LIB_INFO,
            fmt::format(
                "Patched 'PyBytesObject_data' for cinder runtime {}: {}",
                elfPath,
                resolvedOffsets.offsets.PyBytesObject_data)
                .c_str());
      }
      if (resolvedOffsets.offsets.PyVarObject_size ==
          BPF_LIB_DEFAULT_FIELD_OFFSET) {
        resolvedOffsets.offsets.PyVarObject_size =
            kCinder310OffsetConfig.PyVarObject_size;
        strobelight_lib_print(
            STROBELIGHT_LIB_INFO,
            fmt::format(
                "Patched 'PyVarObject_size' for cinder runtime {}: {}",
                elfPath,
                resolvedOffsets.offsets.PyVarObject_size)
                .c_str());
      }
    }
  }
  return resolvedOffsets;
}

uintptr_t PyProcessDiscovery::getElfSymbolAddress(
    const strobelight::ElfFile& elf,
    const std::string& elfPath,
    std::optional<strobelight::ElfFile::Symbol>& symbol) {
  if (!symbol.has_value()) {
    return 0;
  }

  strobelight_lib_print(
      STROBELIGHT_LIB_INFO,
      fmt::format(
          "Found '{}' @ {:#x} in {} section of {}",
          symbol->name,
          symbol->sym.st_value,
          elf.getSectionName(symbol->sym.st_shndx),
          elfPath)
          .c_str());

  return symbol->sym.st_value;
}

const char* PyProcessDiscovery::getElfSymbolStringValue(
    const strobelight::ElfFile& elf,
    const std::string& elfPath,
    const std::optional<strobelight::ElfFile::Symbol>& symbol) {
  if (!symbol.has_value()) {
    return nullptr;
  }

  const GElf_Addr* addrPtr = elf.getSymbolValue<GElf_Addr>(symbol.value());

  if (addrPtr == nullptr) {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format("getSymbolValue failed for: {}", symbol->name).c_str());
    return nullptr;
  }

  GElf_Addr addr = *addrPtr;

  const bool isLib = elf.eType() == ET_DYN;

  if (addr == 0 && isLib) {
    // addr could be 0 for position independent ELF (i.e. shared lib)
    // Adjust the address with data from the relocation section to
    // get the actual offset
    addr += elf.getRelocationAdjustment(*symbol);
  }

  strobelight_lib_print(
      STROBELIGHT_LIB_INFO,
      fmt::format(
          "Found '{}' @ {:#x} in {} section of {}.",
          symbol->name,
          addr,
          elf.getSectionName(symbol->sym.st_shndx),
          elfPath)
          .c_str());

  const char* value = elf.getAddressValue<const char>(addr);

  if (value == nullptr) {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format("Invalid section for addr:{:#x}", addr).c_str());
  } else {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format(
            "String value for '{}' addr:{:#x} is '{}'",
            symbol->name,
            addr,
            value)
            .c_str());
  }
  return value;
}

PyPidData PyProcessDiscovery::computePyPidData(
    const PyBinaryInfo& pyBinaryInfo,
    uintptr_t baseLoadAddr,
    uintptr_t exePyRuntimeAddr) {
  PyPidData pidData = pyBinaryInfo.pidData;

  // A Python runtime and all of its symbols normally live in a single
  // module - either a shared library (e.g. libPython*.so) for most
  // fbcode Python code - or in the executable if the Python
  // runtime is statically linked (e.g. uwsgi).
  if (exePyRuntimeAddr != 0) {
    // In some situations it is possible for a copy of _PyRuntime to be
    // linked the executable but for the runtime itself to remain
    // dynamically linked. In that case the _PyRuntime symbol in the exe
    // trumps the copy in the Python runtime shared library - and it is
    // the exe copy that PyPerf cares about. See T151754482 for more
    // info.
    if (pidData.py_runtime_addr != 0) { // cpython >= 3.7
      // Rebase the previously computed _PyRuntime relative addresses to the
      // copy in the executable.
      pidData.tls_key_addr =
          pidData.tls_key_addr - pidData.py_runtime_addr + exePyRuntimeAddr;
      pidData.current_state_addr = pidData.current_state_addr -
          pidData.py_runtime_addr + exePyRuntimeAddr;
    }
  } else if (pyBinaryInfo.elfType == ET_DYN) {
    // Adjust by baseLoadAddr to convert file to memory addresses.
    // For each Python binary the default (unrelocated) file addresses are
    // cached in pythonBinaryInfoCache_ because they are the same across all
    // processes employing the same binary. Due to Linux address space layout
    // randomization (ASLR) the same Python runtime will be loaded at a
    // different base address in each process.
    if (pidData.current_state_addr != 0) {
      pidData.current_state_addr += baseLoadAddr;
    }
    if (pidData.tls_key_addr != 0) {
      pidData.tls_key_addr += baseLoadAddr;
    }
    if (pidData.gil_locked_addr != 0) {
      pidData.gil_locked_addr += baseLoadAddr;
    }
    if (pidData.gil_last_holder_addr != 0) {
      pidData.gil_last_holder_addr += baseLoadAddr;
    }
  }
  return pidData;
}

} // namespace facebook::strobelight::bpf_lib::python
