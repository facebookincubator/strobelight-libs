// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/python/pystacks/pystacks.h"

// @oss-disable: #include <bpf/uapi/linux/bpf.h>
#include <linux/bpf.h> // @oss-enable
#include <re2/re2.h>

#include <fmt/ostream.h>
#include <iterator>
#include <optional>
#include <set>
#include <vector>

#include <algorithm>
#include <iostream>

#include <shared_mutex>

extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
}

#include <string>
#include "strobelight/bpf_lib/include/FunctionSource.h"
#include "strobelight/bpf_lib/python/discovery/IPyProcessDiscovery.h"

#include "strobelight/bpf_lib/python/include/PySymbolStructs.h"
#include "strobelight/bpf_lib/python/include/structs.h"
#include "strobelight/bpf_lib/python/pystacks.subskel.h"
#include "strobelight/bpf_lib/util/BpfLibLogger.h"

// @oss-disable: #include "strobelight/bpf_lib/python/facebook/DiscoveryUtil.h"
#include "strobelight/bpf_lib/python/DiscoveryUtil.h" // @oss-enable

using namespace facebook::strobelight::bpf_lib::python;

extern "C" {

struct stack_walker_run {
  pystacks_subskel* skel_{nullptr};

  bool manualSymbolRefresh_{};

  // IMPORTANT: pyProcessDiscovery_ must be declared before pidInfoCache_
  // because C++ destroys members in reverse declaration order.
  // pyProcessDiscovery_ holds references to OffsetResolver objects that may
  // be managed by pidInfoCache_, so pyProcessDiscovery_ must be destroyed first
  // while pidInfoCache_ is still valid.
  std::shared_ptr<facebook::strobelight::IPyProcessDiscovery>
      pyProcessDiscovery_;
  std::shared_ptr<
      facebook::strobelight::bpf_lib::discovery::TSharedPidInfoCache>
      pidInfoCache_;
  std::vector<std::string> moduleIdentifierKeywords_;

  std::shared_mutex mapsMutex_;
  std::unordered_map<symbol_id_t, PySymbol> symbols_;
  std::unordered_map<symbol_id_t, bool> garbledSymbolIds_;
};

} // extern "C"

namespace {

struct PySymbolLookupResult {
  bool found = false;
  std::string symbol;
  bool garbled = false;
};

static const re2::RE2 kProfilingStackMetadataRegex(
    ".*profiling.stack_metadata:.*#.*");
static const re2::RE2 kValidPythonSymbolRegex(
    "[\\w\\s\\[\\]\\/\\\\\\:\\.\\-\\<\\>\\#]*");

template <typename T>
inline bool lockedContains(
    const std::unordered_map<symbol_id_t, T>& targetMap,
    std::shared_mutex& targetMutex,
    symbol_id_t& symbol) {
  std::shared_lock<std::shared_mutex> rlock(targetMutex);
  return targetMap.contains(symbol);
}

std::string getModuleNameFromFileName(
    struct stack_walker_run* run,
    const std::string& file) {
  // Seach file path to determine where module name should start
  size_t maxBoundary = std::string::npos;
  std::string matchedKeyword;
  // Find the matching keyword that is farthest into the file path string
  for (const auto& keyword : run->moduleIdentifierKeywords_) {
    size_t trimBoundary = file.rfind(keyword);
    if (trimBoundary != std::string::npos &&
        (maxBoundary == std::string::npos ||
         trimBoundary + keyword.size() > maxBoundary)) {
      maxBoundary = trimBoundary + keyword.size();
      matchedKeyword = keyword;
    }
  }

  // If there was a matching keyword in the file path string, then find next
  // leading "/" to trim from. If the matched keyword ends with a "/" then we
  // will assume that is the leading "/" where trimming should start
  if (maxBoundary != std::string::npos && !matchedKeyword.ends_with("/")) {
    maxBoundary = file.find('/', maxBoundary);
    // If we are able to find a following "/" increment the boundary to trim it
    if (maxBoundary != std::string::npos) {
      maxBoundary++;
    }
  }
  // If we're unable to find a suitable position to trim the filename, exclude
  // it from the frame name
  if (maxBoundary == std::string::npos) {
    return "";
  }
  // Trim the file string if we were able to find an appropriate boundary
  auto moduleName = file.substr(maxBoundary);

  // Trim off the .py file extension if it exists
  if (moduleName.ends_with(".py")) {
    moduleName.erase(moduleName.size() - 3);
  }
  // Properly filter module name as a path
  moduleName = std::filesystem::path(moduleName).lexically_normal().string();
  std::replace(moduleName.begin(), moduleName.end(), '/', '.');
  return moduleName;
}

std::string getSymbolName(
    struct stack_walker_run* run,
    const struct pystacks_symbol& sym) {
  // Read the first string in the qualname field (until it reaches the
  // termination character '\0')
  // There are a few cases that may happen when reading the qualname string:
  // 1. We read a qualname (<class>.<function>) and it is shorter than or equal
  // to the max classname length (BPF_LIB_PYSTACKS_CLASS_NAME_LEN)
  // 2. We read a qualname (<class>.<function>) and it is longer than the max
  // classname length (BPF_LIB_PYSTACKS_CLASS_NAME_LEN)
  // 3. We read a classname (<class>) which is guaranteed to be shorter than or
  // equal to the max classname length (BPF_LIB_PYSTACKS_CLASS_NAME_LEN). This
  // case only happens if we are unable to read the qualname attribute from the
  // PyCodeObject in bpf and fell back to the old method of reading class and
  // function
  std::string qualname =
      std::string(sym.qualname.value).substr(0, BPF_LIB_PYSTACKS_QUAL_NAME_LEN);

  // Case 1 and 2 require no action as we already have the qualname
  // Case 3 requires us to read the function name from the second partition of
  // the qualname memory and combine them in the <class>.<function> format
  // However, case 2 and case 3 intersect, in that the qualname is shorter than
  // or equal to the max length of a class (BPF_LIB_PYSTACKS_CLASS_NAME_LEN). So
  // we need to differentiate the two cases and perform actions accordingly
  if (qualname.length() <= BPF_LIB_PYSTACKS_CLASS_NAME_LEN) {
    // To differentiate between case 2 and case 3, we try to read the function
    // name from the second partition of qualname memory
    std::string funcNameStr =
        std::string(sym.qualname.value + BPF_LIB_PYSTACKS_CLASS_NAME_LEN)
            .substr(0, BPF_LIB_PYSTACKS_FUNCTION_NAME_LEN);
    // If the function name is empty, then we've hit case 2 or a special part of
    // case 3 where class exists and function does not. Both these cases do not
    // require additional action If the function name is not empty, we need to
    // combine it with the class name in the appropriate format
    if (funcNameStr.length() > 0) {
      if (qualname.length() > 0) {
        qualname = fmt::format("{}.{}", qualname, funcNameStr);
      } else {
        qualname = std::move(funcNameStr);
      }
    }
  }

  std::string moduleName = getModuleNameFromFileName(run, sym.filename.value);
  if (moduleName.empty()) {
    return qualname;
  }
  return fmt::format("{}:{}", moduleName, qualname);
}

bool initPyLineTable(
    struct stack_walker_run* run,
    int linetablesFd,
    PySymbol& pySymbol,
    symbol_id_t id) {
  struct pystacks_line_table linetable = {};
  if (bpf_map_lookup_elem(linetablesFd, &id, &linetable) != 0) {
    return false;
  }

  auto pidInfo = run->pidInfoCache_->get(linetable.pid);
  if (!pidInfo) {
    return false;
  }

  if (linetable.addr == 0 || linetable.length == 0 ||
      linetable.first_line == 0 || linetable.pid == 0) {
    return false;
  }

  auto pyRuntimeInfo =
      run->pyProcessDiscovery_->getPyRuntimeInfo(linetable.pid);
  if (pyRuntimeInfo == std::nullopt) {
    return false;
  }

  strobelight_lib_print(
      STROBELIGHT_LIB_INFO,
      fmt::format(
          "initPyLineTable Line table for '{}' in {} is @ {:#x} (length:{} first_line:{})",
          pySymbol.funcname,
          pidInfo->getPid(),
          linetable.addr,
          linetable.length,
          linetable.first_line)
          .c_str());

  pySymbol.linetable = PyLineTable(
      *pidInfo,
      linetable.first_line,
      linetable.addr,
      linetable.length,
      pyRuntimeInfo->versionMajor,
      pyRuntimeInfo->versionMinor);

  return true;
}

void initPySymbols(
    struct stack_walker_run* run,
    int symbolsFd,
    int linetablesFd) {
  size_t newSymbols = 0;
  size_t missingSymbols = 0;
  size_t missingLinetables = 0;
  size_t totalSymbols = 0;

  // used long instead of size_t to avoid clangtidy lint issue
  long totalBPFSymbols = 0;
  long duplicateSymbols = 0;
  long missingQualnameRecoverySymbol = 0;
  struct pystacks_symbol* curSym = nullptr;
  struct pystacks_symbol nextSym = {};
  symbol_id_t id;

  // Iterate over all element in the symbols map. The first iteration with
  // `curSym` = nullptr` will return the first element in the map.
  // https://www.kernel.org/doc/Documentation/bpf/map_hash.rst

  // @lint-ignore CLANGTIDY facebook-hte-NullableDereference
  for (; ::bpf_map_get_next_key(symbolsFd, curSym, &nextSym) == 0;
       curSym = &nextSym) {
    totalBPFSymbols++;
    // Look up the corresponding id for the symbol.
    if (bpf_map_lookup_elem(symbolsFd, &nextSym, &id) != 0) {
      missingSymbols++;
      strobelight_lib_print(
          STROBELIGHT_LIB_INFO,
          fmt::format(
              "Failed to lookup id for symbol {}.{}",
              nextSym.filename.value,
              nextSym.qualname.value)
              .c_str());
      continue;
    }
    if (lockedContains(run->symbols_, run->mapsMutex_, id)) {
      duplicateSymbols++;
      continue; // symbol already cached
    }

    if (nextSym.qualname.fault_addr != 0) {
      // Attempt to read qualname again if a page fault occurred in bpf.
      auto pidInfo = run->pidInfoCache_->get(nextSym.fault_pid);
      if (pidInfo &&
          pidInfo->readMemory(
              nextSym.qualname.value,
              (const void*)nextSym.qualname.fault_addr,
              BPF_LIB_PYSTACKS_QUAL_NAME_LEN) > 0) {
      } else {
        strobelight_lib_print(
            STROBELIGHT_LIB_INFO,
            fmt::format(
                "Failed to read qualname for symbol id {} at {:#x} in {}",
                id,
                nextSym.qualname.fault_addr,
                pidInfo->getPid())
                .c_str());
        missingQualnameRecoverySymbol++;
        continue; // no qualname - not useful
      }
    }

    if (nextSym.filename.fault_addr != 0) {
      // Attempt to read filename again if a page fault occurred in bpf.
      auto pidInfo = run->pidInfoCache_->get(nextSym.fault_pid);
      if (pidInfo &&
          pidInfo->readMemory(
              nextSym.filename.value,
              (const void*)nextSym.filename.fault_addr,
              BPF_LIB_PYSTACKS_FILE_NAME_LEN) > 0) {
      } else {
        strobelight_lib_print(
            STROBELIGHT_LIB_INFO,
            fmt::format(
                "Failed to read filename for symbol id {} at {:#x} in {}",
                id,
                nextSym.qualname.fault_addr,
                pidInfo->getPid())
                .c_str());
        // still have qualname so not skipping symbol
      }
    }

    { // scope to wlock symbols_ during modificaton
      std::unique_lock<std::shared_mutex> wlock(run->mapsMutex_);
      auto& pySymbol = run->symbols_[id];
      pySymbol.funcname = getSymbolName(run, nextSym);
      newSymbols++;

      strobelight_lib_print(
          STROBELIGHT_LIB_INFO,
          fmt::format("Mapped Python symbol {} -> {}", id, pySymbol.funcname)
              .c_str());

      pySymbol.filename = nextSym.filename.value;
      if (!initPyLineTable(run, linetablesFd, pySymbol, id)) {
        missingLinetables++;
      }
      totalSymbols = run->symbols_.size();
    }
  } // scope to wlock symbols_
  if (totalBPFSymbols > 0) {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format(
            "BPF symbols FD table contains {} symbols. ", totalBPFSymbols)
            .c_str());
  }
  if (newSymbols > 0) {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format(
            "Added {} Python symbols to userspace ({} total)",
            newSymbols,
            totalSymbols)
            .c_str());
  }
  if (missingSymbols > 0) {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format("Failed to initialize {} symbols.", missingSymbols)
            .c_str());
  }
  if (duplicateSymbols > 0) {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format("Duplicate {} BPF symbols, skipped.", duplicateSymbols)
            .c_str());
  }
  if (missingQualnameRecoverySymbol > 0) {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format(
            "Unrecoverable qualname (even with fault_pid) for {} symbols.",
            missingQualnameRecoverySymbol)
            .c_str());
  }
  if (missingLinetables > 0) {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format("Failed to initialize {} livetables.", missingLinetables)
            .c_str());
  }
}

PySymbolLookupResult resolvePySymbol(
    struct stack_walker_run* run,
    symbol_id_t id) {
  PySymbolLookupResult result;
  if (!lockedContains(run->symbols_, run->mapsMutex_, id)) {
    // if we have a miss, reload from bpf and try again
    if (!run->manualSymbolRefresh_) {
      initPySymbols(
          run,
          bpf_map__fd(run->skel_->maps.pystacks_symbols),
          bpf_map__fd(run->skel_->maps.pystacks_linetables));
    }

    if (!lockedContains(run->symbols_, run->mapsMutex_, id)) {
      return result;
    }
  }

  { // scope for locking symbols_
    std::shared_lock<std::shared_mutex> rlock(run->mapsMutex_);
    auto symbIt = run->symbols_.find(id);
    if (symbIt == run->symbols_.end()) {
      // shouldn't happen
      return result;
    }
    result.symbol.assign(symbIt->second.funcname);
  }

  result.found = true;

  if (RE2::FullMatch(result.symbol, kProfilingStackMetadataRegex)) {
    return result;
  }

  if (lockedContains(run->garbledSymbolIds_, run->mapsMutex_, id)) {
    { // rlock scope
      std::shared_lock<std::shared_mutex> rlock(run->mapsMutex_);
      auto knownGarbled = run->garbledSymbolIds_.find(id);
      if (knownGarbled != run->garbledSymbolIds_.end()) {
        result.garbled = knownGarbled->second;
      }
    } // rlock scope
  } else {
    result.garbled = !RE2::FullMatch(result.symbol, kValidPythonSymbolRegex);
    { // wlock scope
      std::unique_lock<std::shared_mutex> wlock(run->mapsMutex_);
      run->garbledSymbolIds_.emplace(id, result.garbled);
    } // wlock scope
  }
  return result;
}

using facebook::strobelight::bpf_lib::python::FunctionSource;

FunctionSource resolvePySource(
    struct stack_walker_run* run,
    const struct stack_walker_frame& frame) {
  FunctionSource source;
  source.metadata = FrameMetadata::USER;
  source.line = 0;

  { // scope for locking symbols_
    std::shared_lock<std::shared_mutex> rlock(run->mapsMutex_);
    auto symbIt = run->symbols_.find(frame.symbol_id);
    if (symbIt != run->symbols_.end()) {
      source.file = symbIt->second.filename;
      if (symbIt->second.linetable) {
        source.line =
            symbIt->second.linetable->getLineForInstIndex(frame.inst_idx);
      } else {
        source.line = STACK_WALKER_NO_LINE_INFORMATION;
      }
    }
  }

  strobelight_lib_print(
      STROBELIGHT_LIB_INFO,
      fmt::format(
          "Resolved frame w/ symbol_id:{} inst_idx:{} to {}:{}",
          frame.symbol_id,
          frame.inst_idx,
          source.file,
          source.line)
          .c_str());

  return source;
}

} // namespace

extern "C" {
void pystacks_free(struct stack_walker_run* run) {
  if (nullptr == run) {
    return;
  }
  pystacks_subskel__destroy(run->skel_);
  delete run;
}

struct stack_walker_run* pystacks_init(
    struct bpf_object* bpf_skel_obj,
    struct stack_walker_opts& opts,
    struct stack_walker_discovery_opts* discovery_opts) {
  std::set<pid_t> pidSet;

  if (nullptr != opts.pids) {
    for (size_t idx = 0; idx < opts.pidCount; ++idx) {
      pidSet.insert(opts.pids[idx]);
    }
  }

  auto run = new (std::nothrow) stack_walker_run();

  if (nullptr == run) {
    // @lint-ignore CLANGTIDY facebook-hte-NullableReturn
    return nullptr;
  }

  run->manualSymbolRefresh_ = opts.manualSymbolRefresh;

  run->skel_ = pystacks_subskel__open(bpf_skel_obj),

  discover(
      pidSet, discovery_opts, run->pidInfoCache_, run->pyProcessDiscovery_);

  run->skel_->bss.pid_target_helpers_prog_cfg->has_targeted_pids = true;

  size_t attached_pid_count = 0;
  for (pid_t pid : run->pyProcessDiscovery_->getPythonPids()) {
    bool targeted = true;
    if (bpf_map_update_elem(
            bpf_map__fd(run->skel_->maps.targeted_pids),
            &pid,
            &targeted,
            BPF_ANY) == 0) {
      attached_pid_count++;
    }
  }

  if (attached_pid_count > 0) {
    run->pyProcessDiscovery_->updatePidConfigTable(
        bpf_map__fd(run->skel_->maps.pystacks_pid_config));
    run->pyProcessDiscovery_->updateBinaryIdConfigTable(
        bpf_map__fd(run->skel_->maps.pystacks_binaryid_config));
  }

  strobelight_lib_print(
      STROBELIGHT_LIB_INFO,
      fmt::format("init for pids {}", pidSet.size()).c_str());
  run->skel_->bss.pystacks_prog_cfg->read_leaf_frame = false;
  run->skel_->bss.pystacks_prog_cfg->enable_debug_msgs = false;
  run->skel_->bss.pystacks_prog_cfg->enable_py_src_lines = true;
  run->skel_->bss.pystacks_prog_cfg->stack_max_len = BPF_LIB_MAX_STACK_DEPTH;
  run->skel_->bss.pystacks_prog_cfg->sample_interval = 0;

  return run;
}

int pystacks_symbolize_function(
    struct stack_walker_run* run,
    const struct stack_walker_frame& stackframe,
    char* function_name_buffer,
    size_t function_name_len) {
  if (nullptr == run) {
    return -STACK_WALKER_INVALID_RUN;
  }

  auto function_symbol = resolvePySymbol(run, stackframe.symbol_id);

  if (!function_symbol.found) {
    return -STACK_WALKER_SYMBOL_NOT_FOUND;
  }

  if (function_symbol.garbled) {
    return -STACK_WALKER_GARBLED_SYMBOL;
  }

  const auto len = function_symbol.symbol.length();

  // >= so we have a space for the \0
  if (len >= function_name_len) {
    return -STACK_WALKER_BUFFER_TOO_SMALL;
  }

  strncpy(
      function_name_buffer, function_symbol.symbol.c_str(), function_name_len);

  return len;
}

int pystacks_symbolize_filename_line(
    struct stack_walker_run* run,
    const struct stack_walker_frame& stackframe,
    char* filename_buffer,
    size_t filename_len,
    size_t& line_number) {
  if (nullptr == run) {
    return -STACK_WALKER_INVALID_RUN;
  }

  auto filename_symbol = resolvePySource(run, stackframe);

  if (!filename_symbol.file.empty()) {
    strncpy(filename_buffer, filename_symbol.file.c_str(), filename_len);
    filename_buffer[filename_len - 1] = 0;
    line_number = filename_symbol.line;
  }

  return std::min(filename_len - 1, filename_symbol.file.size());
}

void pystacks_load_symbols(struct stack_walker_run* run) {
  initPySymbols(
      run,
      bpf_map__fd(run->skel_->maps.pystacks_symbols),
      bpf_map__fd(run->skel_->maps.pystacks_linetables));
}

} // extern "C"
