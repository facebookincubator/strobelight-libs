// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/python/discovery/OffsetResolver.h"

#include <algorithm>

namespace facebook::strobelight::bpf_lib {

#define STROBELIGHT_STRINGIFY_HELPER(x) #x
#define STROBELIGHT_STRINGIFY(x) STROBELIGHT_STRINGIFY_HELPER(x)

#define BPF_LIB_MAKE_PROC_SYM_INFO(prefix, name, required) \
  {                                                        \
    prefix STROBELIGHT_STRINGIFY(name), {                  \
      &processOffsets_.name, false, required               \
    }                                                      \
  }

#define BPF_LIB_REQUIRED_SYMBOL(name) \
  BPF_LIB_MAKE_PROC_SYM_INFO("__strobe_", name, true)
#define BPF_LIB_REQUIRED_SYMBOL_SF(name) \
  BPF_LIB_MAKE_PROC_SYM_INFO("__strobe__", name, true)
#define BPF_LIB_OPTIONAL_SYMBOL(name) \
  BPF_LIB_MAKE_PROC_SYM_INFO("__strobe_", name, false)

static constexpr std::string_view kPyOffsetDefaultKey("default");

OffsetResolver::OffsetResolver()
    : headerOffsetsFound_(false),
      headerOffsets_(),
      processOffsets_(),
      symbolNameToInfo_() {
  /* map of
   *  name of global sym in python process ->
   *   (size of sym, addr where to put sym in processOffsets, whether
   * we've seen this sym before)
   */
  symbolNameToInfo_ = {
      BPF_LIB_REQUIRED_SYMBOL(PyObject_type),
      BPF_LIB_REQUIRED_SYMBOL(PyTypeObject_name),
      BPF_LIB_REQUIRED_SYMBOL(PyThreadState_frame),
      BPF_LIB_REQUIRED_SYMBOL(PyThreadState_shadow_frame),
      BPF_LIB_REQUIRED_SYMBOL(PyThreadState_thread),
      BPF_LIB_OPTIONAL_SYMBOL(PyThreadState_interp),
      BPF_LIB_OPTIONAL_SYMBOL(PyInterpreterState_modules),
      BPF_LIB_REQUIRED_SYMBOL(PyFrameObject_back),
      BPF_LIB_REQUIRED_SYMBOL(PyFrameObject_code),
      BPF_LIB_OPTIONAL_SYMBOL(PyFrameObject_lasti),
      BPF_LIB_REQUIRED_SYMBOL(PyFrameObject_localsplus),
      BPF_LIB_REQUIRED_SYMBOL(PyFrameObject_gen),
      BPF_LIB_OPTIONAL_SYMBOL(PyInterpreterFrame_code),
      BPF_LIB_OPTIONAL_SYMBOL(PyInterpreterFrame_previous),
      BPF_LIB_OPTIONAL_SYMBOL(PyInterpreterFrame_localsplus),
      BPF_LIB_OPTIONAL_SYMBOL(PyInterpreterFrame_prev_instr),
      BPF_LIB_OPTIONAL_SYMBOL(_PyCFrame_current_frame),
      BPF_LIB_REQUIRED_SYMBOL(PyGenObject_gi_shadow_frame),
      BPF_LIB_REQUIRED_SYMBOL(PyCodeObject_co_flags),
      BPF_LIB_REQUIRED_SYMBOL(PyCodeObject_filename),
      BPF_LIB_REQUIRED_SYMBOL(PyCodeObject_name),
      BPF_LIB_REQUIRED_SYMBOL(PyCodeObject_varnames),
      BPF_LIB_OPTIONAL_SYMBOL(PyCodeObject_firstlineno),
      BPF_LIB_OPTIONAL_SYMBOL(PyCodeObject_linetable),
      BPF_LIB_OPTIONAL_SYMBOL(PyCodeObject_code_adaptive),
      BPF_LIB_REQUIRED_SYMBOL(PyTupleObject_item),
      BPF_LIB_REQUIRED_SYMBOL(PyCodeObject_qualname),
      BPF_LIB_REQUIRED_SYMBOL(PyCoroObject_cr_awaiter),
      BPF_LIB_REQUIRED_SYMBOL_SF(PyShadowFrame_prev),
      BPF_LIB_REQUIRED_SYMBOL_SF(PyShadowFrame_data),
      BPF_LIB_REQUIRED_SYMBOL_SF(PyShadowFrame_PtrMask),
      BPF_LIB_REQUIRED_SYMBOL_SF(PyShadowFrame_PtrKindMask),
      BPF_LIB_REQUIRED_SYMBOL_SF(PyShadowFrame_PYSF_CODE_RT),
      BPF_LIB_REQUIRED_SYMBOL_SF(PyShadowFrame_PYSF_PYCODE),
      BPF_LIB_REQUIRED_SYMBOL_SF(PyShadowFrame_PYSF_PYFRAME),
      BPF_LIB_REQUIRED_SYMBOL_SF(PyShadowFrame_PYSF_RTFS),
      BPF_LIB_REQUIRED_SYMBOL(CodeRuntime_py_code),
      BPF_LIB_REQUIRED_SYMBOL(RuntimeFrameState_py_code),
      BPF_LIB_REQUIRED_SYMBOL(String_data),
      BPF_LIB_REQUIRED_SYMBOL(TLSKey_offset),
      BPF_LIB_REQUIRED_SYMBOL(TCurrentState_offset),
      BPF_LIB_OPTIONAL_SYMBOL(PyGIL_offset),
      BPF_LIB_OPTIONAL_SYMBOL(PyGIL_last_holder),
      BPF_LIB_OPTIONAL_SYMBOL(PyBytesObject_data),
      BPF_LIB_OPTIONAL_SYMBOL(PyVarObject_size),
      BPF_LIB_OPTIONAL_SYMBOL(PyFrameObject_owner),
      BPF_LIB_OPTIONAL_SYMBOL(PyGenObject_iframe),
      BPF_LIB_REQUIRED_SYMBOL(PyVersion_major),
      BPF_LIB_REQUIRED_SYMBOL(PyVersion_minor),
      BPF_LIB_REQUIRED_SYMBOL(PyVersion_micro),
  };
}

template <typename T>
void OffsetResolver::setOffsetVal(
    const strobelight::ElfFile& elf,
    const strobelight::ElfFile::Symbol& symbol,
    T* addr) {
  const T* val = elf.getSymbolValue<T>(symbol);
  if (val != nullptr) {
    *addr = *val;
  }
}

void OffsetResolver::maybeAddProcessOffsetSymbol(
    const strobelight::ElfFile& elf,
    const strobelight::ElfFile::Symbol& symbol) {
  if (symbol.name.empty()) {
    return;
  }
  auto found = symbolNameToInfo_.find(symbol.name);
  if (found == symbolNameToInfo_.end()) {
    return;
  }
  auto& info = found->second;
  if (info.seen) {
    return;
  }
  info.seen = true;
  std::visit(
      [&](auto* addr) { OffsetResolver::setOffsetVal(elf, symbol, addr); },
      info.addr);
}

template <typename T>
void OffsetResolver::maybeAddProcessOffsetVal(const std::string& name, T& val) {
  auto found = symbolNameToInfo_.find(name);
  if (found == symbolNameToInfo_.end()) {
    return;
  }
  auto& info = found->second;
  if (info.seen) {
    return;
  }
  info.seen = true;
  std::visit([&](auto* addr) { *addr = val; }, info.addr);
}

void OffsetResolver::mergeOffsetResolver(const OffsetResolver& offsetResolver) {
  // Merge process offsets
  for (const auto& symbol : offsetResolver.symbolNameToInfo_) {
    const auto& name = symbol.first;
    const auto& info = symbol.second;
    if (info.seen) {
      std::visit(
          [&](auto arg) {
            OffsetResolver::maybeAddProcessOffsetVal(name, *arg);
          },
          info.addr);
    }
  }
  // Copy header offsets (if this offsetresolver doesn't have header offsets)
  if (!headerOffsetsFound_ && offsetResolver.headerOffsetsFound_) {
    headerOffsetsFound_ = true;
    headerOffsets_ = offsetResolver.headerOffsets_;
  }
}

std::unordered_set<std::string> OffsetResolver::getProcessOffsetSymbolNames() {
  OffsetResolver resolver;
  std::unordered_set<std::string> symbolNames;
  for (const auto& [name, info] : resolver.symbolNameToInfo_) {
    symbolNames.insert(name);
  }
  return symbolNames;
}

const OffsetConfig& OffsetResolver::getHeaderOffsetsForVersion(
    const std::string_view versionString) {
  // look up the appropriate offset config for the version string.
  // Assume an unknown version string is > the latest version, and
  // the latest version will work (i.e. offsets for N will match N+1).
  // The implications of that being wrong is failing to get python
  // stacks, or getting garbage python stacks.
  static const std::unordered_map<std::string_view, OffsetConfig>
      pythonOffsets = {
          {std::string_view("cpython-38"), kPy38OffsetConfig},
          {std::string_view("cpython-39"), kPy39OffsetConfig},
          {std::string_view("cpython-310"), kPy310OffsetConfig},
          {std::string_view("cpython-311"), kPy311OffsetConfig},
          {std::string_view("cpython-312"), kPy312OffsetConfig},
          {kPyOffsetDefaultKey, kPy312OffsetConfig}};

  auto oc = pythonOffsets.find(versionString);
  if (oc == pythonOffsets.end()) {
    return pythonOffsets.at(kPyOffsetDefaultKey);
  } else {
    return oc->second;
  }
}

void OffsetResolver::setHeaderOffsets(const std::string_view versionString) {
  headerOffsets_ = getHeaderOffsetsForVersion(versionString);
  headerOffsetsFound_ = true;
}

bool OffsetResolver::allProcessOffsetsFound() const {
  auto symInfoSeen = [](std::pair<std::string, ProcSymInfo> item) {
    return item.second.seen || !item.second.required;
  };
  return std::all_of(
      symbolNameToInfo_.begin(), symbolNameToInfo_.end(), symInfoSeen);
}

OffsetResolution OffsetResolver::resolveOffsets(bool forceHeaderOffsets) const {
  if (allProcessOffsetsFound() && !forceHeaderOffsets) {
    return {processOffsets_, OffsetResolutionStrategy::Process};
  }
  return {headerOffsets_, OffsetResolutionStrategy::Headers};
}

} // namespace facebook::strobelight::bpf_lib
