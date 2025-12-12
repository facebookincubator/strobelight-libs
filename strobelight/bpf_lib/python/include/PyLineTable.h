// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __PY_LINE_TABLE_H__
#define __PY_LINE_TABLE_H__

#include <sys/types.h>
#include <cstdlib>
#include <optional>

// @oss-disable: #include "strobelight/bpf_lib/python/facebook/DiscoveryUtil.h"
#include "strobelight/bpf_lib/python/DiscoveryUtil.h" // @oss-enable

namespace facebook::strobelight::bpf_lib::python {

class PyLineTable {
 public:
  PyLineTable(
      int firstLine,
      const void* data,
      size_t length,
      int pyMajorVer,
      int pyMinorVer);

  PyLineTable(
      discovery::TSharedPidInfo& pidInfo,
      int firstLine,
      uintptr_t addr,
      size_t length,
      int pyMajorVer,
      int pyMinorVer);

  int getLineForInstIndex(int addrq) const;

 private:
  int pyMajorVer_;
  int pyMinorVer_;

  std::vector<uint8_t> data_;
  int firstLine_;

  int getLineForInstIndexDefault(int addrq) const;
  int getLineForInstIndex310(int addrq) const;

  enum IterControl : int { CONTINUE, BREAK };
  void parseLocationTable(
      const std::function<
          IterControl(uintptr_t start, uintptr_t end, int line)>& fn) const;
};

} // namespace facebook::strobelight::bpf_lib::python

#endif // __PY_LINE_TABLE_H__
