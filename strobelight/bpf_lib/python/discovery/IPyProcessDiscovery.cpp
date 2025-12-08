// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/python/discovery/IPyProcessDiscovery.h"

namespace facebook::strobelight {

const char* IPyProcessDiscovery::getPyInterpreterName(
    PyInterpreter interpreter) {
  switch (interpreter) {
    case PY_INTERPRETER_CPYTHON:
      return "cpython";
    case PY_INTERPRETER_CINDER:
      return "cinder";
    default:
      return "unknown";
  }
}

} // namespace facebook::strobelight
