// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <sys/types.h>
#include <optional>
#include <set>
#include <string>

#include <fmt/format.h>

namespace facebook::strobelight {

/**
 * Pure virtual interface for PyProcessDiscovery implementations.
 * This interface defines the common APIs shared between:
 * - strobelight/bpf_lib/python/discovery/PyProcessDiscovery
 * - strobelight/server/pyperf/PyProcessDiscovery
 */
class IPyProcessDiscovery {
 public:
  virtual ~IPyProcessDiscovery() = default;

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

  /**
   * Update the PID configuration table in the BPF map.
   * @param mapFd File descriptor of the BPF map
   * @return true if successful, false otherwise
   */
  virtual bool updatePidConfigTable(int mapFd) const = 0;

  /**
   * Update the PID configuration table for a specific PID.
   * @param mapFd File descriptor of the BPF map
   * @param pid Process ID to update
   * @return true if successful, false otherwise
   */
  virtual bool updatePidConfigTableForPid(int mapFd, pid_t pid) const = 0;

  /**
   * Update the binary ID configuration table in the BPF map.
   * @param mapFd File descriptor of the BPF map
   */
  virtual void updateBinaryIdConfigTable(int mapFd) const = 0;

  /**
   * Get the set of Python process IDs.
   * @return Set of Python PIDs
   */
  virtual std::set<pid_t> getPythonPids() const = 0;

  /**
   * Get Python runtime information for a specific PID.
   * @param pid Process ID to query
   * @return PyRuntimeInfo if the PID is a Python process, std::nullopt
   * otherwise
   */
  virtual std::optional<PyRuntimeInfo> getPyRuntimeInfo(pid_t pid) const = 0;

  /**
   * Get the name of a Python interpreter type.
   * @param interpreter The interpreter type
   * @return String name of the interpreter
   */
  static const char* getPyInterpreterName(PyInterpreter interpreter);
};

} // namespace facebook::strobelight
