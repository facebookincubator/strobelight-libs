// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "strobelight/bpf_lib/include/logging.h"
#include "strobelight/bpf_lib/python/discovery/IPyProcessDiscovery.h"
#include "strobelight/bpf_lib/python/discovery/PyProcessDiscovery.h"
#include "strobelight/bpf_lib/util/pid_info/SharedPidInfoCache.h"

namespace facebook::strobelight::bpf_lib::discovery {

using TSharedPidInfo = facebook::strobelight::bpf_lib::pid_info::SharedPidInfo;
using TSharedPidInfoCache =
    facebook::strobelight::bpf_lib::pid_info::SharedPidInfoCache;

} // namespace facebook::strobelight::bpf_lib::discovery

extern "C" {

struct stack_walker_discovery_opts {};

inline void discover(
    const std::set<pid_t>& pidSet,
    stack_walker_discovery_opts*,
    std::shared_ptr<
        facebook::strobelight::bpf_lib::discovery::TSharedPidInfoCache>& pic,
    std::shared_ptr<facebook::strobelight::IPyProcessDiscovery>& ppd) {
  pic = facebook::strobelight::bpf_lib::pid_info::getSharedPidInfoCache();
  auto pyProcessDiscovery = std::make_shared<
      facebook::strobelight::bpf_lib::python::PyProcessDiscovery>();
  if (pyProcessDiscovery != nullptr) {
    pyProcessDiscovery->findPythonPids(pidSet);
    ppd = pyProcessDiscovery;
  }
}

} // extern "C"
