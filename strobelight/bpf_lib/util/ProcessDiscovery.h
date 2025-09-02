// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <functional>
#include "strobelight/bpf_lib/util/pid_info/SharedPidInfo.h"

namespace facebook::strobelight::bpf_lib {

enum PidIterControl : int { CONTINUE, BREAK };

typedef std::function<PidIterControl(pid_info::SharedPidInfo& pidInfo)>
    PidCallback;
typedef std::function<void(pid_info::SharedPidInfo& pidInfo)> VoidPidCallback;

/* Use in combination with iteratePids when doing typical 'discovery'
 * phase where all pids are examined by independent discovery logic e.g.:
 *
 * std::vector<VoidPidCallback> discoCbs{checkStrobemeta, checkHHVM};
 * PidCallback discovery = chainDiscoveryCallbacks(discoCbs);
 * iteratePids(discovery);
 *
 * Meant to reduce duplicate iteration of all pids
 */
PidCallback chainDiscoveryCallbacks(
    const std::vector<VoidPidCallback>& callbacks);

void iteratePids(
    // Returns true to break the loop/iteration
    const PidCallback& callback,
    // If there are specific pids you want to target
    const std::set<pid_t>&,
    // For unit tests
    const std::string& chrootDir = "");

} // namespace facebook::strobelight::bpf_lib
