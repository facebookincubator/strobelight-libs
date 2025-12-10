// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/util/ProcessDiscovery.h"

#include <thread>

#include "strobelight/bpf_lib/util/pid_info/SharedPidInfo.h"
#include "strobelight/bpf_lib/util/pid_info/SharedPidInfoCache.h"

namespace facebook::strobelight::bpf_lib {

PidCallback chainDiscoveryCallbacks(
    const std::vector<VoidPidCallback>& callbacks) {
  return
      [&](std::shared_ptr<pid_info::SharedPidInfo>& pidInfo) -> PidIterControl {
        for (const auto& cb : callbacks) {
          cb(pidInfo);
        }
        return PidIterControl::CONTINUE;
      };
}

void iteratePids(
    const PidCallback& callback,
    const std::set<pid_t>& targetedPids,
    const std::string& chrootDir) {
  auto pids = !targetedPids.empty()
      ? std::vector<pid_t>((targetedPids).begin(), (targetedPids).end())
      : pid_info::SharedPidInfo::getRunningPids(chrootDir);

  auto pidInfoCache = chrootDir.empty()
      ? pid_info::getSharedPidInfoCache()
      : std::make_shared<pid_info::SharedPidInfoCache>(chrootDir);

  for (const auto& pid : pids) {
    auto pidInfo = pidInfoCache->get(pid);
    if (!pidInfo || !pidInfo->isAlive()) {
      continue;
    }
    if (callback(pidInfo) == PidIterControl::BREAK) {
      break;
    }
  }
}

} // namespace facebook::strobelight::bpf_lib
