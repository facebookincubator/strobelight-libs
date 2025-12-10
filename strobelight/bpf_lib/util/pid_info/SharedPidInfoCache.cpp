// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/util/pid_info/SharedPidInfoCache.h"

#include <fmt/chrono.h>
#include "strobelight/bpf_lib/util/BpfLibLogger.h"

#include <utility>

namespace facebook::strobelight::bpf_lib::pid_info {

// PIDs can be reused. We assume they will not be reused within 1h.
constexpr std::chrono::hours kCheckPidReuseInterval{1};

std::shared_ptr<pid_info::SharedPidInfoCache> getSharedPidInfoCache() {
  static auto inst = std::make_shared<pid_info::SharedPidInfoCache>();
  return inst;
}

std::shared_ptr<SharedPidInfo> SharedPidInfoCache::get(
    pid_t pid,
    std::optional<std::function<bool(SharedPidInfo&)>> initFn,
    clock::time_point now) {
  const std::lock_guard<std::mutex> lock(cacheMutex_);
  auto cacheIt = cache_.find(pid);
  if (cacheIt != cache_.end()) {
    if (now - cacheIt->second.lastCheck.load() < kCheckPidReuseInterval) {
      cacheIt->second.lastAccess = now;
      return cacheIt->second.pidInfo;
    }
  }

  // Either not in the cache or need to check for pid reuse. Attempt to read
  // info from /proc.
  std::shared_ptr<SharedPidInfo> newPidInfo(new SharedPidInfo(pid, rootDir_));

  if (cacheIt != cache_.end() && !newPidInfo->isKernelProcess()) {
    auto& oldPidInfo = cacheIt->second.pidInfo;
    cacheIt->second.lastAccess = now;

    if (!newPidInfo->hasValidInfo()) {
      return oldPidInfo; // the new info is not an improvement
    }

    if (now - cacheIt->second.lastCheck.load() >= kCheckPidReuseInterval) {
      cacheIt->second.lastCheck = now;

      if (newPidInfo->getStartTimeAfterBoot() ==
          oldPidInfo->getStartTimeAfterBoot()) {
        return oldPidInfo; // it's the same old pid
      }
    }

    cache_.erase(cacheIt);
  }

  // Give initFn an opportunity to mutate the new info
  if (initFn) {
    bool keepIt = (*initFn)(*newPidInfo);
    if (!keepIt) {
      return nullptr;
    }
  } else if (!newPidInfo->hasValidInfo() && !newPidInfo->isKernelProcess()) {
    return nullptr;
  }

  cache_.emplace(pid, CacheData(newPidInfo, now));
  return newPidInfo;
}

// remove items from the cache that were not accessed in the last 'interval'
size_t SharedPidInfoCache::removeUnused(
    clock::duration interval,
    clock::time_point now) {
  const size_t oldCount = cache_.size();
  const std::lock_guard<std::mutex> lock(cacheMutex_);
  size_t removed = 0;
  for (auto it = cache_.cbegin(); it != cache_.cend();) {
    if (now - it->second.lastAccess.load() > interval) {
      it = cache_.erase(it);
      removed++;
    } else {
      ++it;
    }
  }
  const size_t newCount = cache_.size();
  if (removed > 0) {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format(
            "Removed unused entries from SharedPidInfoCache: {} ({} -> {} entries) unused after {}",
            removed,
            oldCount,
            newCount,
            std::chrono::duration_cast<std::chrono::seconds>(interval))
            .c_str());
  }
  return removed;
}

} // namespace facebook::strobelight::bpf_lib::pid_info
