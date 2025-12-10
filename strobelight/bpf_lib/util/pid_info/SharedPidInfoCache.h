// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

#include "strobelight/bpf_lib/util/pid_info/SharedPidInfo.h"

namespace facebook::strobelight::bpf_lib::pid_info {

// Thread-safe cache on top of SharedPidInfo objects. The main difference
// between this class and the original pid_info::PidInfoCache is that this class
// only ever returns a const SharedPidInfo shared_ptr. This
// enables shared / thread-safe access without taking an external lock (more
// than one thread can read from the same SharedPidInfo const info at a time).
class SharedPidInfoCache {
  using clock = std::chrono::steady_clock;

 public:
  // The rootDir parameter is so that in Unit Tests we can make the entire
  // class run under a temporary directory and create mock procfs files.
  explicit SharedPidInfoCache(std::filesystem::path rootDir = "")
      : rootDir_(std::move(rootDir)) {}

  // Find (or add) the SharedPidInfo (const SharedPidInfo) for the
  // requested pid.
  //
  // During the optional initFn is the only non-const access to
  // cached SharedPidInfo and can be used to populate or override some
  // information about the pid. This can be useful if the process has exited but
  // a usable name is known (e.g. comm).
  std::shared_ptr<SharedPidInfo> get(
      pid_t pid,
      std::optional<std::function<bool(SharedPidInfo& newPidInfo)>> initFn =
          std::nullopt,
      clock::time_point now = clock::now());

  size_t size() const {
    const std::lock_guard<std::mutex> lock(cacheMutex_);
    return cache_.size();
  }

  // Remove items from the cache that were not accessed in the last 'interval'.
  size_t removeUnused(
      clock::duration interval,
      clock::time_point now = clock::now());

 private:
  std::filesystem::path rootDir_;

  struct CacheData {
    // last time we verified the start time matches (pid hasn't been reused)
    mutable std::atomic<clock::time_point> lastCheck;
    // last time get(pid) was called
    mutable std::atomic<clock::time_point> lastAccess;

    std::shared_ptr<SharedPidInfo> pidInfo;

    explicit CacheData(
        std::shared_ptr<SharedPidInfo> pidInfo_,
        clock::time_point now = clock::now())
        : lastCheck(now), lastAccess(now), pidInfo(pidInfo_) {}

    CacheData(const CacheData& other)
        : lastCheck(other.lastCheck.load()),
          lastAccess(other.lastAccess.load()),
          pidInfo(other.pidInfo) {}

    CacheData& operator=(CacheData& other) {
      lastCheck.store(other.lastCheck.load());
      lastAccess.store(other.lastAccess.load());
      pidInfo = other.pidInfo;
      return *this;
    }
  };

  mutable std::unordered_map<pid_t, CacheData> cache_;
  mutable std::mutex cacheMutex_;
};

std::shared_ptr<SharedPidInfoCache> getSharedPidInfoCache();

} // namespace facebook::strobelight::bpf_lib::pid_info
