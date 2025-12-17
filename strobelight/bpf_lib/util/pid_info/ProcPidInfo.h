// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <sys/types.h>

#include <bitset>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <strobelight/bpf_lib/util/ElfFile.h>

namespace facebook::strobelight::bpf_lib::pid_info {

// Stats read from /proc/[pid]/stat
// Keep types for utime, stime, num_threads specified in 'man proc'
struct Stats {
  unsigned long utime;
  unsigned long stime;
  long threadCount;
  int64_t rssBytes;
};

struct MemoryMapping {
  uintptr_t startAddr;
  uintptr_t endAddr;
  unsigned long long fileOffset;
  bool readable;
  bool writable;
  bool executable;
  bool shared;
  dev_t devMajor;
  dev_t devMinor;
  ino_t inode;
  std::string name;
};

enum class IterControl { CONTINUE, BREAK };

using MemoryMappingCallback = std::function<IterControl(const MemoryMapping&)>;
// Returning a reference to the OPENED Elf file for re-use by the callback fn
using MemoryMappingWithBaseLoadAddressCallback = std::function<IterControl(
    const MemoryMapping&,
    std::optional<uintptr_t>,
    const std::shared_ptr<strobelight::ElfFile>&)>;

// Wrapper for lazily initialized fields (only read and parsed when requested).
// Initialization is thread-safe and will only occur once.
template <typename T>
struct Lazy {
  const T& get(const std::function<void(T& val)>& initFn = [](T& /* t */) {
  }) const {
    std::call_once(flag_, [&] {
      val_ = std::make_unique<T>();
      initFn(*val_);
    });
    return *val_;
  }

 private:
  mutable std::once_flag flag_;
  mutable std::unique_ptr<T> val_;

  // for testing
  friend class PidInfoTestMutator;
  T& getMutable() {
    return const_cast<T&>(get());
  }
};

// This class is not thread safe. Use synchonizaton on top
// of this if you want to use this from multiple threads.
class ProcPidInfo {
 public:
  // The rootDir parameter is so that in Unit Tests we can make the entire
  // class run under a temporary directory and create mock procfs files.
  explicit ProcPidInfo(pid_t pid, std::string rootDir = "");
  // Empty constructor to allow creating a mock as a child class
  explicit ProcPidInfo(std::string rootDir);
  virtual ~ProcPidInfo();

  bool hasValidInfo() const {
    return validInfo_;
  }

  bool isAlive() const;

  /**
   * Basic Process attributes already read on initialization
   */

  pid_t getPid() const;
  pid_t getNSPid() const;
  const std::string& getName() const;
  const std::string& getState() const;
  uid_t getUid() const;
  gid_t getGid() const;
  pid_t getParentPid() const;

  // NOTE: ThreadGroupId (tgid) is the same as PID if the instance was created
  // with an actual process id. You can create ProcPidInfo with a thread ID as
  // well and everything will work fine (/proc/<thread id>/ directory is not
  // listed on 'ls /proc', but thread stats can be read from there) - in that
  // case getThreadGroupId will return the actual process PID that the thread
  // belongs to (tgid in kernel terminology)
  pid_t getThreadGroupId() const;
  pid_t getNSThreadGroupId() const;

  // Memory related information
  std::string getVmSize() const;
  std::string getVmHwm() const;
  std::string getVmRss() const;
  std::string getRssAnon() const;
  std::string getRssFile() const;
  std::string getRssShmem() const;
  std::string getAnonHugePage() const;

  uint64_t getVmSizeBytes() const;
  uint64_t getVmHwmBytes() const;
  uint64_t getVmRssBytes() const;
  uint64_t getRssAnonBytes() const;
  uint64_t getRssFileBytes() const;
  uint64_t getRssShmemBytes() const;

  uint64_t getPssBytes() const;
  uint64_t getPssAnonBytes() const;
  uint64_t getPssFileBytes() const;
  uint64_t getPssShmemBytes() const;
  uint64_t getSwapPssBytes() const;
  uint64_t getAnonHugePageBytes() const;

  uint64_t getSigBlk() const;
  bool testSigBlk(int signum) const;
  uint64_t getSigIgn() const;
  bool testSigIgn(int signum) const;
  uint64_t getSigCgt() const;
  bool testSigCgt(int signum) const;

  static bool isKernelProcessPid(
      pid_t pid,
      const std::filesystem::path& rootDir = "",
      pid_t ppid = -1);
  bool isKernelProcess() const;
  std::optional<std::string> getExe() const;
  const Stats& getStats() const;

  std::chrono::seconds getStartTimeAfterBoot() const;

  /**
   * Process constant attributes only read when requested
   */
  time_t getStartTime() const;
  std::chrono::system_clock::time_point getStartTimeSystemClock() const;

  std::optional<std::string> getChrootPath() const;
  std::optional<std::string> getChrootRelativeExe() const;
  std::filesystem::path getProcfsCwd() const;
  std::optional<std::vector<std::string>> getCmdLine() const;
  std::shared_ptr<std::map<std::string, std::string>> getCgroups() const;
  std::optional<std::string> getPidNamespace() const;
  std::optional<uint64_t> getPidNamespaceId() const;
  std::optional<std::string> getMountNamespace() const;
  std::optional<uint64_t> getMountNamespaceId() const;

  using EnvMap = std::unordered_map<std::string_view, std::string_view>;
  const EnvMap& getEnvVars() const;
  std::optional<std::string> getEnvVar(std::string_view key) const;
  const std::string& getEnvRaw() const;

  /**
   * Common Process environment attributes
   */
  std::optional<std::string> getMallocConf() const;

  // Refresh Process stats
  bool updateStats();

  // Refresh Process basic attributes
  bool updateInfo();
  // Refresh Process proportional set size stats
  bool updatePssStats();

  // Get all TIDs of active Threads of the Process
  std::vector<pid_t> getRunningThreads() const;

  static std::vector<pid_t> getRunningThreadsForPid(
      pid_t pid,
      const std::string& rootDir = "");

  // Read and parse the individual line from a memory map
  static bool readMemoryMapLine(const std::string& line, MemoryMapping& module);

  // Iterate over all Memory mappping entries of the Process
  //
  // Returns true if we successfully iterated over all memory-mappings
  // or completed early because the callback returned BREAK.
  //
  // Returns false if there were any errors iterating over the memory
  // mappings or if the callback exited with an exception.
  bool iterateAllMemoryMappings(const MemoryMappingCallback& callback) const;
  bool iterateAllMemoryMappings(
      const MemoryMappingWithBaseLoadAddressCallback& callback) const;

  static bool iterateAllMemoryMappingsForPid(
      pid_t pid,
      const MemoryMappingCallback& callback,
      const std::string& rootDir = "");
  static bool iterateAllMemoryMappingsForPid(
      pid_t pid,
      const MemoryMappingWithBaseLoadAddressCallback& callback,
      const std::string& rootDir = "");

  // Copy up to `len` bytes starting at address `src` in the process to `dest`
  // (must be at least `len` bytes long).
  //
  // NOTE: There is no guarantee of atomicity. The data being read can be
  // mutated by the process during the read. Suspend the process during the read
  // if this is a concern.
  //
  // Returns number of bytes read or -1 on error.
  // @lint-ignore CLANGTIDY bugprone-easily-swappable-parameters
  ssize_t readMemory(void* dest, const void* src, size_t len) const;

  static ssize_t
  readMemoryFromPid(pid_t pid, void* dest, const void* src, size_t len);

  // Copy a nul-terminated string from the process at the specified `src`
  // address. The `dest` buffer must be at least `maxLen` bytes long.
  // The string written to `dest` is always nul-terminated. Any string
  // longer than `maxLen - 1` will be truncated.
  //
  // NOTE: There is no guarantee of atomicity. The data being read can be
  // mutated by the process during the read. Suspend the process during the read
  // if this is a concern.
  //
  // Returns the length of the string written to `dest`.
  size_t readCString(char* dest, const char* src, size_t maxLen) const;

  static size_t
  readCStringFromPid(pid_t pid, char* dest, const char* src, size_t maxLen);

  // Returns the given \p path relative to the symlink file that points to the
  // process' root filesystem, without actually resolving symlink, specifically:
  //
  // if \p path is empty, returns path to the root filesystem, e.g.
  // "/proc/0/root" if \p path is absolute, returns full path to the file or
  // directory, e.g.
  // "/proc/0/root/etc/twwhoami" for "/etc/twwhoami"
  // if \p path is relative, returns full path to the file or directory, e.g.
  // "/proc/0/root/tmp/perf-1.dump" for "tmp/perf-1.dump"
  std::filesystem::path getProcfsRoot(const std::filesystem::path& path) const;

  static std::filesystem::path getProcfsRootForPid(
      pid_t pid,
      const std::filesystem::path& path,
      const std::filesystem::path& rootDir = "");

  // Get path in procfs relative to the rootDir
  std::filesystem::path getProcfsPath(const std::string& option) const;

  static std::filesystem::path getProcfsPathForPid(
      pid_t pid,
      const std::string& option,
      const std::filesystem::path& rootDir = "");

  // Returns vector of pids of all running processes
  // The rootDir parameter is so that in Unit Tests we can make this static
  // method run under a temporary directory and create mock procfs files.
  static std::vector<pid_t> getRunningPids(const std::string& rootDir = "");

  // Check if the process with the PID exists
  // The rootDir parameter is so that in Unit Tests we can make this static
  // method run under a temporary directory and create mock procfs files.
  static bool pidExists(pid_t pid, const std::string& rootDir = "");

  virtual std::string getScriptName() const;

 protected:
  /**
   * Process constant attributes only read when requested
   */

  // (Re-)Read and parse basic process attributes
  bool readProcInfo();

  // (Re-)Read and parse process memory stats including PSS.
  bool readProcSmapsRollup();

  // (Re-)Reads process stats including CPU time, RSS, Thread count, etc.
  bool readProcStat();

  void readProcExe();

  // Read and store the PID namespace for this process
  void readPidNamespace();

  // Read and parse Process constant attributes when requested
  struct Environment {
    std::string raw;
    EnvMap vars;
  };

  static bool readEnvironmentForPid(
      pid_t pid,
      const std::filesystem::path& rootDir,
      Environment& environment);
  const Environment& getEnvironment() const;

  bool getTargetNamespace(std::string& target_namespace) const;

  static bool readPidListFromDirectory(
      const std::string& path,
      std::vector<pid_t>& result);

  static bool readProcfsFileToString(
      const std::string& filename,
      std::string* contents);

  static bool readProcfsSymlink(
      const std::string& linkname,
      std::string* filename);

  // Basic Process attributes read on initialization
  const pid_t pid_;
  pid_t nspid_ = 0;
  pid_t ppid_;
  pid_t tgid_ = 0;
  pid_t nstgid_ = 0;
  uid_t uid_;
  gid_t gid_;
  std::string name_;
  std::string state_;
  std::optional<std::string> exe_;
  std::chrono::seconds startTimeAfterBoot_ = std::chrono::seconds(0);

  // Process memory attributes to be read from /proc/<pid>/status
  uint64_t vmsize_;
  uint64_t vmhwm_;
  uint64_t vmrss_;
  uint64_t rssanon_;
  uint64_t rssfile_;
  uint64_t rssshmem_;

  // Signal Info Bitfields
  uint64_t sigblk_;
  uint64_t sigign_;
  uint64_t sigcgt_;

  // Process proportional memory attributes read from /proc/<pid>/smaps_rollup
  uint64_t pss_{};
  uint64_t pssanon_{};
  uint64_t pssfile_{};
  uint64_t pssshmem_{};
  uint64_t swappss_{};
  uint64_t anonhugepage_{};

  // Process constant attributes only read when requested
  Lazy<std::chrono::system_clock::time_point> startTime_;
  Lazy<std::optional<std::string>> chrootPath_;
  Lazy<std::optional<std::string>> relativeExe_;
  Lazy<Environment> environment_;
  Lazy<std::shared_ptr<std::map<std::string, std::string>>> cgroups_;
  Lazy<std::optional<std::vector<std::string>>> cmdLine_;
  Lazy<std::optional<std::string>> pidNamespace_;
  Lazy<std::optional<std::string>> mountNamespace_;

  // Stats of the Process
  Stats stats_;

  // ProcPidInfo internals
  std::filesystem::path rootDir_;
  bool validInfo_;
};

} // namespace facebook::strobelight::bpf_lib::pid_info
