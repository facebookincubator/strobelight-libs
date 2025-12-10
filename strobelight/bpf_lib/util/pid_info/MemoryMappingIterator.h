// Copyright (c) Meta Platforms, Inc. and affiliates.
#pragma once

#include <sys/types.h>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

#include <strobelight/bpf_lib/util/ElfFile.h>

#include "strobelight/bpf_lib/util/pid_info/ProcPidInfo.h"

namespace facebook::strobelight::bpf_lib::pid_info {

struct MemoryMapping;

struct MemoryMappingElfInfo {
  std::shared_ptr<strobelight::ElfFile> elfFile;
  uintptr_t baseLoadAddress{0};

  MemoryMappingElfInfo(
      pid_t pid,
      const std::string& rootDir,
      const MemoryMapping& mm);
};

/**
 * Iterator for the memory mappings (VMAs) of a process. Lazily resolves the
 * base load address and ELF file for each mapping (only when requested).
 */
class MemoryMappingIterator {
 public:
  using iterator_category = std::input_iterator_tag;
  using value_type = MemoryMapping;
  using difference_type = std::ptrdiff_t;
  using pointer = const MemoryMapping*;
  using reference = const MemoryMapping&;

  // Default constructor creates an end iterator
  MemoryMappingIterator();

  // Constructor for begin iterator
  MemoryMappingIterator(pid_t pid, std::string rootDir);

  // Copy constructor
  MemoryMappingIterator(const MemoryMappingIterator& other);

  // Move constructor
  MemoryMappingIterator(MemoryMappingIterator&& other) noexcept;

  // Copy assignment operator
  MemoryMappingIterator& operator=(const MemoryMappingIterator& other);

  // Move assignment operator
  MemoryMappingIterator& operator=(MemoryMappingIterator&& other) noexcept;

  ~MemoryMappingIterator();

  reference operator*() const;

  pointer operator->() const;

  MemoryMappingIterator& operator++();

  MemoryMappingIterator operator++(int);

  // Equality operator
  bool operator==(const MemoryMappingIterator& other) const;

  // Inequality operator
  bool operator!=(const MemoryMappingIterator& other) const;

  // Get the base load address for the current mapping
  std::optional<uintptr_t> getBaseLoadAddress() const;

  // Get the ELF file for the current mapping
  std::shared_ptr<strobelight::ElfFile> getElfFile() const;

 private:
  pid_t pid_;
  std::string rootDir_;
  bool atEnd_;

  std::fstream mapFile_;
  std::streampos mapPos_; // tellg isn't const

  MemoryMapping currentMapping_;

  std::unordered_map<std::string, MemoryMapping> elfFileFirstMapping_;
  mutable std::optional<MemoryMappingElfInfo> currentElfInfo_;

  void openProcPidMaps();
  void next();
};

} // namespace facebook::strobelight::bpf_lib::pid_info
