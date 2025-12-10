// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/util/pid_info/MemoryMappingIterator.h"

#include <errno.h>
#include <fmt/core.h>
#include <filesystem>
#include <utility>

#include "strobelight/bpf_lib/util/BpfLibLogger.h"
#include "strobelight/bpf_lib/util/pid_info/ProcPidInfo.h"
#include "strobelight/bpf_lib/util/pid_info/ProcUtil.h"

static constexpr std::string_view kAnonHugePage = "/anon_hugepage";
static constexpr std::string_view kDeleted = " (deleted)";

namespace facebook::strobelight::bpf_lib::pid_info {

// Resolving from proc maps is trickier than just resolving the main exe
// directly, due to non-fixed load addresses. The basic algorithm used is as
// follows:
//   For each buildId/binary mapping in /proc/<pid>/maps get the entry
//   with the lowest startAddr (ignoring shared and non-readable mappings);
//   this should happen automatically because they are ordered this way.
//
//   For the buildId iterate over all the ELF program headers and get the
//   default load address (p_vaddr) and offset (p_offset) for the lowest
//   loadable (LOAD) segment. They should be in this order already.
//
//   In order to compute the 'slide'/base-load-address of a shared or
//   relocatable binary we will take the start address of the lowest
//   memory mapping and subtract the fileOffset of the same memory mapping
//   and then substract the difference between the p_vaddr and p_offset above:
//   slide = (mmStartAddr - mmFileOffset) - (lowest p_vaddr - lowest p_offset)
//
//   Most of the time mmFileOffset and lowest p_offset are the same.
//
//   Why?
//   From the ELF spec: https://refspecs.linuxfoundation.org/elf/elf.pdf
//   "Though the system chooses virtual addresses for individual processes, it
//   maintains the segments’ relative positions. Because position-independent
//   code uses relative addressing between segments, the difference between
//   virtual addresses in memory must match the difference between virtual
//   addresses in the file. The difference between the virtual address of any
//   segment in memory and the corresponding virtual address in the file is thus
//   a single constant value for any one executable or shared object in a given
//   process."
//
//   This essentialy means that the base-load-address for each binary (within
//   the context of a process) is the same for all of its memory mappings in
//   order to maintain relative addressing. So all we have to do is find the
//   lowest mapping for each binary, then subtract the fileOffset to get the
//   absolute address that corresponds to file offset zero, then subtract the
//   difference between the default load address (p_vaddr) and the fileOffset
//   (p_offset) from the lowest LOAD segment to get the amount to substract
//   from absolute virtual addresses to the virtual addresses in the
//   ELF file.
//
//   Note: Matching a memory mapping to the LOAD segment(s) in it is hard!
//   You can have instances where multiple memory mappings contain a
//   single LOAD segment (e.g. huge_pages):
//   3fc00000-41600000 r-xp 3d000000 00:1d 257 admarket.adfinder/adfinder
//   41600000-46a95000 r-xp 3ea00000 00:1d 257 admarket.adfinder/adfinder
//   ELF Program Header:
//   Type           Offset             VirtAddr           PhysAddr
//               FileSiz            MemSiz              Flags  Align
//   LOAD           0x000000003d000000 0x000000003fc00000 0x000000003fc00000
//               0x0000000006e94a14 0x0000000006e94a14  R E    0x200000
//
//   There can also be one mapping for several LOAD segments e.g.
//   7f621c2f6000-7f621c51b000 r-xp 00000000 00:1b 129076798 libstdc++.so.6.0.29
//   ELF Program Header:
//   Type           Offset             VirtAddr           PhysAddr
//               FileSiz            MemSiz              Flags  Align
//   LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
//               0x00000000000985f8 0x00000000000985f8  R      0x1000
//   LOAD           0x0000000000099000 0x0000000000099000 0x0000000000099000
//                0x0000000000129759 0x0000000000129759  R E    0x1000
//   LOAD           0x00000000001c3000 0x00000000001c3000 0x00000000001c3000
//                0x000000000006125d 0x000000000006125d  R      0x1000
//
//   There can be memory mappings with NO load segments e.g.
//   7f621cd6d000-7f621cd6e000 ---p 002e2000 00:1b 129103448 libpython3.8.so.1.0
//
//   This is why we're just taking the first non-shared and readable mapping
//   and matching it against the first LOAD segment instead of attempting to
//   find the matching LOAD segment for each memory mapping.
//
//   Note2: Memory Mappings backed by a file marked as (deleted) still resolve
//   to the correct, original file when opening this file via the map_files path
//   (e.g. proc/<pid>/map_files/xxx-yyy); you will be reading the inode that
//   was actually mapped into the process.

MemoryMappingIterator::MemoryMappingIterator()
    : pid_(0), atEnd_(true), mapPos_(0), currentMapping_() {}

MemoryMappingIterator::MemoryMappingIterator(pid_t pid, std::string rootDir)
    : pid_(pid),
      rootDir_(std::move(rootDir)),
      atEnd_(false),
      mapPos_(0),
      currentMapping_() {
  openProcPidMaps();
  if (mapFile_.is_open()) {
    next();
  } else {
    atEnd_ = true;
  }
}

MemoryMappingIterator::MemoryMappingIterator(const MemoryMappingIterator& other)
    : pid_(other.pid_),
      rootDir_(other.rootDir_),
      atEnd_(other.atEnd_),
      mapPos_(other.mapPos_),
      currentMapping_(other.currentMapping_),
      elfFileFirstMapping_(other.elfFileFirstMapping_),
      currentElfInfo_(other.currentElfInfo_) {
  if (!other.atEnd_ && other.mapFile_.is_open()) {
    openProcPidMaps();
    // Seek to the same position
    mapFile_.seekg(mapPos_);
  }
}

MemoryMappingIterator::MemoryMappingIterator(
    MemoryMappingIterator&& other) noexcept
    : pid_(other.pid_),
      rootDir_(std::move(other.rootDir_)),
      atEnd_(other.atEnd_),
      mapPos_(other.mapPos_),
      currentMapping_(std::move(other.currentMapping_)),
      elfFileFirstMapping_(std::move(other.elfFileFirstMapping_)),
      currentElfInfo_(std::move(other.currentElfInfo_)) {
  // Note: We can't move the fstream directly, so we need to close the old one
  // and open a new one
  if (!other.atEnd_ && other.mapFile_.is_open()) {
    // Close the other's file stream
    other.mapFile_.close();
    // Open a new file stream
    openProcPidMaps();
    // Seek to the same position
    mapFile_.seekg(mapPos_);
  }

  // Reset the moved-from object to a valid but empty state
  other.pid_ = 0;
  other.atEnd_ = true;
  other.mapPos_ = 0;
}

MemoryMappingIterator& MemoryMappingIterator::operator=(
    const MemoryMappingIterator& other) {
  if (this != &other) {
    pid_ = other.pid_;
    rootDir_ = other.rootDir_;
    atEnd_ = other.atEnd_;
    mapPos_ = other.mapPos_;
    currentMapping_ = other.currentMapping_;
    elfFileFirstMapping_ = other.elfFileFirstMapping_;
    currentElfInfo_ = other.currentElfInfo_;

    if (mapFile_.is_open()) {
      mapFile_.close();
    }
    if (!other.atEnd_ && other.mapFile_.is_open()) {
      openProcPidMaps();
      // Seek to the same position
      mapFile_.seekg(mapPos_);
    }
  }
  return *this;
}

MemoryMappingIterator& MemoryMappingIterator::operator=(
    MemoryMappingIterator&& other) noexcept {
  if (this != &other) {
    // Close our file stream if open
    if (mapFile_.is_open()) {
      mapFile_.close();
    }

    // Move all member variables
    pid_ = other.pid_;
    rootDir_ = std::move(other.rootDir_);
    atEnd_ = other.atEnd_;
    mapPos_ = other.mapPos_;
    currentMapping_ = std::move(other.currentMapping_);
    elfFileFirstMapping_ = std::move(other.elfFileFirstMapping_);
    currentElfInfo_ = std::move(other.currentElfInfo_);

    // Note: We can't move the fstream directly, so we need to close the old one
    // and open a new one
    if (!other.atEnd_ && other.mapFile_.is_open()) {
      // Close the other's file stream
      other.mapFile_.close();
      // Open a new file stream
      openProcPidMaps();
      // Seek to the same position
      mapFile_.seekg(mapPos_);
    }

    // Reset the moved-from object to a valid but empty state
    other.pid_ = 0;
    other.atEnd_ = true;
    other.mapPos_ = 0;
  }
  return *this;
}

MemoryMappingIterator::~MemoryMappingIterator() {
  if (mapFile_.is_open()) {
    mapFile_.close();
  }
}

MemoryMappingIterator::reference MemoryMappingIterator::operator*() const {
  return currentMapping_;
}

MemoryMappingIterator::pointer MemoryMappingIterator::operator->() const {
  return &currentMapping_;
}

MemoryMappingIterator& MemoryMappingIterator::operator++() {
  next();
  return *this;
}

MemoryMappingIterator MemoryMappingIterator::operator++(int) {
  MemoryMappingIterator tmp(*this);
  next();
  return tmp;
}

bool MemoryMappingIterator::operator==(
    const MemoryMappingIterator& other) const {
  if (atEnd_ && other.atEnd_) {
    return true;
  }
  if (atEnd_ || other.atEnd_) {
    return false;
  }
  return pid_ == other.pid_ &&
      currentMapping_.startAddr == other.currentMapping_.startAddr &&
      currentMapping_.endAddr == other.currentMapping_.endAddr;
}

bool MemoryMappingIterator::operator!=(
    const MemoryMappingIterator& other) const {
  return !(*this == other);
}

void MemoryMappingIterator::openProcPidMaps() {
  auto filename = ProcPidInfo::getProcfsPathForPid(pid_, "maps", rootDir_);
  mapFile_.open(filename, std::ios_base::in);
  if (!mapFile_.is_open()) {
    atEnd_ = true;
  }
  mapPos_ = 0;
}

void MemoryMappingIterator::next() {
  if (atEnd_ || !mapFile_.is_open()) {
    atEnd_ = true;
    return;
  }

  const auto prevDevMajor = currentMapping_.devMajor;
  const auto prevDevMinor = currentMapping_.devMinor;
  const auto prevInode = currentMapping_.inode;

  std::string line;
  std::getline(mapFile_, line);
  mapPos_ = mapFile_.tellg();

  if (!mapFile_ || !ProcPidInfo::readMemoryMapLine(line, currentMapping_)) {
    atEnd_ = true;
    return;
  }

  if (!currentMapping_.shared && currentMapping_.readable) {
    elfFileFirstMapping_.emplace(currentMapping_.name, currentMapping_);
  }

  if (atEnd_ || currentMapping_.devMajor != prevDevMajor ||
      currentMapping_.devMinor != prevDevMinor ||
      currentMapping_.inode != prevInode) {
    // In the common case the mappings for a file are grouped together
    // in /proc/<pid>/maps so it is unlikely that we will thrash the
    // mappingElfInfo_ cache.
    currentElfInfo_ = std::nullopt;
  }
}

std::optional<uintptr_t> MemoryMappingIterator::getBaseLoadAddress() const {
  if (!currentElfInfo_.has_value()) {
    auto itr = elfFileFirstMapping_.find(currentMapping_.name);
    if (itr == elfFileFirstMapping_.end()) {
      return std::nullopt;
    }
    currentElfInfo_ = MemoryMappingElfInfo(pid_, rootDir_, itr->second);
  }
  return currentElfInfo_->baseLoadAddress;
}

std::shared_ptr<strobelight::ElfFile> MemoryMappingIterator::getElfFile()
    const {
  if (!currentElfInfo_.has_value()) {
    auto itr = elfFileFirstMapping_.find(currentMapping_.name);
    if (itr == elfFileFirstMapping_.end()) {
      static const std::shared_ptr<strobelight::ElfFile> kEmpty;
      return kEmpty;
    }
    currentElfInfo_ = MemoryMappingElfInfo(pid_, rootDir_, itr->second);
  }
  return currentElfInfo_->elfFile;
}

MemoryMappingElfInfo::MemoryMappingElfInfo(
    pid_t pid,
    const std::string& rootDir,
    const MemoryMapping& mm) {
  // Skip shared or non-readable mappings
  if (mm.shared || !mm.readable) {
    return;
  }

  // Skip mappings without a name or with non-absolute paths
  if (mm.name.empty() || mm.name[0] != '/' ||
      (mm.name.starts_with(kAnonHugePage))) {
    return;
  };

  elfFile = std::make_shared<strobelight::ElfFile>();

  // /proc/<pid>/map_files/ paths are preferred for accessing ELF files of
  // mappings because they work correctly for deleted / modified files as
  // well as container based process files.
  //
  // According to the procfs man page
  // (https://man7.org/linux/man-pages/man5/procfs.5.html):
  //
  // "Capabilities are required to read the contents of the symbolic links
  // in this directory: before Linux 5.9, the reading process requires
  // CAP_SYS_ADMIN in the initial user namespace; since Linux 5.9, the
  // reading process must have either CAP_SYS_ADMIN or
  // CAP_CHECKPOINT_RESTORE in the user namespace where it resides."
  //
  // If the reading process doesn't have CAP_SYS_ADMIN we fall back to
  // reading from /proc/<pid>/root/<mapping name>.
  std::filesystem::path file;
  if (haveEffectiveSysAdminCapability()) {
    file = ProcPidInfo::getProcfsPathForPid(pid, "map_files", rootDir) /
        fmt::format("{:x}-{:x}", mm.startAddr, mm.endAddr);
  } else {
    if (mm.name.find(kDeleted) != std::string::npos) {
      elfFile = nullptr;
      return;
    }
    file = ProcPidInfo::getProcfsRootForPid(pid, mm.name, rootDir);
  }

  auto elfFileRes = elfFile->open(file.c_str());
  if (!elfFileRes) {
    strobelight_lib_print(
        STROBELIGHT_LIB_DEBUG,
        fmt::format(
            "Failed to open {} as ELF binary: {} ({}).",
            file.c_str(),
            strerror(errno),
            errno)
            .c_str());
    elfFile = nullptr;
    return;
  }

  if (elfFile->eType() == ET_EXEC) {
    // If this isn't relocatable e.g. not ET_REL or ET_DYN
    // then it should always be loaded at the default load address
    // even if there is some alignment padding in the memory mapping
    // so let's not mess around with address adjustment.
    baseLoadAddress = 0;
  } else {
    std::optional<Elf64_Addr> lowestVaddr = std::nullopt;
    Elf64_Off lowestOffset = 0;

    elfFile->iterateProgramHeaders([&](const GElf_Phdr& h) {
      if (h.p_type == PT_LOAD) {
        lowestVaddr = h.p_vaddr;
        lowestOffset = h.p_offset;
        return true;
      }
      return false;
    });
    if (!lowestVaddr) {
      strobelight_lib_print(
          STROBELIGHT_LIB_DEBUG,
          fmt::format(
              "Could not find an eligible virtual load address for {} @ {} - {} in process {}",
              mm.name,
              (void*)mm.startAddr,
              (void*)mm.endAddr,
              pid)
              .c_str());
    } else {
      baseLoadAddress =
          (mm.startAddr - mm.fileOffset) - (*lowestVaddr - lowestOffset);
    }
  }
}

} // namespace facebook::strobelight::bpf_lib::pid_info
