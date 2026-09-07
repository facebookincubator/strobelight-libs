// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <fcntl.h>
#include <sys/types.h>
#include <cstdio>
#include <functional>
#include <initializer_list>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unordered_map>
#include <unordered_set>

#include <elf.h>
#include <gelf.h>
#include <libelf.h>

namespace facebook::strobelight {

class ElfFile {
 public:
  struct Symbol {
    size_t elfShrdIdx;
    GElf_Shdr sHdr;
    GElf_Sym sym;
    std::string name;
  };

  ElfFile()
      : elfFile_(nullptr),
        fd_(-1),
        fileMMap_(nullptr),
        fileMMapLength_(0),
        eType_(ET_NONE),
        initialized_(false) {}
  ~ElfFile();

  ElfFile(ElfFile&& other) noexcept;
  ElfFile& operator=(ElfFile&& other) noexcept;

  bool open(const std::string& path);

  inline GElf_Half eType() const {
    if (!initialized_) {
      return ET_NONE;
    }
    return eType_;
  }

  void iterateProgramHeaders(
      const std::function<bool(const GElf_Phdr&)>& func) const;

  std::string getSectionName(size_t index) const noexcept;

  std::unordered_map<std::string, std::optional<Symbol>> getSymbolsByName(
      const std::unordered_set<std::string>& names) const noexcept;

  GElf_Sxword getRelocationAdjustment(const Symbol& symbol) const;

  template <class T>
  T* const at(GElf_Off offset) const noexcept {
    static_assert(
        std::is_standard_layout<T>::value && std::is_trivial<T>::value,
        "non-pod");
    GElf_Off end;
    if (__builtin_add_overflow(offset, sizeof(T), &end) ||
        end > fileMMapLength_) {
      return nullptr;
    }
    return reinterpret_cast<T*>(fileMMap_ + offset);
  }

  // Retrieve value from a virtual address. This requires removing the virtual
  // address offset of the section from the virtual address to be retrieved,
  // then adding that to the section offset in the file. The value can then be
  // retrieved as an offset in the file.
  template <class T>
  const T* const valueAt(const GElf_Shdr& section, const GElf_Addr addr)
      const noexcept {
    std::unordered_set<unsigned char> types{ET_EXEC, ET_DYN, ET_CORE};

    if (!initialized_ || !types.contains(eType_)) {
      return nullptr;
    }

    GElf_Addr addrEnd;
    GElf_Addr sectionEnd;
    if (addr < section.sh_addr ||
        __builtin_add_overflow(addr, sizeof(T), &addrEnd) ||
        __builtin_add_overflow(section.sh_addr, section.sh_size, &sectionEnd) ||
        addrEnd > sectionEnd) {
      return nullptr;
    }

    // skip sections with no actual data. ref: https://fburl.com/ni2edr2h
    if (section.sh_type == SHT_NOBITS) {
      const static T t = {};
      return &t;
    }

    GElf_Off offset;
    if (__builtin_add_overflow(
            section.sh_offset, (addr - section.sh_addr), &offset)) {
      return nullptr;
    }

    return at<T>(offset);
  }

  template <class T>
  const T* getSymbolValue(const Symbol& symbol) const noexcept {
    GElf_Shdr sectionHeader;
    if (!initialized_ || !getSection(symbol.sym.st_shndx, sectionHeader)) {
      return nullptr;
    }

    return valueAt<T>(sectionHeader, symbol.sym.st_value);
  }

  bool getSectionContainingAddress(GElf_Addr addr, GElf_Shdr& sectionHeader)
      const noexcept;

  template <class T>
  const T* getAddressValue(const GElf_Addr addr) const noexcept {
    GElf_Shdr sectionHeader;
    if (!getSectionContainingAddress(addr, sectionHeader)) {
      return nullptr;
    }

    return valueAt<T>(sectionHeader, addr);
  }

  bool initialized() const {
    return initialized_;
  }

  bool isPie();

 private:
  ElfFile(const ElfFile&) = delete;
  ElfFile& operator=(const ElfFile&) = delete;

  bool getSection(size_t index, GElf_Shdr& sectionHeader) const noexcept;

  Elf* elfFile_{};
  int fd_{};
  char* fileMMap_{};
  size_t fileMMapLength_{};
  GElf_Half eType_{};
  bool initialized_{};
};

} // namespace facebook::strobelight
