// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/python/include/PyLineTable.h"
#include "strobelight/bpf_lib/util/BpfLibLogger.h"

#include <fmt/format.h>
#include <sys/types.h>
#include <cstdlib>

namespace facebook::strobelight::bpf_lib::python {

static constexpr size_t kMaxLineTableSize = 1 * 1024 * 1024;
static constexpr size_t kPyCodeUnitSize = 2;

PyLineTable::PyLineTable(
    int firstLine,
    const void* data,
    size_t length,
    int pyMajorVer,
    int pyMinorVer)
    : pyMajorVer_(pyMajorVer),
      pyMinorVer_(pyMinorVer),
      data_((const uint8_t*)data, (const uint8_t*)data + length),
      firstLine_(firstLine) {}

PyLineTable::PyLineTable(
    pid_info::SharedPidInfo& pidInfo,
    int firstLine,
    uintptr_t addr,
    size_t length,
    int pyMajorVer,
    int pyMinorVer)
    : pyMajorVer_(pyMajorVer),
      pyMinorVer_(pyMinorVer),
      data_(),
      firstLine_(firstLine) {
  if (length > kMaxLineTableSize) {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format(
            "Bad line table size ({} bytes) in process {}",
            length,
            pidInfo.getPid())
            .c_str());
    return;
  }

  data_.resize(length);
  if (pidInfo.readMemory(data_.data(), (void*)addr, length) !=
      (ssize_t)length) {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format(
            "Failed to read {} byte line table at {:#x} in process ",
            length,
            addr,
            pidInfo.getPid())
            .c_str());
    data_.clear();
    return;
  }
}

int PyLineTable::getLineForInstIndex(int addrq) const {
  if (pyMajorVer_ > 3 || (pyMajorVer_ == 3 && pyMinorVer_ > 10)) {
    return getLineForInstIndexDefault(addrq);
  } else if (pyMajorVer_ == 3 && pyMinorVer_ == 10) {
    return getLineForInstIndex310(addrq);
  } else {
    return 0;
  }
}

int PyLineTable::getLineForInstIndex310(int addrq) const {
  if (addrq < 0) {
    return firstLine_;
  }
  uintptr_t offset = addrq * kPyCodeUnitSize;

  // https://github.com/python/cpython/blob/3.10/Objects/lnotab_notes.txt#L57-L79
  int line = firstLine_;
  uintptr_t start, end = 0;

  struct PyLineTableEntry {
    uint8_t offsetDelta;
    int8_t lineDelta;
  };
  const size_t entryCount = data_.size() / sizeof(PyLineTableEntry);
  const PyLineTableEntry* entries =
      reinterpret_cast<const PyLineTableEntry*>(data_.data());
  for (size_t ii = 0; ii < entryCount; ++ii) {
    auto& entry = entries[ii];

    if (entry.lineDelta == 0) {
      end += entry.offsetDelta;
      continue;
    }
    start = end;
    end = start + entry.offsetDelta;
    if (entry.lineDelta == -128) {
      // No valid line number -- skip entry
      continue;
    }
    line += entry.lineDelta;
    if (end == start) {
      // Empty range, omit.
      continue;
    }
    if (start <= offset && offset < end) {
      return line;
    }
  }

  return 0;
}

int PyLineTable::getLineForInstIndexDefault(int addrq) const {
  if (addrq < 0) {
    return firstLine_;
  }
  uintptr_t offset = addrq * kPyCodeUnitSize;

  int ret = 0;
  try {
    parseLocationTable([&](uintptr_t start, uintptr_t end, int line) {
      if (offset >= start && offset < end) {
        ret = line;
        return IterControl::BREAK;
      } else if (end > offset) {
        return IterControl::BREAK;
      }
      return IterControl::CONTINUE;
    });
  } catch (const std::exception& e) {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format("Failed to parse location table: {}", e.what()).c_str());
  }
  return ret;
}

void PyLineTable::parseLocationTable(
    const std::function<IterControl(
        uintptr_t /* start */,
        uintptr_t /* end */,
        int /* line */)>& fn) const {
  // https://github.com/python/cpython/blob/main/InternalDocs/locations.md
  // https://github.com/benfred/py-spy/blob/master/src/python_interpreters.rs#L304-L346

  auto itr = data_.begin(), end = data_.end();

  auto read = [&]() -> uint8_t {
    if (itr < end) {
      return *itr++;
    } else {
      throw std::out_of_range("line table read out of range");
    }
  };

  auto read_varint = [&]() -> unsigned int {
    uint8_t b = read();
    unsigned int val = b & 63;
    unsigned int shift = 0;
    while (b & 64) {
      b = read();
      shift += 6;
      val += static_cast<unsigned int>(b & 63) << shift;
    }
    return val;
  };

  auto read_signed_varint = [&]() -> int {
    unsigned int uval = read_varint();
    if (uval & 1) {
      return static_cast<int>(-(uval >> 1));
    } else {
      return static_cast<int>(uval >> 1);
    }
  };

  int line_number = firstLine_;
  int32_t addr = 0;

  while (itr < end) {
    uint8_t byte = read();
    int32_t delta = (static_cast<int32_t>(byte & 7)) + 1;
    uint8_t code = (byte >> 3) & 15;

    int32_t line_delta;
    if (code == 15) {
      line_delta = 0;
    } else if (code == 14) {
      line_delta = read_signed_varint();
      read_varint(); // end line
      read_varint(); // start column
      read_varint(); // end column
    } else if (code == 13) {
      line_delta = read_signed_varint();
    } else if (code >= 10 && code <= 12) {
      line_delta = code - 10;
      read(); // start column
      read(); // end column
    } else {
      line_delta = 0;
      read(); // column
    }
    line_number += line_delta;

    int end_addr = addr + delta * 2;
    if (fn(addr, end_addr, line_number) != IterControl::CONTINUE) {
      break;
    }
    addr = end_addr;
  }
}

} // namespace facebook::strobelight::bpf_lib::python
