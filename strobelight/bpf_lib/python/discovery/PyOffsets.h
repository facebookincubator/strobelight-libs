// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "strobelight/bpf_lib/python/include/OffsetConfig.h"

namespace facebook::strobelight::bpf_lib {

// @dep=//strobelight/bpf_lib/python/discovery:cinder310_offset
extern const OffsetConfig kCinder310OffsetConfig;

// @dep=//strobelight/bpf_lib/python/discovery:py312_offset
extern const OffsetConfig kPy312OffsetConfig;

// @dep=//strobelight/bpf_lib/python/discovery:py311_offset
extern const OffsetConfig kPy311OffsetConfig;

// @dep=//strobelight/bpf_lib/python/discovery:py310_offset
extern const OffsetConfig kPy310OffsetConfig;

// @dep=//strobelight/bpf_lib/python/discovery:py39_offset
extern const OffsetConfig kPy39OffsetConfig;

// @dep=//strobelight/bpf_lib/python/discovery:py38_offset
extern const OffsetConfig kPy38OffsetConfig;

std::ostream& operator<<(std::ostream& os, const OffsetConfig& offsets);

} // namespace facebook::strobelight::bpf_lib
