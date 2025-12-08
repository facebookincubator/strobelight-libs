// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/python/include/OffsetConfig.h"

namespace facebook::strobelight::bpf_lib {

// clang-format off
//
// Python 3.11 introduces the new _PyInterpreterFrame structure for improved
// performance, but with different field layout than Python 3.12.
//
// Key differences from 3.10:
// - Uses PyThreadState_cframe instead of PyThreadState_frame
// - Uses _PyInterpreterFrame instead of PyFrameObject
// - Frame walking via PyInterpreterFrame_previous instead of PyFrameObject_back
//
// Key differences from 3.12:
// - _PyCFrame.current_frame at offset 8 (3.12 has it at 0 - removed use_tracing)
// - PyInterpreterFrame has different field ordering (f_code at 32 vs 0)
// - PyInterpreterFrame_previous at offset 48 (3.12 has it at 8)
//
// Offsets measured from Python 3.11.14 on x86_64 Linux
//
// clang-format on

/*
Items that no longer exist in 3.11 (compared to 3.10):
- PyThreadState_frame, replaced by PyThreadState_cframe and
_PyCFrame_current_frame
- PyFrameObject_back, replaced by PyInterpreterFrame_previous
- PyFrameObject_code, replaced by PyInterpreterFrame_code
- PyFrameObject_lasti, replaced by PyInterpreterFrame_prev_instr
- PyFrameObject_localsplus, replaced by PyInterpreterFrame_localsplus

Items that differ from 3.12:
- _PyCFrame still has use_tracing field (removed in 3.12)
- PyInterpreterFrame layout not yet optimized (reorganized in 3.12)
*/

extern const OffsetConfig kPy311OffsetConfig = [] {
  OffsetConfig config;
  config.PyObject_type = 8; // offsetof(PyObject, ob_type)
  config.PyTypeObject_name = 24; // offsetof(PyTypeObject, tp_name)

  // cframe wraps around frame (introduced in 3.11)
  config.PyThreadState_cframe = 56; // offsetof(PyThreadState, cframe)
  config.PyThreadState_thread = 152; // offsetof(PyThreadState, thread_id)

  // _PyCFrame structure (still has use_tracing field in 3.11)
  config._PyCFrame_current_frame = 8; // offsetof(_PyCFrame, current_frame)

  // _PyInterpreterFrame structure (different layout than 3.12)
  config.PyInterpreterFrame_code = 32; // offsetof(_PyInterpreterFrame, f_code)
  config.PyInterpreterFrame_previous =
      48; // offsetof(_PyInterpreterFrame, previous)
  config.PyInterpreterFrame_localsplus =
      72; // offsetof(_PyInterpreterFrame, localsplus)
  config.PyInterpreterFrame_prev_instr =
      56; // offsetof(_PyInterpreterFrame, prev_instr)

  // Code object offsets
  config.PyCodeObject_co_flags = 48; // offsetof(PyCodeObject, co_flags)
  config.PyCodeObject_filename = 112; // offsetof(PyCodeObject, co_filename)
  config.PyCodeObject_name = 120; // offsetof(PyCodeObject, co_name)
  config.PyCodeObject_qualname = 128; // offsetof(PyCodeObject, co_qualname)
  config.PyCodeObject_linetable = 136; // offsetof(PyCodeObject, co_linetable)
  config.PyCodeObject_firstlineno =
      72; // offsetof(PyCodeObject, co_firstlineno)

  // Other object offsets
  config.PyTupleObject_item = 24; // offsetof(PyTupleObject, ob_item)
  config.PyBytesObject_data = 32; // offsetof(PyBytesObject, ob_sval)
  config.PyVarObject_size = 16; // offsetof(PyVarObject, ob_size)
  config.String_data = 48; // sizeof(PyASCIIObject)

  // TLS offset for getting per-thread state
  // TLSKey_offset = offsetof(_PyRuntimeState, gilstate) +
  // offsetof(_gilstate_runtime_state, autoTSSkey) + offsetof(Py_tss_t, _key)
  config.TLSKey_offset = 596;
  // TCurrentState_offset = offsetof(_PyRuntimeState, gilstate) +
  // offsetof(_gilstate_runtime_state, tstate_current)
  config.TCurrentState_offset = 576;
  config.PyGIL_offset = 376;
  config.PyGIL_last_holder = 368;

  // Version
  config.PyVersion_major = 3;
  config.PyVersion_minor = 11;
  config.PyVersion_micro = 0;

  return config;
}();

} // namespace facebook::strobelight::bpf_lib
