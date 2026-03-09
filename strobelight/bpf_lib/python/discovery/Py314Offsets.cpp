// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/python/include/OffsetConfig.h"

namespace facebook::strobelight::bpf_lib {

// clang-format off
//
// $ buck2 run @//mode/opt -c python.force_py_version=3.14 //strobelight/belljar/framework/pyperf/scripts:generate_common_314_cpython
// ...
// Running as process pid XXXXXX
// Running forever
//
// $ lldb -p <pid>
// (lldb) command script import ~/fbsource/fbcode/strobelight/scripts/pyperf_lldb.py
// (lldb) dump_py_offsets
//
// clang-format on

/*
Key changes in Python 3.13+:
- _PyCFrame was REMOVED
- PyThreadState->cframe->current_frame is now PyThreadState->current_frame
directly
- This simplifies frame access from a 2-step read to a 1-step read

Items that no longer exist in 3.13+:
- PyThreadState_cframe (removed, use PyThreadState_current_frame instead)
- _PyCFrame_current_frame (removed, cframe struct no longer exists)

Deprecated offsets (same as 3.12):
- PyFrameObject_gen, replaced by runtime function _PyFrame_GetGenerator()
- PyCodeObject_varnames
- PyGIL_offset (T186091105 to remove)
- PyGIL_last_holder (T186091105 to remove)
*/

extern const OffsetConfig kPy314OffsetConfig = [] {
  OffsetConfig config;
  config.PyObject_type = 8; // offsetof(PyObject, ob_type)
  config.PyTypeObject_name = 24; // offsetof(PyTypeObject, tp_name)

  // Python 3.13+: current_frame is directly in PyThreadState (no cframe)
  config.PyThreadState_current_frame =
      72; // offsetof(PyThreadState, current_frame)
  config.PyThreadState_thread = 152; // offsetof(PyThreadState, thread_id)
  config.PyThreadState_interp = 16; // offsetof(PyThreadState, interp)
  // PyInterpreterState_modules not found in 3.14 - structure was refactored
  // config.PyInterpreterState_modules = N/A;

  // PyInterpreterFrame offsets for Python 3.14
  // Note: f_code renamed to f_executable, prev_instr renamed to instr_ptr
  config.PyInterpreterFrame_code = 0; // f_executable at offset 0
  config.PyInterpreterFrame_previous =
      8; // offsetof(_PyInterpreterFrame, previous)
  config.PyInterpreterFrame_localsplus =
      80; // offsetof(_PyInterpreterFrame, localsplus)
  config.PyInterpreterFrame_prev_instr =
      56; // instr_ptr at offset 56 (prev_instr renamed)

  config.PyCodeObject_co_flags = 48; // offsetof(PyCodeObject, co_flags)
  config.PyCodeObject_filename = 112; // offsetof(PyCodeObject, co_filename)
  config.PyCodeObject_name = 120; // offsetof(PyCodeObject, co_name)
  config.PyCodeObject_qualname = 128; // offsetof(PyCodeObject, co_qualname)
  config.PyCodeObject_linetable = 136; // offsetof(PyCodeObject, co_linetable)
  config.PyCodeObject_firstlineno =
      68; // offsetof(PyCodeObject, co_firstlineno)
  config.PyCodeObject_code_adaptive =
      208; // offsetof(PyCodeObject, co_code_adaptive)
  config.PyTupleObject_item = 32; // offsetof(PyTupleObject, ob_item)
  config.TLSKey_offset = 2340; // offsetof(_PyRuntimeState, autoTSSkey._key)
  config.PyBytesObject_data = 32; // offsetof(PyBytesObject, ob_sval)
  config.PyVarObject_size = 16; // offsetof(PyVarObject, ob_size)
  config.String_data = 40; // sizeof(PyASCIIObject)
  config.PyVersion_major = 3;
  config.PyVersion_minor = 14;
  config.PyVersion_micro = 3;
  config.PyCoroObject_cr_awaiter = 64; // offsetof(PyCoroObject, cr_ci_awaiter)
  config.PyGenObject_iframe = 80;
  config.PyFrameObject_owner = 70;

  return config;
}();

} // namespace facebook::strobelight::bpf_lib
