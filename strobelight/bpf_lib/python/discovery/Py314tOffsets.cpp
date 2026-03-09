// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/python/include/OffsetConfig.h"

namespace facebook::strobelight::bpf_lib {

// clang-format off
//
// $ buck2 run @//mode/opt //strobelight/belljar/framework/pyperf/scripts:generate_common_314t_cpython
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
Python 3.14t (free-threaded, no-GIL build):
- PyObject layout changes: ob_tid, ob_mutex, ob_gc_bits, ob_ref_local,
  ob_ref_shared are added before ob_type, shifting ob_type from offset 8 to 24.
  This cascades to all structs embedding PyObject (PyCodeObject, PyTupleObject,
  PyASCIIObject, etc.).
- No GIL: ceval.gil.locked and gilstate.tstate_current are absent/meaningless.
  TCurrentState_offset, PyGIL_offset, PyGIL_last_holder are left at default
  (9999) so BPF returns GIL_STATE_NO_INFO.
- autoTSSkey still exists in _PyRuntimeState but at a different offset.

Items that no longer exist in 3.13+:
- PyThreadState_cframe (removed, use PyThreadState_current_frame instead)
- _PyCFrame_current_frame (removed, cframe struct no longer exists)

Deprecated offsets (same as 3.12):
- PyFrameObject_gen, replaced by runtime function _PyFrame_GetGenerator()
- PyCodeObject_varnames

PyFrameObject_owner is at offset 78, shifted from 3.14 GIL build's 74 because
Py_GIL_DISABLED adds int32_t tlbc_index (4 bytes) before return_offset.
*/

extern const OffsetConfig kPy314tOffsetConfig = [] {
  OffsetConfig config;
  config.PyObject_type =
      24; // offsetof(PyObject, ob_type) - shifted by free-threading fields
  config.PyTypeObject_name = 40; // offsetof(PyTypeObject, tp_name)

  // Python 3.13+: current_frame is directly in PyThreadState (no cframe)
  config.PyThreadState_current_frame =
      72; // offsetof(PyThreadState, current_frame)
  config.PyThreadState_thread = 152; // offsetof(PyThreadState, thread_id)
  config.PyThreadState_interp = 16; // offsetof(PyThreadState, interp)

  // PyInterpreterFrame offsets for Python 3.14t
  // Note: f_code renamed to f_executable, prev_instr renamed to instr_ptr
  config.PyInterpreterFrame_code = 0; // f_executable at offset 0
  config.PyInterpreterFrame_previous =
      8; // offsetof(_PyInterpreterFrame, previous)
  config.PyInterpreterFrame_localsplus =
      80; // offsetof(_PyInterpreterFrame, localsplus)
  config.PyInterpreterFrame_prev_instr =
      56; // instr_ptr at offset 56 (prev_instr renamed)

  config.PyCodeObject_co_flags = 64; // offsetof(PyCodeObject, co_flags)
  config.PyCodeObject_filename = 128; // offsetof(PyCodeObject, co_filename)
  config.PyCodeObject_name = 136; // offsetof(PyCodeObject, co_name)
  config.PyCodeObject_qualname = 144; // offsetof(PyCodeObject, co_qualname)
  config.PyCodeObject_linetable = 152; // offsetof(PyCodeObject, co_linetable)
  config.PyCodeObject_firstlineno =
      84; // offsetof(PyCodeObject, co_firstlineno)
  config.PyCodeObject_code_adaptive =
      232; // offsetof(PyCodeObject, co_code_adaptive)
  config.PyTupleObject_item = 48; // offsetof(PyTupleObject, ob_item)
  config.TLSKey_offset = 2340; // offsetof(_PyRuntimeState, autoTSSkey._key)
  config.PyBytesObject_data = 48; // offsetof(PyBytesObject, ob_sval)
  config.PyVarObject_size = 32; // offsetof(PyVarObject, ob_size)
  config.String_data = 56; // sizeof(PyASCIIObject)
  config.PyVersion_major = 3;
  config.PyVersion_minor = 14;
  config.PyVersion_micro = 3;
  config.PyCoroObject_cr_awaiter = 80; // offsetof(PyCoroObject, cr_ci_awaiter)
  config.PyGenObject_iframe = 96;
  config.PyFrameObject_owner = 78; // offsetof(_PyInterpreterFrame, owner)
  config.PyDebugOffsets_free_threaded =
      16; // offsetof(_Py_DebugOffsets, free_threaded)

  // GIL-related offsets left at default (BPF_LIB_DEFAULT_FIELD_OFFSET = 9999)
  // because free-threaded Python has no GIL.
  // TCurrentState_offset, PyGIL_offset, PyGIL_last_holder remain at 9999.

  return config;
}();

} // namespace facebook::strobelight::bpf_lib
