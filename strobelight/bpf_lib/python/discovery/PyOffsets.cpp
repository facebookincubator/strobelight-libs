// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <ostream>
#include "strobelight/bpf_lib/python/include/OffsetConfig.h"

namespace facebook::strobelight::bpf_lib {

std::ostream& operator<<(std::ostream& os, const OffsetConfig& offsets) {
  os << "OffsetConfig:";
  os << "\n\t OffsetConfig.PyObject_type : " << offsets.PyObject_type
     << "\n\t OffsetConfig.PyTypeObject_name : " << offsets.PyTypeObject_name
     << "\n\t OffsetConfig.PyThreadState_frame : "
     << offsets.PyThreadState_frame
     << "\n\t OffsetConfig.PyThreadState_shadow_frame : "
     << offsets.PyThreadState_shadow_frame
     << "\n\t OffsetConfig.PyThreadState_thread : "
     << offsets.PyThreadState_thread
     << "\n\t OffsetConfig.PyThreadState_interp : "
     << offsets.PyThreadState_interp
     << "\n\t OffsetConfig.PyInterpreterState_modules : "
     << offsets.PyInterpreterState_modules
     << "\n\t OffsetConfig.PyFrameObject_back : " << offsets.PyFrameObject_back
     << "\n\t OffsetConfig.PyFrameObject_code : " << offsets.PyFrameObject_code
     << "\n\t OffsetConfig.PyFrameObject_lasti : "
     << offsets.PyFrameObject_lasti
     << "\n\t OffsetConfig.PyFrameObject_localsplus : "
     << offsets.PyFrameObject_localsplus
     << "\n\t OffsetConfig.PyFrameObject_gen : " << offsets.PyFrameObject_gen
     << "\n\t OffsetConfig.PyGenObject_gi_shadow_frame : "
     << offsets.PyGenObject_gi_shadow_frame
     << "\n\t OffsetConfig.PyCodeObject_co_flags : "
     << offsets.PyCodeObject_co_flags
     << "\n\t OffsetConfig.PyCodeObject_filename : "
     << offsets.PyCodeObject_filename
     << "\n\t OffsetConfig.PyCodeObject_name : " << offsets.PyCodeObject_name
     << "\n\t OffsetConfig.PyCodeObject_varnames : "
     << offsets.PyCodeObject_varnames
     << "\n\t OffsetConfig.PyCodeObject_firstlineno : "
     << offsets.PyCodeObject_firstlineno
     << "\n\t OffsetConfig.PyCodeObject_linetable : "
     << offsets.PyCodeObject_linetable
     << "\n\t OffsetConfig.PyCodeObject_code_adaptive : "
     << offsets.PyCodeObject_code_adaptive
     << "\n\t OffsetConfig.PyCodeObject_qualname : "
     << offsets.PyCodeObject_qualname
     << "\n\t OffsetConfig.PyTupleObject_item : " << offsets.PyTupleObject_item
     << "\n\t OffsetConfig.PyCoroObject_cr_awaiter : "
     << offsets.PyCoroObject_cr_awaiter
     << "\n\t OffsetConfig.PyShadowFrame_prev : " << offsets.PyShadowFrame_prev
     << "\n\t OffsetConfig.PyShadowFrame_data : " << offsets.PyShadowFrame_data
     << "\n\t OffsetConfig.PyShadowFrame_PtrMask : "
     << offsets.PyShadowFrame_PtrMask
     << "\n\t OffsetConfig.PyShadowFrame_PtrKindMask : "
     << offsets.PyShadowFrame_PtrKindMask
     << "\n\t OffsetConfig.PyShadowFrame_PYSF_CODE_RT : "
     << offsets.PyShadowFrame_PYSF_CODE_RT
     << "\n\t OffsetConfig.PyShadowFrame_PYSF_PYCODE : "
     << offsets.PyShadowFrame_PYSF_PYCODE
     << "\n\t OffsetConfig.PyShadowFrame_PYSF_PYFRAME : "
     << offsets.PyShadowFrame_PYSF_PYFRAME
     << "\n\t OffsetConfig.PyShadowFrame_PYSF_RTFS : "
     << offsets.PyShadowFrame_PYSF_RTFS
     << "\n\t OffsetConfig.CodeRuntime_py_code : "
     << offsets.CodeRuntime_py_code
     << "\n\t OffsetConfig.RuntimeFrameState_py_code : "
     << offsets.RuntimeFrameState_py_code
     << "\n\t OffsetConfig.String_data : " << offsets.String_data
     << "\n\t OffsetConfig.TLSKey_offset : " << offsets.TLSKey_offset
     << "\n\t OffsetConfig.TCurrentState_offset : "
     << offsets.TCurrentState_offset
     << "\n\t OffsetConfig.PyGIL_offset : " << offsets.PyGIL_offset
     << "\n\t OffsetConfig.PyGIL_last_holder : " << offsets.PyGIL_last_holder
     << "\n\t OffsetConfig.PyBytesObject_data : " << offsets.PyBytesObject_data
     << "\n\t OffsetConfig.PyVarObject_size : " << offsets.PyVarObject_size
     << "\n\t OffsetConfig.PyFrameObject_owner : "
     << offsets.PyFrameObject_owner
     << "\n\t OffsetConfig.PyGenObject_iframe : " << offsets.PyGenObject_iframe
     << "\n\t OffsetConfig.PyVersion_major : " << offsets.PyVersion_major
     << "\n\t OffsetConfig.PyVersion_minor : " << offsets.PyVersion_minor
     << "\n\t OffsetConfig.PyVersion_micro : " << offsets.PyVersion_micro
     << "\n";

  return os;
}

} // namespace facebook::strobelight::bpf_lib
