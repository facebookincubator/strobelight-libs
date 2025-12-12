// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_PYSTACKS_H__
#define __BPF_LIB_PYSTACKS_H__

// @oss-disable: #include <bpf/uapi/linux/bpf.h>
#include <linux/bpf.h> // @oss-enable
#include <sys/types.h>
#include "strobelight/bpf_lib/include/stack_walker.h"
#include "strobelight/bpf_lib/python/include/structs.h"

#ifdef __cplusplus
extern "C" {
#endif

struct stack_walker_run;
struct stack_walker_discovery_opts;

struct stack_walker_run* pystacks_init(
    struct bpf_object* bpf_skel_obj,
    struct stack_walker_opts& opts,
    // @lint-ignore CLANGTIDY facebook-hte-BadImplicitCast
    struct stack_walker_discovery_opts* discovery_opts = NULL);

/* Symbolize the function from the stack and store it in the supplied buffer.
 * returns the length of the function name, or an error
 * run: handle to the pystacks run
 * stackframe: stackframe from bpf to symbolize
 * function_name_buffer: buffer allocated by caller to store the function name
 * function_name_len: number of frames to store in the buffer
 */
int pystacks_symbolize_function(
    struct stack_walker_run* run,
    const struct stack_walker_frame& stackframe,
    char* function_name_buffer,
    size_t function_name_len);

/* Symbolize the file name from the stack and store it in the supplied buffer.
 * returns the length of the filename, or an error
 * run: handle to the pystacks run
 * stackframe: stackframe from bpf to symbolize
 * filename_buffer: buffer allocated by caller to store the filename
 * filename_len: number of frames to store in the buffer
 * line_number: line number in the symbolized filename
 */
int pystacks_symbolize_filename_line(
    struct stack_walker_run* run,
    const struct stack_walker_frame& stackframe,
    char* filename_buffer,
    size_t filename_len,
    size_t& line_number);

void pystacks_free(struct stack_walker_run* run);

void pystacks_load_symbols(struct stack_walker_run* run);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
