# SPDX-License-Identifier: (LGPL-2.1-only OR BSD-2-Clause)
# Copyright (c) Meta Platforms, Inc. and affiliates.

OUTPUT ?= $(abspath .output)
CLANG ?= clang
LIBBPF_SRC := $(abspath ../../../libbpf/src)
BPFTOOL_SRC := $(abspath ../../../bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
ARCH ?= $(shell uname -m)

# specify directory containing vmlinux.h 
# if not provided, the file will be generated
VMLINUX_INCLUDE ?=

# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I ../../..
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

HELPERS := common bpf_read_helpers namespace_helpers pid_target_helpers pthread_helpers task_helpers

LIBS := common

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(LIBS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(patsubst %,%.bpf.o,$(LIBS))

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

ifeq ($(strip $(VMLINUX_INCLUDE)),)
vmlinux:| $(BPFTOOL) $(OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(OUTPUT)/vmlinux.h
else
vmlinux:
	$(call msg,NOOP,$@)
endif
.PHONY: vmlinux

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR= \
		    install install_uapi_headers

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# common lib objects
%.tmp.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) | $(OUTPUT) $(BPFTOOL) vmlinux
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__$(ARCH)__		      \
		     $(VMLINUX_INCLUDE) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(OUTPUT)/$@

# common lib
common: | $(patsubst %,%.tmp.bpf.o,$(HELPERS))
	$(Q)$(BPFTOOL) gen object $(OUTPUT)/$@.bpf.o $(OUTPUT)/*.tmp.bpf.o

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
