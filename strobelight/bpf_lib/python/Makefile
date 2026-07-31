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

STROBELIGHT_ROOT := ../../..

INSTALL_DIR ?=
INSTALL_LIBS := libpystacks.a libpython_discovery.a libstrobelight_util.a strobelight/bpf_lib/python/pystacks.subskel.h
INSTALL_HEADERS := strobelight/bpf_lib/common/common.h strobelight/bpf_lib/python/pystacks/pystacks.bpf.h strobelight/bpf_lib/python/pystacks/pystacks.h strobelight/bpf_lib/python/include/structs.h strobelight/bpf_lib/include/stack_walker.h strobelight/bpf_lib/include/structs.h strobelight/bpf_lib/include/logging.h

CXX_VERSION ?= -std=c++20

SRC_DIRS := src

# specify directory containing vmlinux.h 
# if not provided, the file will be generated
VMLINUX_INCLUDE ?=

INCLUDES := -I$(OUTPUT) -I ../../..
CFLAGS := -fPIE -g -Wall $(CXX_VERSION)
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS) -lstdc++

LIBS := python_discovery pystacks

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

ALL_LDFLAGS += -lelf -lz -lcap -lfmt

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
	$(Q)rm -rf $(OUTPUT)

$(OUTPUT) $(OUTPUT)/pystacks $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT) $(OUTPUT)/strobelight/bpf_lib/python:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

ifeq ($(strip $(VMLINUX_INCLUDE)),)
vmlinux:| $(BPFTOOL) $(OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(OUTPUT)/vmlinux.h

install_vmlinux: | vmlinux
	$(call install_file,$(OUTPUT),vmlinux.h,$(INSTALL_DIR)) \

else
vmlinux:
	$(call msg,NOOP,$@)

install_vmlinux:
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

SRCS := $(shell find $(SRC_DIRS) -name '*.cpp')
OBJS := $(SRCS:%=$(OUTPUT)/%.o)
PYSTACKS_BPF_SRCS := $(shell find $(pystacks) -name '*.bpf.c')

$(OUTPUT)/%.cpp.o: %.cpp | $(LIBBPF_OBJ) $(BPFTOOL) vmlinux
	$(call msg,CLANG,$@)
	mkdir -p $(dir $@)
	$(CLANG) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

python_discovery: | $(LIBBPF_OBJ)
	$(call msg,LIB,$@)
	$(Q)$(MAKE) OUTPUT=$(OUTPUT) -C discovery

# bpf objects
%.tmp.bpf.o: %.bpf.c $(wildcard %.h) | $(OUTPUT) $(OUTPUT)/pystacks $(BPFTOOL) $(LIBBPF_OBJ) vmlinux
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -mcpu=v3 -target bpf -D__$(ARCH)__		      \
         $(VMLINUX_INCLUDE) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)                    \
		     -c $(filter %.c,$^) -o $(OUTPUT)/$@

util:
	$(call msg,BPF,$@)
	$(Q)$(MAKE) OUTPUT=$(OUTPUT) -C ../util

common:
	$(call msg,BPF,$@)
	$(Q)$(MAKE) OUTPUT=$(OUTPUT) -C ../common

# bpf lib
pystacks.bpf: | $(patsubst %.bpf.c,%.tmp.bpf.o,$(PYSTACKS_BPF_SRCS)) $(BPFTOOL) $(LIBBPF_OBJ) common $(OUTPUT)/strobelight/bpf_lib/python
	$(call msg,BPF,$@)
	$(Q)$(BPFTOOL) gen object $(OUTPUT)/$@.o $(OUTPUT)/pystacks/*.tmp.bpf.o $(OUTPUT)/common.bpf.o
	$(Q)$(BPFTOOL) gen subskeleton $(OUTPUT)/$@.o name pystacks_subskel > $(OUTPUT)/strobelight/bpf_lib/python/pystacks.subskel.h

# pystacks c interface
pystacks: python_discovery $(OBJS) pystacks.bpf $(OUTPUT)/pystacks/pystacks.cpp.o util
	$(call msg,LIB,$@)
	$(CLANG) -v $(OBJS) $(OUTPUT)/pystacks/pystacks.cpp.o $(OUTPUT)/libstrobelight_util.a -o $(OUTPUT)/lib$@.a $(ALL_LDFLAGS) --emit-static-lib
.PHONY: pystacks


# install_file src_dir, rel_file_path, install_dir
define install_file =
	$(call msg,INSTALL_FILE,$1/$2,$3/$2)
	$(Q)mkdir -p `dirname $3/$2`
	$(Q)cp $1/$2 $3/$2
endef

install: all install_vmlinux
	$(call msg,INSTALL,$@,$(INSTALL_DIR))
	$(call install_file,$(OUTPUT),libpystacks.a,$(INSTALL_DIR))
	$(call install_file,$(OUTPUT),libpython_discovery.a,$(INSTALL_DIR))
	$(call install_file,$(OUTPUT),libstrobelight_util.a,$(INSTALL_DIR))
	$(call install_file,$(OUTPUT),pystacks.bpf.o,$(INSTALL_DIR))
	$(call install_file,$(OUTPUT),strobelight/bpf_lib/python/pystacks.subskel.h,$(INSTALL_DIR))
	$(call install_file,$(OUTPUT),linux/bpf.h,$(INSTALL_DIR))

	$(call install_file,$(abspath $(STROBELIGHT_ROOT)),strobelight/bpf_lib/common/common.h,$(INSTALL_DIR))
	$(call install_file,$(abspath $(STROBELIGHT_ROOT)),strobelight/bpf_lib/python/pystacks/pystacks.bpf.h,$(INSTALL_DIR))
	$(call install_file,$(abspath $(STROBELIGHT_ROOT)),strobelight/bpf_lib/python/pystacks/pystacks.h,$(INSTALL_DIR))
	$(call install_file,$(abspath $(STROBELIGHT_ROOT)),strobelight/bpf_lib/python/include/structs.h,$(INSTALL_DIR))
	$(call install_file,$(abspath $(STROBELIGHT_ROOT)),strobelight/bpf_lib/include/stack_walker.h,$(INSTALL_DIR))
	$(call install_file,$(abspath $(STROBELIGHT_ROOT)),strobelight/bpf_lib/include/structs.h,$(INSTALL_DIR))


# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
