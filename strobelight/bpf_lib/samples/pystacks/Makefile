# SPDX-License-Identifier: (LGPL-2.1-only OR BSD-2-Clause)
# Copyright (c) Meta Platforms, Inc. and affiliates.

OUTPUT ?= $(abspath .output)
CLANG ?= clang
LIBBPF_SRC := $(abspath ../../../../libbpf/src)
BPFTOOL_SRC := $(abspath ../../../../bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
ARCH ?= $(shell uname -m)

CXX_VERSION ?= -std=c++20

SRC_DIRS := .

INCLUDES := -I$(OUTPUT) -I ../../../..
CFLAGS := -g -Wall $(CXX_VERSION)
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS) -lstdc++

LIBS := pystacks_sample.bpf pystacks_sample


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

ALL_LDFLAGS += -lelf -lz -lcap -lfmt -lm -lre2

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

$(OUTPUT) $(OUTPUT)/pystacks $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT) $(OUTPUT)/strobelight/bpf_lib/python $(OUTPUT)/strobelight/bpf_lib/samples/pystacks:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

vmlinux:| $(BPFTOOL) $(OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(OUTPUT)/vmlinux.h
.PHONY: vmlinux

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@ $(OUTPUT))
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR= \
		    install install_uapi_headers

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

BPF_SRCS := $(shell find $(SRC_DIRS) -name '*.bpf.c')
BPF_OBJS := $(BPF_SRCS:%=$(OUTPUT)/%.o)

SRCS := $(shell find $(SRC_DIRS) -name '*.cpp')
OBJS := $(SRCS:%=$(OUTPUT)/%.o)

$(OUTPUT)/%.cpp.o: %.cpp | $(LIBBPF_OBJ) $(BPFTOOL) vmlinux
	$(call msg,CLANG,$@)
	mkdir -p $(dir $@)
	$(CLANG) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# JMW TODO: make and install pystacks lib
pystacks: | $(OUTPUT)
	$(call msg,LIB,$@)
	$(Q)$(MAKE) INSTALL_DIR=$(OUTPUT) -C ../../python install
# 	JMW TODO install

# bpf objects
$(OUTPUT)/%.bpf.c.o: %.bpf.c $(wildcard %.h) | pystacks $(OUTPUT) $(BPFTOOL) $(LIBBPF_OBJ) vmlinux
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -mcpu=v3 -target bpf -D__$(ARCH)__		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $@

# bpf lib
# pystacks_sample.bpf: | $(patsubst %.bpf.c,%.tmp.bpf.o,$(BPF_SRCS)) $(BPFTOOL) $(LIBBPF_OBJ) $(OUTPUT) $(OUTPUT)/strobelight/bpf_lib/samples/pystacks
pystacks_sample.bpf: | $(BPF_OBJS) $(BPFTOOL) $(LIBBPF_OBJ) $(OUTPUT) $(OUTPUT)/strobelight/bpf_lib/samples/pystacks
	$(call msg,BPF,$@)
	$(Q)$(BPFTOOL) gen object $(OUTPUT)/$@.o $(BPF_OBJS) $(OUTPUT)/pystacks.bpf.o
	$(Q)$(BPFTOOL) gen skeleton $(OUTPUT)/$@.o name pystacks_sample > $(OUTPUT)/strobelight/bpf_lib/samples/pystacks/pystacks_sample.skel.h

pystacks_sample:  pystacks_sample.bpf $(OBJS) $(LIBBPF_OBJ)
	$(call msg,LIB,$@)
	$(CLANG) -v -mcpu=v3 $(OBJS) $(OUTPUT)/libpystacks.a $(OUTPUT)/libpython_discovery.a $(OUTPUT)/libstrobelight_util.a $(OUTPUT)/libbpf.a -o $(OUTPUT)/$@ $(ALL_LDFLAGS)
.PHONY: pystacks

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
