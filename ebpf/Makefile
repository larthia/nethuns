LLC ?= llc
CLANG ?= clang
CC ?= gcc

KERNEL ?= /lib/modules/$(shell uname -r)/build/

CFLAGS ?= -Ikernel_include/tools
CFLAGS += -Ikernel_include/tools/include
CFLAGS += -Ikernel_include/tools/lib
CFLAGS += -Ikernel_include/tools/perf

CFLAGS_BPF ?= -I../libbpf/src
CFLAGS_BPF ?= -I$(KERNEL)/tools/include
CFLAGS_BPF += -I$(KERNEL)/tools/perf
CFLAGS_BPF += -I$(KERNEL)/usr/include
CFLAGS_BPF += -I$(KERNEL)/arch/x86/include

all: net_xdp.o

net_xdp.o: net_xdp.c
	$(CLANG) -g -c $< $(CFLAGS) $(CFLAGS_BPF) -D__KERNEL__ -D__BPF_TRACING__  -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -Wno-unknown-warning-option -O2 -emit-llvm -c -o -| llc -march=bpf -filetype=obj  -o $@

clean:
	rm -f net_xdp.o

