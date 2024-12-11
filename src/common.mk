ARCH 		?= $(shell uname -m|sed 's/x86_64/x86/'|sed 's/aarch64/arm/')
LIBBPF_PATH  = $(ROOTDIR)/../lib/libbpf/src
LIBBPF_FLAGS = -I$(LIBBPF_PATH) -L$(LIBBPF_PATH) -l:libbpf.a -lbpf
LIBELF_FLAGS ?= $(shell pkg-config --static --libs libelf)
COMMON_INCLUDES = -I.
RELEASE_DIR  = $(ROOTDIR)/../dst

all: $(APPS)

release_dest: $(APPS)
	mkdir -p $(RELEASE_DIR)
	cp $(APPS) $(RELEASE_DIR)

release: release_dest
	make clean

%.o: %.c
	$(call msg,CC,$@)
	clang -Wall -O2 $(CFLAGS) -c $< -o $@ $(INCLUDES) $(COMMON_INCLUDES)

# Build application binary
$(APPS): %: | $(APPS).skel.h libbpf $(OBJ)
	$(call msg,BINARY,$@)
	clang -Wall -O2 $@.c $(CFLAGS) $(OBJ) $(LIBBPF_FLAGS) $(LIBELF_FLAGS) -o $@ -static
	strip $@

# eBPF skeleton
$(APPS).skel.h: $(APPS).bpf.o
	$(call msg,GEN-SKEL,$@)
	bpftool gen skeleton $< > $@

$(APPS).bpf.o: $(EBPF).bpf.o
	$(call msg,BPF,$@)
	bpftool gen object $@ $<

# build each eBPF object file
$(EBPF).bpf.o: $(EBPF).bpf.c vmlinux.h
	$(call msg,BPF,$@)
	clang -O2 -g -Wall -target bpf -D__KERNEL__ -D__TARGET_ARCH_$(ARCH) $(CFLAGS) $(INCLUDES) $(COMMON_INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	llvm-strip -g --strip-unneeded $@

vmlinux.h:
	$(call msg,VMH, $@)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

libbpf:
	make -C $(LIBBPF_PATH)

clean:
	rm -f $(APPS) $(EBPF).bpf.o $(EBPF).skel.h vmlinux.h $(EXTRA_APPS) $(OBJ) $(APPS).bpf.o $(APPS).skel.h

xdpstatus:
	watch -n 0.5 bpftool net

debug:
	cat /sys/kernel/debug/tracing/trace_pipe

.PHONY: clean debug xdpstatus