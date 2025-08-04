APP = ttrace
BINARY = ttrace

APPOBJS = $(APP).o
BPFOBJ = $(APP).bpf.o

CXX = g++
CLANG = clang
LDLIBS = -lelf -lbpf
CXXFLAGS = -g -O2 -Wall
LDFLAGS =

ARCH := $(shell uname -m)

BPF_CFLAGS = -g -O2 -target bpf

ifeq ($(ARCH),x86_64)
	BPF_CFLAGS += -D__TARGET_ARCH_x86
else ifeq ($(ARCH),aarch64)
	BPF_CFLAGS += -D__TARGET_ARCH_arm64
else ifeq ($(ARCH),riscv64)
	BPF_CFLAGS += -D__TARGET_ARCH_riscv
else
	$(error Unsupported architecture: $(ARCH))
endif

all: $(BINARY)

$(BINARY): $(APPOBJS) $(BPFOBJ)
	@echo "LINKING  $@"
	$(CXX) $(LDFLAGS) $(APPOBJS) -o $@ $(LDLIBS)

$(APP).o: $(APP).cpp vmlinux.h
	@echo "CXX      $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BPFOBJ): $(APP).bpf.c vmlinux.h
	@echo "CLANG    $<"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

vmlinux.h:
	@echo "BTF      $@"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	@echo "CLEAN"
	rm -f $(BINARY) $(APPOBJS) $(BPFOBJ) vmlinux.h

install: $(BINARY)
	@echo "INSTALL  $(BINARY) to $(DESTDIR)$(PREFIX)/bin"
	install -D -m 0755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)

uninstall:
	@echo "UNINSTALL $(BINARY) from $(DESTDIR)$(PREFIX)/bin"
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BINARY)

.PHONY: all clean install unintsall
