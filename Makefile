APP = ttrace
BINARY = ttrace

CC = gcc
CXX = g++
CLANG = clang
LDLIBS = -lelf -lbpf
CXXFLAGS = -g -O2 -Wall
APPOBJS = $(APP).o
BPFOBJ = $(APP).bpf.o


all: $(BINARY)


$(BINARY): $(APPOBJS) $(BPFOBJ)
	@echo "LINKING  $@"
	$(CXX) $(LDFLAGS) $(APPOBJS) -o $@ $(LDLIBS)

$(APP).o: $(APP).cpp vmlinux.h
	@echo "CXX      $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BPFOBJ): $(APP).bpf.c vmlinux.h
	@echo "CLANG    $<"
	$(CLANG) -g -O2 -target bpf -c $< -o $@

vmlinux.h:
	@echo "BTF      $@"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	@echo "CLEAN"
	rm -f $(BINARY) $(APPOBJS) $(BPFOBJ) vmlinux.h

.PHONY: all clean