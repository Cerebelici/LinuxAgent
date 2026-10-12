CC ?= gcc
CLANG ?= clang
BPFTOOL ?= bpftool

ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
	TARGET_ARCH := -D__TARGET_ARCH_x86
else ifeq ($(ARCH),aarch64)
	TARGET_ARCH := -D__TARGET_ARCH_arm64
else ifeq ($(ARCH),arm64)
	TARGET_ARCH := -D__TARGET_ARCH_arm64
endif

CFLAGS ?= -Wall -Wextra -Werror -O2 -g
BPF_CFLAGS := -g -O2 -target bpf $(TARGET_ARCH)

LIBS := -lbpf -lelf -lpthread -lcurl -lssl -lcrypto -lz

all: bpf proc_exec

vmlinux.h:
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		echo "[+] Dumping vmlinux.h from kernel BTF..."; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	elif [ ! -f vmlinux.h ]; then \
		echo "[-] Error: vmlinux.h missing and no /sys/kernel/btf/vmlinux found"; \
		exit 1; \
	fi

bpf: vmlinux.h proc_exec.bpf.o proc_exec.skel.h

proc_exec.bpf.o: proc_exec.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c proc_exec.bpf.c -o proc_exec.bpf.o

proc_exec.skel.h: proc_exec.bpf.o
	$(BPFTOOL) gen skeleton proc_exec.bpf.o > proc_exec.skel.h

proc_exec: proc_exec.c identity.c exporter.c proc_exec.skel.h identity.h exporter.h
	$(CC) $(CFLAGS) proc_exec.c identity.c exporter.c $(LIBS) -o proc_exec

clean:
	rm -f proc_exec proc_exec.bpf.o proc_exec.skel.h

test: all
	python3 tests/mock_sentinel.py --test

.PHONY: all bpf clean test
