#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this script with root privileges: sudo ./run.sh"
  exit 1
fi

bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h


echo "[+] Step 1/4: Compiling eBPF kernel code for ARM..."
clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -c proc_exec.bpf.c -o proc_exec.bpf.o

echo "[+] Step 2/4: Generating BPF skeleton header..."
bpftool gen skeleton proc_exec.bpf.o > proc_exec.skel.h

echo "[+] Step 3/4: Compiling user-space loader binary..."
gcc -O2 -g proc_exec.c -lbpf -lelf -o proc_exec

echo "[+] Step 4/4: Starting eBPF Security Agent..."
echo "---------------------------------------------------------------------------------"
./proc_exec
