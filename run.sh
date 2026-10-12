#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this script with root privileges: sudo ./run.sh"
  exit 1
fi

# Detect architecture for BPF compilation
ARCH=$(uname -m)
case "$ARCH" in
  aarch64|arm64)
    TARGET_ARCH="-D__TARGET_ARCH_arm64"
    ARCH_NAME="ARM64"
    ;;
  x86_64)
    TARGET_ARCH="-D__TARGET_ARCH_x86"
    ARCH_NAME="x86_64"
    ;;
  *)
    TARGET_ARCH=""
    ARCH_NAME="$ARCH"
    ;;
esac

# Generate vmlinux.h if BTF is available, otherwise verify existing header
if [ -f /sys/kernel/btf/vmlinux ]; then
  echo "[+] Dumping vmlinux.h from running kernel BTF..."
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
elif [ ! -f vmlinux.h ]; then
  echo "[-] ERROR: /sys/kernel/btf/vmlinux not found and vmlinux.h does not exist."
  echo "    Ensure BTF is enabled in kernel or provide a pre-generated vmlinux.h."
  exit 1
fi

echo "[+] Step 1/4: Compiling eBPF kernel code for $ARCH_NAME..."
clang -g -O2 -target bpf $TARGET_ARCH -c proc_exec.bpf.c -o proc_exec.bpf.o

echo "[+] Step 2/4: Generating BPF skeleton header..."
bpftool gen skeleton proc_exec.bpf.o > proc_exec.skel.h

echo "[+] Step 3/4: Compiling user-space EDR agent binary..."
gcc -O2 -g proc_exec.c -lbpf -lelf -lpthread -o proc_exec

echo "[+] Step 4/4: Starting eBPF EDR Security Agent..."
echo "---------------------------------------------------------------------------------"
./proc_exec "$@"
