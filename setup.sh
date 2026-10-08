#!/usr/bin/env bash
set -e

echo "[+] Updating system packages..."
sudo apt-get update -y

echo "[+] Installing compilation toolchain and eBPF dependencies..."
sudo apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    pkg-config \
    linux-headers-$(uname -r) \
    linux-tools-common \
    linux-tools-$(uname -r) || true

echo "[+] Checking bpftool installation..."
if ! command -v bpftool &> /dev/null; then
    echo "[!] bpftool not found via linux-tools. Attempting generic install..."
    sudo apt-get install -y linux-tools-generic || true
fi

# Verify BTF support in kernel
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "[!] WARNING: /sys/kernel/btf/vmlinux not found."
    echo "    Your running kernel may not support BTF (Compile-Once Run-Everywhere)."
else
    echo "[+] BTF support verified (/sys/kernel/btf/vmlinux exists)."
fi

echo "[+] Environment setup complete!"