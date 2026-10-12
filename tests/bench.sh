#!/usr/bin/env bash
set -e

# Benchmark runner for Cerberus agent (DEV-02)
# Measures CPU and RSS memory consumption under synthetic load

AGENT_PID=$(pidof proc_exec || true)
if [ -z "$AGENT_PID" ]; then
    echo "[-] proc_exec is not currently running. Start the agent first before running bench.sh."
    exit 1
fi

echo "[+] Measuring performance for proc_exec (PID: $AGENT_PID)..."
DURATION=60

if command -v stress-ng &> /dev/null; then
    echo "[+] Running stress-ng load generator for ${DURATION}s..."
    stress-ng --exec 4 --timeout "${DURATION}s" --backoff 5000 &
    STRESS_PID=$!
fi

if command -v pidstat &> /dev/null; then
    echo "[+] Sampling proc_exec metrics with pidstat..."
    pidstat -u -r -p "$AGENT_PID" 1 "$DURATION"
else
    echo "[!] pidstat not installed, falling back to ps sampling..."
    for i in $(seq 1 "$DURATION"); do
        ps -p "$AGENT_PID" -o %cpu,%mem,rss,comm
        sleep 1
    done
fi

if [ -n "$STRESS_PID" ]; then
    wait "$STRESS_PID" 2>/dev/null || true
fi

echo "[+] Benchmark finished successfully."
