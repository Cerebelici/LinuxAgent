#!/usr/bin/env python3
"""
Mock Sentinel server and integration test suite for Cerberus agent (DEV-02).
Uses standard library http.server and urllib only.
"""

import argparse
import gzip
import io
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

DEFAULT_ENROLL_TOKEN = "cerberus-default-enroll-token-12345"
DEFAULT_PORT = 8080

VALID_EVENT_TYPES = {
    "EXEC",
    "CONNECT",
    "BASH_READLINE",
    "PROC_INJECTION",
    "FILE_TAMPER",
    "PRIV_ESC",
    "KERNEL_MODULE",
    "MEMFD_CREATE",
}

UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


class MockSentinelState:
    def __init__(self):
        self.lock = threading.Lock()
        self.enroll_token = DEFAULT_ENROLL_TOKEN
        self.enrolled_agents = {}  # agent_id -> token
        self.received_batches = []
        self.received_events = []
        self.fail_telemetry_500_count = 0  # if > 0, decrement and return 500
        self.fail_telemetry_401_count = 0
        self.fail_telemetry_400_count = 0
        self.schema_violations = []

    def reset(self):
        with self.lock:
            self.received_batches.clear()
            self.received_events.clear()
            self.schema_violations.clear()
            self.fail_telemetry_500_count = 0
            self.fail_telemetry_401_count = 0
            self.fail_telemetry_400_count = 0


state = MockSentinelState()


class MockSentinelHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Quiet default logging unless debugging
        if os.environ.get("DEBUG_SENTINEL"):
            super().log_message(format, *args)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        # Decompress gzip if encoded
        if self.headers.get("Content-Encoding") == "gzip":
            try:
                buf = io.BytesIO(body)
                with gzip.GzipFile(fileobj=buf) as f:
                    body = f.read()
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"gzip decompression failed: {e}"}).encode())
                return

        path = self.path.split("?")[0]

        if path == "/api/v1/agent/enroll":
            self.handle_enroll(body)
        elif path == "/api/v1/agent/telemetry":
            self.handle_telemetry(body)
        else:
            self.send_response(404)
            self.end_headers()

    def handle_enroll(self, body):
        try:
            req = json.loads(body.decode("utf-8"))
        except Exception as e:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": f"invalid json: {e}"}).encode())
            return

        agent_id = req.get("agent_id")
        enrollment_token = req.get("enrollment_token")

        if not agent_id or not UUID_REGEX.match(agent_id):
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"invalid agent_id uuid"}')
            return

        if enrollment_token != state.enroll_token:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"invalid enrollment token"}')
            return

        token = f"tok_{os.urandom(16).hex()}"
        with state.lock:
            state.enrolled_agents[agent_id] = token

        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"agent_token": token}).encode())

    def handle_telemetry(self, body):
        with state.lock:
            if state.fail_telemetry_500_count > 0:
                state.fail_telemetry_500_count -= 1
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"simulated 500 internal server error"}')
                return

            if state.fail_telemetry_401_count > 0:
                state.fail_telemetry_401_count -= 1
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"unauthorized"}')
                return

            if state.fail_telemetry_400_count > 0:
                state.fail_telemetry_400_count -= 1
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"bad request"}')
                return

        # Auth validation
        auth_hdr = self.headers.get("Authorization", "")
        if not auth_hdr.startswith("Bearer "):
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"missing or invalid Authorization header"}')
            return

        agent_id_hdr = self.headers.get("X-Cerberus-Agent-Id", "")
        if not agent_id_hdr or not UUID_REGEX.match(agent_id_hdr):
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"missing or invalid X-Cerberus-Agent-Id header"}')
            return

        token = auth_hdr[len("Bearer "):].strip()
        with state.lock:
            expected = state.enrolled_agents.get(agent_id_hdr)
            if not expected or expected != token:
                # If enrolled agents map is empty, accept for standalone test, otherwise enforce
                if state.enrolled_agents:
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"unrecognized agent token"}')
                    return

        # Schema validation
        try:
            batch = json.loads(body.decode("utf-8"))
        except Exception as e:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": f"invalid json: {e}"}).encode())
            return

        violations = self.validate_batch_schema(batch, agent_id_hdr)
        if violations:
            with state.lock:
                state.schema_violations.extend(violations)
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "schema violations", "details": violations}).encode())
            return

        events = batch.get("events", [])
        with state.lock:
            state.received_batches.append(batch)
            state.received_events.extend(events)

        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"accepted": len(events), "rejected": 0}).encode())

    def validate_batch_schema(self, batch, header_agent_id):
        errs = []
        if batch.get("schema_version") != 1:
            errs.append(f"schema_version must be 1, got {batch.get('schema_version')}")

        agent = batch.get("agent")
        if not isinstance(agent, dict):
            errs.append("missing or non-dict agent object")
        else:
            if agent.get("agent_id") != header_agent_id:
                errs.append(f"agent_id mismatch: header {header_agent_id} vs body {agent.get('agent_id')}")
            for field in ["agent_id", "boot_id", "hostname", "agent_version", "kernel"]:
                val = agent.get(field)
                if not val or not isinstance(val, str):
                    errs.append(f"agent.{field} must be non-empty string")
            interfaces = agent.get("interfaces")
            if not isinstance(interfaces, list):
                errs.append("agent.interfaces must be a list")

        bhdr = batch.get("batch")
        if not isinstance(bhdr, dict):
            errs.append("missing or non-dict batch header")
        else:
            if not isinstance(bhdr.get("seq"), int) or bhdr.get("seq") < 0:
                errs.append("batch.seq must be non-negative integer")
            if not isinstance(bhdr.get("dropped_since_last"), int) or bhdr.get("dropped_since_last") < 0:
                errs.append("batch.dropped_since_last must be non-negative integer")
            if not isinstance(bhdr.get("sent_at"), str) or len(bhdr.get("sent_at")) == 0:
                errs.append("batch.sent_at must be non-empty string")

        events = batch.get("events")
        if not isinstance(events, list):
            errs.append("events must be a list")
        else:
            for i, ev in enumerate(events):
                ev_type = ev.get("type")
                if ev_type not in VALID_EVENT_TYPES:
                    errs.append(f"event[{i}] invalid type: {ev_type}")
                for req in ["ts", "pid", "ppid", "uid", "gid", "comm"]:
                    if req not in ev:
                        errs.append(f"event[{i}] missing {req}")
                data = ev.get("data")
                if not isinstance(data, dict):
                    errs.append(f"event[{i}] missing or non-dict data")
                else:
                    if ev_type == "EXEC" and "filename" not in data:
                        errs.append(f"event[{i}] EXEC missing filename")
                    elif ev_type == "CONNECT":
                        fam = data.get("family")
                        if fam not in ("inet", "inet6"):
                            errs.append(f"event[{i}] CONNECT invalid family {fam}")
                        if "dst_ip" not in data or "dst_port" not in data:
                            errs.append(f"event[{i}] CONNECT missing dst_ip or dst_port")
                    elif ev_type == "BASH_READLINE" and "command" not in data:
                        errs.append(f"event[{i}] BASH_READLINE missing command")
                    elif ev_type == "PROC_INJECTION":
                        if data.get("method") not in ("process_vm_writev", "ptrace"):
                            errs.append(f"event[{i}] PROC_INJECTION invalid method")
                    elif ev_type == "FILE_TAMPER" and "path" not in data:
                        errs.append(f"event[{i}] FILE_TAMPER missing path")
                    elif ev_type == "PRIV_ESC":
                        if "old_uid" not in data or "target_uid" not in data:
                            errs.append(f"event[{i}] PRIV_ESC missing old_uid or target_uid")
                    elif ev_type == "KERNEL_MODULE" and "args" not in data:
                        errs.append(f"event[{i}] KERNEL_MODULE missing args")
                    elif ev_type == "MEMFD_CREATE" and "name" not in data:
                        errs.append(f"event[{i}] MEMFD_CREATE missing name")

        return errs


def start_server(host="127.0.0.1", port=DEFAULT_PORT):
    server = HTTPServer((host, port), MockSentinelHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    return server


def run_unit_tests():
    print("[*] Running unit validation tests for Mock Sentinel schema validator...")
    handler = MockSentinelHandler
    # Test valid envelope
    valid_batch = {
        "schema_version": 1,
        "agent": {
            "agent_id": "00000000-0000-0000-0000-000000000001",
            "boot_id": "boot-1",
            "hostname": "test-box",
            "agent_version": "0.1.0",
            "kernel": "6.8.0",
            "interfaces": [{"name": "eth0", "mac": "00:11:22:33:44:55", "ipv4": ["1.2.3.4"], "ipv6": []}],
        },
        "batch": {"seq": 1, "sent_at": "2026-10-12T12:00:00Z", "dropped_since_last": 0},
        "events": [
            {
                "type": "EXEC",
                "ts": "2026-10-12T12:00:00.100Z",
                "pid": 123,
                "ppid": 1,
                "uid": 1000,
                "gid": 1000,
                "comm": "sh",
                "data": {"filename": "/bin/sh"},
            },
            {
                "type": "CONNECT",
                "ts": "2026-10-12T12:00:00.200Z",
                "pid": 123,
                "ppid": 1,
                "uid": 1000,
                "gid": 1000,
                "comm": "sh",
                "data": {"family": "inet", "dst_ip": "10.0.0.1", "dst_port": 80},
            },
        ],
    }

    dummy = MockSentinelHandler.__new__(MockSentinelHandler)
    errs = dummy.validate_batch_schema(valid_batch, "00000000-0000-0000-0000-000000000001")
    assert not errs, f"Expected no errors on valid batch, got: {errs}"

    # Test invalid event type
    bad_batch = dict(valid_batch)
    bad_batch["events"] = [{"type": "INVALID_TYPE", "ts": "x", "pid": 1, "ppid": 1, "uid": 0, "gid": 0, "comm": "a", "data": {}}]
    errs2 = dummy.validate_batch_schema(bad_batch, "00000000-0000-0000-0000-000000000001")
    assert any("INVALID_TYPE" in e for e in errs2), f"Expected error for INVALID_TYPE, got {errs2}"
    print("[+] Unit validation tests passed successfully.")


def run_integration_tests(port=8899):
    print(f"[*] Starting Mock Sentinel on 127.0.0.1:{port} for integration tests...")
    server = start_server("127.0.0.1", port)
    run_unit_tests()

    # Verify agent binary exists
    agent_bin = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "proc_exec"))
    if not os.path.exists(agent_bin):
        print(f"[-] Agent binary not found at {agent_bin}. Please run 'make' first.")
        sys.exit(1)

    print("[*] Running symbol isolation check...")
    nm_out = subprocess.check_output(f"nm {agent_bin} | grep process_siem_command | wc -l", shell=True).decode().strip()
    if int(nm_out) != 0:
        print(f"[-] Symbol check failed: found {nm_out} occurrences of process_siem_command!")
        sys.exit(1)
    print("[+] Symbol isolation verified: 0 process_siem_command symbols found.")

    print(f"[+] Mock Sentinel running on 127.0.0.1:{port}. Waiting for telemetry...")
    # Clean up token file in /tmp/test-cerberus-token
    token_file = "/tmp/test-cerberus-token"
    if os.path.exists(token_file):
        os.remove(token_file)

    # Ensure tracefs is mounted if in Linux container
    if os.path.exists("/sys/kernel/tracing") and not os.path.exists("/sys/kernel/tracing/events"):
        subprocess.run("mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null", shell=True)

    # Launch agent with insecure-http and test token
    cmd = [
        agent_bin,
        "--sentinel-url", f"http://127.0.0.1:{port}",
        "--enroll-token", DEFAULT_ENROLL_TOKEN,
        "--token-file", token_file,
        "--insecure-http",
        "-v"
    ]

    print(f"[*] Launching agent: {' '.join(cmd)}")
    agent_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        # Wait up to 6 seconds for initial enrollment & first flush
        time.sleep(3)
        with state.lock:
            enrolled = len(state.enrolled_agents)
        if enrolled == 0:
            print("[!] Agent enrollment not yet seen, waiting additional 3 seconds...")
            time.sleep(3)

        # Trigger test command to generate EXEC and CONNECT events
        print("[*] Generating test activity (bash + connect)...")
        subprocess.run(f"bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}; ls /tmp' 2>/dev/null", shell=True)
        time.sleep(2)

        with state.lock:
            print(f"[+] Total batches received so far: {len(state.received_batches)}")
            print(f"[+] Total events received so far: {len(state.received_events)}")
            print(f"[+] Enrolled agents: {list(state.enrolled_agents.keys())}")
            if state.schema_violations:
                print(f"[-] Schema violations encountered: {state.schema_violations}")
                sys.exit(1)

        # Check self-loop prevention: no CONNECT event should have pid == agent_proc.pid or comm == "proc_exec"
        agent_pid = agent_proc.pid
        with state.lock:
            for ev in state.received_events:
                if ev.get("type") == "CONNECT" and (ev.get("pid") == agent_pid or ev.get("comm") == "proc_exec"):
                    print(f"[-] FAIL: Agent self-loop detected! Found CONNECT from agent PID {ev.get('pid')} (comm: {ev.get('comm')})")
                    sys.exit(1)
        print("[+] Self-loop check passed: no CONNECT events from agent's own PID or comm.")

        # Test retry logic with 500
        print("[*] Setting mock to fail telemetry with 500 three times...")
        with state.lock:
            state.fail_telemetry_500_count = 3
            initial_batch_count = len(state.received_batches)

        # Trigger more activity and wait for retries across backoffs
        subprocess.run(f"bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}; echo hello' 2>/dev/null", shell=True)
        
        deadline = time.time() + 25
        while time.time() < deadline:
            with state.lock:
                if state.fail_telemetry_500_count == 0 and len(state.received_batches) > initial_batch_count:
                    break
            time.sleep(0.5)

        with state.lock:
            print(f"[+] Remaining 500 counts: {state.fail_telemetry_500_count}")
            if state.fail_telemetry_500_count > 0:
                print(f"[-] FAIL: Agent did not retry and exhaust 500 errors (remaining: {state.fail_telemetry_500_count})")
                sys.exit(1)
            # Ensure sequence contiguous
            seqs = [b["batch"]["seq"] for b in state.received_batches]
            print(f"[+] Batch sequences recorded: {seqs}")
            for i in range(len(seqs) - 1):
                if seqs[i+1] != seqs[i] + 1:
                    print(f"[-] FAIL: Sequence numbers not contiguous: {seqs}")
                    sys.exit(1)

        print("[+] Integration test completed successfully!")

    finally:
        agent_proc.terminate()
        try:
            agent_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            agent_proc.kill()
        server.shutdown()
        if os.path.exists(token_file):
            os.remove(token_file)


def main():
    parser = argparse.ArgumentParser(description="Mock Sentinel HTTP Server for Cerberus Agent")
    parser.add_argument("--host", default="0.0.0.0", help="Listen host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Listen port (default: {DEFAULT_PORT})")
    parser.add_argument("--enroll-token", default=DEFAULT_ENROLL_TOKEN, help="Expected enrollment token")
    parser.add_argument("--test", action="store_true", help="Run automated test suite")
    args = parser.parse_args()

    state.enroll_token = args.enroll_token

    if args.test:
        run_integration_tests(port=8899)
    else:
        print(f"[*] Starting Mock Sentinel on {args.host}:{args.port}...")
        server = HTTPServer((args.host, args.port), MockSentinelHandler)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            server.shutdown()


if __name__ == "__main__":
    main()
