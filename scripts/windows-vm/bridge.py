"""Private bridge between an isolated Windows guest and the test runner."""
import hashlib
import json
import os
import re
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PAYLOAD = Path("/payload")
RESULTS = Path("/storage/netflow-results")
RUN_ID = os.environ["NETFLOW_RUN_ID"]
FILES = ("netflow-app.test.exe", "NetFlow.msi", "netflow-vm-agent.exe")
if len(RUN_ID) != 32 or any(c not in "0123456789abcdef" for c in RUN_ID):
    raise ValueError("invalid run ID")
RESULTS.mkdir(parents=True, exist_ok=True)
files = {}
manifest = None

def monitor_command(conn, command):
    conn.sendall((command + "\n").encode("ascii"))
    data = b""
    while b"(qemu) " not in data:
        block = conn.recv(65536)
        if not block or len(data) > 8 * 1024 * 1024:
            raise OSError("invalid QEMU monitor response")
        data += block
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", data.decode("utf-8", "replace"))

def detach_setup_media():
    # SetupComplete has copied C:\OEM before FirstLogonCommands runs. Only
    # unplug the unique QEMU USB setup disk, never the guest's system disk.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect("/run/shm/monitor.sock")
        greeting = b""
        while b"(qemu) " not in greeting:
            part = conn.recv(65536)
            if not part:
                raise OSError("QEMU monitor closed")
            greeting += part
        tree = monitor_command(conn, "info qom-tree")
        section = tree.split("/peripheral-anon (container)", 1)
        if len(section) != 2:
            raise ValueError("QEMU peripheral tree unavailable")
        section = section[1].split("\n  /", 1)[0]
        devices = re.findall(r"(?m)^    /(device\[\d+\]) \(usb-storage\)\s*$", section)
        if not devices:
            return
        if len(devices) != 1:
            raise ValueError("unexpected number of USB storage devices")
        qtree = monitor_command(conn, "info qtree")
        if qtree.count('drive = "setup"') != 1 or qtree.count("dev: usb-storage") != 1:
            raise ValueError("USB storage is not the unique setup medium")
        response = monitor_command(conn, "device_del /machine/peripheral-anon/" + devices[0])
        if "Error" in response or "not found" in response:
            raise OSError("QEMU refused to unplug setup medium")
        for _ in range(20):
            time.sleep(0.5)
            if "(usb-storage)" not in monitor_command(conn, "info qom-tree"):
                print("Windows guest: setup medium detached", flush=True)
                return
        raise OSError("QEMU setup medium did not detach")

def load_manifest():
    global manifest
    if manifest is not None:
        return manifest
    if not (PAYLOAD / "ready").is_file():
        return None
    candidate = {}
    for name in FILES:
        path = PAYLOAD / name
        digest = hashlib.sha256()
        with path.open("rb") as src:
            for block in iter(lambda: src.read(1024 * 1024), b""):
                digest.update(block)
        candidate[name] = {"sha256": digest.hexdigest(), "size": path.stat().st_size}
    expected = json.loads((PAYLOAD / "expected.json").read_text(encoding="utf-8"))
    if set(expected) != {"NetFlow.exe", "netflow-agent.exe", "netflow-kernel-worker.exe"}:
        raise ValueError("invalid expected binary list")
    files.update(candidate)
    manifest = json.dumps({"id": RUN_ID, "files": files, "expected": expected}, separators=(",", ":")).encode()
    return manifest

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def send_bytes(self, status, body, kind="application/octet-stream"):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self.send_bytes(200, b"OK", "text/plain")
        if self.path == "/v1/manifest":
            try:
                body = load_manifest()
                if body is None:
                    return self.send_bytes(503, b"Preparing test payload", "text/plain")
                return self.send_bytes(200, body, "application/json")
            except (OSError, ValueError):
                return self.send_bytes(503, b"Invalid test payload", "text/plain")
        if self.path.startswith("/v1/files/"):
            name = self.path.removeprefix("/v1/files/")
            if name in FILES:
                with (PAYLOAD / name).open("rb") as src:
                    self.send_response(200)
                    self.send_header("Content-Length", str(files[name]["size"]))
                    self.end_headers()
                    while block := src.read(1024 * 1024):
                        self.wfile.write(block)
                return
        self.send_error(404)

    def do_POST(self):
        if self.path == "/v1/event":
            try:
                length = int(self.headers.get("Content-Length", "-1"))
                if not 1 <= length <= 64:
                    raise ValueError("invalid event size")
                event = self.rfile.read(length).decode("ascii")
                if event not in {"setup-start", "setup-refused", "setup-reboot", "agent-elevated", "agent-ready", "agent-update"}:
                    raise ValueError("invalid event")
                print("Windows guest: " + event, flush=True)
                if event == "setup-start":
                    detach_setup_media()
                return self.send_bytes(200, b"OK", "text/plain")
            except (ValueError, UnicodeDecodeError, OSError) as err:
                print("Windows guest event failed: " + str(err), flush=True)
                return self.send_error(400)
        if self.path != "/v1/result":
            return self.send_error(404)
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if not 1 <= length <= 2 * 1024 * 1024:
                raise ValueError("invalid result size")
            raw = self.rfile.read(length)
            result = json.loads(raw)
            if result.get("id") != RUN_ID or not isinstance(result.get("ok"), bool):
                raise ValueError("invalid result")
            destination = RESULTS / (RUN_ID + ".json")
            tmp = RESULTS / (RUN_ID + ".tmp")
            tmp.write_bytes(raw)
            os.replace(tmp, destination)
            self.send_bytes(200, b"OK", "text/plain")
        except (ValueError, OSError, json.JSONDecodeError):
            self.send_error(400)

ThreadingHTTPServer(("127.0.0.1", 18765), Handler).serve_forever()
