"""Private bridge between an isolated Windows guest and the test runner."""
import hashlib
import json
import os
import re
import socket
import threading
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
media_started = threading.Event()
media_ready = threading.Event()
setup_rebooted = threading.Event()

def monitor_command(conn, command):
    conn.sendall((command + "\n").encode("ascii"))
    data = b""
    while b"(qemu) " not in data:
        block = conn.recv(65536)
        if not block or len(data) > 8 * 1024 * 1024:
            raise OSError("invalid QEMU monitor response")
        data += block
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", data.decode("utf-8", "replace"))

def desktop_ready(conn):
    """Recognize the disposable guest's Windows taskbar before sending keys."""
    target = Path("/tmp/netflow-desktop.ppm")
    monitor_command(conn, "screendump " + str(target))
    data = target.read_bytes()
    header = re.match(rb"P6\s+(\d+)\s+(\d+)\s+255\s", data)
    if not header:
        return False
    width, height = map(int, header.groups())
    pixels = data[header.end():]
    if width < 640 or height < 480 or width > 4096 or height > 2160 or len(pixels) != width * height * 3:
        return False
    light = dark = 0
    for y in range(height - 36, height - 4):
        for x in range(4, 44):
            offset = (y * width + x) * 3
            r, g, b = pixels[offset:offset + 3]
            light += r > 190 and g > 190 and b > 190
            dark += r < 95 and g < 95 and b < 95
    return light > 20 and dark > 300

def start_media_from_desktop(conn, drive):
    """Start only our fixed executable; no shell or guest command is used."""
    # An unsuccessful drive attempt can leave both an error dialog and the
    # Run dialog open. Close both before trying the next fixed path.
    for _ in range(3):
        monitor_command(conn, "sendkey esc 100")
        time.sleep(.5)
    monitor_command(conn, "sendkey meta_l-r 100")
    # The Run dialog may take several seconds to receive focus on a cold,
    # single-CPU guest. Clear its history only after it has opened.
    time.sleep(4)
    monitor_command(conn, "sendkey ctrl-a 100")
    command = drive + r":\netflow-vm-agent.exe"
    for char in command:
        key = {":": "shift-semicolon", "\\": "backslash", ".": "dot", "-": "minus"}.get(char, char)
        if len(key) == 1 and key.isupper():
            key = "shift-" + key.lower()
        monitor_command(conn, "sendkey " + key + " 75")
        time.sleep(.1)
    monitor_command(conn, "sendkey ret 100")

def drive_order(previous):
    letters = "DEFGHIJKLMNOPQRSTUVWXYZ"
    if len(previous) == 1 and previous in letters:
        index = letters.index(previous)
        return "".join(sorted(letters, key=lambda drive: (abs(letters.index(drive) - index), letters.index(drive))))
    return letters

def bootstrap_media_agent():
    # Fresh installations complete their first-logon setup and reboot first.
    if not (Path("/storage/windows.boot").exists() or Path("/storage/windows.system").exists()):
        if not setup_rebooted.wait(900):
            return
        # First-logon setup schedules a reboot to enable UAC; wait for it
        # before trying the non-elevated test agent on a fresh installation.
        if media_started.wait(90):
            return
    last_drive = RESULTS / "last-media-drive"
    try:
        previous = last_drive.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        previous = ""
    while not media_started.is_set():
        completed = True
        for drive in drive_order(previous):
            if media_started.is_set():
                return
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                    conn.settimeout(10)
                    conn.connect("/run/shm/monitor.sock")
                    greeting = b""
                    while b"(qemu) " not in greeting:
                        part = conn.recv(65536)
                        if not part:
                            raise OSError("QEMU monitor closed")
                        greeting += part
                    if not desktop_ready(conn):
                        completed = False
                        break
                    print("Windows guest: starting read-only media agent at " + drive + ":", flush=True)
                    start_media_from_desktop(conn, drive)
            except (OSError, ValueError):
                completed = False
                break
            if media_started.wait(10):
                try:
                    tmp = RESULTS / (RUN_ID + ".drive.tmp")
                    tmp.write_text(drive, encoding="ascii")
                    os.replace(tmp, last_drive)
                except OSError as err:
                    print("Windows guest: could not remember media drive: " + str(err), flush=True)
                return
        if completed and not media_started.is_set():
            # Do not loop indefinitely or report success when Windows refuses
            # to start the agent (for example due to a security detection).
            tmp = RESULTS / (RUN_ID + ".tmp")
            tmp.write_text(json.dumps({"id": RUN_ID, "ok": False, "output": "", "error": "could not start the read-only media agent; check guest security history and optical media"}), encoding="utf-8")
            os.replace(tmp, RESULTS / (RUN_ID + ".json"))
            return
        if media_started.wait(15):
            return

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
        if self.path == "/v1/provider.yaml":
            return self.send_bytes(200, b"proxies:\n  - {name: remote, type: ss, server: 127.0.0.1, port: 3, cipher: aes-128-gcm, password: test}\n", "text/plain")
        if self.path == "/v1/rules.yaml":
            return self.send_bytes(200, b"payload:\n  - '+.fresh.netflow-test.example'\n  - '+.second.netflow-test.example'\n", "text/plain")
        if self.path == "/v1/manifest":
            try:
                body = load_manifest()
                if body is None:
                    return self.send_bytes(503, b"Preparing test payload", "text/plain")
                return self.send_bytes(200, body, "application/json")
            except (OSError, ValueError):
                return self.send_bytes(503, b"Invalid test payload", "text/plain")
        self.send_error(404)

    def do_POST(self):
        if self.path == "/v1/event":
            try:
                length = int(self.headers.get("Content-Length", "-1"))
                if not 1 <= length <= 64:
                    raise ValueError("invalid event size")
                event = self.rfile.read(length).decode("ascii")
                if event not in {"setup-start", "setup-refused", "setup-reboot", "agent-elevated", "agent-ready", "media-agent-starting", "media-agent-ready", "media-agent-refused", "test-start", "test-finished"}:
                    raise ValueError("invalid event")
                print("Windows guest: " + event, flush=True)
                if event == "setup-start":
                    detach_setup_media()
                elif event == "setup-reboot":
                    setup_rebooted.set()
                elif event == "media-agent-starting":
                    media_started.set()
                elif event == "media-agent-ready":
                    media_ready.set()
                elif event == "media-agent-refused" and not media_ready.is_set():
                    tmp = RESULTS / (RUN_ID + ".tmp")
                    tmp.write_text(json.dumps({"id": RUN_ID, "ok": False, "output": "", "error": "guest did not pass QEMU and single-disk checks"}), encoding="utf-8")
                    os.replace(tmp, RESULTS / (RUN_ID + ".json"))
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

threading.Thread(target=bootstrap_media_agent, daemon=True).start()
ThreadingHTTPServer(("127.0.0.1", 18765), Handler).serve_forever()
