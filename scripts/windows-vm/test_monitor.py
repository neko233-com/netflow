"""Exercise setup-media removal in throwaway, paused QEMU instances."""
import ast
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time

source = Path("/opt/netflow/bridge.py")
tree = ast.parse(source.read_text(encoding="utf-8"), str(source))
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"monitor_command", "detach_setup_media", "desktop_ready", "start_media_from_desktop", "drive_order", "bootstrap_media_agent"}]
if len(functions) != 6:
    raise RuntimeError("setup-media monitor functions missing")
scope = {"re": re, "socket": socket, "time": time, "Path": Path}
exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), "exec"), scope)
if scope["drive_order"]("F") != "FEGDHIJKLMNOPQRSTUVWXYZ" or scope["drive_order"]("../bad") != "DEFGHIJKLMNOPQRSTUVWXYZ":
    raise AssertionError("invalid remembered media drive handling")

# Verify desktop recognition and fixed keyboard input without a live guest.
screen = Path("/tmp/netflow-desktop.ppm")
original_monitor = scope["monitor_command"]
commands = []
scope["monitor_command"] = lambda _conn, command: commands.append(command)
width, height = 640, 480
pixels = bytearray(width * height * 3)
screen.write_bytes(f"P6\n{width} {height}\n255\n".encode() + pixels)
if scope["desktop_ready"](None):
    raise AssertionError("blank screen accepted as a desktop")
for y in range(height - 36, height - 32):
    for x in range(4, 20):
        offset = (y * width + x) * 3
        pixels[offset:offset + 3] = b"\xff\xff\xff"
screen.write_bytes(f"P6\n{width} {height}\n255\n".encode() + pixels)
if not scope["desktop_ready"](None):
    raise AssertionError("desktop taskbar was not recognized")
scope["time"] = type("NoSleep", (), {"sleep": staticmethod(lambda _seconds: None)})
commands.clear()
scope["start_media_from_desktop"](None, "D")
if commands[:5] != ["sendkey esc 100"] * 3 + ["sendkey meta_l-r 100", "sendkey ctrl-a 100"] or commands[-1] != "sendkey ret 100" or not all(command.startswith("sendkey ") for command in commands):
    raise AssertionError("unexpected media bootstrap input")
scope["monitor_command"], scope["time"] = original_monitor, time
screen.unlink()

# No agent acknowledgement after one complete drive scan is an explicit
# failure, while a successful acknowledgement must not produce one.
class ImmediateEvent:
    def __init__(self):
        self.set_value = False
    def is_set(self):
        return self.set_value
    def wait(self, _timeout):
        return self.set_value
    def set(self):
        self.set_value = True

class FakeSocket:
    def __enter__(self): return self
    def __exit__(self, *_args): pass
    def settimeout(self, _timeout): pass
    def connect(self, _address): pass
    def recv(self, _size): return b"(qemu) "

with tempfile.TemporaryDirectory(prefix="netflow-bootstrap-test-") as directory:
    base = Path(directory)
    fake_socket = type("FakeSocketModule", (), {"AF_UNIX": 1, "SOCK_STREAM": 1, "socket": staticmethod(lambda *_args: FakeSocket())})
    scope.update({"Path": lambda value: base if value == "/storage/windows.boot" else Path(value), "RESULTS": base, "RUN_ID": "a" * 32, "os": os, "json": json, "socket": fake_socket, "desktop_ready": lambda _conn: True, "time": type("NoSleep", (), {"sleep": staticmethod(lambda _seconds: None)}), "print": lambda *_args, **_kwargs: None})
    attempted = []
    scope["media_started"] = ImmediateEvent()
    scope["start_media_from_desktop"] = lambda _conn, drive: attempted.append(drive)
    scope["bootstrap_media_agent"]()
    result = json.loads((base / ("a" * 32 + ".json")).read_text())
    if result["ok"] or "security history" not in result["error"] or "".join(attempted) != "DEFGHIJKLMNOPQRSTUVWXYZ":
        raise AssertionError("failed media bootstrap did not report its error")
    (base / ("a" * 32 + ".json")).unlink()
    scope["media_started"] = ImmediateEvent()
    scope["start_media_from_desktop"] = lambda _conn, _drive: scope["media_started"].set()
    scope["bootstrap_media_agent"]()
    if (base / ("a" * 32 + ".json")).exists():
        raise AssertionError("acknowledged media bootstrap was reported as failed")
    if (base / "last-media-drive").read_text() != "D":
        raise AssertionError("successful media drive was not remembered")

scope["Path"], scope["socket"], scope["time"] = Path, socket, time
del scope["print"]

monitor = Path("/run/shm/monitor.sock")
if monitor.exists():
    raise RuntimeError("refusing to attach to an existing QEMU monitor")

for extra in (False, True):
    with tempfile.TemporaryDirectory(prefix="netflow-monitor-test-") as directory:
        setup = Path(directory) / "setup.img"
        setup.write_bytes(bytes(1024))
        args = ["qemu-system-x86_64", "-S", "-nodefaults", "-machine", "q35", "-m", "64", "-display", "none", "-monitor", "unix:/run/shm/monitor.sock,server=on,wait=off", "-device", "qemu-xhci", "-drive", f"file={setup},if=none,id=setup,format=raw", "-device", "usb-storage,drive=setup,removable=on"]
        if extra:
            other = Path(directory) / "other.img"
            other.write_bytes(bytes(1024))
            args.extend(["-drive", f"file={other},if=none,id=other,format=raw", "-device", "usb-storage,drive=other,removable=on"])
        process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 15
            while not monitor.exists() and time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("test QEMU exited before opening its monitor")
                time.sleep(0.1)
            if not monitor.exists():
                raise RuntimeError("test QEMU monitor timed out")
            if extra:
                try:
                    scope["detach_setup_media"]()
                except ValueError as err:
                    if "unexpected number" not in str(err):
                        raise
                else:
                    raise AssertionError("multiple USB storage devices were accepted")
            else:
                scope["detach_setup_media"]()
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            if monitor.exists():
                monitor.unlink()

print("Setup-media detach and multiple-device guard passed")
