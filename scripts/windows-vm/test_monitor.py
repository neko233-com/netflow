"""Exercise setup-media removal in throwaway, paused QEMU instances."""
import ast
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time

source = Path("/opt/netflow/bridge.py")
tree = ast.parse(source.read_text(encoding="utf-8"), str(source))
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"monitor_command", "detach_setup_media"}]
if len(functions) != 2:
    raise RuntimeError("setup-media monitor functions missing")
scope = {"re": re, "socket": socket, "time": time}
exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), "exec"), scope)

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
