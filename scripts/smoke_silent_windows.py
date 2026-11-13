"""Verify native silent startup with an isolated configuration on Windows."""
import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
VERSION = json.loads((ROOT / "mygo.json").read_text(encoding="utf-8"))["version"]


def windows_for_pid(pid):
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.GetWindowThreadProcessId.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.DWORD))
    user32.GetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
    user32.IsWindowVisible.argtypes = (wintypes.HWND,)
    windows = []
    def visit(handle, _):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(handle, ctypes.byref(owner))
        if owner.value == pid:
            title = ctypes.create_unicode_buffer(256)
            user32.GetWindowTextW(handle, title, len(title))
            if title.value == "NetFlow":
                windows.append(bool(user32.IsWindowVisible(handle)))
        return True
    callback = callback_type(visit)
    if not user32.EnumWindows(callback, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    return windows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-Quiet", action="store_true", help="run without a console or visible test window")
    parser.add_argument("-Installed", action="store_true")
    args = parser.parse_args()
    if os.name != "nt":
        raise RuntimeError("Windows is required")
    build = (ROOT / "build").resolve(strict=True)
    sandbox = Path(tempfile.mkdtemp(prefix="netflow-silent-", dir=build)).resolve()
    if sandbox.parent != build or not sandbox.name.startswith("netflow-silent-"):
        raise RuntimeError("unexpected test directory")
    app = None
    try:
        source = (Path(os.environ["LOCALAPPDATA"]) / "Programs" / "NetFlow") if args.Installed else (build / f"release-artifacts-{VERSION}" / "windows-amd64")
        data = sandbox / "data"
        data.mkdir()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        (data / "config.yaml").write_text(f"mixed-port: {port}\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\nipv6: false\ndns:\n  enable: false\ntun:\n  enable: false\nrules:\n  - MATCH,DIRECT\n", encoding="utf-8")
        prefs = {"Language": "zh", "SilentStart": True}
        (data / "settings.json").write_text(json.dumps({"prefs": json.dumps(prefs)}), encoding="utf-8")
        env = dict(os.environ, NETFLOW_CONFIG_DIR=str(data), GOMAXPROCS="1")
        app = subprocess.Popen([str(source / "NetFlow.exe")], cwd=sandbox, env=env,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=subprocess.CREATE_NO_WINDOW | subprocess.BELOW_NORMAL_PRIORITY_CLASS)
        agent = str(source / "netflow-agent.exe")
        deadline = time.monotonic() + 30
        while True:
            if app.poll() is not None:
                raise RuntimeError(f"desktop exited early: {app.returncode}")
            result = subprocess.run([agent, "--config-dir", str(data), "status"], capture_output=True, timeout=4,
                                    creationflags=subprocess.CREATE_NO_WINDOW | subprocess.BELOW_NORMAL_PRIORITY_CLASS)
            if result.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("desktop agent did not start")
            time.sleep(0.2)
        windows = windows_for_pid(app.pid)
        if not windows or any(windows):
            raise RuntimeError(f"silent startup window visibility unexpected: {windows}")
        if not json.loads(result.stdout)["running"]:
            raise RuntimeError("core did not start in silent mode")
        print("Windows silent startup: hidden native window and running core verified.")
    finally:
        if app and app.poll() is None:
            app.terminate()
            app.wait(timeout=10)
        if sandbox.parent == build and sandbox.name.startswith("netflow-silent-") and not sandbox.is_symlink():
            shutil.rmtree(sandbox)


if __name__ == "__main__":
    main()
