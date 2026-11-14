"""Verify an installed GeoData update through a local proxy without TUN changes."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
COMMIT = "d12e37856df12a62bb4647da66d20feddb8783a6"
URL = f"https://raw.githubusercontent.com/maxmind/MaxMind-DB/{COMMIT}/test-data/GeoIP2-Country-Test.mmdb"
FLAGS = subprocess.CREATE_NO_WINDOW | subprocess.BELOW_NORMAL_PRIORITY_CLASS

def main():
    if os.name != "nt":
        raise RuntimeError("Windows is required")
    build = (ROOT / "build").resolve(strict=True)
    sandbox = Path(tempfile.mkdtemp(prefix="netflow-geo-smoke-", dir=build)).resolve()
    if sandbox.parent != build or not sandbox.name.startswith("netflow-geo-smoke-"):
        raise RuntimeError("unexpected smoke directory")
    app = None
    log = None
    try:
        installed = Path(os.environ["LOCALAPPDATA"]) / "Programs" / "NetFlow"
        for name in ("NetFlow.exe", "netflow-agent.exe", "netflow-kernel-worker.exe"):
            shutil.copyfile(installed / name, sandbox / name)
        data = sandbox / "data"
        data.mkdir()
        (data / "settings.json").write_text(json.dumps({"prefs": json.dumps({"SilentStart": True})}), encoding="utf-8")
        (data / "Country.mmdb").write_bytes(b"old synthetic database")
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        (data / "config.yaml").write_text(
            f"mixed-port: {port}\nport: 0\nsocks-port: 0\nmode: direct\nlog-level: error\n"
            f"dns: {{enable: false}}\ntun: {{enable: false}}\ngeox-url: {{mmdb: '{URL}'}}\nrules: ['MATCH,DIRECT']\n",
            encoding="utf-8",
        )
        env = dict(os.environ, NETFLOW_CONFIG_DIR=str(data), GOMAXPROCS="1")
        log = (sandbox / "app.log").open("wb")
        agent = str(sandbox / "netflow-agent.exe")
        def call(*args):
            result = subprocess.run([agent, "--config-dir", str(data), *args], capture_output=True, text=True, timeout=35, creationflags=FLAGS)
            if result.returncode:
                raise RuntimeError(f"agent {args}: {result.stderr}")
            return json.loads(result.stdout)
        def start():
            proc = subprocess.Popen([str(sandbox / "NetFlow.exe")], env=env, cwd=sandbox, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, creationflags=FLAGS)
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError(f"GUI exited: {proc.returncode}")
                try:
                    if call("status")["running"]:
                        return proc
                except (RuntimeError, subprocess.TimeoutExpired):
                    pass
                time.sleep(.25)
            proc.terminate()
            proc.wait(timeout=10)
            raise RuntimeError("GUI did not become ready")
        app = start()
        result = call("update-geo")
        if not result.get("accepted"):
            raise RuntimeError(f"update not accepted: {result}")
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            state = call("status")
            if state.get("geo_error"):
                raise RuntimeError(f"GeoData download failed: {state['geo_error']}")
            if not state.get("geo_pending") and state.get("geo_restart_required"):
                break
            time.sleep(.25)
        else:
            raise RuntimeError("GeoData update timed out")
        if (data / "Country.mmdb").read_bytes() != b"old synthetic database":
            raise RuntimeError("database changed while the kernel was running")
        app.terminate()
        app.wait(timeout=10)
        app = start()
        got = hashlib.sha256((data / "Country.mmdb").read_bytes()).digest()
        expected = hashlib.sha256((ROOT / "internal" / "app" / "testdata" / "GeoIP2-Country-Test.mmdb").read_bytes()).digest()
        if got != expected or (data / ".netflow-geodata-pending").exists():
            raise RuntimeError("downloaded database was not applied on restart")
        print("Windows installed: GeoData HTTPS download through the local proxy and restart application passed.")
    finally:
        if app and app.poll() is None:
            app.terminate()
            app.wait(timeout=10)
        if log:
            log.close()
        if sandbox.parent == build and sandbox.name.startswith("netflow-geo-smoke-") and not sandbox.is_symlink():
            shutil.rmtree(sandbox)

if __name__ == "__main__":
    main()
