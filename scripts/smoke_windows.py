"""Run the Windows portable ZIP against a local HTTP origin, without OS proxy changes."""

import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import zipfile


ROOT = Path(__file__).resolve().parent.parent
VERSION = json.loads((ROOT / "mygo.json").read_text(encoding="utf-8"))["version"]
ARCHIVE = ROOT / "build" / "releases" / VERSION / f"NetFlow-{VERSION}-windows-amd64-portable.zip"


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"netflow-release-smoke-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main():
    if os.name != "nt":
        raise RuntimeError("This smoke test needs Windows")
    build = (ROOT / "build").resolve(strict=True)
    sandbox = Path(tempfile.mkdtemp(prefix="netflow-smoke-", dir=build)).resolve()
    if sandbox.parent != build or not sandbox.name.startswith("netflow-smoke-"):
        raise RuntimeError("unexpected smoke-test path")
    app = None
    origin = None
    try:
        with zipfile.ZipFile(ARCHIVE) as z, z.open("NetFlow/NetFlow.exe") as src, (sandbox / "NetFlow.exe").open("wb") as dst:
            shutil.copyfileobj(src, dst)
        origin = HTTPServer(("127.0.0.1", 0), Origin)
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        thread.start()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        data = sandbox / "data"
        data.mkdir()
        (data / "config.yaml").write_text(
            f"mixed-port: {port}\nport: 0\nsocks-port: 0\nallow-lan: false\n"
            "mode: rule\nlog-level: error\nipv6: false\ngeo-auto-update: false\n"
            "dns:\n  enable: false\ntun:\n  enable: false\nrules:\n  - MATCH,DIRECT\n",
            encoding="utf-8",
        )
        env = dict(os.environ, NETFLOW_CONFIG_DIR=str(data), GOMAXPROCS="1")
        app = subprocess.Popen([str(sandbox / "NetFlow.exe")], env=env, cwd=sandbox,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=subprocess.CREATE_NO_WINDOW)
        deadline = time.monotonic() + 30
        while True:
            if app.poll() is not None:
                raise RuntimeError(f"NetFlow exited early: {app.returncode}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("proxy port did not start")
                time.sleep(0.2)
        origin_address = f"127.0.0.1:{origin.server_port}"
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", f"http://{origin_address}/", headers={"Host": origin_address})
        response = conn.getresponse()
        payload = response.read()
        conn.close()
        if response.status != 200 or payload != b"netflow-release-smoke-ok":
            raise RuntimeError(f"proxy returned {response.status}, {payload!r}")
        print("Portable Windows binary forwarded a local HTTP request successfully.")
    finally:
        if app and app.poll() is None:
            app.terminate()
            app.wait(timeout=10)
        if origin:
            origin.shutdown()
            origin.server_close()
        # Only the uniquely created smoke-test directory is removed.
        if sandbox.parent == build and sandbox.name.startswith("netflow-smoke-") and not sandbox.is_symlink():
            shutil.rmtree(sandbox)


if __name__ == "__main__":
    main()
