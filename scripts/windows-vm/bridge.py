"""Private bridge between an isolated Windows guest and the test runner."""
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PAYLOAD = Path("/payload")
RESULTS = Path("/storage/netflow-results")
RUN_ID = os.environ["NETFLOW_RUN_ID"]
FILES = ("netflow-app.test.exe", "NetFlow.msi")
if len(RUN_ID) != 32 or any(c not in "0123456789abcdef" for c in RUN_ID):
    raise ValueError("invalid run ID")
RESULTS.mkdir(parents=True, exist_ok=True)
files = {}
manifest = None

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
