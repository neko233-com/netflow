"""Run the Windows portable ZIP against a local HTTP origin, without OS proxy changes."""

import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import queue
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
    parser = argparse.ArgumentParser()
    parser.add_argument("-Quiet", action="store_true", help="start with the native window hidden")
    args = parser.parse_args()
    if os.name != "nt":
        raise RuntimeError("This smoke test needs Windows")
    build = (ROOT / "build").resolve(strict=True)
    sandbox = Path(tempfile.mkdtemp(prefix="netflow-smoke-", dir=build)).resolve()
    if sandbox.parent != build or not sandbox.name.startswith("netflow-smoke-"):
        raise RuntimeError("unexpected smoke-test path")
    app = None
    origin = None
    try:
        installed = os.environ.get("NETFLOW_SMOKE_INSTALLED") == "1"
        if installed:
            for name in ("NetFlow.exe", "netflow-agent.exe", "netflow-kernel-worker.exe"):
                shutil.copyfile(Path(os.environ["LOCALAPPDATA"]) / "Programs" / "NetFlow" / name, sandbox / name)
        else:
            with zipfile.ZipFile(ARCHIVE) as z:
                for name in ("NetFlow.exe", "netflow-agent.exe", "netflow-kernel-worker.exe"):
                    with z.open("NetFlow/" + name) as src, (sandbox / name).open("wb") as dst:
                        shutil.copyfileobj(src, dst)
        origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        thread.start()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        data = sandbox / "data"
        data.mkdir()
        if args.Quiet:
            prefs = {"Language": "zh", "SilentStart": True}
            (data / "settings.json").write_text(json.dumps({"prefs": json.dumps(prefs)}), encoding="utf-8")
        (data / "config.yaml").write_text(
            f"mixed-port: {port}\nport: 0\nsocks-port: 0\nallow-lan: false\n"
            "mode: rule\nlog-level: error\nipv6: false\ngeo-auto-update: false\n"
            "dns:\n  enable: false\ntun:\n  enable: false\n"
            "proxy-groups:\n  - name: SmokeGroup\n    type: select\n    proxies: [DIRECT, REJECT]\n"
            "rules:\n  - MATCH,DIRECT\n",
            encoding="utf-8",
        )
        env = dict(os.environ, NETFLOW_CONFIG_DIR=str(data), GOMAXPROCS="1")
        app = subprocess.Popen([str(sandbox / "NetFlow.exe")], env=env, cwd=sandbox,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=subprocess.CREATE_NO_WINDOW | subprocess.BELOW_NORMAL_PRIORITY_CLASS)
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
        agent = str(sandbox / "netflow-agent.exe")
        def call(*args, data=None):
            result = subprocess.run([agent, "--config-dir", str(data_dir), *args], input=data, capture_output=True,
                                    text=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW | subprocess.BELOW_NORMAL_PRIORITY_CLASS)
            if result.returncode:
                raise RuntimeError(f"agent {args}: {result.stderr}")
            return json.loads(result.stdout)
        data_dir = data
        deadline = time.monotonic() + 15
        while True:
            try:
                status = call("status")
                break
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)
        if not status["running"] or status["tun"] or status["tun_pending"]:
            raise RuntimeError("unexpected initial core or TUN state")
        tun_result = call("tun", "off")
        if not tun_result["accepted"] or tun_result["pending"] or tun_result["tun"]:
            raise RuntimeError("safe TUN-off command failed")
        groups = call("groups")["groups"]
        if not any(g["name"] == "SmokeGroup" and len(g["nodes"]) == 2 for g in groups):
            raise RuntimeError("agent did not list real proxy group members")
        if call("rules", "0", "1")["total"] < 1:
            raise RuntimeError("agent did not list active rules")
        if not call("select", "SmokeGroup", "REJECT")["ok"]:
            raise RuntimeError("agent proxy selection failed")
        if not call("mode", "global")["ok"] or not call("mode", "rule")["ok"]:
            raise RuntimeError("agent mode changes failed")
        if call("close-connection", "missing")["closed"]:
            raise RuntimeError("agent reported a nonexistent connection as closed")
        change = {"scope":"global", "operation":"set", "layer":{"prepend":["IP-CIDR,127.0.0.1/32,REJECT"]}}
        proposal = call("preview", data=json.dumps(change))
        call("apply", proposal["proposal_id"])
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("GET", f"http://{origin_address}/", headers={"Host": origin_address})
            blocked = conn.getresponse()
            if blocked.status == 200:
                raise RuntimeError("REJECT rule did not block the local request")
        except (ConnectionResetError, http.client.RemoteDisconnected):
            pass
        finally:
            conn.close()
        proposal = call("preview", data=json.dumps({"scope":"global", "operation":"clear"}))
        call("apply", proposal["proposal_id"])
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", f"http://{origin_address}/", headers={"Host": origin_address})
        response = conn.getresponse()
        if response.status != 200 or response.read() != b"netflow-release-smoke-ok":
            raise RuntimeError("clearing the rule did not restore routing")
        conn.close()
        tunnel = socket.create_connection(("127.0.0.1", port), timeout=5)
        tunnel.sendall(f"CONNECT {origin_address} HTTP/1.1\r\nHost: {origin_address}\r\n\r\n".encode())
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = tunnel.recv(4096)
            if not chunk:
                raise RuntimeError("CONNECT ended before response")
            header += chunk
        if b" 200 " not in header.split(b"\r\n", 1)[0]:
            raise RuntimeError(f"CONNECT failed: {header!r}")
        deadline = time.monotonic() + 5
        while True:
            status = call("status")
            matches = [item for item in status.get("connections", []) if item.get("DestinationPort") == str(origin.server_port)]
            if matches:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("active CONNECT absent from status")
            time.sleep(0.1)
        connection_id = matches[0]["ID"]
        proposal = call("preview", data=json.dumps({"scope":"connection", "operation":"set", "connection_id":connection_id, "policy":"REJECT", "ttl_seconds":5}))
        call("apply", proposal["proposal_id"])
        tunnel.sendall(f"GET / HTTP/1.1\r\nHost: {origin_address}\r\nConnection: close\r\n\r\n".encode())
        existing_response = b""
        while True:
            chunk = tunnel.recv(4096)
            if not chunk:
                break
            existing_response += chunk
        tunnel.close()
        if b"netflow-release-smoke-ok" not in existing_response:
            raise RuntimeError("existing connection was unexpectedly interrupted")
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("GET", f"http://{origin_address}/", headers={"Host": origin_address})
            if conn.getresponse().status == 200:
                raise RuntimeError("connection-derived rule did not reject matching new traffic")
        except (ConnectionResetError, http.client.RemoteDisconnected):
            pass
        finally:
            conn.close()
        deadline = time.monotonic() + 12
        while call("status")["overrides"].get("connections"):
            if time.monotonic() >= deadline:
                raise RuntimeError("connection rule did not expire")
            time.sleep(0.25)
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", f"http://{origin_address}/", headers={"Host": origin_address})
        response = conn.getresponse()
        if response.status != 200 or response.read() != b"netflow-release-smoke-ok":
            raise RuntimeError("routing was not restored after expiry")
        conn.close()
        mcp = subprocess.Popen([agent, "--config-dir", str(data_dir), "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW | subprocess.BELOW_NORMAL_PRIORITY_CLASS)
        lines = queue.Queue()
        threading.Thread(target=lambda: [lines.put(line) for line in mcp.stdout], daemon=True).start()
        def rpc(payload):
            mcp.stdin.write(json.dumps(payload) + "\n"); mcp.stdin.flush()
            try:
                return json.loads(lines.get(timeout=15))
            except queue.Empty:
                raise RuntimeError("MCP response timed out")
        try:
            response = rpc({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{"protocolVersion":"2025-06-18", "capabilities":{}, "clientInfo":{"name":"smoke", "version":"1"}}})
            if "result" not in response:
                raise RuntimeError(f"MCP initialize failed: {response}")
            mcp.stdin.write(json.dumps({"jsonrpc":"2.0", "method":"notifications/initialized"}) + "\n"); mcp.stdin.flush()
            response = rpc({"jsonrpc":"2.0", "id":2, "method":"tools/list", "params":{}})
            names = {item["name"] for item in response["result"]["tools"]}
            expected = {"netflow_status", "netflow_set_tun", "netflow_preview_rewrite", "netflow_apply_rewrite", "netflow_proxy_groups", "netflow_rules",
                        "netflow_select_proxy", "netflow_set_mode", "netflow_use_profile", "netflow_close_connection",
                        "netflow_migration_preview", "netflow_migration_import", "netflow_migration_export"}
            if names != expected:
                raise RuntimeError(f"unexpected MCP tools: {names}")
            response = rpc({"jsonrpc":"2.0", "id":3, "method":"tools/call", "params":{"name":"netflow_status", "arguments":{}}})
            if response.get("result", {}).get("isError") or "error" in response:
                raise RuntimeError(f"MCP status failed: {response}")
            response = rpc({"jsonrpc":"2.0", "id":4, "method":"tools/call", "params":{"name":"netflow_proxy_groups", "arguments":{}}})
            if response.get("result", {}).get("isError") or "error" in response:
                raise RuntimeError(f"MCP proxy groups failed: {response}")
        finally:
            mcp.terminate(); mcp.wait(timeout=10)
        print(f"Windows {'installed' if installed else 'portable'}: routing, CLI global/connection rewrites and expiry, MCP handshake/status passed.")
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
