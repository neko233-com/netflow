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
    app_log = None
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
        app_log = (sandbox / "app.log").open("wb")
        app = subprocess.Popen([str(sandbox / "NetFlow.exe")], env=env, cwd=sandbox,
                               stdin=subprocess.DEVNULL, stdout=app_log, stderr=subprocess.STDOUT,
                               creationflags=subprocess.CREATE_NO_WINDOW | subprocess.BELOW_NORMAL_PRIORITY_CLASS)
        deadline = time.monotonic() + 30
        while True:
            if app.poll() is not None:
                raise RuntimeError(f"NetFlow exited early: {app.returncode}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    break
            except OSError as error:
                if time.monotonic() >= deadline:
                    app_log.flush()
                    details = (sandbox / "app.log").read_text(encoding="utf-8", errors="replace")[-2000:]
                    raise RuntimeError(f"proxy port {port} did not start: {error}; application log: {details}")
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
        if call("tun-autostart")["enabled"]:
            raise RuntimeError("GUI TUN autostart was not opt-in")
        if not call("tun-autostart", "on")["enabled"] or call("status")["tun"]:
            raise RuntimeError("startup preference changed current TUN")
        if call("tun-autostart", "off")["enabled"]:
            raise RuntimeError("GUI TUN autostart was not disabled")
        diagnostics = call("diagnostics")
        if diagnostics["schema_version"] != 1 or diagnostics["app_version"] != VERSION or not diagnostics["core_running"] or diagnostics["tun"]:
            raise RuntimeError("unexpected diagnostics")
        build_info = subprocess.check_output(["go", "version", "-m", str(sandbox / "NetFlow.exe")], text=True,
                                             creationflags=subprocess.CREATE_NO_WINDOW | subprocess.BELOW_NORMAL_PRIORITY_CLASS).splitlines()
        core_version = None
        for index, line in enumerate(build_info):
            fields = line.split()
            if fields[:2] == ["dep", "github.com/metacubex/mihomo"] and len(fields) >= 3:
                core_version = fields[2]
                if index + 1 < len(build_info):
                    replacement = build_info[index + 1].split()
                    if len(replacement) >= 3 and replacement[0] == "=>":
                        core_version = replacement[2]
                break
        if not core_version or diagnostics["core_version"] != core_version.removeprefix("v"):
            raise RuntimeError("reported core version differs from the executable build metadata")
        if any(key in diagnostics for key in ("config_dir", "profiles", "connections", "token", "tun_error")):
            raise RuntimeError("diagnostics exposed user data")
        if set(status["tun_stacks"]) != {"system", "mixed", "gvisor", "mips"}:
            raise RuntimeError("release build is missing TUN protocol stacks")
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
        page = call("preview-rules", proposal["proposal_id"], "after", "0", "2")
        if not page["rules"] or page["rules"][0] != "IP-CIDR,127.0.0.1/32,REJECT" or page["total"] != proposal["rules_after_total"]:
            raise RuntimeError("CLI preview page did not match the proposed rules")
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
            matches = [item for item in status.get("connections", []) if item.get("DestinationPort") == str(origin.server_port) and item.get("SourcePort") == str(tunnel.getsockname()[1])]
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
        # A rollback restores only the selected matcher and must not reroute an
        # already established socket. Exercise the packaged CLI end to end.
        tunnel = socket.create_connection(("127.0.0.1", port), timeout=5)
        tunnel.sendall(f"CONNECT {origin_address} HTTP/1.1\r\nHost: {origin_address}\r\n\r\n".encode())
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = tunnel.recv(4096)
            if not chunk:
                raise RuntimeError("rollback CONNECT ended before response")
            header += chunk
        if b" 200 " not in header.split(b"\r\n", 1)[0]:
            raise RuntimeError("rollback CONNECT failed")
        deadline = time.monotonic() + 5
        while True:
            status = call("status")
            matches = [item for item in status.get("connections", []) if item.get("DestinationPort") == str(origin.server_port) and item.get("SourcePort") == str(tunnel.getsockname()[1])]
            if matches:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("rollback connection absent from status")
            time.sleep(0.1)
        connection_id = matches[0]["ID"]
        before_revision = status["revision"]
        proposal = call("preview", data=json.dumps({"scope":"connection", "operation":"set", "connection_id":connection_id, "policy":"REJECT", "ttl_seconds":60}))
        reject_revision = call("apply", proposal["proposal_id"])["revision"]
        proposal = call("preview", data=json.dumps({"scope":"connection", "operation":"set", "connection_id":connection_id, "policy":"DIRECT", "ttl_seconds":60}))
        call("apply", proposal["proposal_id"])
        history = call("rewrite-history")["entries"]
        if reject_revision not in [entry["revision"] for entry in history]:
            raise RuntimeError("connection history missing")
        proposal = call("rollback-preview", data=json.dumps({"revision":reject_revision, "scope":"connection", "connection_id":connection_id}))
        call("apply", proposal["proposal_id"])
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("GET", f"http://{origin_address}/", headers={"Host": origin_address})
            if conn.getresponse().status == 200:
                raise RuntimeError("connection rollback did not restore REJECT")
        except (ConnectionResetError, http.client.RemoteDisconnected):
            pass
        finally:
            conn.close()
        proposal = call("rollback-preview", data=json.dumps({"revision":before_revision, "scope":"connection", "connection_id":connection_id}))
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
            raise RuntimeError("rollback interrupted established connection")
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", f"http://{origin_address}/", headers={"Host": origin_address})
        response = conn.getresponse()
        if response.status != 200 or response.read() != b"netflow-release-smoke-ok":
            raise RuntimeError("connection rollback did not clear the matcher")
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
            expected = {"netflow_status", "netflow_diagnostics", "netflow_kernel_options", "netflow_set_kernel_option", "netflow_shutdown_headless", "netflow_set_tun", "netflow_tun_autostart", "netflow_set_tun_autostart", "netflow_update_geodata", "netflow_preview_rewrite", "netflow_preview_rules", "netflow_cancel_preview", "netflow_apply_rewrite", "netflow_rewrite_history", "netflow_preview_rollback", "netflow_clear_rewrite_history", "netflow_proxy_groups", "netflow_rules",
                        "netflow_profiles", "netflow_profile_settings", "netflow_update_profile_settings", "netflow_replace_profile_url", "netflow_import_profile", "netflow_update_profile", "netflow_profile_job_status", "netflow_delete_profile",
                        "netflow_backup_create", "netflow_backup_job_status", "netflow_restore_backup", "netflow_backup_schedule", "netflow_backup_schedule_set", "netflow_webdav_config", "netflow_webdav_save", "netflow_webdav_clear", "netflow_webdav_list", "netflow_webdav_upload", "netflow_webdav_restore",
                        "netflow_providers", "netflow_update_provider", "netflow_provider_job_status",
                        "netflow_select_proxy", "netflow_set_mode", "netflow_use_profile", "netflow_close_connection",
                        "netflow_migration_preview", "netflow_migration_import", "netflow_migration_export"}
            if names != expected:
                raise RuntimeError(f"unexpected MCP tools: {names}")
            response = rpc({"jsonrpc":"2.0", "id":14, "method":"tools/call", "params":{"name":"netflow_set_tun_autostart", "arguments":{"enabled":True}}})
            if response.get("result", {}).get("isError") or not response.get("result", {}).get("structuredContent", {}).get("enabled") or call("status")["tun"]:
                raise RuntimeError(f"MCP TUN startup preference failed: {response}")
            response = rpc({"jsonrpc":"2.0", "id":15, "method":"tools/call", "params":{"name":"netflow_set_tun_autostart", "arguments":{"enabled":False}}})
            if response.get("result", {}).get("isError") or response.get("result", {}).get("structuredContent", {}).get("enabled"):
                raise RuntimeError(f"MCP TUN startup preference reset failed: {response}")
            proposal = call("preview", data=json.dumps({"scope":"global", "operation":"clear"}))
            response = rpc({"jsonrpc":"2.0", "id":12, "method":"tools/call", "params":{"name":"netflow_preview_rules", "arguments":{"proposal_id":proposal["proposal_id"], "stage":"after", "offset":0, "limit":2}}})
            if response.get("result", {}).get("isError") or response.get("result", {}).get("structuredContent", {}).get("total") != proposal["rules_after_total"]:
                raise RuntimeError(f"MCP preview page failed: {response}")
            response = rpc({"jsonrpc":"2.0", "id":13, "method":"tools/call", "params":{"name":"netflow_cancel_preview", "arguments":{"proposal_id":proposal["proposal_id"]}}})
            if response.get("result", {}).get("isError") or not response.get("result", {}).get("structuredContent", {}).get("ok"):
                raise RuntimeError(f"MCP cancel preview failed: {response}")
            response = rpc({"jsonrpc":"2.0", "id":10, "method":"tools/call", "params":{"name":"netflow_rewrite_history", "arguments":{}}})
            if response.get("result", {}).get("isError") or not response.get("result", {}).get("structuredContent", {}).get("entries"):
                raise RuntimeError(f"MCP rewrite history failed: {response}")
            response = rpc({"jsonrpc":"2.0", "id":11, "method":"tools/call", "params":{"name":"netflow_clear_rewrite_history", "arguments":{}}})
            if response.get("result", {}).get("isError") or "revision" not in response.get("result", {}).get("structuredContent", {}):
                raise RuntimeError(f"MCP clear history failed: {response}")
            if call("rewrite-history")["entries"]:
                raise RuntimeError("history was not cleared")
            response = rpc({"jsonrpc":"2.0", "id":7, "method":"tools/call", "params":{"name":"netflow_kernel_options", "arguments":{}}})
            if response.get("result", {}).get("isError") or "error" in response or "overrides" not in response.get("result", {}).get("structuredContent", {}) or response.get("result", {}).get("structuredContent", {}).get("effective", {}).get("log_level") != "error":
                raise RuntimeError(f"MCP kernel options failed: {response}")
            response = rpc({"jsonrpc":"2.0", "id":8, "method":"tools/call", "params":{"name":"netflow_set_kernel_option", "arguments":{"name":"log-level", "string_value":"warning"}}})
            if "error" in response or response.get("result", {}).get("isError") or response.get("result", {}).get("structuredContent", {}).get("overrides", {}).get("log_level") != "warning" or response.get("result", {}).get("structuredContent", {}).get("effective", {}).get("log_level") != "warning":
                raise RuntimeError(f"MCP kernel option update failed: {response}")
            response = rpc({"jsonrpc":"2.0", "id":9, "method":"tools/call", "params":{"name":"netflow_set_kernel_option", "arguments":{"name":"log-level", "inherit":True}}})
            if "error" in response or response.get("result", {}).get("isError") or "overrides" not in response.get("result", {}).get("structuredContent", {}) or "log_level" in response.get("result", {}).get("structuredContent", {}).get("overrides", {}) or response.get("result", {}).get("structuredContent", {}).get("effective", {}).get("log_level") != "error":
                raise RuntimeError(f"MCP kernel option inheritance failed: {response}")
            response = rpc({"jsonrpc":"2.0", "id":3, "method":"tools/call", "params":{"name":"netflow_status", "arguments":{}}})
            if response.get("result", {}).get("isError") or "error" in response:
                raise RuntimeError(f"MCP status failed: {response}")
            response = rpc({"jsonrpc":"2.0", "id":4, "method":"tools/call", "params":{"name":"netflow_diagnostics", "arguments":{}}})
            if response.get("result", {}).get("isError") or "error" in response or response.get("result", {}).get("structuredContent", {}).get("app_version") != VERSION:
                raise RuntimeError(f"MCP diagnostics failed: {response}")
            response = rpc({"jsonrpc":"2.0", "id":4, "method":"tools/call", "params":{"name":"netflow_proxy_groups", "arguments":{}}})
            if response.get("result", {}).get("isError") or "error" in response:
                raise RuntimeError(f"MCP proxy groups failed: {response}")
            response = rpc({"jsonrpc":"2.0", "id":6, "method":"tools/call", "params":{"name":"netflow_providers", "arguments":{}}})
            if response.get("result", {}).get("isError") or "error" in response or response.get("result", {}).get("structuredContent", {}).get("proxy") != []:
                raise RuntimeError(f"MCP provider list failed: {response}")
            response = rpc({"jsonrpc":"2.0", "id":5, "method":"tools/call", "params":{"name":"netflow_update_geodata", "arguments":{}}})
            if response.get("result", {}).get("isError") or not response.get("result", {}).get("structuredContent", {}).get("accepted"):
                raise RuntimeError(f"MCP GeoData request failed: {response}")
            deadline = time.monotonic() + 15
            while True:
                status = call("status")
                if not status.get("geo_pending") and status.get("geo_error"):
                    if "没有可更新" not in status["geo_error"]:
                        raise RuntimeError(f"unexpected GeoData status: {status['geo_error']}")
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("MCP GeoData completion was not reported")
                time.sleep(0.2)
        finally:
            mcp.terminate(); mcp.wait(timeout=10)
        headless_dir = sandbox / "headless-data"
        headless_dir.mkdir()
        (headless_dir / "config.yaml").write_text(
            "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\n"
            "dns: {enable: false}\ntun: {enable: false}\nrules: ['MATCH,DIRECT']\n",
            encoding="utf-8",
        )
        with (sandbox / "headless.log").open("wb") as headless_log:
            headless = subprocess.Popen([agent, "--config-dir", str(headless_dir), "serve", "--tun=false"],
                stdout=headless_log, stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW | subprocess.BELOW_NORMAL_PRIORITY_CLASS)
            try:
                deadline = time.monotonic() + 30
                while True:
                    if headless.poll() is not None:
                        raise RuntimeError(f"headless exited early: {headless.returncode}")
                    result = subprocess.run([agent, "--config-dir", str(headless_dir), "status"], capture_output=True,
                        text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW | subprocess.BELOW_NORMAL_PRIORITY_CLASS)
                    if result.returncode == 0:
                        status = json.loads(result.stdout)
                        if status.get("headless") and status.get("running") and not status.get("tun"):
                            break
                    if time.monotonic() >= deadline:
                        raise RuntimeError("headless Agent did not become ready")
                    time.sleep(0.2)
                result = subprocess.run([agent, "--config-dir", str(headless_dir), "shutdown"], capture_output=True,
                    text=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW | subprocess.BELOW_NORMAL_PRIORITY_CLASS)
                if result.returncode or not json.loads(result.stdout).get("ok"):
                    raise RuntimeError(f"headless shutdown failed: {result.stderr}")
                if headless.wait(timeout=30) != 0:
                    raise RuntimeError("headless service exited with an error")
            finally:
                if headless.poll() is None:
                    headless.terminate()
                    headless.wait(timeout=10)
        print(f"Windows {'installed' if installed else 'portable'}: GUI routing, headless CLI, rewrites and expiry, diagnostics and MCP checks passed.")
    finally:
        if app and app.poll() is None:
            app.terminate()
            app.wait(timeout=10)
        if app_log:
            app_log.close()
        if origin:
            origin.shutdown()
            origin.server_close()
        # Only the uniquely created smoke-test directory is removed.
        if sandbox.parent == build and sandbox.name.startswith("netflow-smoke-") and not sandbox.is_symlink():
            shutil.rmtree(sandbox)


if __name__ == "__main__":
    main()
