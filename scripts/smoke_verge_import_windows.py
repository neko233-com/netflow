"""Read a real Verge directory or ZIP and import into a disposable NetFlow directory."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    if os.name != "nt" or len(sys.argv) != 2:
        raise SystemExit("usage: python scripts/smoke_verge_import_windows.py <Verge directory or ZIP>")
    source = Path(sys.argv[1]).resolve(strict=True)
    build = (ROOT / "build").resolve(strict=True)
    sandbox = Path(tempfile.mkdtemp(prefix="netflow-verge-import-", dir=build)).resolve(strict=True)
    if sandbox.parent != build or not sandbox.name.startswith("netflow-verge-import-"):
        raise RuntimeError("unexpected sandbox path")
    target = sandbox / "data"
    agent = Path(os.environ["LOCALAPPDATA"]) / "Programs" / "NetFlow" / "netflow-agent.exe"
    try:
        def call(command):
            process = subprocess.run([str(agent), "--config-dir", str(target), command, str(source)],
                                     capture_output=True, text=True, timeout=60,
                                     creationflags=subprocess.CREATE_NO_WINDOW | subprocess.BELOW_NORMAL_PRIORITY_CLASS)
            if process.returncode:
                raise RuntimeError(f"{command} failed: {process.stderr.strip()}")
            return json.loads(process.stdout)
        preview = call("migrate-preview")
        result = call("migrate-import")
        catalog = json.loads((target / "profiles.json").read_text(encoding="utf-8"))
        count = len(preview.get("profiles", []))
        if count == 0 or result.get("imported") != count or len(catalog.get("items", [])) != count:
            raise RuntimeError("imported profile count did not match preview")
        for item in catalog["items"]:
            path = (target / item["file"]).resolve(strict=True)
            if not path.is_relative_to((target / "profiles").resolve(strict=True)) or not path.is_file():
                raise RuntimeError("invalid imported profile path")
        print(f"Installed Agent: imported {count} Verge profiles into an isolated directory.")
    finally:
        resolved = sandbox.resolve(strict=True)
        if resolved.parent != build or not resolved.name.startswith("netflow-verge-import-"):
            raise RuntimeError("refusing to remove an unexpected sandbox")
        shutil.rmtree(resolved)


if __name__ == "__main__":
    main()
