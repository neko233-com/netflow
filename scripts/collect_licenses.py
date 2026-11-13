"""Copy notices of modules used by the Windows and macOS release binaries.

Run from the repository root after downloading Go modules. Existing files are
left intact; review the manifest when dependencies change.
"""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess


ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "LICENSES" / "third_party"
TARGETS = (("windows", "amd64"), ("darwin", "arm64"))


def objects(data):
    decoder = json.JSONDecoder()
    index = 0
    while index < len(data):
        while index < len(data) and data[index].isspace():
            index += 1
        if index == len(data):
            return
        obj, index = decoder.raw_decode(data, index)
        yield obj


def safe_name(name):
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name)


def main():
    modules = {}
    for goos, goarch in TARGETS:
        env = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED="0", GOMAXPROCS="1", GOFLAGS="-p=1")
        data = subprocess.check_output(["go", "list", "-deps", "-json", "./cmd/clash-go"], cwd=ROOT, env=env, text=True, encoding="utf-8")
        for package in objects(data):
            module = package.get("Module")
            if not module or module.get("Main"):
                continue
            source = module.get("Replace", module)
            key = (module["Path"], module.get("Version", ""))
            item = modules.setdefault(key, {"root": source.get("Dir", ""), "packages": set()})
            if package.get("Dir"):
                item["packages"].add(package["Dir"])

    DEST.mkdir(parents=True, exist_ok=True)
    lines = ["# Third-party notices", "", "The folders contain notices shipped by the modules used to build the Windows amd64 and macOS arm64 binaries.", "The original module paths and versions are listed below. Module source is available at the corresponding Go module path and version.", ""]
    missing = []
    for (name, version), info in sorted(modules.items()):
        directory = info["root"]
        if not directory:
            missing.append(f"{name}@{version}: module directory unavailable")
            continue
        source = Path(directory)
        directories = {source}
        for package_dir in info["packages"]:
            folder = Path(package_dir)
            while folder != source and source in folder.parents:
                directories.add(folder)
                folder = folder.parent
        candidates = sorted(p for d in directories for p in d.iterdir() if p.is_file() and re.match(r"(?i)^(licen[cs]e|copying|notice)(\.|$|[-_])", p.name))
        folder = safe_name(f"{name}@{version}")
        if not candidates:
            missing.append(f"{name}@{version}: no root license or notice found")
            continue
        target = DEST / folder
        target.mkdir(exist_ok=True)
        for file in candidates:
            dest = target / file.relative_to(source)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(file, dest)
        lines.append(f"- `{name}@{version}` — [{folder}]({folder}/)")

    goroot = Path(subprocess.check_output(["go", "env", "GOROOT"], cwd=ROOT, text=True).strip())
    (DEST / "go").mkdir(exist_ok=True)
    shutil.copyfile(goroot / "LICENSE", DEST / "go" / "LICENSE")
    lines.append("- Go standard library — [go](go/)")
    if missing:
        lines += ["", "## Modules without a root notice", ""] + [f"- {entry}" for entry in missing]
    (DEST / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Collected {len(modules) - len(missing)} modules; {len(missing)} need review.")
    for entry in missing:
        print(entry)


if __name__ == "__main__":
    main()
