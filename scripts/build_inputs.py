"""Record and check inputs for a local release without modifying its assets."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
FILES = (
    "go.mod", "go.sum", "mygo.json", "version.go", "README.md", "LICENSE",
    "scripts/build-release.ps1", "scripts/package_release.py",
    "scripts/fix_msi_components.py", "scripts/build_inputs.py",
)
DIRECTORIES = ("cmd", "internal", "resources", "installer", "LICENSES")
SKIP_DIRS = {"__pycache__"}
VERSION_RE = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?\Z")
PROGRAMS = ("NetFlow.exe", "netflow-agent.exe", "netflow-kernel-worker.exe")


def version_at(root):
    version = json.loads((root / "mygo.json").read_text(encoding="utf-8"))["version"]
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise ValueError("invalid release version")
    return version


def input_files(root):
    files = [root / name for name in FILES]
    for directory in DIRECTORIES:
        base = root / directory
        if not base.is_dir() or base.is_symlink():
            raise ValueError(f"missing or linked input directory: {directory}")
        for current, dirs, names in os.walk(base, followlinks=False):
            current = Path(current)
            generated = {"windows-amd64", "darwin-arm64"} if current == root / "resources" else set()
            dirs[:] = [name for name in dirs if name not in SKIP_DIRS and name not in generated]
            for name in dirs:
                if (current / name).is_symlink() or getattr(os.path, "isjunction", lambda _: False)(current / name):
                    raise ValueError("linked input directory")
            for name in names:
                if name.endswith("_test.go") or name.endswith((".pyc", ".pyo")):
                    continue
                files.append(current / name)
    for path in files:
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"missing or linked input: {path.relative_to(root)}")
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def digest_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_digest(root, go_environment):
    digest = hashlib.sha256(b"netflow-release-inputs-v1\0")
    digest.update(json.dumps(go_environment, sort_keys=True, separators=(",", ":")).encode())
    for path in input_files(root):
        name = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(bytes.fromhex(digest_file(path)))
    return digest.hexdigest()


def go_environment():
    env = dict(os.environ, GOWORK="off", CGO_ENABLED="0", GOFLAGS="-p=1 -tags=with_gvisor,no_tailscale -buildvcs=false")
    env.pop("GOOS", None)
    env.pop("GOARCH", None)
    output = subprocess.check_output(
        ["go", "env", "-json", "GOVERSION", "GOAMD64", "GOARM64", "GOEXPERIMENT"],
        env=env, text=True, encoding="utf-8",
    )
    return json.loads(output)


def paths(root, version):
    staging = root / "build" / f"release-artifacts-{version}"
    release = root / "build" / "releases" / version
    return staging, release, release / f"NetFlow-{version}-windows-amd64.msi"


def assert_paths_safe(root, targets):
    def check(path):
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"linked output path: {path.relative_to(root)}")
        if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
            raise ValueError(f"hard-linked output file: {path.relative_to(root)}")
        return True

    for relative in targets:
        current = root
        for part in relative.parts:
            current = current / part
            if not check(current):
                break
        else:
            if current.is_dir():
                for folder, dirs, files in os.walk(current, followlinks=False):
                    for name in dirs + files:
                        check(Path(folder) / name)


def assert_output_paths_safe(root, version):
    assert_paths_safe(root, (
        Path("resources/windows-amd64"), Path("resources/darwin-arm64"),
        Path("build/netflow-release.lock"), Path("build") / f"release-artifacts-{version}",
        Path("build/msi") / version, Path("build/releases") / version,
    ))


def assert_release_destination_empty(root, version):
    assert_output_paths_safe(root, version)
    _, release, _ = paths(root, version)
    names = (
        f"NetFlow-{version}-windows-amd64.msi",
        f"NetFlow-{version}-windows-amd64-portable.zip",
        f"NetFlow-{version}-macos-arm64.zip",
        f"NetFlow-{version}-windows-amd64-setup.exe",
        "SHA256SUMS.txt",
    )
    for name in names:
        if os.path.lexists(release / name):
            raise FileExistsError(f"release asset already exists: {name}")


def snapshot(root, environment):
    version = version_at(root)
    staging, _, msi = paths(root, version)
    outputs = {name: digest_file(staging / "windows-amd64" / name) for name in PROGRAMS}
    outputs["msi"] = digest_file(msi)
    return {"schema": 1, "version": version, "source_sha256": source_digest(root, environment), "outputs": outputs}


def record(root, expected, environment):
    assert_output_paths_safe(root, version_at(root))
    current = snapshot(root, environment)
    if current["source_sha256"] != expected:
        raise ValueError("release inputs changed during the build; artifacts are unverified")
    staging, _, _ = paths(root, current["version"])
    target = staging / "build-inputs.json"
    fd, name = tempfile.mkstemp(prefix=".build-inputs-", suffix=".tmp", dir=staging)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            json.dump(current, output, sort_keys=True, indent=2)
            output.write("\n")
        os.replace(name, target)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def verify(root, environment):
    version = version_at(root)
    assert_output_paths_safe(root, version)
    staging, _, _ = paths(root, version)
    stored = json.loads((staging / "build-inputs.json").read_text(encoding="utf-8"))
    if stored != snapshot(root, environment):
        raise ValueError("release inputs or Windows artifacts changed; build a new version before validation")


def main():
    if len(sys.argv) < 2:
        raise ValueError("expected check-output, check-vm, fingerprint, record or verify")
    command = sys.argv[1]
    if command == "check-output" and len(sys.argv) == 2:
        assert_release_destination_empty(ROOT, version_at(ROOT))
    elif command == "check-vm" and len(sys.argv) == 2:
        assert_paths_safe(ROOT, (Path("build/windows-vm-validator.lock"), Path("build/windows-vm-context"), Path("build/windows-vm-payload")))
    elif command == "fingerprint" and len(sys.argv) == 2:
        print(source_digest(ROOT, go_environment()))
    elif command == "record" and len(sys.argv) == 3 and re.fullmatch(r"[0-9a-f]{64}", sys.argv[2]):
        record(ROOT, sys.argv[2], go_environment())
    elif command == "verify" and len(sys.argv) == 2:
        verify(ROOT, go_environment())
        print("Release inputs and Windows artifacts verified")
    else:
        raise ValueError("invalid command")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
