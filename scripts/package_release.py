"""Package and structurally validate MyGo's Windows and macOS build output."""

import hashlib
import json
from pathlib import Path
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parent.parent
VERSION = json.loads((ROOT / "mygo.json").read_text(encoding="utf-8"))["version"]
BUILD = ROOT / "build" / f"release-artifacts-{VERSION}"
OUT = ROOT / "build" / "releases" / VERSION


def check_pe(path, require_amd64=True, subsystem=2):
    with path.open("rb") as f:
        header = f.read(64)
        if header[:2] != b"MZ":
            raise ValueError(f"not a PE executable: {path}")
        offset = struct.unpack_from("<I", header, 60)[0]
        f.seek(offset)
        pe = f.read(96)
    machine = struct.unpack_from("<H", pe, 4)[0]
    magic = struct.unpack_from("<H", pe, 24)[0]
    if pe[:4] != b"PE\0\0" or machine not in (0x14C, 0x8664) or (require_amd64 and (machine != 0x8664 or magic != 0x20B)):
        raise ValueError(f"unexpected PE architecture: {path}")
    if magic not in (0x10B, 0x20B) or struct.unpack_from("<H", pe, 24 + 68)[0] != subsystem:
        raise ValueError(f"unexpected Windows executable subsystem: {path}")


def check_icon_resource(path):
    """Ensure the Windows background worker carries icon and icon-group resources."""
    with path.open("rb") as f:
        f.seek(0, 2)
        length = f.tell()

        def read_at(offset, size):
            if offset < 0 or size < 0 or offset + size > length:
                raise ValueError(f"truncated PE resource in {path}")
            f.seek(offset)
            data = f.read(size)
            if len(data) != size:
                raise ValueError(f"truncated PE resource in {path}")
            return data

        dos = read_at(0, 64)
        if dos[:2] != b"MZ":
            raise ValueError(f"not a PE executable: {path}")
        pe_offset = struct.unpack_from("<I", dos, 60)[0]
        header = read_at(pe_offset, 24)
        if header[:4] != b"PE\0\0":
            raise ValueError(f"invalid PE header: {path}")
        section_count = struct.unpack_from("<H", header, 6)[0]
        optional_size = struct.unpack_from("<H", header, 20)[0]
        if not 1 <= section_count <= 96:
            raise ValueError(f"invalid PE sections: {path}")
        optional = read_at(pe_offset + 24, optional_size)
        if len(optional) < 136 or struct.unpack_from("<H", optional)[0] != 0x20B or struct.unpack_from("<I", optional, 108)[0] < 3:
            raise ValueError(f"missing PE resource directory: {path}")
        rva, resource_size = struct.unpack_from("<II", optional, 128)
        sections = read_at(pe_offset + 24 + optional_size, section_count * 40)
        root = None
        for offset in range(0, len(sections), 40):
            _, address, raw_size, raw_offset = struct.unpack_from("<IIII", sections, offset + 8)
            if address <= rva and rva - address < raw_size and resource_size <= raw_size - (rva - address):
                root = raw_offset + rva - address
                break
        if root is None or resource_size < 16:
            raise ValueError(f"missing PE icon resources: {path}")
        directory = read_at(root, 16)
        named, ids = struct.unpack_from("<HH", directory, 12)
        count = named + ids
        if count > 4096 or 16 + count * 8 > resource_size:
            raise ValueError(f"invalid PE resource directory: {path}")
        entries = read_at(root + 16, count * 8)
        kinds = set()
        for i in range(count):
            name, child = struct.unpack_from("<II", entries, i * 8)
            if not (name & 0x80000000) and (child & 0x80000000) and (child & 0x7FFFFFFF) <= resource_size - 16:
                kinds.add(name)
        if not {3, 14}.issubset(kinds):  # RT_ICON and RT_GROUP_ICON
            raise ValueError(f"missing PE icon or icon group: {path}")


def check_tun_build_tags(path):
    info = subprocess.check_output(["go", "version", "-m", str(path)], text=True, encoding="utf-8")
    lines = [line.split("-tags=", 1)[1].strip() for line in info.splitlines() if "-tags=" in line]
    if len(lines) != 1 or not {"with_gvisor", "no_tailscale"}.issubset(set(lines[0].split(","))):
        raise ValueError(f"missing TUN build tags: {path}")
    for line in info.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "build" and fields[1].startswith("vcs"):
            raise ValueError(f"unexpected embedded VCS metadata: {path}")


def check_macho(path):
    with path.open("rb") as f:
        header = f.read(32)
        commands = f.read(struct.unpack_from("<I", header, 20)[0]) if len(header) == 32 else b""
    if len(header) < 32 or struct.unpack_from("<I", header)[0] != 0xFEEDFACF or struct.unpack_from("<I", header, 4)[0] != 0x100000C:
        raise ValueError(f"not a 64-bit arm64 Mach-O: {path}")
    offset = 0
    for _ in range(struct.unpack_from("<I", header, 16)[0]):
        command, size = struct.unpack_from("<II", commands, offset)
        if size < 8 or offset + size > len(commands):
            raise ValueError("invalid Mach-O load command")
        if command == 0x32 and size >= 24:  # LC_BUILD_VERSION
            platform, minimum = struct.unpack_from("<II", commands, offset + 8)
            if platform != 1:
                raise ValueError("Mach-O does not target macOS")
            return (minimum >> 16, (minimum >> 8) & 255, minimum & 255)
        offset += size
    raise ValueError("Mach-O has no macOS build version")


def zip_tree(source, target, prefix, executable, exclude=()):
    with zipfile.ZipFile(target, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as z:
        for file in sorted(source.rglob("*")):
            if not file.is_file():
                continue
            if file.is_symlink():
                raise ValueError(f"unexpected symlink: {file}")
            rel = file.relative_to(source).as_posix()
            if rel in exclude:
                continue
            info = zipfile.ZipInfo(f"{prefix}/{rel}", (2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            mode = 0o755 if rel in (executable, "Contents/Resources/netflow-agent", "Contents/Resources/netflow-kernel-worker") else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with file.open("rb") as src, z.open(info, "w", force_zip64=True) as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
    with zipfile.ZipFile(target) as z:
        bad = z.testzip()
        if bad:
            raise ValueError(f"invalid ZIP entry: {bad}")
        if executable.startswith("Contents/MacOS/"):
            for program in (executable, "Contents/Resources/netflow-agent", "Contents/Resources/netflow-kernel-worker"):
                entry = z.getinfo(f"{prefix}/{program}")
                if not ((entry.external_attr >> 16) & 0o111):
                    raise ValueError(f"the macOS program lost its execute bit: {program}")


def main():
    windows = BUILD / "windows-amd64"
    mac = BUILD / "darwin-arm64" / "NetFlow.app"
    check_pe(windows / "NetFlow.exe")
    check_pe(windows / "netflow-agent.exe", subsystem=3)
    check_pe(windows / "netflow-kernel-worker.exe")
    check_icon_resource(windows / "netflow-kernel-worker.exe")
    check_tun_build_tags(windows / "NetFlow.exe")
    check_tun_build_tags(windows / "netflow-agent.exe")
    check_tun_build_tags(windows / "netflow-kernel-worker.exe")
    check_macho(mac / "Contents/Resources/netflow-agent")
    check_macho(mac / "Contents/Resources/netflow-kernel-worker")
    check_tun_build_tags(mac / "Contents/Resources/netflow-agent")
    check_tun_build_tags(mac / "Contents/Resources/netflow-kernel-worker")
    with (mac / "Contents" / "Info.plist").open("rb") as f:
        plist = plistlib.load(f)
    executable = "Contents/MacOS/" + plist["CFBundleExecutable"]
    minimum = check_macho(mac / executable)
    check_tun_build_tags(mac / executable)
    if plist.get("CFBundleIdentifier") != "com.neko233.netflow":
        raise ValueError("unexpected macOS bundle identifier")
    plist_min = tuple(int(n) for n in plist["LSMinimumSystemVersion"].split("."))
    if (plist_min + (0, 0, 0))[:3] < minimum:
        raise ValueError(f"plist minimum {plist_min} is older than executable minimum {minimum}")
    # Apple bundle version fields use numeric components; the pre-release
    # suffix remains in the app UI, archive name, and GitHub release tag.
    bundle_version = VERSION.split("-", 1)[0]
    if not re.fullmatch(r"\d+\.\d+\.\d+", bundle_version):
        raise ValueError("bundle version must have three numeric components")
    plist["CFBundleVersion"] = bundle_version
    plist["CFBundleShortVersionString"] = bundle_version
    with (mac / "Contents" / "Info.plist").open("wb") as f:
        plistlib.dump(plist, f, sort_keys=False)
    for folder in (windows, mac / "Contents" / "Resources"):
        for expected in ("LICENSE", "LICENSES", "README.md"):
            if not (folder / expected).exists():
                raise ValueError(f"missing bundled file: {folder / expected}")
    OUT.mkdir(parents=True, exist_ok=True)
    installers = sorted(windows.glob("*setup*.exe"))
    if len(installers) > 1:
        raise ValueError("multiple Windows installers found")
    with tempfile.TemporaryDirectory(prefix=".packaging-", dir=OUT) as tmp:
        stage = Path(tmp)
        win_zip = stage / f"NetFlow-{VERSION}-windows-amd64-portable.zip"
        mac_zip = stage / f"NetFlow-{VERSION}-macos-arm64.zip"
        zip_tree(windows, win_zip, "NetFlow", "NetFlow.exe", exclude=[p.name for p in installers])
        zip_tree(mac, mac_zip, "NetFlow.app", executable)
        msi_source = ROOT / "build" / "msi" / VERSION / f"NetFlow-{VERSION}-windows-amd64.msi"
        if msi_source.read_bytes()[:8] != bytes.fromhex("d0cf11e0a1b11ae1"):
            raise ValueError("invalid MSI compound file header")
        msi = stage / msi_source.name
        shutil.copyfile(msi_source, msi)
        artifacts = [win_zip, mac_zip, msi]
        if installers:
            check_pe(installers[0], require_amd64=False)
            installer = stage / f"NetFlow-{VERSION}-windows-amd64-setup.exe"
            shutil.copyfile(installers[0], installer)
            artifacts.append(installer)
        checksums = []
        for file in sorted(artifacts):
            h = hashlib.sha256()
            with file.open("rb") as f:
                for block in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(block)
            checksums.append(f"{h.hexdigest()}  {file.name}")
        sums = stage / "SHA256SUMS.txt"
        sums.write_text("\n".join(checksums) + "\n", encoding="utf-8")
        files = artifacts + [sums]
        for file in files:
            if (OUT / file.name).exists():
                raise FileExistsError(OUT / file.name)
        for file in files:
            file.rename(OUT / file.name)
            print(OUT / file.name)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, struct.error) as error:
        sys.exit(str(error))
