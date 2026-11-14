import struct
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from package_release import check_icon_resource, check_tun_build_tags


def pe_with_icons():
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x86, 1)
    struct.pack_into("<H", data, 0x94, 0xF0)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<II", data, optional + 128, 0x1000, 0x100)
    section = optional + 0xF0
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x400)
    struct.pack_into("<HH", data, 0x40C, 0, 2)
    struct.pack_into("<IIII", data, 0x410, 3, 0x80000020, 14, 0x80000030)
    return data


class IconResourceTest(unittest.TestCase):
    def test_icon_types_and_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "worker.exe"
            data = pe_with_icons()
            path.write_bytes(data)
            check_icon_resource(path)
            struct.pack_into("<I", data, 0x418, 99)
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                check_icon_resource(path)
            path.write_bytes(pe_with_icons()[:0x415])
            with self.assertRaises(ValueError):
                check_icon_resource(path)


class ReleaseBuildInfoTest(unittest.TestCase):
    def test_requires_tags_and_rejects_embedded_workspace_metadata(self):
        good = "program\n\tbuild\t-tags=with_gvisor,no_tailscale\n\tbuild\tGOAMD64=v1\n"
        with patch("package_release.subprocess.check_output", return_value=good):
            check_tun_build_tags(Path("program"))
        with patch("package_release.subprocess.check_output", return_value=good + "\tbuild\tvcs.revision=stale\n"):
            with self.assertRaisesRegex(ValueError, "VCS metadata"):
                check_tun_build_tags(Path("program"))
        with patch("package_release.subprocess.check_output", return_value="program\n"):
            with self.assertRaisesRegex(ValueError, "TUN build tags"):
                check_tun_build_tags(Path("program"))


if __name__ == "__main__":
    unittest.main()
