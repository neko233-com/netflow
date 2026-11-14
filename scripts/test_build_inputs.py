import json
import os
from pathlib import Path
import tempfile
import unittest

import build_inputs


class BuildInputsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in build_inputs.FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture", encoding="utf-8")
        (self.root / "mygo.json").write_text('{"version":"1.2.3-alpha.1"}', encoding="utf-8")
        for name in build_inputs.DIRECTORIES:
            (self.root / name).mkdir(parents=True, exist_ok=True)
        (self.root / "cmd" / "main.go").write_text("package main", encoding="utf-8")
        (self.root / "resources" / "icon.ico").write_bytes(b"icon")
        self.environment = {"GOVERSION": "go-fixture", "GOAMD64": "v1"}

    def fingerprint(self):
        return build_inputs.source_digest(self.root, self.environment)

    def prepare_outputs(self):
        version = build_inputs.version_at(self.root)
        staging, release, msi = build_inputs.paths(self.root, version)
        (staging / "windows-amd64").mkdir(parents=True)
        release.mkdir(parents=True)
        for name in build_inputs.PROGRAMS:
            (staging / "windows-amd64" / name).write_bytes(name.encode())
        msi.write_bytes(b"msi fixture")
        return staging, release, msi

    def test_digest_tracks_inputs_but_ignores_generated_binaries_and_tests(self):
        before = self.fingerprint()
        generated = self.root / "resources" / "windows-amd64"
        generated.mkdir()
        (generated / "generated.exe").write_bytes(b"generated")
        (self.root / "cmd" / "main_test.go").write_text("changed test", encoding="utf-8")
        self.assertEqual(before, self.fingerprint())
        (self.root / "cmd" / "main.go").write_text("package changed", encoding="utf-8")
        self.assertNotEqual(before, self.fingerprint())

    def test_record_verify_and_reject_changed_inputs_or_outputs(self):
        staging, _, msi = self.prepare_outputs()
        expected = self.fingerprint()
        build_inputs.record(self.root, expected, self.environment)
        build_inputs.verify(self.root, self.environment)
        stored = json.loads((staging / "build-inputs.json").read_text(encoding="utf-8"))
        self.assertEqual(stored["source_sha256"], expected)
        original = msi.read_bytes()
        msi.write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "artifacts changed"):
            build_inputs.verify(self.root, self.environment)
        msi.write_bytes(original)
        binary = staging / "windows-amd64" / "NetFlow.exe"
        original_binary = binary.read_bytes()
        binary.write_bytes(b"tampered executable")
        with self.assertRaisesRegex(ValueError, "artifacts changed"):
            build_inputs.verify(self.root, self.environment)
        binary.write_bytes(original_binary)
        with self.assertRaisesRegex(ValueError, "inputs or Windows artifacts changed"):
            build_inputs.verify(self.root, {"GOVERSION": "different"})
        (self.root / "README.md").write_text("modified", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "inputs or Windows artifacts changed"):
            build_inputs.verify(self.root, self.environment)
        with self.assertRaisesRegex(ValueError, "changed during the build"):
            build_inputs.record(self.root, expected, self.environment)

    def test_release_collision_fails_without_changing_existing_file(self):
        version = build_inputs.version_at(self.root)
        build_inputs.assert_release_destination_empty(self.root, version)
        _, _, msi = self.prepare_outputs()
        original = msi.read_bytes()
        with self.assertRaises(FileExistsError):
            build_inputs.assert_release_destination_empty(self.root, version)
        self.assertEqual(msi.read_bytes(), original)

    def test_version_cannot_escape_build_directory(self):
        (self.root / "mygo.json").write_text('{"version":"1.2.3-../../escape"}', encoding="utf-8")
        with self.assertRaises(ValueError):
            build_inputs.version_at(self.root)

    def test_hard_linked_generated_output_is_rejected(self):
        generated = self.root / "resources" / "windows-amd64"
        generated.mkdir()
        original = self.root / "outside.txt"
        original.write_bytes(b"keep")
        try:
            os.link(original, generated / "netflow-agent.exe")
        except OSError as error:
            self.skipTest(f"hard links unavailable: {error}")
        with self.assertRaisesRegex(ValueError, "hard-linked output"):
            build_inputs.assert_release_destination_empty(self.root, build_inputs.version_at(self.root))
        self.assertEqual(original.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
