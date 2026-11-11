"""Material data integrity and existence-only source references; no proofs/network."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/fixtures/material/validate-material.mjs"
READY = (ROOT / "node_modules/ajv").is_dir()


class MaterialReferencesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert READY, (
            "run `npm ci` at the repository root before the material policy tests"
        )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def check(self, reference):
        code = (
            f"import {{validateReference}} from {json.dumps(SCRIPT.as_uri())};"
            "await validateReference(process.argv[1],JSON.parse(process.argv[2]));"
        )
        return subprocess.run(
            [
                "node",
                "--input-type=module",
                "-e",
                code,
                str(self.root),
                json.dumps(reference),
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_source_references_must_exist(self):
        for name in [
            "noir/test/src/lib.nr",
            "scripts/test/tool.mjs",
        ]:
            with self.subTest(name=name):
                path = self.write(name, b"chosen source\n")
                self.assertEqual(self.check({"path": name}).returncode, 0)
                path.write_bytes(b"maintained source changes\n")
                self.assertEqual(self.check({"path": name}).returncode, 0)
                path.unlink()
                missing = self.check({"path": name})
                self.assertNotEqual(missing.returncode, 0)
                self.assertIn("ENOENT", missing.stderr)

    def test_authentic_data_and_arbitrary_toml_keep_exact_hashes(self):
        for name in [
            "fixtures/material/test/provider-public/jwks.json",
            "fixtures/material/test/provider-test/Browser.toml",
            "fixtures/material/test/provider-test/config.js",
        ]:
            with self.subTest(name=name):
                data = b"recorded authentic sample\n"
                path = self.write(name, data)
                reference = {"path": name, "sha256": hashlib.sha256(data).hexdigest()}
                self.assertEqual(self.check(reference).returncode, 0)
                self.assertNotEqual(self.check({"path": name}).returncode, 0)
                path.write_bytes(b"tampered sample\n")
                bad = self.check(reference)
                self.assertNotEqual(bad.returncode, 0)
                self.assertIn("SHA256 mismatch", bad.stderr)

    def test_source_alias_cannot_hide_data_identity_or_workspace_escape(self):
        data = self.write("fixtures/material/test/key.json", b"key")
        name = "scripts/test/tool.mjs"
        alias = self.root / name
        alias.parent.mkdir(parents=True)
        alias.symlink_to(data)
        self.assertIn(
            "Data reference requires SHA256", self.check({"path": name}).stderr
        )
        alias.unlink()
        source = self.write("noir/test/src/lib.nr", b"maintained source")
        reverse = self.root / "fixtures/material/test/data.json"
        reverse.symlink_to(source)
        bad_data = self.check(
            {"path": str(reverse.relative_to(self.root)), "sha256": "0" * 64}
        )
        self.assertNotEqual(bad_data.returncode, 0)
        self.assertIn("SHA256 mismatch", bad_data.stderr)
        # A real outside file exercises containment rather than only missing-file rejection.
        with tempfile.NamedTemporaryFile(dir=self.root.parent) as outside:
            alias.symlink_to(outside.name)
            self.assertIn(
                "Reference escapes workspace", self.check({"path": name}).stderr
            )
