"""Regressions for portable pinned source extraction and tamper rejection."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "world_fixtures", ROOT / "scripts/world-id/import_world_id_fixtures.py"
)
EXTRACTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXTRACTOR)


class FixtureSourceTests(unittest.TestCase):
    def test_exact_existing_vectors_without_git_checkout(self):
        # Source hashes bind the same public vectors; no proof or .git access is needed.
        for name, value in EXTRACTOR.extract().items():
            self.assertEqual(
                (ROOT / "fixtures/world-id" / name).read_text(),
                json.dumps(value, indent=2) + "\n",
            )

    def test_tampered_source_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            provenance = root / "fixtures/world-id/provenance.json"
            provenance.parent.mkdir(parents=True)
            provenance.write_bytes(
                (ROOT / "fixtures/world-id/provenance.json").read_bytes()
            )
            source = (
                root / "fixtures/world-id/upstream/world-id-contracts/src/test/data/InclusionProof.json"
            )
            source.parent.mkdir(parents=True)
            source.write_text("{}")
            with patch.object(EXTRACTOR, "ROOT", root):
                with self.assertRaisesRegex(AssertionError, "InclusionProof.json"):
                    EXTRACTOR.extract()

    def test_provenance_records_the_relation_behind_each_key(self):
        provenance = json.loads(
            (ROOT / "fixtures/world-id/provenance.json").read_text()
        )
        v4 = provenance["relations"]["nullifier-v4-key.json"]
        self.assertEqual(v4["publicInputs"], 15)
        self.assertRegex(v4["ceremonyR1csSha256"], "^[0-9a-f]{64}$")
        self.assertRegex(v4["ceremonyWasmSha256"], "^[0-9a-f]{64}$")
        self.assertIn("circom 2.2.3", v4["compiler"])
        v3 = provenance["relations"]["semaphore16-key.json"]
        self.assertIn("circomlib 2.0.2", v3["circuit"])
        self.assertEqual(provenance["relations"], EXTRACTOR.RELATIONS)

    def test_changed_revision_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            provenance = root / "fixtures/world-id/provenance.json"
            provenance.parent.mkdir(parents=True)
            data = json.loads((ROOT / "fixtures/world-id/provenance.json").read_text())
            data["repositories"]["world-id-contracts"] = "different"
            provenance.write_text(json.dumps(data))
            with patch.object(EXTRACTOR, "ROOT", root):
                with self.assertRaisesRegex(AssertionError, "revisions"):
                    EXTRACTOR.extract()


class PublishedSourceTests(unittest.TestCase):
    def test_required_sources_are_in_the_git_file_set(self):
        # A green test in a populated checkout must not hide files missing from clones.
        import subprocess

        output = subprocess.check_output(
            [
                "git",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
                "fixtures/world-id/upstream",
            ],
            cwd=ROOT,
        )
        eligible = {ROOT / name.decode() for name in output.split(b"\0") if name}
        provenance = json.loads(
            (ROOT / "fixtures/world-id/provenance.json").read_text()
        )
        required = {ROOT / "fixtures/world-id/upstream" / name for name in provenance["sources"]}
        required.update(
            {
                ROOT / "fixtures/world-id/upstream/world-id-contracts/LICENSE",
                ROOT / "fixtures/world-id/upstream/world-id-protocol/LICENSE",
            }
        )
        missing = sorted(
            str(path.relative_to(ROOT))
            for path in required
            if not path.is_file() or path not in eligible
        )
        self.assertEqual(
            missing, [], "Required fixture/native source is absent or ignored"
        )
