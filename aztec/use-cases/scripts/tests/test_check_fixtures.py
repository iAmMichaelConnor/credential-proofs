"""Tests of scripts/check_fixtures.py: the manifest comparison ignores source
hashes, and a regenerated fixture that differs from the committed file is
reported. The two end-to-end tests run the real generators of one instance in
a private copy, so they need the nargo of Aztec 6.0.0, `npm ci` in
aztec/use-cases and a built packages/credential-proofs-inputs (as the generators do)
and are skipped without them."""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

TOOLS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(TOOLS))

import check_fixtures  # noqa: E402

INSTANCE = "account-authorisation/google"
READY = check_fixtures.skipped_reason() is None


def run_main(*argv):
    out = io.StringIO()
    with mock.patch.object(sys, "argv", ["check_fixtures.py", *argv]):
        with redirect_stdout(out):
            code = check_fixtures.main()
    return code, out.getvalue()


class ComparisonTest(unittest.TestCase):
    def test_source_hashes_are_not_compared(self):
        old = {"claims": {"a": 1}, "inputs": {"x": "1"}}
        new = {"claims": {"a": 1}, "inputs": {"x": "2"}}
        self.assertEqual(check_fixtures.comparable(old), check_fixtures.comparable(new))
        new["claims"]["a"] = 2
        self.assertNotEqual(
            check_fixtures.comparable(old), check_fixtures.comparable(new)
        )

    def test_outputs_are_normalised_paths(self):
        record = {
            "outputs": {"src/fixture.nr": "a", "src/../../../adapters/x/src/fixture.nr": "b"},
        }
        self.assertEqual(
            check_fixtures.outputs_of(Path("."), record),
            {"src/fixture.nr", "../../adapters/x/src/fixture.nr"},
        )

    def test_missing_tool_skips_unless_required(self):
        with mock.patch.object(check_fixtures.nr_format, "available", return_value=False):
            code, text = run_main("--check", "--only", INSTANCE)
            self.assertEqual((code, text.startswith("skipped:")), (0, True))
            code, _ = run_main("--check", "--only", INSTANCE, "--require")
            self.assertEqual(code, 1)

    def test_every_manifest_is_listed(self):
        code, text = run_main("--list")
        self.assertEqual(code, 0)
        listed = set(text.split())
        self.assertIn(INSTANCE, listed)
        self.assertEqual(
            listed,
            {str(p.parent.parent.relative_to(check_fixtures.PROJECT)) for p in check_fixtures.PROJECT.glob("*/*/fixtures/manifest.json")},
        )
        self.assertEqual(len(listed), 55)


@unittest.skipUnless(
    READY, "needs the nargo of Aztec 6.0.0 and the generators' npm packages"
)
class EndToEndTest(unittest.TestCase):
    def test_committed_fixture_is_regenerated_exactly(self):
        code, text = run_main("--check", "--only", INSTANCE)
        self.assertEqual((code, text.strip()), (0, "1 instances checked, 0 drifted"))

    def test_a_changed_fixture_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory) / "use-cases"
            shutil.copytree(
                check_fixtures.PROJECT,
                copy,
                ignore=shutil.ignore_patterns("target", "__pycache__", "node_modules"),
            )
            (copy / "node_modules").symlink_to(
                check_fixtures.PROJECT / "node_modules", target_is_directory=True
            )
            fixture = copy / INSTANCE / "src/fixture.nr"
            fixture.write_text(
                fixture.read_text().replace("pub global NOW", "pub global NOW_", 1)
            )
            with mock.patch.object(check_fixtures, "PROJECT", copy):
                code, text = run_main("--check", "--only", INSTANCE)
            self.assertEqual(code, 1)
            self.assertIn("src/fixture.nr: differs from the regenerated file", text)


if __name__ == "__main__":
    unittest.main()
