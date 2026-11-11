"""Host-only fixture checks with an independent signature oracle; no Noir proofs."""

import contextlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "scripts/fixtures"
READY = (ROOT / "node_modules/@noble/curves").is_dir()


def run(command, cwd):
    """None if `command` succeeds in `cwd`, else its output."""
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    return None if result.returncode == 0 else result.stdout + result.stderr


@contextlib.contextmanager
def private_copy(paths):
    """A scratch copy of `paths` (relative to the repository) with node_modules linked."""
    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        for path in paths:
            source, target = ROOT / path, work / path
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                shutil.copyfile(source, target)
        (work / "node_modules").symlink_to(ROOT / "node_modules")
        yield work


@unittest.skipUnless(READY, "needs installed credential dependencies")
class AuthGeneratorTests(unittest.TestCase):
    def test_deterministic_test_signatures_verify_with_node_crypto(self):
        script = """import assert from 'node:assert/strict';
import{verify,createPublicKey}from'node:crypto';
import{localP256Key,signLocalP256}from'./scripts/fixtures/lib/local-p256-key.mjs';
for(const scalar of [42,43,44]){
 const message=Buffer.from('public deterministic fixture');
 const signature=signLocalP256(scalar,message);
 assert.deepEqual(signature,signLocalP256(scalar,message));
 const key=createPublicKey(localP256Key(scalar).privateKey);
 assert(verify('sha256',message,{key,dsaEncoding:'ieee-p1363'},signature));
 assert(!verify('sha256',Buffer.from('changed fixture'),{key,dsaEncoding:'ieee-p1363'},signature));
}"""
        self.assertIsNone(run(["node", "--input-type=module", "-e", script], ROOT))

    def test_line_custom_nonce_preserves_iat_regressions_and_production_prefix(self):
        copy = [
            "scripts/fixtures/lib",
            "scripts/fixtures/templates",
            "scripts/fixtures/generate-line-fixture.py",
            "package.json",
            "packages/credential-proofs-inputs/package.json",
            "noir/line/src/lib.nr",
        ]
        with private_copy(copy) as work:
            (work / "target/kat/line").mkdir(parents=True)
            (work / "fixtures/data").mkdir(parents=True)
            source = (work / "noir/line/src/lib.nr").read_text()
            (work / "noir/line/src/lib.nr").write_text(
                source.replace(
                    "// Synthetic scalar 42;",
                    "// Synthetic stale fixture sentinel\n// Synthetic scalar 42;",
                    1,
                )
            )
            nonce = "01" * 32
            error = run(
                [sys.executable, "scripts/fixtures/generate-line-fixture.py", nonce], work
            )
            self.assertIsNone(error)
            fresh = (work / "noir/line/src/lib.nr").read_text()
            self.assertNotIn("stale fixture sentinel", fresh)
            self.assertEqual(
                fresh.split("// Synthetic")[0], source.split("// Synthetic")[0]
            )
            self.assertEqual(
                set(re.findall(r"fn line_[a-z_]+", fresh)),
                set(re.findall(r"fn line_[a-z_]+", source)),
            )
            tail = fresh[fresh.index("fn line_signed_iat") :]
            self.assertEqual(tail.count(nonce), 2)
            self.assertNotIn("0" * 64, tail)


try:
    import cryptography
except ImportError:
    cryptography = None


@unittest.skipUnless(cryptography, "needs pinned Python fixture requirements")
class X509PublicKeyTests(unittest.TestCase):
    def test_saved_keys_match_only_synthetic_certificate_chains(self):
        import json
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        for provider, names in (
            ("jpki", {"root", "holder", "responder"}),
        ):
            directory = ROOT / "fixtures/data/x509-test-keys" / provider
            paths = sorted(directory.glob("*.pem"))
            self.assertEqual(
                {p.name.removesuffix("-test-only.key.pem") for p in paths}, names
            )
            material = ROOT / "fixtures/material" / provider / "local-test"
            record = json.loads((material / "fixture.json").read_text())
            self.assertIs(record["synthetic"], True)
            for path in paths:
                name = path.name.removesuffix("-test-only.key.pem")
                key = serialization.load_pem_private_key(path.read_bytes(), None)
                cert = x509.load_der_x509_certificate(
                    (material / (name + ".der")).read_bytes()
                )
                self.assertIn("SYNTHETIC TEST AUTHORITY", cert.subject.rfc4514_string())
                self.assertEqual(
                    key.public_key().public_numbers(),
                    cert.public_key().public_numbers(),
                )
                issuer = x509.load_der_x509_certificate(
                    (material / "root.der").read_bytes()
                )
                issuer.public_key().verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )

    def test_missing_saved_key_never_creates_a_replacement(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "x509_fixture", FIXTURES / "lib/x509_fixture.py"
        )
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch) / "missing"
            with self.assertRaisesRegex(FileNotFoundError, "public synthetic test key"):
                helper.test_key(directory, "root")
            self.assertFalse(directory.exists())
