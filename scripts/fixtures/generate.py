#!/usr/bin/env python3
"""Regenerate the fixtures and generated Noir tests; with --check, fail on drift.

Every generator runs, in order, in a scratch copy of the repository: the fixture
generators sign synthetic credentials with deliberately public test keys (or
re-encode saved public material) and write the committed fixture files, the
generated Noir test modules and, under target/kat/, the inputs of the end-to-end
known-answer tests; kat.py then turns those inputs into
noir/<package>/src/known_answer_tests.nr. Every generator is deterministic (fixed
keys, RFC 6979 or saved signatures, fixed clocks), so a rerun reproduces the
committed files byte for byte.

The Noir files they write are formatted with `nargo fmt` ($NARGO, else `nargo` on PATH),
and the SHA-256 of each changed file a material manifest references is updated.
Without --check the changed files are copied back, and the known-answer inputs
are kept under target/kat/ for inspection. With --check nothing is written and
any difference fails.

Requires Node.js 22, Python 3 with `cryptography` (scripts/fixtures/requirements.txt), and at the
repository root `npm ci && npm run build`. The Anon Aadhaar step also needs a
groth16-verifier checkout at tag v0.1.0 with its hints SDK built
(`npm ci && npm run build` in packages/groth16-verifier-hints), named by $GROTH16_VERIFIER.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
F = "scripts/fixtures"
BUILDERS = "packages/credential-proofs-inputs/tests/builders/dist/cli.js"
INPUTS = "packages/credential-proofs-inputs/scripts"
PY = sys.executable

# Run from the repository root, in order: later steps read files earlier ones write.
STEPS = [
    ["node", f"{F}/generate-entra.mjs", "0006da20d1ed15aba22054e3f9e439ad91a56f2b7fbfae464dfed0d357d2245a"],
    ["node", f"{F}/generate-facebook-local.mjs"],
    ["node", f"{F}/generate-component-fixtures.mjs"],
    ["node", f"{INPUTS}/alipay-inputs.mjs", "import", "fixtures/data/alipay/upstream-v2-file-upload.json", "target/kat/alipay_v2/Prover.toml"],
    ["node", f"{INPUTS}/alipay-inputs.mjs", "import", "fixtures/data/alipay/synthetic-v3.json", "target/kat/alipay_v3/Prover.toml"],
    ["node", f"{INPUTS}/wechatpay-inputs.mjs", "import", "fixtures/data/wechatpay/synthetic-v3.json", "target/kat/wechatpay_v3/Prover.toml"],
    [PY, f"{F}/generate-historical-oidc-fixtures.py"],
    ["node", f"{F}/generate-linkedin-local.mjs"],
    ["node", f"{F}/generate-singpass-local.mjs"],
    ["node", f"{F}/generate-philsys-local.mjs"],
    ["node", f"{F}/philsys/serialization-vectors.mjs"],
    [PY, f"{F}/generate-line-fixture.py"],
    ["node", f"{F}/generate-govbr.mjs"],
    ["node", f"{F}/govbr-noir-vectors.mjs"],
    ["node", f"{F}/generate-franceconnect-fixture.mjs"],
    ["node", f"{F}/generate-franceconnect-fixture.mjs", "0" * 64, "standard"],
    ["node", f"{F}/franceconnect-noir-vectors.mjs"],
    ["node", f"{F}/generate-university-local.mjs"],
    ["node", f"{F}/generate-aadhaar-secure-qr-fixtures.mjs"],
    ["node", f"{F}/generate-rsa-signature-fixtures.mjs"],
    ["node", f"{F}/generate-ed25519-local.mjs"],
    ["node", f"{F}/generate-peer-v4-standalone-local.mjs"],
    ["node", f"{F}/generate-reclaim-public-fixture.mjs"],
    ["node", f"{F}/generate-zupass-holder-approval.mjs"],
    ["node", f"{F}/generate-zupass-fixture.cjs"],
    ["node", BUILDERS, "synthetic", "oidc", "google", "--out", "fixtures/data/generated/google.synthetic.toml"],
    ["node", BUILDERS, "synthetic", "oidc", "apple", "--out", "fixtures/data/generated/apple.synthetic.toml"],
    ["node", BUILDERS, "synthetic", "pod", "--out", "fixtures/data/generated/zupass.synthetic.toml", "--entry", "event"],
    ["node", BUILDERS, "synthetic", "ethereum", "--out-dir", "fixtures/data/generated"],
    ["node", BUILDERS, "synthetic", "oidc", "telegram", "--out", "target/kat/telegram/Prover.toml"],
    ["node", BUILDERS, "synthetic", "oidc", "kakao", "--out", "target/kat/kakao/Prover.toml",
     "--audience", "synthetic-kakao-rest-app-key", "--subject", "123456789", "--nonce", "0" * 64],
    ["node", BUILDERS, "synthetic", "oidc", "miargentina", "--out", "target/kat/miargentina/Prover.toml",
     "--audience", "synthetic-miargentina-client", "--subject", "synthetic-miargentina-subject", "--nonce", "0" * 64],
    [PY, f"{F}/generate-x509-noir-vectors.py"],
    ["node", f"{F}/anon-aadhaar/prepare-fixture.mjs"],
    [PY, f"{F}/generate-x509-fixtures.py", "jpki",
     "--account", "003aa588713f4c0b6cd81477fb23bc29aacc7485ebb0fa9c128a3f9824d84195",
     "--action", "0aaf375211d8d2e3ef48e36ef4a621b2f26c73c1068fd4d04597a3d90a6dc28b"],
    [PY, f"{F}/generate-zkemail-header-tests.py"],
    [PY, f"{F}/generate-passkey-vectors.py"],
    [PY, f"{F}/generate-wechatpay-scanner-tests.py"],
    [PY, f"{F}/generate-ed25519-edge-vectors.py"],
]

# Known-answer inputs that are saved material rather than a generator's output.
COPIES = {
    "fixtures/data/generated/ethereum-personal-sign.synthetic.toml": "target/kat/ethereum_personal_sign/Prover.toml",
    "fixtures/data/generated/ethereum-siwe.synthetic.toml": "target/kat/ethereum_siwe/Prover.toml",
    "fixtures/data/generated/ethereum-secret-key.synthetic.toml": "target/kat/ethereum_secret_key/Prover.toml",
    "fixtures/material/passkey/provider-test/oxide-assertion.toml": "target/kat/passkey/Prover.toml",
}

# The committed trees the generators write into.
TREES = ("noir", "fixtures")


def nargo():
    return os.environ.get("NARGO", "nargo")


def format_noir(sources):
    """Return each Noir source as `nargo fmt` formats it (the formatter is per file)."""
    if not sources:
        return []
    with tempfile.TemporaryDirectory(prefix="fmt-") as scratch:
        package = Path(scratch)
        (package / "src").mkdir()
        (package / "Nargo.toml").write_text('[package]\nname = "fmt_scratch"\ntype = "lib"\nauthors = [""]\n')
        (package / "src/lib.nr").write_text("".join(f"mod file_{i};\n" for i in range(len(sources))))
        for i, source in enumerate(sources):
            (package / f"src/file_{i}.nr").write_text(source)
        subprocess.run([nargo(), "fmt"], cwd=package, check=True)
        return [(package / f"src/file_{i}.nr").read_text() for i in range(len(sources))]


def files(base):
    return {
        str(path.relative_to(base))
        for tree in TREES
        for path in (base / tree).rglob("*")
        if path.is_file() and not {"target", "export", "__pycache__"} & set(path.relative_to(base).parts)
    }


def changed(work):
    """Paths under TREES whose content in `work` differs from the repository."""
    return sorted(
        p for p in files(work) if not (ROOT / p).is_file() or (ROOT / p).read_bytes() != (work / p).read_bytes()
    )


def update_manifest_hashes(work, paths):
    """Recompute the SHA-256 of each changed file that a material manifest references."""
    paths = set(paths)
    for manifest in sorted((work / "fixtures/material").glob("*/manifest.json")):
        text = manifest.read_text()
        data = json.loads(text)
        for entry in data["materials"]:
            for ref in entry["files"] + entry["verification"]["evidence"]:
                if ref["path"] in paths and "sha256" in ref:
                    ref["sha256"] = hashlib.sha256((work / ref["path"]).read_bytes()).hexdigest()
        new = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
        if new != text:
            manifest.write_text(new)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if a committed file differs; write nothing")
    check = parser.parse_args().check
    for need in ("node_modules/credential-proofs-inputs", "packages/credential-proofs-inputs/dist", BUILDERS):
        if not (ROOT / need).exists():
            sys.exit(f"missing {need}: run `npm ci && npm run build` at the repository root")
    if not os.environ.get("GROTH16_VERIFIER"):
        sys.exit("set GROTH16_VERIFIER to a groth16-verifier checkout (see the docstring)")
    sys.path.insert(0, str(ROOT / F))
    import kat

    with tempfile.TemporaryDirectory(prefix="generate-") as scratch:
        work = Path(scratch) / "repo"
        shutil.copytree(
            ROOT,
            work,
            ignore=shutil.ignore_patterns(".git", "target", "export", "node_modules", "__pycache__"),
        )
        (work / "node_modules").symlink_to(ROOT / "node_modules")
        for entry in kat.KATS:
            (work / "target/kat" / entry["name"]).mkdir(parents=True)
        before = {p: (work / p).stat().st_mtime_ns for p in files(work)}
        for command in STEPS:
            subprocess.run(command, cwd=work, check=True, stdout=subprocess.DEVNULL)
        for source, target in COPIES.items():
            shutil.copyfile(work / source, work / target)
        kat.write_modules(work / "target/kat", work / "noir")
        # Format every Noir file a generator wrote.
        noir = [
            p for p in sorted(files(work)) if p.endswith(".nr") and before.get(p) != (work / p).stat().st_mtime_ns
        ]
        for path, text in zip(noir, format_noir([(work / p).read_text() for p in noir])):
            (work / path).write_text(text)
        update_manifest_hashes(work, changed(work))
        stale = changed(work)
        if check:
            if stale:
                sys.exit("stale generated files:\n  " + "\n  ".join(stale))
            print("generated files are up to date")
            return
        for path in stale:
            (ROOT / path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(work / path, ROOT / path)
        shutil.rmtree(ROOT / "target/kat", ignore_errors=True)
        shutil.copytree(work / "target/kat", ROOT / "target/kat")
    print(f"updated {len(stale)} generated files" + "".join(f"\n  {p}" for p in stale))


if __name__ == "__main__":
    main()
