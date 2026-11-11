#!/usr/bin/env python3
"""Regenerate the use-case fixtures and compare them with the committed files.

Every instance with `fixtures/manifest.json` records the argv of the generator
that wrote its `src/fixture.nr`. This driver runs that argv again, in a private copy of the repository layout, and compares the outputs
with the committed files byte for byte. The manifest is compared too, except for
the `inputs` hashes of the generator and library sources: they change whenever a
source file changes and do not describe the fixture.

    python3 aztec/use-cases/scripts/check_fixtures.py --check      # report drift, write nothing
    python3 aztec/use-cases/scripts/check_fixtures.py              # rewrite drifted fixtures
    python3 aztec/use-cases/scripts/check_fixtures.py --check --only login-link/google

The generators are seeded and deterministic (public seeds, fixed clocks), need
no network and make no proof. They need:
- `npm ci` in aztec/use-cases, and `npm ci && npm run build` in
  packages/credential-proofs-inputs and in packages/credential-proofs-inputs/tests/builders;
- Python 3 with `cryptography` (the X.509 chains of x509.py);
- the nargo of Aztec 6.0.0 ($NARGO, else `aztec-nargo` or `nargo` on PATH),
  which formats the output.
Without them the driver prints "skipped" and exits 0; `--require` turns that
into a failure.
"""

import argparse
import concurrent.futures
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
ROOT = PROJECT.parents[1]
sys.path.insert(0, str(PROJECT / "scripts/fixtures/generators"))
import nr_format  # noqa: E402

# Directories of the repository that generators only read.
LINKED = ("noir", "fixtures", "packages", "scripts")
IGNORED = ("__pycache__", "node_modules", "target")


def skipped_reason():
    """Why the generators cannot run here, or None."""
    if not nr_format.available():
        return "the nargo of Aztec 6.0.0 is not installed (set NARGO)"
    # The generators import the built packages through aztec/use-cases/node_modules.
    modules = PROJECT / "node_modules"
    if (
        not (modules / "viem").is_dir()
        or not (modules / "credential-proofs-inputs/dist/src").is_dir()
        or not (modules / "credential-proofs-test-builders/dist").is_dir()
    ):
        return (
            "npm ci in aztec/use-cases, and npm ci && npm run build in packages/credential-proofs-inputs"
            " and its tests/builders, are needed"
        )
    if importlib.util.find_spec("cryptography") is None:
        return "the Python package cryptography is not installed"
    return None


def instances(only):
    rows = []
    for path in sorted(PROJECT.glob("*/*/fixtures/manifest.json")):
        name = str(path.parent.parent.relative_to(PROJECT))
        if only and not any(part in name for part in only):
            continue
        rows.append(name)
    return rows


def comparable(record):
    """The manifest without the source hashes."""
    record = json.loads(json.dumps(record))
    record.pop("inputs", None)
    return record


def outputs_of(directory, record):
    """Fixture files that the manifest says generators write, relative to the instance."""
    return {os.path.normpath(name) for name in record.get("outputs", {})}


def run(argv, cwd, env):
    """None, or the failure of `argv` with the tail of its output."""
    done = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, env=env)
    if done.returncode:
        return f"{' '.join(map(str, argv))} failed:\n{(done.stdout + done.stderr)[-2000:]}"
    return None


def run_instance(name, workdir):
    """Regenerate one instance in a private copy; returns (problems, changed files)."""
    directory = PROJECT / name
    manifest = json.loads((directory / "fixtures/manifest.json").read_text())
    problems = []
    # A private copy of the repository layout: aztec/use-cases is copied, the
    # rest that generators read is linked.
    mirror = Path(workdir) / name.replace("/", "__")
    (mirror / "aztec").mkdir(parents=True)
    for link in LINKED:
        if (ROOT / link).exists():
            os.symlink(ROOT / link, mirror / link)
    shutil.copy2(ROOT / "aztec/noirfmt.toml", mirror / "aztec/noirfmt.toml")
    shutil.copytree(
        PROJECT, mirror / "aztec/use-cases", ignore=shutil.ignore_patterns(*IGNORED)
    )
    os.symlink(PROJECT / "node_modules", mirror / "aztec/use-cases/node_modules")
    env = {**os.environ, "NARGO": nr_format.nargo()}
    generator = manifest["generator"]
    argv = [sys.executable if a in ("python3", "python") else a for a in generator["argv"]]
    error = run(argv, mirror / generator["cwd"], env)
    if error:
        problems.append("generator failed: " + error)
        return problems, []
    fresh_dir = mirror / "aztec/use-cases" / name
    fresh_manifest = json.loads((fresh_dir / "fixtures/manifest.json").read_text())
    changed = []
    for output in sorted(
        outputs_of(directory, manifest) | outputs_of(fresh_dir, fresh_manifest)
    ):
        old = directory / output
        new = fresh_dir / output
        if not new.is_file():
            problems.append(f"{output}: the generator did not write it")
        elif not old.is_file() or old.read_bytes() != new.read_bytes():
            problems.append(f"{output}: differs from the regenerated file")
            changed.append((new, old))
    if comparable(fresh_manifest) != comparable(manifest):
        keys = sorted(
            key
            for key in set(comparable(fresh_manifest)) | set(comparable(manifest))
            if comparable(fresh_manifest).get(key) != comparable(manifest).get(key)
        )
        problems.append(
            "fixtures/manifest.json differs from the regenerated one: "
            + ", ".join(keys)
        )
    # In rewrite mode the manifest is rewritten too, which refreshes its source hashes.
    changed.append(
        (fresh_dir / "fixtures/manifest.json", directory / "fixtures/manifest.json")
    )
    return problems, changed


def publish(pairs):
    """Copy each regenerated file over the committed one."""
    for source, destination in pairs:
        if not destination.is_file() or source.read_bytes() != destination.read_bytes():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true", help="report drift; write nothing")
    parser.add_argument(
        "--require",
        action="store_true",
        help="fail when a generator prerequisite is missing",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        help="instances whose path contains this text",
    )
    parser.add_argument(
        "--instance",
        action="append",
        default=[],
        help="check exactly this instance path (repeatable)",
    )
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1))
    parser.add_argument(
        "--list", action="store_true", help="list the instances and exit"
    )
    args = parser.parse_args()

    names = instances(args.only)
    if args.instance:
        unknown = set(args.instance) - set(instances([]))
        if unknown:
            parser.error("unknown fixture instance: " + ", ".join(sorted(unknown)))
        names = [name for name in names if name in args.instance]
    if args.list:
        print("\n".join(names))
        return 0
    reason = skipped_reason()
    if reason:
        print(f"skipped: {reason}")
        return 1 if args.require else 0
    failures = {}
    writes = {}
    with tempfile.TemporaryDirectory(prefix="uc-fixtures-") as workdir:
        with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
            futures = {pool.submit(run_instance, n, workdir): n for n in names}
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    problems, changed = future.result()
                except Exception as error:  # report, do not abort the others
                    problems, changed = (
                        [f"generator error: {type(error).__name__}: {error}"],
                        [],
                    )
                if problems:
                    failures[name] = problems
                writes[name] = changed
        if not args.check:
            for name, changed in sorted(writes.items()):
                problems = failures.get(name, [])
                if any(
                    p.startswith("generator") or "did not write" in p
                    for p in problems
                ):
                    continue
                publish(changed)
    for name, problems in sorted(failures.items()):
        for problem in problems:
            print(f"{name}: {problem}")
    if args.check:
        print(f"{len(names)} instances checked, {len(failures)} drifted")
        return 1 if failures else 0
    print(f"{len(names)} instances regenerated")
    # Rewrite mode fails when a generator cannot run or does not write a fixture.
    broken = [
        p
        for ps in failures.values()
        for p in ps
        if p.startswith("generator") or "did not write" in p
    ]
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
