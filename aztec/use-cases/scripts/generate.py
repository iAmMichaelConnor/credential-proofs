#!/usr/bin/env python3
"""Generate the uniform parts of aztec/use-cases from use-cases.json.

Writes every instance Nargo.toml and src/main.nr (whose header carries the
row's `notes`), each use-case README instance table, the top-level grid and the use-case block of the Aztec
workspace members in aztec/Nargo.toml (ARCHITECTURE.md, "Generated files").
Hand-written parts are kept: the `// BEGIN HAND-WRITTEN <name>` regions of
main.nr, the README text outside the generated blocks, src/test.nr,
src/fixture.nr and fixtures/.

`--check` writes nothing. It fails when any generated file differs from the
committed one, and it lints what the generator does not write: the tests in
src/test.nr (required tests present; every rejected case, and any other test
that expects a failure, expects a named failure; a required body calls something and asserts no constant false), no
extra contract function in a HAND-WRITTEN region, no instance README (an instance's caveats
are its `notes`), the fixture manifest and its src/fixture.nr hash, and instance directories
missing from use-cases.json. use-cases.json itself is refused when an
instance uses test-only evidence or a provider adapter for a use case that
the provider does not declare. It formats the generated Noir with `nargo fmt`
(scripts/fixtures/generators/nr_format.py: $NARGO, else `aztec-nargo` or
`nargo` on PATH, the nargo of Aztec 6.0.0, with aztec/noirfmt.toml), runs no
compiler and reads no network.

`--list` prints the packages for scripts/test-use-cases.sh, one per line:
role, directory, package name and use case (tab-separated).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import re
import string
import sys
import textwrap
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/fixtures/generators"))

import nr_format  # noqa: E402

AZTEC = {
    "git": "https://github.com/aztec-labs-eng/aztec-nr",
    "tag": "v6.0.0",
    "directory": "aztec",
}
# Dependency targets with these prefixes are relative to the repository root;
# any other target is relative to aztec/use-cases.
REPOSITORY_PREFIXES = ("noir/", "vendor/", "aztec/")
# The line of aztec/Nargo.toml after which the generator writes the use-case
# workspace members, up to the closing `]`.
WORKSPACE_MARKER = "    # Use cases"
FIXTURE_SCHEMA = "uc-fixture-v1"
REGION = re.compile(
    r"^(?P<indent>[ \t]*)// BEGIN HAND-WRITTEN (?P<name>[a-z_]+)\n"
    r"(?P<body>.*?)"
    r"^(?P=indent)// END HAND-WRITTEN (?P=name)\n",
    re.MULTILINE | re.DOTALL,
)
MARKERS = {
    "instances": (
        "<!-- use-case-instances:start -->",
        "<!-- use-case-instances:end -->",
    ),
    "grid": ("<!-- use-case-grid:start -->", "<!-- use-case-grid:end -->"),
}


class ManifestError(ValueError):
    pass


def load(root):
    manifest = json.loads((root / "use-cases.json").read_text())
    if manifest.get("schema_version") != 1:
        raise ManifestError("use-cases.json: unsupported schema_version")
    return manifest


def camel(name):
    return "".join(part[:1].upper() + part[1:] for part in re.split(r"[_-]", name))


def relative(source_dir, target, root):
    """Path from an instance directory to a target. Targets are relative to
    the project root, or to the repository root when they start with one of
    REPOSITORY_PREFIXES (`noir/<package>`)."""
    repository = root.parents[1]
    base = (
        repository / target
        if target.startswith(REPOSITORY_PREFIXES)
        else root / target
    )
    return PurePosixPath(os.path.relpath(base, root / source_dir)).as_posix()


ADAPTER_KINDS = {"family", "provider", "scheme", "test"}
TESTING = "aztec/use-cases/testing"


def test_only(target):
    """Whether a dependency target (as `relative` reads it) resolves into
    aztec/use-cases/testing, however it is spelled. A non-path target (for
    example a git dependency) is not test-only code."""
    if not isinstance(target, str):
        return False
    if posixpath.isabs(target):
        # relative() would accept it through `root / target`; refuse it.
        raise ManifestError(f"Dependency paths must be relative: {target}")
    repository_relative = target.startswith(REPOSITORY_PREFIXES)
    resolved = posixpath.normpath(
        target if repository_relative else f"aztec/use-cases/{target}"
    )
    return resolved == TESTING or resolved.startswith(TESTING + "/")


def entries(manifest):
    """Normalised instances, then template checks."""
    result = []
    use_cases, adapters = manifest["use_cases"], manifest["adapters"]
    seen = set()
    for kind, rows in (
        ("instance", manifest.get("instances", [])),
        ("template", manifest.get("template_checks", [])),
    ):
        for row in rows:
            use_case = row["use_case"]
            if use_case not in use_cases:
                raise ManifestError(f"Unknown use case: {use_case}")
            spec = use_cases[use_case]
            scheme = row.get("scheme", "template")
            if not re.fullmatch(r"[a-z][a-z0-9_]*", scheme):
                raise ManifestError(f"Scheme id must be snake_case: {scheme}")
            directory = row.get("directory", f"{use_case}/{scheme}")
            if len(PurePosixPath(directory).parts) != 2:
                raise ManifestError(
                    f"Instance directory must have depth 2: {directory}"
                )
            if directory in seen:
                raise ManifestError(f"Duplicate instance: {directory}")
            seen.add(directory)
            account = use_case == "account-authorisation"
            var = "auth" if account else "evidence"
            dependencies = {
                "aztec": AZTEC,
                spec["core"]: f"{use_case}/common",
            }
            if kind == "instance" and not account:
                # uc_trust names the terms' TrustPolicy for the instance tests.
                # Accounts and template checks do not use it.
                dependencies["uc_trust"] = "trust"
            uses = []
            adapter_name = row.get("adapter")
            adapter = adapters.get(adapter_name) if adapter_name else None
            if adapter_name and adapter is None:
                raise ManifestError(f"Unknown adapter: {adapter_name}")
            if adapter and adapter["kind"] not in ADAPTER_KINDS:
                raise ManifestError(
                    f"{adapter_name}: adapter kind must be one of {sorted(ADAPTER_KINDS)}"
                )
            if kind == "instance":
                # An instance on unverified test evidence would look like a
                # real example (README grid, package list) and accept forgeries.
                if adapter and adapter["kind"] == "test":
                    raise ManifestError(
                        f"{directory}: the test adapter {adapter_name} is for template checks only"
                    )
                paths = dict(row.get("dependencies", {}))
                if adapter:
                    paths[adapter["crate"]] = adapter["path"]
                    if adapter["kind"] == "provider":
                        family = adapters[adapter["family"]]
                        paths[family["crate"]] = family["path"]
                for alias, path in paths.items():
                    if test_only(path):
                        raise ManifestError(
                            f"{directory}: dependency {alias} is test-only code ({path})"
                        )
                if PurePosixPath(directory).parts[0] == "testing":
                    raise ManifestError(f"{directory}: instances live outside testing/")
            elif PurePosixPath(directory).parts[0] != "testing":
                raise ManifestError(f"{directory}: template checks live in testing/")
            wrapper = None
            if adapter and adapter["kind"] == "provider":
                family = adapters[adapter["family"]]
                # Each provider declares the use cases its evidence supports
                # (for example a global `sub` is not a pairwise person for
                # uniqueness); the family wrapper alone does not decide it.
                declared_key = "bearer_use_cases" if row.get("bearer") else "use_cases"
                if "use_cases" not in adapter:
                    raise ManifestError(
                        f"{adapter_name}: a provider adapter must declare its use_cases"
                    )
                if use_case not in adapter.get(declared_key, []):
                    raise ManifestError(
                        f"{directory}: provider {adapter_name} does not declare "
                        f"{use_case} in {declared_key}"
                    )
                wrappers = family[
                    "bearer_wrappers" if row.get("bearer") else "wrappers"
                ]
                if use_case not in wrappers:
                    raise ManifestError(
                        f"{adapter['family']} has no {use_case} wrapper for {directory}"
                    )
                wrapper = wrappers[use_case]
                dependencies[family["crate"]] = family["path"]
                uses.append(f"use {family['crate']}::{wrapper};")
            family_name = row.get("family")
            if family_name is not None:
                # An account whose in-crate input implements the family's
                # provider trait itself (the OIDC accounts). It has no
                # provider adapter crate and is an account only.
                family = adapters.get(family_name)
                if family is None or family["kind"] != "family":
                    raise ManifestError(f"{directory}: unknown family {family_name}")
                if adapter or not row.get("input_in_crate"):
                    raise ManifestError(
                        f"{directory}: a family row must have an in-crate input and no adapter"
                    )
                if use_case != "account-authorisation":
                    raise ManifestError(
                        f"{directory}: an in-crate family input is for accounts only"
                    )
                wrapper = family["wrappers"][use_case]
                dependencies[family["crate"]] = family["path"]
                uses.append(f"use {family['crate']}::{wrapper};")
            if row.get("input_in_crate"):
                input_type = row["input"]
            elif adapter is None:
                raise ManifestError(
                    f"{directory}: an adapter or an in-crate input is needed"
                )
            elif adapter["kind"] == "provider":
                # A provider may name another input type for one use case
                # (the university affiliation gate).
                input_type = adapter.get("types", {}).get(use_case, adapter["input"])
            else:
                if use_case not in adapter.get("types", {}):
                    raise ManifestError(f"{adapter_name} has no {use_case} type")
                input_type = adapter["types"][use_case]
            if adapter and not row.get("input_in_crate"):
                # An in-crate input (accounts) implements the provider trait
                # itself and needs only the family crate.
                dependencies[adapter["crate"]] = adapter["path"]
                uses.append(f"use {adapter['crate']}::{input_type};")
            for alias, path in row.get("dependencies", {}).items():
                dependencies[alias] = path
            for alias in dependencies:
                if alias != "aztec" and alias < "aztec":
                    # An aztec-dependent alias that sorts before `aztec`
                    # changes ABI struct paths. Keep every alias after it.
                    raise ManifestError(
                        f"{directory}: dependency alias {alias} sorts before aztec"
                    )
            modules = row.get("modules", [])
            for name in modules:
                if not re.fullmatch(r"[a-z][a-z0-9_]*", str(name)):
                    raise ManifestError(
                        f"{directory}: module name must be snake_case: {name}"
                    )
            notes = row.get("notes", [])
            if not isinstance(notes, list) or not all(
                isinstance(note, str) and note.strip() and "\n" not in note
                for note in notes
            ):
                raise ManifestError(
                    f"{directory}: notes must be a list of one-line strings"
                )
            choice = bool(row.get("choice"))
            if choice and use_case not in {"attribute-gating", "uniqueness"}:
                raise ManifestError(
                    f"{directory}: only gating and uniqueness take a choice"
                )
            core_function = {
                "attribute-gating": "gate_with_choice" if choice else "gate",
                "uniqueness": "once_with_choice" if choice else "once",
            }.get(use_case, spec["entrypoint"])
            result.append(
                {
                    "kind": kind,
                    "use_case": use_case,
                    "scheme": scheme,
                    "scheme_title": row.get("scheme_title", camel(scheme)),
                    "category": row.get("category"),
                    "directory": directory,
                    "package": row.get("package", f"{scheme}_{spec['package_suffix']}"),
                    "contract": row.get(
                        "contract", camel(scheme) + spec["contract_suffix"]
                    ),
                    "adapter": adapter_name,
                    "adapter_crate": adapter["crate"] if adapter else None,
                    "adapter_path": adapter["path"] if adapter else None,
                    "wrapper": wrapper,
                    "input_type": input_type,
                    "input_in_crate": bool(row.get("input_in_crate")),
                    "input_expr": f"{wrapper} {{ input: {var} }}" if wrapper else var,
                    "uses": sorted(uses),
                    "dependencies": dependencies,
                    "choice": choice,
                    "bearer": bool(row.get("bearer")),
                    "core_function": core_function,
                    "txe": bool(row.get("txe")) and kind == "instance",
                    "skip_tests": row.get("skip_tests", {}),
                    # Instance-specific residual risks and caveats: the header
                    # of src/main.nr and the use-case README table show them.
                    "notes": notes,
                    # Extra hand-written modules of an account (zkEmail's profile).
                    "modules": modules,
                }
            )
    return result


# Per use case: (entrypoint, first parameter, return type, binding of the
# core result, core module). The evidence parameter and core arguments
# follow from the instance.
SHAPES = {
    "account-authorisation": (
        "entrypoint",
        "payload: AppPayload",
        "",
        None,
        "uc_account",
    ),
    "login-link": ("link", "terms: LinkTerms", " -> Field", "claim", "uc_login_link"),
    "attribute-gating": ("act", "terms: GateTerms", "", "claim", "uc_attribute_gate"),
    "uniqueness": ("act_once", "terms: UniqueTerms", "", "claim", "uc_uniqueness"),
    "payment-settlement": (
        "settle",
        "order: Order",
        "",
        "payment",
        "uc_payment_settlement",
    ),
    "event-proof": ("on_event", "terms: EventTerms", "", "event", "uc_event_proof"),
}
MAX_WIDTH = 120  # max_width of aztec/noirfmt.toml


def call_lines(indent, head, arguments, tail):
    """One line, or one argument per line as nargo fmt lays it out."""
    line = f"{indent}{head}({', '.join(arguments)}){tail}"
    if len(line) <= MAX_WIDTH:
        return line
    inner = "".join(f"{indent}    {argument},\n" for argument in arguments)
    return f"{indent}{head}(\n{inner}{indent}){tail}"


def entrypoint_lines(entry):
    function, first, returns, result, module = SHAPES[entry["use_case"]]
    var = "auth" if entry["use_case"] == "account-authorisation" else "evidence"
    parameters = [first, f"{var}: {entry['input_type']}"]
    arguments = ["self.context", first.split(":")[0], entry["input_expr"]]
    if entry["choice"]:
        parameters.append("choice: Field")
        arguments.append("choice")
    signature = call_lines("    ", f"fn {function}", parameters, f"{returns} {{")
    head = f"{module}::{entry['core_function']}"
    if result:
        head = f"let {result} = {head}"
    return signature, call_lines("        ", head, arguments, ";")


def template(root, name):
    return string.Template((root / "scripts/templates" / name).read_text())


def regions(text):
    return {m["name"]: m["body"] for m in REGION.finditer(text)}


def merge_regions(generated, existing):
    """Keep the hand-written bodies of `existing` in `generated`."""
    kept = regions(existing) if existing is not None else {}

    def replace(match):
        body = kept.get(match["name"], match["body"])
        return (
            f"{match['indent']}// BEGIN HAND-WRITTEN {match['name']}\n"
            f"{body}"
            f"{match['indent']}// END HAND-WRITTEN {match['name']}\n"
        )

    return REGION.sub(replace, generated)


def nargo_toml(root, entry):
    lines = []
    for alias in sorted(entry["dependencies"], key=lambda a: (a != "aztec", a)):
        target = entry["dependencies"][alias]
        if isinstance(target, dict):
            # A pinned remote dependency: aztec, or a scheme crate's own
            # `sha256` that an account imports directly.
            if set(target) - {"directory"} != {"git", "tag"}:
                raise ManifestError(f"{entry['directory']}: {alias} needs git and tag")
            fields = [f'{key} = "{target[key]}"' for key in ("git", "tag", "directory") if key in target]
            lines.append(f"{alias} = {{ {', '.join(fields)} }}")
            continue
        path = relative(entry["directory"], target, root)
        lines.append(f'{alias} = {{ path = "{path}" }}')
    return template(root, "Nargo.toml.tmpl").substitute(
        package=entry["package"], dependencies="\n".join(lines)
    )


def notes_header(entry):
    """The instance's `notes` as `//!` lines after the generated header, or
    nothing."""
    if not entry["notes"]:
        return ""
    lines = [
        "",
        "//!",
        f"//! Residual risk and notes (see also {entry['use_case']}/README.md):",
    ]
    for note in entry["notes"]:
        lines += textwrap.wrap(
            note,
            width=MAX_WIDTH,
            initial_indent="//! - ",
            subsequent_indent="//!   ",
            break_long_words=False,
            break_on_hyphens=False,
        )
    return "\n".join(lines)


def main_nr(root, manifest, entry, existing):
    spec = manifest["use_cases"][entry["use_case"]]
    # nargo fmt sorts a run of `use` lines by path, so the generated lines
    # (the core's terms type, the family wrapper, the adapter input) are sorted
    # together; sorting them apart would leave a package that `nargo fmt` rewrites.
    _, first, _, _, module = SHAPES[entry["use_case"]]
    lines = list(entry["uses"])
    if entry["use_case"] != "account-authorisation":
        lines.append(f"use {module}::{first.split(': ')[1]};")
    uses = "".join(f"    {line}\n" for line in sorted(lines))
    signature, call = entrypoint_lines(entry)
    text = template(root, f"main/{spec['template']}.nr.tmpl").substitute(
        contract=entry["contract"],
        title=spec["title"],
        scheme_title=entry["scheme_title"],
        notes=notes_header(entry),
        modules=""
        if entry["kind"] == "template"
        else "\nmod fixture;\nmod test;\n"
        + "".join(f"pub mod {name};\n" for name in entry["modules"]),
        uses=uses,
        signature=signature,
        call=call,
    )
    return merge_regions(text, existing)


def replace_block(text, kind, body, path):
    start, end = MARKERS[kind]
    if text.count(start) != 1 or text.count(end) != 1:
        raise ManifestError(f"{path}: needs one {start} ... {end} block")
    head, rest = text.split(start, 1)
    _, tail = rest.split(end, 1)
    return f"{head}{start}\n{body}\n{end}{tail}"


def adapter_cell(entry):
    """The adapter column of a use-case README table (paths from `<use case>/`)."""
    if not entry["adapter_crate"] or entry["input_in_crate"]:
        return "in-crate input" + (
            f" via `{entry['wrapper']}`" if entry["wrapper"] else ""
        )
    link = f"[`{entry['adapter_crate']}`](../{entry['adapter_path']}/src/lib.nr)"
    if entry["wrapper"]:
        link += f" via `{entry['wrapper']}`"
    return link


def entrypoint_signature(manifest, use_case, choice):
    spec = manifest["use_cases"][use_case]
    first = {
        "account-authorisation": "payload, auth",
        "payment-settlement": "order, evidence",
    }.get(use_case, "terms, evidence")
    return f"`{spec['entrypoint']}({first}{', choice' if choice else ''})`"


def required_tests(manifest, entry):
    spec = manifest["use_cases"][entry["use_case"]]
    names = list(spec["required_tests"])
    return [n for n in names if n not in entry["skip_tests"]]


def except_for(rows, label):
    """` (<scheme>: <label(entry)>, ...)` for the rows where label is not None."""
    cases = [f"{e['scheme']}: {label(e)}" for e in rows if label(e) is not None]
    return f" ({'; '.join(cases)})" if cases else ""


def use_case_table(manifest, use_case, rows):
    """One row per instance, linking its contract source, with the
    instance's `notes` (its residual risks beyond the use-case rules)."""
    if not rows:
        return "No instances yet."
    spec = manifest["use_cases"][use_case]
    package = f"<scheme>_{spec['package_suffix']}"
    choice = [e["scheme"] for e in rows if e["choice"]]
    no_txe = [e["scheme"] for e in rows if not e["txe"]]
    lines = [
        "Each instance is a contract in `<scheme>/src/main.nr`, entrypoint "
        + entrypoint_signature(manifest, use_case, False)
        + (
            f" ({', '.join(choice)}: "
            + entrypoint_signature(manifest, use_case, True)
            + ")"
            if choice
            else ""
        )
        + f", package `{package}`"
        + except_for(
            rows,
            lambda e: f"`{e['package']}`"
            if e["package"] != f"{e['scheme']}_{spec['package_suffix']}"
            else None,
        )
        + f", tested by `scripts/test-use-cases.sh {use_case}/<scheme>`"
        + (f" (no TXE tests for {', '.join(no_txe)})" if no_txe else "")
        + ". Its `src/test.nr` has the tests "
        + ", ".join(f"`{n}`" for n in spec["required_tests"])
        + "; [use-cases.json](../use-cases.json) records each exception and its reason."
        + " The category is the evidence category of"
        + " [ARCHITECTURE.md](../ARCHITECTURE.md#evidence-and-authority).",
        "",
        "| Instance | Category | Contract | Adapter | Residual risk and notes |",
        "| --- | --- | --- | --- | --- |",
    ]
    for entry in rows:
        scheme = entry["scheme"]
        notes = " ".join(entry["notes"]).replace("|", "\\|") or "-"
        lines.append(
            f"| [{scheme}]({scheme}/src/main.nr) | "
            f"{entry['category'] if entry['category'] is not None else '-'} | "
            f"`{entry['contract']}` | {adapter_cell(entry)} | {notes} |"
        )
    return "\n".join(lines)


def grid(manifest, rows):
    lines = [
        "Generated from [use-cases.json](use-cases.json) by",
        "[scripts/generate.py](scripts/generate.py). Each category lists its implemented instances.",
        "",
        "| Use case | Instances | Statement |",
        "| --- | ---: | --- |",
    ]
    for use_case, spec in manifest["use_cases"].items():
        count = sum(entry["use_case"] == use_case for entry in rows)
        statement = spec["statement"]
        if use_case == "login-link":
            statement = (
                "A challenge-bound login, or explicitly accepted bearer evidence, "
                "links an identity."
            )
        lines.append(f"| [{use_case}]({use_case}/README.md) | {count} | {statement} |")
    return "\n".join(lines)


def package_name(root, path):
    """The Nargo package name of a base package directory."""
    manifest_path = root / path / "Nargo.toml"
    if not manifest_path.is_file():
        raise ManifestError(f"Missing {path}/Nargo.toml")
    return tomllib.loads(manifest_path.read_text())["package"]["name"]


def read(path):
    return path.read_text() if path.is_file() else None


def packages(root, manifest, rows=None):
    """Every package of aztec/use-cases as (role, directory, package name,
    use case): the base packages (trust and the cores), the
    test support crates, the adapters, the test adapter, the template checks
    and the instances, each group sorted by directory."""
    rows = entries(manifest) if rows is None else rows
    result = []
    for role, directories in (
        ("base", manifest["base_packages"]),
        ("testing", sorted(manifest["testing_packages"])),
        (
            "adapter",
            sorted({a["path"] for a in manifest["adapters"].values() if a["kind"] != "test"}),
        ),
        (
            "test_adapter",
            sorted({a["path"] for a in manifest["adapters"].values() if a["kind"] == "test"}),
        ),
    ):
        for directory in directories:
            use_case = next(
                (u for u in manifest["use_cases"] if directory == f"{u}/common"), ""
            )
            result.append((role, directory, package_name(root, directory), use_case))
    for kind, role in (("template", "template"), ("instance", "instance")):
        for entry in sorted(
            (e for e in rows if e["kind"] == kind), key=lambda e: e["directory"]
        ):
            result.append(
                (role, entry["directory"], entry["package"], entry["use_case"])
            )
    return result


def workspace_toml(text, rows):
    """aztec/Nargo.toml with the lines after WORKSPACE_MARKER, up to the
    closing `]` of `members`, replaced by the use-case packages."""
    if text is None:
        raise ManifestError("Missing ../Nargo.toml (the Aztec workspace)")
    lines = text.split("\n")
    if lines.count(WORKSPACE_MARKER) != 1:
        raise ManifestError(f"../Nargo.toml: needs one '{WORKSPACE_MARKER.strip()}' line")
    start = lines.index(WORKSPACE_MARKER) + 1
    end = next((i for i in range(start, len(lines)) if lines[i] == "]"), None)
    if end is None:
        raise ManifestError(f"../Nargo.toml: no ']' after '{WORKSPACE_MARKER.strip()}'")
    members = [f'    "use-cases/{row[1]}",' for row in rows]
    return "\n".join(lines[:start] + members + lines[end:])


def outputs(root, manifest=None):
    """Every generated file, keyed by path relative to the project root."""
    manifest = manifest or load(root)
    rows = entries(manifest)
    result = {}
    for entry in rows:
        directory = entry["directory"]
        result[f"{directory}/Nargo.toml"] = nargo_toml(root, entry)
        main = f"{directory}/src/main.nr"
        result[main] = main_nr(root, manifest, entry, read(root / main))
    for use_case in manifest["use_cases"]:
        path = f"{use_case}/README.md"
        text = read(root / path)
        if text is None:
            raise ManifestError(f"Missing {path}")
        instances = [
            e for e in rows if e["kind"] == "instance" and e["use_case"] == use_case
        ]
        result[path] = replace_block(
            text,
            "instances",
            use_case_table(
                manifest, use_case, sorted(instances, key=lambda e: e["scheme"])
            ),
            path,
        )
    text = read(root / "README.md")
    result["README.md"] = replace_block(
        text,
        "grid",
        grid(manifest, [e for e in rows if e["kind"] == "instance"]),
        "README.md",
    )
    result["../Nargo.toml"] = workspace_toml(
        read(root.parent / "Nargo.toml"), packages(root, manifest, rows)
    )
    noir = [path for path in result if path.endswith(".nr")]
    for path, text in zip(noir, nr_format.format_sources([result[p] for p in noir])):
        result[path] = text
    return result


# Attributes that make a contract function callable (an ABI entry), under
# any path (`#[external]`, `#[functions::external]`, `#[f::external]`). A
# hand-written region must not add one: the only entrypoint is the generated
# one, which calls the core.
ENTRY_ATTRIBUTE = re.compile(
    r"#\[\s*(?:\w+\s*::\s*)*(external|private|public|utility|initializer)\b"
    # An alias would hide the attribute: `use ...::external as ext;` or
    # `use aztec::macros::functions as f;`.
    r"|\b(external|private|public|utility|initializer|functions|macros)\s+as\s+\w"
)
TEST_ITEM = re.compile(
    r"#\[test(?P<args>[^\]]*)\]\s*(?:pub\s+)?(?:unconstrained\s+)?fn\s+(?P<name>\w+)"
    r"\s*\([^)]*\)[^{]*\{"
)
NAMED_FAILURE = re.compile(r'\(\s*should_fail_with\s*=\s*"(?P<message>[^"]*)"\s*\)')
# Calls that do not exercise anything by themselves.
NOT_A_CALL = {
    "assert",
    "assert_eq",
    "assert_ne",
    "print",
    "println",
    "std",
    "if",
    "for",
    "while",
}


def strip_comments(text):
    """Text without comments and string contents, for token scans."""
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def generated_names(text):
    """Names that the generated part of main.nr imports or calls by a short
    path. A hand-written `mod` or `use ... as` with one of these names
    could redirect the generated entrypoint's call."""
    outside = REGION.sub("", text)
    names = set()
    for line in re.findall(r"^\s*use\s+([^;]+);", outside, re.M):
        names.update(re.findall(r"\w+", line))
    names.update(re.findall(r"\b(\w+)::\w+\s*\(", outside))
    return names - {"self", "crate", "super", "aztec"} | {"aztec"}


def region_problems(directory, text, aliases=()):
    problems = []
    protected = generated_names(text) | set(aliases)
    for name, body in regions(text).items():
        clean = strip_comments(body)
        match = ENTRY_ATTRIBUTE.search(clean)
        if match:
            problems.append(
                f"{directory}: HAND-WRITTEN {name} adds a #[{match[1] or match[2]}] function; "
                "the generated entrypoint is the only one"
            )
        for shadow in re.findall(
            r"\bmod\s+(\w+)|\bas\s+(\w+)|\b(?:fn|struct|global|trait|type|enum)\s+(\w+)",
            clean,
        ):
            shadowed = next(n for n in shadow if n)
            if shadowed in protected:
                problems.append(
                    f"{directory}: HAND-WRITTEN {name} shadows {shadowed}, "
                    "which the generated code uses"
                )
    return problems


def test_bodies(text):
    """{name: (attribute arguments, body)} of the #[test] functions."""
    result = {}
    for match in TEST_ITEM.finditer(text):
        depth, i = 1, match.end()
        clean = strip_comments(text[i:])
        j = 0
        while j < len(clean) and depth:
            depth += {"{": 1, "}": -1}.get(clean[j], 0)
            j += 1
        result[match["name"]] = (match["args"], clean[: j - 1])
    return result


def rejected_problem(directory, kind, name, args):
    """A `*_rejected` test must expect a named failure."""
    expected = NAMED_FAILURE.fullmatch(args)
    if expected and expected["message"].strip():
        return []
    return [f'{directory}: {kind} {name} needs #[test(should_fail_with = "<message>")]']


def test_problems(directory, test, names):
    """What a lint can check of the tests. It cannot show that a test fails
    for the stated reason or that it exercises the instance: reviewers check
    that. It checks that every rejected case (required or not) and any other
    test that expects a failure names the failure, and that each required
    body calls a function other than an assertion and asserts no constant
    false."""
    problems = []
    bodies = test_bodies(test)
    for name in names:
        if name not in bodies:
            problems.append(f"{directory}: missing required test {name}")
            continue
        args, body = bodies[name]
        args = args.strip()
        if name.endswith("_rejected"):
            problems += rejected_problem(directory, "required test", name, args)
        elif "should_fail" in args:
            problems.append(
                f"{directory}: required test {name} must not expect a failure"
            )
        calls = set(re.findall(r"\b(\w+)\s*(?:::\s*<[^>]*>\s*)?\(", body))
        if not calls - NOT_A_CALL:
            problems.append(f"{directory}: required test {name} calls nothing")
        if re.search(r"\bassert\s*\(\s*false\b", body):
            problems.append(f"{directory}: required test {name} asserts false")
    # Tests beyond the required ones follow the same failure rule.
    for name, (args, _) in sorted(bodies.items()):
        if name in names:
            continue
        args = args.strip()
        if name.endswith("_rejected"):
            problems += rejected_problem(directory, "test", name, args)
        elif "should_fail" in args:
            expected = NAMED_FAILURE.fullmatch(args)
            if not (expected and expected["message"].strip()):
                problems.append(f"{directory}: test {name} needs a named failure")
    return problems


def lint(root, manifest=None):
    """Checks of hand-written parts. Returns a list of problems."""
    manifest = manifest or load(root)
    rows = entries(manifest)
    problems = []
    for entry in rows:
        directory = root / entry["directory"]
        main = read(directory / "src/main.nr")
        if main is not None:
            problems += region_problems(entry["directory"], main, entry["dependencies"])
        if entry["kind"] == "template":
            if (directory / "src/test.nr").exists():
                problems.append(f"{entry['directory']}: template checks have no tests")
            continue
        test = read(directory / "src/test.nr")
        if test is None:
            problems.append(f"{entry['directory']}: missing src/test.nr")
        else:
            problems += test_problems(entry["directory"], test, required_tests(manifest, entry))
        # An instance's own caveats are its `notes` (main.nr header and the
        # use-case table); the code and the use-case README say the rest.
        if (directory / "README.md").exists():
            problems.append(
                f"{entry['directory']}/README.md: instances have no README; "
                "put its caveats in the row's notes in use-cases.json"
            )
        manifest_path = directory / "fixtures/manifest.json"
        fixture = directory / "src/fixture.nr"
        if not manifest_path.is_file():
            problems.append(f"{entry['directory']}: missing fixtures/manifest.json")
        elif not fixture.is_file():
            problems.append(f"{entry['directory']}: missing src/fixture.nr")
        else:
            record = json.loads(manifest_path.read_text())
            if record.get("schema") != FIXTURE_SCHEMA:
                problems.append(
                    f"{entry['directory']}: fixture schema is not {FIXTURE_SCHEMA}"
                )
            for key in ("scheme", "use_case", "kind", "generator", "key_provenance"):
                if key not in record:
                    problems.append(
                        f"{entry['directory']}: fixture manifest lacks {key}"
                    )
            if (
                record.get("scheme") != entry["scheme"]
                or record.get("use_case") != entry["use_case"]
            ):
                problems.append(
                    f"{entry['directory']}: fixture manifest names another instance"
                )
            if record.get("kind") not in {
                "synthetic",
                "public-test-vector",
                "recorded-live",
            }:
                problems.append(f"{entry['directory']}: unknown fixture kind")
            digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
            if record.get("outputs", {}).get("src/fixture.nr") != digest:
                problems.append(
                    f"{entry['directory']}: src/fixture.nr differs from its manifest; regenerate it"
                )
            for output, recorded_digest in sorted(record.get("outputs", {}).items()):
                # Other outputs, such as an adapter's test fixture, are paths
                # relative to the instance directory.
                if output == "src/fixture.nr":
                    continue
                other = (directory / output).resolve()
                if (
                    not other.is_file()
                    or hashlib.sha256(other.read_bytes()).hexdigest() != recorded_digest
                ):
                    problems.append(
                        f"{entry['directory']}: {output} differs from its manifest; regenerate it"
                    )
    known = {e["directory"] for e in rows}
    for use_case in manifest["use_cases"]:
        for nargo in sorted((root / use_case).glob("*/Nargo.toml")):
            name = nargo.parent.name
            if name != "common" and f"{use_case}/{name}" not in known:
                problems.append(f"{use_case}/{name}: instance not in use-cases.json")
    for nargo in sorted((root / "testing").glob("template_*/Nargo.toml")):
        if f"testing/{nargo.parent.name}" not in known:
            problems.append(
                f"testing/{nargo.parent.name}: template check not in use-cases.json"
            )
    return problems


def run(root, check):
    manifest = load(root)
    generated = outputs(root, manifest)
    drift = []
    for path, content in sorted(generated.items()):
        target = root / path
        if read(target) != content:
            drift.append(path)
            if not check:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content)
    problems = lint(root, manifest)
    return drift, problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--check", action="store_true", help="fail on drift; write nothing"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="print the packages (role, directory, package, use case)",
    )
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.list:
        try:
            root = args.root.resolve()
            rows = packages(root, load(root))
        except (ManifestError, KeyError) as error:
            print(f"use-cases.json: {error}", file=sys.stderr)
            return 2
        for role, directory, package, use_case in rows:
            print("\t".join([role, directory, package, use_case or "-"]))
        return 0
    try:
        drift, problems = run(args.root.resolve(), args.check)
    except RuntimeError as error:
        print(f"nargo fmt: {error}", file=sys.stderr)
        return 2
    except (ManifestError, KeyError) as error:
        print(f"use-cases.json: {error}", file=sys.stderr)
        return 2
    for path in drift:
        print(("drift: " if args.check else "wrote: ") + path)
    for problem in problems:
        print("lint: " + problem)
    print(
        json.dumps(
            {
                "check": args.check,
                "generated_files_differing": len(drift),
                "lint_problems": len(problems),
            }
        )
    )
    return 1 if (args.check and drift) or problems else 0


if __name__ == "__main__":
    sys.exit(main())
