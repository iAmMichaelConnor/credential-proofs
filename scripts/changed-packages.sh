#!/usr/bin/env bash
# Print what a pull request must test: the packages, host code and example contracts that the files changed
# since <base-ref> can affect, through the Nargo path dependencies, the generators and their inputs.
#
#   ./scripts/changed-packages.sh origin/main    # one key=JSON line per output, for $GITHUB_OUTPUT
#   ./scripts/changed-packages.sh --all          # the same outputs, everything selected (push to main)
#   ./scripts/changed-packages.sh --self-test    # check every rule below against this repository
#
# Outputs:
#   noir        noir/ workspace members to test (scripts/run-tests.sh, per-PR mode)
#   benchmarks  the members of `noir` with a src/benchmarks.nr
#   host        true when the host job (host packages, fixture manifests, World ID fixture checks and the
#               script unit tests) must run
#   examples    groups for the examples job: `check` (type-check of the packages in `aztec`), `world-id`,
#               `cores`, `adapters` and, per use case, the affected instances (aztec/use-cases/scripts/test-use-cases.sh
#               selectors), split into groups of at most 6
#   aztec       the aztec/ workspace packages to type-check (`aztec-nargo check --package`)
#
# The changed files are `git diff -z --no-renames --name-only <base-ref>...HEAD`: a rename is a deletion and an
# addition, and a deleted path is classified like any other. Each file takes the first rule that claims it:
#
#   1. scripts/world-id/, fixtures/world-id/: the World ID packages (noir/world_id_*, aztec/world-id-*) and
#      everything that depends on them.
#   2. scripts/fixtures/, fixtures/ (any file, LICENSE and *.md included): the noir/ members with files the
#      fixture generators write, without their dependents (a regenerated file is itself in the diff and selects
#      its dependents by rule 4), and the use-case instances whose fixtures/manifest.json lists the file.
#      The generated members are the known-answer test packages of scripts/fixtures/kat.py (KATS) and every
#      member that a generator source (scripts/fixtures outside tests/, and each script scripts/fixtures/generate.py
#      runs) names as noir/<member>.
#   3. packages/ (any file, LICENSE and *.md included): the generated noir/ members of rule 2 and every use-case
#      instance. The generators import the host packages, and a fixture manifest lists only a generator's direct
#      inputs, so no narrower set is safe.
#   4. A file in a Nargo package (noir/, vendor/ or aztec/ workspace member, `*_slow_tests` crates included;
#      *.md included): that package and every package that depends on it, transitively.
#   5. aztec/use-cases/use-cases.json: the instances whose entry changed or was added; any other change to the
#      file (or a file that cannot be read on either side) selects every instance, `cores` and `adapters`.
#   6. aztec/use-cases/scripts/templates/main/<template>.nr.tmpl: the instances and template checks of the use
#      cases generated from that template. Any other file there (a new include, a renamed template) selects
#      everything.
#   7. aztec/use-cases/scripts/fixtures/: the instances whose fixtures/manifest.json lists the file (a manifest
#      lists its generator's helper modules too); a file no manifest lists selects every instance.
#   8. aztec/use-cases/scripts/tests/, aztec/use-cases/scripts/check_fixtures.py and the *.md files of
#      aztec/use-cases outside a package (the README tables generate.py writes, ARCHITECTURE.md): the host job only.
#      `scripts/generate.py --check`, which checks the generated README tables, runs on every pull request.
#   9. Documentation: the top-level *.md files, LICENSE and NOTICE, and docs/. Selects nothing, not even the host
#      job.
#  10. Anything else selects everything: the rest of scripts/ (this script, run-tests.sh, the generators' entry
#      points), .github/, the workspace manifests (aztec/Nargo.toml, noir/Nargo.toml), the toolchain files
#      (aztec/.aztecrc, aztec/noirfmt.toml), the npm manifests and lockfiles and every file no rule claims.
#
# Every file except documentation (rule 9) also selects the host job. A test-use-cases.sh selector follows from
# each selected aztec/use-cases package: an instance selects itself, trust, a core (`*/common`),
# testing/core_tests or testing/family_oidc_tests selects `cores`, an adapter or the test adapter `adapters`, and
# testing/terms_shell, which every TXE test deploys, `cores` and every instance. An aztec/world-id-* package
# selects `world-id`. `check` type-checks every selected aztec/ package.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 - "$@" <<'PY'
import importlib.util
import json
import posixpath
import re
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath

sys.dont_write_bytecode = True  # kat.py and generate.py are imported only to read their tables
GROUP_SIZE = 6
USE_CASES = "aztec/use-cases/use-cases.json"
TEMPLATES = "aztec/use-cases/scripts/templates/main/"
KEYS = ("noir", "benchmarks", "host", "examples", "aztec")


def members(workspace):
    return tomllib.loads(Path(workspace, "Nargo.toml").read_text())["workspace"]["members"]


def nargo_dirs():
    """Every Nargo package of the repository: {directory: [path dependency directories]}."""
    dirs = [f"noir/{m}" for m in members("noir")] + [f"aztec/{m}" for m in members("aztec")]
    dirs += sorted(str(p.parent) for p in Path("vendor").glob("*/Nargo.toml"))
    graph = {}
    for d in dirs:
        deps = tomllib.loads(Path(d, "Nargo.toml").read_text()).get("dependencies", {})
        graph[d] = [posixpath.normpath(posixpath.join(d, v["path"])) for v in deps.values() if isinstance(v, dict) and "path" in v]
    return graph


def use_case_listing():
    """aztec/ package directory -> (role, selector, use case), from generate.py --list."""
    rows = subprocess.run(
        [sys.executable, "aztec/use-cases/scripts/generate.py", "--list"], capture_output=True, text=True, check=True
    ).stdout
    out = {}
    for line in rows.splitlines():
        role, directory, _package, use_case = line.split("\t")[:4]
        out[f"aztec/use-cases/{directory}"] = (role, directory, use_case)
    return out


def manifests():
    """Instance selector -> the repository files its fixture generators read."""
    out = {}
    for path in Path("aztec/use-cases").glob("*/*/fixtures/manifest.json"):
        record = json.loads(path.read_text())
        files = set(record.get("inputs", {}))
        argv = record.get("generator", {}).get("argv")
        if argv:
            files.add(f"aztec/use-cases/{argv[1]}")
        out[str(path.parent.parent.relative_to("aztec/use-cases"))] = files
    return out


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generated_noir_packages():
    """noir/ members with a file written by the scripts/fixtures generators (rule 2)."""
    names = set(members("noir"))
    out = {f"noir/{e['tests']}" for e in load_module("fixtures_kat", "scripts/fixtures/kat.py").KATS}
    steps = load_module("fixtures_generate", "scripts/fixtures/generate.py").STEPS
    sources = {p for p in Path("scripts/fixtures").rglob("*") if p.is_file() and "tests" not in p.parts}
    sources |= {Path(s[1]) for s in steps if len(s) > 1 and Path(s[1]).is_file()}
    for source in sources:
        if source.suffix in (".mjs", ".cjs", ".js", ".py", ".inc"):
            out |= {f"noir/{m}" for m in re.findall(r"\bnoir/([A-Za-z0-9_]+)", source.read_text()) if m in names}
    return out


def changed_instances(old, new):
    """Instances whose use-cases.json entry changed or was added, or None when anything else in the file
    changed or either side is missing or unreadable."""
    try:
        old, new = json.loads(old), json.loads(new)
        rest = lambda m: {k: v for k, v in m.items() if k != "instances"}
        if rest(old) != rest(new):
            return None
        key = lambda e: e.get("directory", f"{e['use_case']}/{e.get('scheme', 'template')}")
        before = {key(e): e for e in old["instances"]}
        return {key(e) for e in new["instances"] if before.get(key(e)) != e}
    except (TypeError, ValueError, KeyError, AttributeError):
        return None


CONTEXT = {}


def context():
    if not CONTEXT:
        CONTEXT.update(graph=nargo_dirs(), listing=use_case_listing(), inputs=manifests())
        CONTEXT["generated"] = generated_noir_packages()
        CONTEXT["spec"] = json.loads(Path(USE_CASES).read_text())["use_cases"]
    return CONTEXT


def is_documentation(f):
    return ("/" not in f and (f.endswith(".md") or f in ("LICENSE", "NOTICE"))) or f.startswith("docs/")


def select(files, use_cases=None, everything=False):
    """The outputs for the changed `files`; `use_cases` is (base text, head text) of use-cases.json."""
    ctx = context()
    graph, listing, instance_inputs, spec = ctx["graph"], ctx["listing"], ctx["inputs"], ctx["spec"]
    instances = {d for role, d, _ in listing.values() if role == "instance"}
    world_id = {d for d in graph if d.startswith(("noir/world_id_", "aztec/world-id-"))}

    dirty = set()  # Nargo package directories selected with their dependents
    direct = set()  # noir/ packages selected without their dependents (their generated files)
    host = False
    picked = set()  # use-case selectors picked by a rule other than the dependency graph
    checked = set()  # aztec/ packages to type-check besides the affected ones

    def owner(f):
        best = None
        for d in graph:
            if f.startswith(d + "/") and (best is None or len(d) > len(best)):
                best = d
        return best

    def listing_users(f):
        return {i for i, inputs in instance_inputs.items() if f in inputs}

    for f in files:
        if not is_documentation(f):
            host = True
        if f.startswith(("scripts/world-id/", "fixtures/world-id/")):
            dirty |= world_id
        elif f.startswith(("scripts/fixtures/", "fixtures/")):
            direct |= ctx["generated"]
            picked |= listing_users(f)
        elif f.startswith("packages/"):
            direct |= ctx["generated"]
            picked |= instances
        elif owner(f):
            dirty.add(owner(f))
        elif f == USE_CASES:
            changed = changed_instances(*use_cases) if use_cases else None
            picked |= (instances | {"cores", "adapters"}) if changed is None else changed & instances
        elif f.startswith(TEMPLATES):
            name = f.removeprefix(TEMPLATES)
            users = {u for u, s in spec.items() if f"{s['template']}.nr.tmpl" == name}
            if not users:
                everything = True
            for d, (role, directory, use_case) in listing.items():
                if use_case in users and role == "instance":
                    picked.add(directory)
                elif use_case in users and role == "template":
                    checked.add(d)
        elif f.startswith("aztec/use-cases/scripts/fixtures/"):
            picked |= listing_users(f) or instances
        elif f.startswith("aztec/use-cases/scripts/tests/") or f == "aztec/use-cases/scripts/check_fixtures.py":
            pass
        elif f.startswith("aztec/use-cases/") and f.endswith(".md"):
            pass
        elif is_documentation(f):
            pass
        else:
            everything = True

    if everything:
        dirty = set(graph)
        host = True
        picked |= instances | {"cores", "adapters"}

    # Every package that depends, transitively, on a changed one.
    affected = set(dirty)
    grew = True
    while grew:
        grew = False
        for d, deps in graph.items():
            if d not in affected and affected.intersection(deps):
                affected.add(d)
                grew = True

    # A change to the shell selects every test that deploys it.
    if "aztec/use-cases/testing/terms_shell" in affected:
        picked |= instances | {"cores"}

    noir = sorted(d.removeprefix("noir/") for d in affected | direct if d.startswith("noir/"))
    selectors = set(picked)
    checked |= {d for d in affected if d.startswith("aztec/")}
    checked |= {f"aztec/use-cases/{s}" for s in picked if "/" in s}
    for d in affected:
        if d.startswith("aztec/world-id-"):
            selectors.add("world-id")
            continue
        role, directory, _ = listing.get(d, ("", "", ""))
        if role == "instance":
            selectors.add(directory)
        elif role == "base" or directory in ("testing/core_tests", "testing/family_oidc_tests"):
            selectors.add("cores")
        elif role in ("adapter", "test_adapter"):
            selectors.add("adapters")

    examples = []
    if checked:
        examples.append("check")
    examples += [s for s in ("world-id", "cores", "adapters") if s in selectors]
    for use_case in spec:
        group = sorted(s for s in selectors if s.startswith(use_case + "/"))
        for i in range(0, len(group), GROUP_SIZE):
            examples.append(" ".join(group[i : i + GROUP_SIZE]))
    return {
        "noir": noir,
        "benchmarks": [p for p in noir if Path(f"noir/{p}/src/benchmarks.nr").is_file()],
        "host": host,
        "examples": examples,
        "aztec": sorted(tomllib.loads(Path(d, "Nargo.toml").read_text())["package"]["name"] for d in checked),
    }


def select_all():
    return select([], everything=True)


def parse_names(raw):
    """The paths of `git diff -z --name-only` output."""
    return [name for name in raw.decode("utf-8", "surrogateescape").split("\0") if name]


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, check=True).stdout


def diff(base):
    """The changed files since the merge base of `base` and HEAD, and use-cases.json on both sides."""
    files = parse_names(git("diff", "-z", "--no-renames", "--name-only", f"{base}...HEAD"))
    if USE_CASES not in files:
        return files, None
    merge_base = git("merge-base", base, "HEAD").decode().strip()

    def show(rev):
        try:
            return git("show", f"{rev}:{USE_CASES}").decode()
        except subprocess.CalledProcessError:
            return None

    return files, (show(merge_base), show("HEAD"))


def self_test():
    """Each case checks one rule through relations to independent sources: the workspace manifests, the
    Nargo.toml dependencies, generate.py --list, the fixture manifests and scripts/fixtures/kat.py."""
    ctx = context()
    graph = ctx["graph"]
    rows = [
        line.split("\t")
        for line in subprocess.run(
            [sys.executable, "aztec/use-cases/scripts/generate.py", "--list"], capture_output=True, text=True, check=True
        ).stdout.splitlines()
    ]
    instances = {r[1] for r in rows if r[0] == "instance"}
    noir_members = set(members("noir"))
    aztec_members = members("aztec")
    package = lambda d: tomllib.loads(Path(d, "Nargo.toml").read_text())["package"]["name"]
    uc_json = Path(USE_CASES).read_text()
    uc = json.loads(uc_json)
    listed = {}
    for path in Path("aztec/use-cases").glob("*/*/fixtures/manifest.json"):
        for f in json.loads(path.read_text()).get("inputs", {}):
            listed.setdefault(f, set()).add(str(path.parent.parent.relative_to("aztec/use-cases")))
    kats = {f"noir/{e['tests']}" for e in load_module("fixtures_kat_test", "scripts/fixtures/kat.py").KATS}
    s4 = {"noir/rsa_signature", "noir/university_auth", "noir/anon_aadhaar_v2_auth"}
    nothing = {"noir": [], "benchmarks": [], "host": False, "examples": [], "aztec": []}
    every = select_all()

    reverse = {}
    for d, deps in graph.items():
        for dep in deps:
            reverse.setdefault(dep, set()).add(d)

    def dependents(roots):
        seen, stack = set(), list(roots)
        while stack:
            d = stack.pop()
            if d not in seen:
                seen.add(d)
                stack += reverse.get(d, ())
        return seen

    def sel(r):
        return {s for group in r["examples"] for s in group.split()}

    failures = []
    count = 0

    def case(name, files, *checks, use_cases=None):
        nonlocal count
        count += 1
        got = select(files, use_cases)
        for label, ok in checks:
            if not ok(got):
                failures.append(f"FAIL {name}: {label}\n  got {json.dumps(got)}")

    is_every = ("selects everything", lambda r: r == every)
    is_nothing = ("selects nothing", lambda r: r == nothing)
    host_only = ("selects the host job only", lambda r: r == dict(nothing, host=True))
    host = ("selects the host job", lambda r: r["host"] is True)
    no_noir = ("selects no noir/ package", lambda r: r["noir"] == [])
    no_cores = ("does not select cores", lambda r: "cores" not in sel(r))
    all_instances = ("selects every instance", lambda r: instances <= sel(r))

    def graph_rule(root):
        """The package and its dependents, mapped to each output; no instance outside them."""
        down = dependents([root])
        return (
            ("noir = the dependents of " + root, lambda r: set(r["noir"]) == {d[5:] for d in down if d.startswith("noir/")}),
            ("aztec = the aztec/ dependents", lambda r: set(r["aztec"]) == {package(d) for d in down if d.startswith("aztec/")}),
            ("instances = the dependent instances", lambda r: sel(r) & instances == {d[16:] for d in down} & instances),
            host,
        )

    generated_noir = (
        "noir contains every known-answer and generated package",
        lambda r: (kats | s4) <= {f"noir/{p}" for p in r["noir"]} and set(r["noir"]) != noir_members,
    )

    # Rule 10: each select-everything file class.
    for f in ("aztec/Nargo.toml", "noir/Nargo.toml", "aztec/.aztecrc", "aztec/noirfmt.toml", "package-lock.json",
              "aztec/use-cases/package-lock.json", "package.json", "scripts/run-tests.sh", "scripts/changed-packages.sh",
              "scripts/generate.py", ".github/workflows/test.yml", "unclaimed.txt"):
        case(f"select everything: {f}", [f], is_every)

    # Rule 4: the dependency graph.
    for root in ("noir/kakao", "noir/oidc", "vendor/noir-ed25519", "aztec/use-cases/login-link/google"):
        case(f"package {root}", [f"{root}/src/lib.nr"], *graph_rule(root))
    case("core (*/common)", ["aztec/use-cases/login-link/common/src/lib.nr"],
         ("selects cores", lambda r: "cores" in sel(r)), *graph_rule("aztec/use-cases/login-link/common"))
    case("testing/core_tests", ["aztec/use-cases/testing/core_tests/src/lib.nr"],
         ("selects cores", lambda r: "cores" in sel(r)))
    case("uc_terms_shell", ["aztec/use-cases/testing/terms_shell/src/main.nr"],
         all_instances, ("selects cores", lambda r: "cores" in sel(r)))
    case("test_adapter", ["aztec/use-cases/testing/test_adapter/src/lib.nr"],
         ("selects adapters", lambda r: "adapters" in sel(r)), *graph_rule("aztec/use-cases/testing/test_adapter"))
    case("Markdown in a package", ["noir/kakao/README.md"], *graph_rule("noir/kakao"))

    # Rule 1: World ID.
    world_id = {d for d in graph if d.startswith(("noir/world_id_", "aztec/world-id-"))}
    world_id_checks = (
        ("selects world-id", lambda r: "world-id" in sel(r)),
        ("noir and aztec contain every World ID package and dependent",
         lambda r: {d[5:] for d in dependents(world_id) if d.startswith("noir/")} <= set(r["noir"])
         and {package(d) for d in dependents(world_id) if d.startswith("aztec/")} <= set(r["aztec"])),
        host,
    )
    case("fixtures/world-id", ["fixtures/world-id/provenance.json"], *world_id_checks)
    case("fixtures/world-id LICENSE", ["fixtures/world-id/upstream/world-id-contracts/LICENSE"], *world_id_checks)
    case("scripts/world-id", ["scripts/world-id/world_id4_foundation.mjs"], *world_id_checks)

    # Rule 2: Noir fixture generators and inputs.
    pem = "fixtures/data/synthetic-rs256-private.pem"
    case("fixtures/ file listed in a manifest", [pem], generated_noir, host, no_cores,
         ("instances = those whose manifest lists it", lambda r: sel(r) & instances == listed[pem]))
    case("fixture generator", ["scripts/fixtures/generate-govbr.mjs"], generated_noir, host,
         ("no instance", lambda r: not sel(r) & instances))
    case("shared Noir generator helper", ["scripts/fixtures/lib/x509_fixture.py"], generated_noir, host)
    case("Markdown under fixtures/", ["fixtures/material/README.md"], generated_noir, host)
    case("LICENSE under fixtures/", ["fixtures/anon-aadhaar/LICENSE"], generated_noir, host)
    for path in ("noir/rsa_signature/src/api_tests.nr", "noir/university_auth/src/fixture.nr",
                 "noir/anon_aadhaar_v2_auth/src/lib.nr"):
        case(f"generated file {path}", ["fixtures/data/x"],
             (f"{path} is a generated package", lambda r, p=path: p.rsplit("/src/", 1)[0] in ctx["generated"]))
    headed = {str(p).split("/src/")[0] for m in noir_members for p in Path("noir", m).rglob("*.nr")
              if re.search(r"Generated (by|synthetic)", "".join(p.open().readlines()[:3]))}
    case("files with a generated header", ["fixtures/data/x"],
         ("each is in a generated package", lambda r: headed <= ctx["generated"]))

    # Rule 3: host packages.
    jws = "packages/credential-proofs-inputs/src/jws.ts"
    case("packages/ file in no manifest", [jws], ("the file is in no manifest", lambda r: jws not in listed),
         all_instances, generated_noir, host)
    case("LICENSE under packages/", ["packages/credential-proofs-world-id/LICENSE"], all_instances, host)
    case("Markdown under packages/", ["packages/credential-proofs-world-id/README.md"], all_instances, host)

    # Rule 5: use-cases.json.
    one = json.loads(uc_json)
    entry = next(e for e in one["instances"] if f"{e['use_case']}/{e.get('scheme')}" == "login-link/google")
    entry["notes"] = entry.get("notes", []) + ["changed"]
    case("use-cases.json instance entry", [USE_CASES],
         ("selects that instance only", lambda r: sel(r) == {"check", "login-link/google"}),
         ("aztec = that instance", lambda r: r["aztec"] == [package("aztec/use-cases/login-link/google")]),
         no_noir, use_cases=(uc_json, json.dumps(one)))
    other = json.loads(uc_json)
    other["use_cases"]["login-link"]["title"] += " changed"
    case("use-cases.json other key", [USE_CASES], all_instances,
         ("selects cores and adapters", lambda r: {"cores", "adapters"} <= sel(r)), use_cases=(uc_json, json.dumps(other)))
    case("use-cases.json deleted", [USE_CASES], all_instances, use_cases=(uc_json, None))

    # Rule 6: templates.
    login = {u for u, s in uc["use_cases"].items() if s["template"] == "login-link"}
    case("known template", [TEMPLATES + "login-link.nr.tmpl"], no_noir, no_cores,
         ("instances = those of its use cases", lambda r: sel(r) & instances == {i for i in instances if i.split("/")[0] in login}),
         ("aztec contains its template checks",
          lambda r: {r_[2] for r_ in rows if r_[0] == "template" and r_[3] in login} <= set(r["aztec"])))
    case("renamed template", [TEMPLATES + "login-link.nr.tmpl", TEMPLATES + "login_link_v2.nr.tmpl"], is_every)
    case("new template include", [TEMPLATES + "shared.nr.inc"], is_every)

    # Rule 7: use-case fixture generators.
    oidc = "aztec/use-cases/scripts/fixtures/generators/oidc.mjs"
    case("listed use-case generator", [oidc], no_noir,
         ("instances = those whose manifest lists it", lambda r: sel(r) & instances == listed[oidc]))
    case("shared use-case generator helper", ["aztec/use-cases/scripts/fixtures/generators/nr_format.mjs"],
         ("the file is in no manifest", lambda r: "aztec/use-cases/scripts/fixtures/generators/nr_format.mjs" not in listed),
         all_instances, no_noir)

    # Rule 8: host only.
    for f in ("aztec/use-cases/scripts/tests/test_generate.py", "aztec/use-cases/scripts/check_fixtures.py",
              "aztec/use-cases/login-link/README.md", "aztec/use-cases/ARCHITECTURE.md"):
        case(f"host only: {f}", [f], host_only)

    # Rule 9: documentation.
    case("root README.md", ["README.md"], is_nothing)
    case("documentation", ["CHANGELOG.md", "LICENSE", "NOTICE", "docs/SECURITY.md"], is_nothing)

    # Deleted paths and the diff format.
    gone = "noir/kakao/src/deleted_module.nr"
    case("deleted path", [gone], ("the path does not exist", lambda r: not Path(gone).exists()), *graph_rule("noir/kakao"))
    names = parse_names(b"noir/kakao/src/a b.nr\0README.md\0")
    case("path with a space", names, ("is read whole", lambda r: names == ["noir/kakao/src/a b.nr", "README.md"]),
         *graph_rule("noir/kakao"))

    # --all against independent sources.
    count += 1
    groups = [g.split() for g in every["examples"] if "/" in g]
    for label, ok in (
        ("keys", list(every) == list(KEYS)),
        ("noir = noir/Nargo.toml members", every["noir"] == sorted(noir_members)),
        ("benchmarks = members with src/benchmarks.nr",
         every["benchmarks"] == sorted(m for m in noir_members if Path(f"noir/{m}/src/benchmarks.nr").is_file())),
        ("host", every["host"] is True),
        ("aztec = aztec/Nargo.toml members", every["aztec"] == sorted(package(f"aztec/{m}") for m in aztec_members)),
        ("examples = check, world-id, cores, adapters, then every generate.py --list instance",
         every["examples"][:4] == ["check", "world-id", "cores", "adapters"] and sel(every) - {"check", "world-id", "cores", "adapters"} == instances),
        ("groups of at most 6, one use case each",
         all(len(g) <= GROUP_SIZE and len({s.split("/")[0] for s in g}) == 1 for g in groups)),
    ):
        if not ok:
            failures.append(f"FAIL --all: {label}\n  got {json.dumps(every)}")
    print("\n".join(failures + [f"{count} cases, {len(failures)} failures"]))
    return 1 if failures else 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    if len(argv) != 1 or argv[0].startswith("-") and argv[0] != "--all":
        print("usage: scripts/changed-packages.sh <base-ref> | --all | --self-test", file=sys.stderr)
        return 2
    if argv == ["--all"]:
        result = select_all()
    else:
        try:
            files, use_cases = diff(argv[0])
        except subprocess.CalledProcessError as error:
            print(f"{' '.join(error.cmd)}: {error.stderr.decode().strip()}", file=sys.stderr)
            return 2
        result = select(files, use_cases)
    for key, value in result.items():
        print(f"{key}={json.dumps(value, separators=(',', ':'))}")
    return 0


sys.exit(main(sys.argv[1:]))
PY
