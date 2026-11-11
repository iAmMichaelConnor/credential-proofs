"""Golden, drift and lint tests of scripts/generate.py.

The golden input (golden/input, files end in `.in`) is a small project with
one instance per contract template and variant: an in-crate account input
with the OIDC wrapper, a provider login link, a bearer login link, a gate, a
uniqueness instance with a free choice, a settlement, an event and a
template check. The expected output (golden/expected, files end in
`.golden`) is committed. Set UC_UPDATE_GOLDEN=1 to rewrite it after an
intended template change, and review the diff.

The golden input is hand-written on purpose. It is a scenario of this test, not a
circuit fixture: it must not follow use-cases.json, so that a change to the real
instances never moves the expected output. It holds instances that the real project
does not have (the anon_aadhaar rows), and no script derives it.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[2] / "scripts"
PROJECT = TOOLS.parent
GOLDEN = Path(__file__).resolve().parent / "golden"
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(PROJECT / "scripts/fixtures/generators"))

import generate  # noqa: E402
import nr_format  # noqa: E402


def project_copy(directory):
    """The golden input as a project tree, with the real templates."""
    root = Path(directory) / "aztec" / "use-cases"
    for source in sorted((GOLDEN / "input").rglob("*.in")):
        target = root / source.relative_to(GOLDEN / "input").with_suffix("")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    # The Aztec workspace manifest sits above the project, under the
    # repository root.
    for source in sorted((GOLDEN / "input_repository").rglob("*.in")):
        target = root.parents[1] / source.relative_to(
            GOLDEN / "input_repository"
        ).with_suffix("")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    shutil.copytree(TOOLS / "templates", root / "scripts/templates")
    return root


def golden_name(path):
    """A golden file name for a generated path; `../Nargo.toml` (the Aztec
    workspace) is kept inside the golden directory as `_workspace/Nargo.toml`."""
    return path.replace("../", "_workspace/")


class GoldenOutput(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = project_copy(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_generated_output_equals_committed_golden_files(self):
        generated = generate.outputs(self.root)
        lint = generate.lint(self.root)
        expected_dir = GOLDEN / "expected"
        if os.environ.get("UC_UPDATE_GOLDEN") == "1":
            shutil.rmtree(expected_dir, ignore_errors=True)
            for path, content in generated.items():
                target = expected_dir / (golden_name(path) + ".golden")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content)
            (expected_dir / "lint.txt.golden").write_text("\n".join(lint) + "\n")
        expected = {
            str(p.relative_to(expected_dir))[: -len(".golden")]: p.read_text()
            for p in expected_dir.rglob("*.golden")
        }
        expected_lint = expected.pop("lint.txt").splitlines()
        generated = {golden_name(p): c for p, c in generated.items()}
        self.assertEqual(sorted(generated), sorted(expected))
        for path, content in generated.items():
            self.assertEqual(content, expected[path], path)
        self.assertEqual(lint, expected_lint)

    def test_top_index_links_category_tables_and_counts_instances(self):
        generated = generate.outputs(self.root)["README.md"]
        self.assertIn("[login-link](login-link/README.md) | 2 |", generated)
        self.assertIn("The account owner approved this exact payload.", generated)
        self.assertIn("explicitly accepted bearer evidence", generated)
        self.assertNotIn("Whoever controls this external identity", generated)
        self.assertNotIn("| Scheme | Category |", generated)
        self.assertNotIn("design section", generated)

    def test_table_links_contract_sources_and_shows_notes(self):
        generated = generate.outputs(self.root)
        self.assertNotIn("login-link/google/README.md", generated)
        table = generated["login-link/README.md"]
        self.assertIn("| [google](google/src/main.nr) |", table)
        self.assertIn("| [linkedin](linkedin/src/main.nr) |", table)
        self.assertIn("entrypoint `link(terms, evidence)`", table)
        self.assertIn("has the tests `valid`, `replay_rejected`,", table)
        # google has no notes; linkedin's are joined, with the pipe escaped.
        self.assertIn("via `OidcLink` | - |", table)
        self.assertIn(
            "(`ALSO_IDP \\| ALSO_COPY_HOLDER`) until the bearer ceiling or the "
            "token's expiry. `sub` is treated as pairwise. |",
            table,
        )
        gate = generated["attribute-gating/README.md"]
        self.assertIn("(govbr: `act(terms, evidence, choice)`)", gate)

    def test_notes_head_the_contract_source(self):
        generated = generate.outputs(self.root)
        main = generated["login-link/linkedin/src/main.nr"]
        self.assertIn(
            "//! HAND-WRITTEN regions.\n//!\n"
            "//! Residual risk and notes (see also login-link/README.md):\n"
            "//! - Bearer: any holder of a copy of the token can link the subject",
            main,
        )
        self.assertIn(
            "//! - `sub` is treated as pairwise.\nuse aztec::macros::aztec;", main
        )
        self.assertTrue(all(len(line) <= generate.MAX_WIDTH for line in main.splitlines()))
        google = generated["login-link/google/src/main.nr"]
        self.assertIn("//! HAND-WRITTEN regions.\nuse aztec::macros::aztec;", google)

    def test_notes_must_be_one_line_strings(self):
        for notes in ("one string", ["two\nlines"], [""]):
            with self.subTest(notes=notes):
                manifest = generate.load(self.root)
                manifest["instances"][1]["notes"] = notes
                with self.assertRaisesRegex(generate.ManifestError, "notes"):
                    generate.entries(manifest)

    def test_check_mode_after_generation_has_no_drift(self):
        drift, _ = generate.run(self.root, check=False)
        self.assertTrue(drift)
        drift, _ = generate.run(self.root, check=True)
        self.assertEqual(drift, [])

    def test_check_mode_writes_nothing_and_reports_drift(self):
        before = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        drift, _ = generate.run(self.root, check=True)
        after = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertIn("login-link/google/src/main.nr", drift)
        self.assertIn("../Nargo.toml", drift)

    def test_edit_of_a_generated_part_is_drift(self):
        generate.run(self.root, check=False)
        for path, edit in [
            (
                "login-link/google/Nargo.toml",
                lambda t: t.replace("uc_family_oidc", "oidc_family"),
            ),
            (
                "login-link/google/src/main.nr",
                lambda t: t.replace("OidcLink {", "OidcAccount {"),
            ),
            (
                "payment-settlement/README.md",
                lambda t: t.replace("wechatpay", "alipay"),
            ),
            ("../Nargo.toml", lambda t: t.replace('"use-cases/trust"', '"use-cases/x"')),
        ]:
            target = self.root / path
            original = target.read_text()
            target.write_text(edit(original))
            drift, _ = generate.run(self.root, check=True)
            self.assertEqual(drift, [path], path)
            target.write_text(original)

    def test_hand_written_parts_are_kept(self):
        generate.run(self.root, check=False)
        main = self.root / "login-link/google/src/main.nr"
        self.assertIn("global KEPT: Field = 1;", main.read_text())
        self.assertIn("let _ = KEPT;", main.read_text())
        main.write_text(main.read_text().replace("let _ = KEPT;", "let _ = KEPT + 1;"))
        top = self.root / "README.md"
        self.assertIn("Text after the grid stays.", top.read_text())
        drift, _ = generate.run(self.root, check=True)
        self.assertEqual(drift, [])
        generate.run(self.root, check=False)
        self.assertIn("let _ = KEPT + 1;", main.read_text())

    def test_workspace_block_lists_every_package_and_keeps_the_rest(self):
        text = generate.outputs(self.root)["../Nargo.toml"]
        self.assertTrue(text.startswith('[workspace]\nmembers = [\n    # Other packages\n    "other/contract",\n    # Use cases\n    "use-cases/trust",\n'))
        self.assertNotIn("use-cases/stale", text)
        self.assertTrue(text.endswith('    "use-cases/uniqueness/anon_aadhaar",\n]\n'))
        members = [line.strip()[1:-2] for line in text.splitlines() if line.startswith('    "use-cases/')]
        self.assertEqual(
            members[:4],
            ["use-cases/trust", "use-cases/account-authorisation/common", "use-cases/testing/terms_shell", "use-cases/adapters/anon_aadhaar"],
        )
        self.assertIn("use-cases/testing/template_attribute_gate", members)
        self.assertIn("use-cases/event-proof/reclaim", members)
        self.assertEqual(len(members), len(set(members)))

    def test_workspace_needs_the_marker(self):
        path = self.root.parent / "Nargo.toml"
        path.write_text("[workspace]\nmembers = [\n]\n")
        with self.assertRaisesRegex(generate.ManifestError, "needs one '# Use cases' line"):
            generate.outputs(self.root)
        path.unlink()
        with self.assertRaisesRegex(generate.ManifestError, "Missing ../Nargo.toml"):
            generate.outputs(self.root)

    def test_list_carries_roles_and_use_cases(self):
        rows = {row[1]: row for row in generate.packages(self.root, generate.load(self.root))}
        self.assertEqual(rows["trust"][:4], ("base", "trust", "uc_trust", ""))
        self.assertEqual(rows["account-authorisation/common"][3], "account-authorisation")
        self.assertEqual(rows["testing/terms_shell"][0], "testing")
        self.assertEqual(rows["adapters/oidc"][:3], ("adapter", "adapters/oidc", "uc_family_oidc"))
        self.assertEqual(
            rows["account-authorisation/google"],
            ("instance", "account-authorisation/google", "google_auth_account", "account-authorisation"),
        )
        self.assertEqual(rows["login-link/google"][3], "login-link")
        self.assertEqual(rows["testing/template_attribute_gate"][0], "template")

    def test_list_prints_tab_separated_rows(self):
        with tempfile.TemporaryFile("w+") as out:
            stdout, sys.stdout = sys.stdout, out
            try:
                self.assertEqual(generate.main(["--list", "--root", str(self.root)]), 0)
            finally:
                sys.stdout = stdout
            out.seek(0)
            lines = out.read().splitlines()
        self.assertIn("base\ttrust\tuc_trust\t-", lines)
        self.assertIn("instance\tlogin-link/google\tgoogle_login_link\tlogin-link", lines)

    def test_dependencies_resolve_from_the_repository_or_the_project(self):
        out = generate.outputs(self.root)
        toml = out["account-authorisation/google/Nargo.toml"]
        self.assertIn(
            'aztec = { git = "https://github.com/aztec-labs-eng/aztec-nr", tag = "v6.0.0", directory = "aztec" }',
            toml,
        )
        self.assertIn('oidc = { path = "../../../../noir/oidc" }', toml)
        self.assertIn('uc_account = { path = "../common" }', toml)


class Lint(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = project_copy(self.temp.name)
        generate.run(self.root, check=False)

    def tearDown(self):
        self.temp.cleanup()

    def problems(self):
        return [
            p for p in generate.lint(self.root) if p.startswith("login-link/google")
        ]

    def complete_google(self):
        directory = self.root / "login-link/google"
        names = generate.required_tests(
            generate.load(self.root),
            next(
                e
                for e in generate.entries(generate.load(self.root))
                if e["directory"] == "login-link/google"
            ),
        )
        (directory / "src/test.nr").write_text(
            "".join(
                (
                    f'#[test(should_fail_with = "{n}")]\n'
                    if n.endswith("_rejected")
                    else "#[test]\n"
                )
                + f"unconstrained fn {n}() {{\n    run();\n}}\n\n"
                for n in names
            )
        )
        fixture = "pub global X: Field = 1;\n"
        (directory / "src/fixture.nr").write_text(fixture)
        (directory / "fixtures").mkdir(exist_ok=True)
        record = {
            "schema": "uc-fixture-v1",
            "scheme": "google",
            "use_case": "login-link",
            "kind": "synthetic",
            "generator": {"argv": ["true"]},
            "key_provenance": "test",
            "outputs": {
                "src/fixture.nr": __import__("hashlib")
                .sha256(fixture.encode())
                .hexdigest()
            },
        }
        (directory / "fixtures/manifest.json").write_text(json.dumps(record))
        return directory, record

    def test_complete_instance_has_no_problem(self):
        self.complete_google()
        self.assertEqual(self.problems(), [])

    def test_missing_required_test_is_reported(self):
        directory, _ = self.complete_google()
        test = directory / "src/test.nr"
        test.write_text(
            test.read_text().replace("fn stale_rejected", "fn stale_rejected_later")
        )
        self.assertEqual(
            self.problems(), ["login-link/google: missing required test stale_rejected"]
        )

    def edit_test(self, old, new):
        directory, _ = self.complete_google()
        test = directory / "src/test.nr"
        text = test.read_text()
        self.assertIn(old, text)
        test.write_text(text.replace(old, new, 1))

    def test_rejected_test_needs_a_named_failure(self):
        for attribute in [
            "#[test(should_fail)]",
            '#[test(should_fail_with = "")]',
            "#[test]",
        ]:
            with self.subTest(attribute=attribute):
                self.edit_test(
                    '#[test(should_fail_with = "stale_rejected")]', attribute
                )
                self.assertEqual(
                    self.problems(),
                    [
                        "login-link/google: required test stale_rejected needs "
                        '#[test(should_fail_with = "<message>")]'
                    ],
                )

    def test_valid_test_must_not_expect_a_failure(self):
        self.edit_test(
            "#[test]\nunconstrained fn valid",
            '#[test(should_fail_with = "x")]\nunconstrained fn valid',
        )
        self.assertEqual(
            self.problems(),
            ["login-link/google: required test valid must not expect a failure"],
        )

    def test_empty_or_constant_false_test_body_is_reported(self):
        self.edit_test("fn valid() {\n    run();\n}", "fn valid() {\n    // run();\n}")
        self.assertEqual(
            self.problems(), ["login-link/google: required test valid calls nothing"]
        )
        self.edit_test(
            "fn replay_rejected() {\n    run();\n}",
            'fn replay_rejected() {\n    run();\n    assert(false, "replay_rejected");\n}',
        )
        self.assertEqual(
            self.problems(),
            ["login-link/google: required test replay_rejected asserts false"],
        )

    def test_assertions_and_block_comments_are_not_calls(self):
        for body in [
            "assert(true);",
            "let _ = 1; /* run(); */",
            "assert_eq(1, 1);",
            "if (true) {}",
        ]:
            with self.subTest(body=body):
                self.edit_test(
                    "fn valid() {\n    run();\n}", f"fn valid() {{\n    {body}\n}}"
                )
                self.assertEqual(
                    self.problems(),
                    ["login-link/google: required test valid calls nothing"],
                )

    def add_test(self, text):
        directory, _ = self.complete_google()
        test = directory / "src/test.nr"
        test.write_text(test.read_text() + text)

    def test_extra_rejected_test_follows_the_required_rule(self):
        # A rejected test beyond the required ones needs a named
        # failure too, constrained or unconstrained.
        for head in ["unconstrained fn", "fn"]:
            for attribute in ["#[test(should_fail)]", "#[test]"]:
                with self.subTest(head=head, attribute=attribute):
                    self.add_test(
                        f"{attribute}\n{head} extra_rejected() {{\n    run();\n}}\n"
                    )
                    self.assertEqual(
                        self.problems(),
                        [
                            "login-link/google: test extra_rejected needs "
                            '#[test(should_fail_with = "<message>")]'
                        ],
                    )
        self.add_test(
            '#[test(should_fail_with = "x")]\nfn extra_rejected() {\n    run();\n}\n'
        )
        self.assertEqual(self.problems(), [])

    def test_other_test_expecting_a_failure_names_it(self):
        self.add_test(
            '#[test(should_fail_with = "Refused")]\nunconstrained fn refused_when_x() {\n    run();\n}\n'
        )
        self.assertEqual(self.problems(), [])
        self.add_test(
            "#[test(should_fail)]\nunconstrained fn refused_when_x() {\n    run();\n}\n"
        )
        self.assertEqual(
            self.problems(),
            [
                "login-link/google: test refused_when_x needs a named failure"
            ],
        )

    def test_path_qualified_and_aliased_entry_attributes_are_reported(self):
        self.complete_google()
        main = self.root / "login-link/google/src/main.nr"
        text = main.read_text()
        for item in [
            '#[functions::external("public")]\n    fn bypass() {}',
            '#[macros::functions::external("public")]\n    fn bypass() {}',
            "use aztec::macros::functions as f;",
            "use aztec::macros as m;",
        ]:
            with self.subTest(item=item):
                main.write_text(
                    text.replace(
                        "    // BEGIN HAND-WRITTEN items\n",
                        f"    // BEGIN HAND-WRITTEN items\n    {item}\n",
                        1,
                    )
                )
                problems = self.problems()
                self.assertEqual(len(problems), 1, problems)
                self.assertIn(
                    "function; the generated entrypoint is the only one", problems[0]
                )

    def test_shadowing_a_generated_name_is_reported(self):
        self.complete_google()
        main = self.root / "login-link/google/src/main.nr"
        text = main.read_text()
        for item, name in [
            ("mod uc_login_link {}", "uc_login_link"),
            ("use crate::x as OidcLink;", "OidcLink"),
            ("struct LinkTerms {}", "LinkTerms"),
            ("type uc_login_link = Evil;", "uc_login_link"),
        ]:
            with self.subTest(item=item):
                main.write_text(
                    text.replace(
                        "    // BEGIN HAND-WRITTEN items\n",
                        f"    // BEGIN HAND-WRITTEN items\n    {item}\n",
                        1,
                    )
                )
                self.assertEqual(
                    self.problems(),
                    [
                        f"login-link/google: HAND-WRITTEN items shadows {name}, "
                        "which the generated code uses"
                    ],
                )

    def test_extra_entrypoint_in_a_hand_written_region_is_reported(self):
        self.complete_google()
        main = self.root / "login-link/google/src/main.nr"
        text = main.read_text()
        bypass = (
            "    // BEGIN HAND-WRITTEN items\n"
            '    // A #[external("private")] in a comment is fine.\n'
            '    #[external("public")]\n'
            "    fn bypass() {}\n"
        )
        main.write_text(text.replace("    // BEGIN HAND-WRITTEN items\n", bypass, 1))
        self.assertEqual(
            self.problems(),
            [
                "login-link/google: HAND-WRITTEN items adds a #[external] function; "
                "the generated entrypoint is the only one"
            ],
        )
        main.write_text(
            text.replace(
                "    // BEGIN HAND-WRITTEN items\n",
                "    // BEGIN HAND-WRITTEN items\n"
                "    use aztec::macros::functions::external as entry;\n",
                1,
            )
        )
        self.assertEqual(
            self.problems(),
            [
                "login-link/google: HAND-WRITTEN items adds a #[external] function; "
                "the generated entrypoint is the only one"
            ],
        )
        main.write_text(
            text.replace(
                "    // BEGIN HAND-WRITTEN items\n",
                '    // BEGIN HAND-WRITTEN items\n    // #[external("private")] mention\n',
                1,
            )
        )
        self.assertEqual(self.problems(), [])

    def test_skipped_test_is_not_required(self):
        problems = [
            p for p in generate.lint(self.root) if p.startswith("login-link/linkedin")
        ]
        self.assertNotIn(
            "login-link/linkedin: missing required test wrong_challenge_rejected",
            problems,
        )
        self.assertIn(
            "login-link/linkedin: missing required test replay_rejected", problems
        )

    def test_instance_readme_is_reported(self):
        self.complete_google()
        (self.root / "login-link/google/README.md").write_text("# Google\n")
        self.assertEqual(
            self.problems(),
            [
                "login-link/google/README.md: instances have no README; "
                "put its caveats in the row's notes in use-cases.json"
            ],
        )

    def test_edited_fixture_is_reported(self):
        directory, _ = self.complete_google()
        (directory / "src/fixture.nr").write_text("pub global X: Field = 2;\n")
        self.assertEqual(
            self.problems(),
            [
                "login-link/google: src/fixture.nr differs from its manifest; regenerate it"
            ],
        )

    def test_edited_secondary_output_is_reported(self):
        # A manifest can record other generated files, such as an
        # adapter's test fixture, by path relative to the instance directory.
        directory, record = self.complete_google()
        other = self.root / "adapters/google_fixture.nr"
        other.parent.mkdir(exist_ok=True)
        other.write_text("pub global Y: Field = 1;\n")
        record["outputs"]["../../adapters/google_fixture.nr"] = hashlib.sha256(
            other.read_bytes()
        ).hexdigest()
        (directory / "fixtures/manifest.json").write_text(json.dumps(record))
        self.assertEqual(self.problems(), [])
        other.write_text("pub global Y: Field = 2;\n")
        self.assertEqual(
            self.problems(),
            [
                "login-link/google: ../../adapters/google_fixture.nr differs from its manifest; regenerate it"
            ],
        )

    def test_fixture_manifest_for_another_instance_is_reported(self):
        directory, record = self.complete_google()
        record["scheme"] = "apple"
        (directory / "fixtures/manifest.json").write_text(json.dumps(record))
        self.assertIn(
            "login-link/google: fixture manifest names another instance",
            self.problems(),
        )

    def test_unlisted_instance_directory_is_reported(self):
        stray = self.root / "login-link/apple"
        stray.mkdir()
        (stray / "Nargo.toml").write_text("")
        self.assertIn(
            "login-link/apple: instance not in use-cases.json", generate.lint(self.root)
        )


class ManifestErrors(unittest.TestCase):
    def manifest(self, change):
        with tempfile.TemporaryDirectory() as directory:
            root = project_copy(directory)
            data = json.loads((root / "use-cases.json").read_text())
            change(data)
            (root / "use-cases.json").write_text(json.dumps(data))
            return generate.outputs(root)

    def test_dependency_alias_before_aztec_is_rejected(self):
        def change(data):
            data["instances"][0]["dependencies"] = {"aaa": "noir/x"}

        with self.assertRaisesRegex(generate.ManifestError, "sorts before aztec"):
            self.manifest(change)

    def test_unknown_adapter_is_rejected(self):
        def change(data):
            data["instances"][1]["adapter"] = "nope"

        with self.assertRaisesRegex(generate.ManifestError, "Unknown adapter"):
            self.manifest(change)

    def test_wrapper_must_exist_for_the_use_case(self):
        def change(data):
            data["adapters"]["google"]["use_cases"].append("payment-settlement")
            data["instances"].append(
                {
                    "use_case": "payment-settlement",
                    "scheme": "google",
                    "adapter": "google",
                }
            )

        with self.assertRaisesRegex(
            generate.ManifestError, "no payment-settlement wrapper"
        ):
            self.manifest(change)

    def test_provider_must_declare_the_use_case(self):
        # Google's sub is one account and the same for every client, so it
        # declares no uniqueness although the family has a wrapper (N5).
        def change(data):
            data["instances"].append(
                {"use_case": "uniqueness", "scheme": "google", "adapter": "google"}
            )

        with self.assertRaisesRegex(
            generate.ManifestError, "google does not declare uniqueness in use_cases"
        ):
            self.manifest(change)

    def test_provider_without_a_declaration_is_rejected(self):
        def change(data):
            del data["adapters"]["google"]["use_cases"]

        with self.assertRaisesRegex(
            generate.ManifestError, "must declare its use_cases"
        ):
            self.manifest(change)

    def test_bearer_row_needs_a_bearer_declaration(self):
        def change(data):
            data["instances"][1]["bearer"] = True

        with self.assertRaisesRegex(
            generate.ManifestError, "does not declare login-link in bearer_use_cases"
        ):
            self.manifest(change)

    def test_instance_on_test_evidence_is_rejected(self):
        def test_adapter(data):
            data["adapters"]["template"] = {
                "path": "testing/test_adapter",
                "crate": "uc_test_adapter",
                "kind": "test",
                "types": {"event-proof": "DummyEvidence"},
            }
            data["instances"].append(
                {
                    "use_case": "event-proof",
                    "scheme": "fake",
                    "adapter": "template",
                }
            )

        def test_dependency(data):
            data["instances"][1]["dependencies"] = {
                "uc_test_adapter": "testing/test_adapter"
            }

        def template_outside_testing(data):
            data["template_checks"][0]["directory"] = "attribute-gating/template"

        def spelled(path):
            def change(data):
                data["instances"][1]["dependencies"] = {"uc_x": path}

            return change

        def unknown_kind(data):
            data["adapters"]["direct"] = {
                "path": "testing/test_adapter",
                "crate": "uc_test_adapter",
                "kind": "direct",
            }
            data["instances"][1]["adapter"] = "direct"

        def scheme_adapter_in_testing(data):
            data["adapters"]["wechatpay"]["path"] = "testing/test_adapter"

        for change, message in [
            (spelled("aztec/use-cases/testing/test_adapter"), "is test-only code"),
            (spelled("./testing/test_adapter"), "is test-only code"),
            (spelled("trust/../testing/test_adapter"), "is test-only code"),
            (spelled("/abs/aztec/use-cases/testing/test_adapter"), "must be relative"),
            (unknown_kind, "adapter kind must be one of"),
            (scheme_adapter_in_testing, "is test-only code"),
            (test_adapter, "for template checks only"),
            (test_dependency, "is test-only code"),
            (template_outside_testing, "template checks live in testing/"),
        ]:
            with self.subTest(message=message):
                with self.assertRaisesRegex(generate.ManifestError, message):
                    self.manifest(change)

    def test_choice_only_for_gating_and_uniqueness(self):
        def change(data):
            data["instances"][1]["choice"] = True

        with self.assertRaisesRegex(generate.ManifestError, "take a choice"):
            self.manifest(change)

    def test_duplicate_instance_is_rejected(self):
        def change(data):
            data["instances"].append(dict(data["instances"][1]))

        with self.assertRaisesRegex(generate.ManifestError, "Duplicate instance"):
            self.manifest(change)

    def test_git_dependency_and_extra_module(self):
        # An account that imports a pinned remote crate directly and
        # keeps a hand-written module (zkEmail: sha256 and `profile`).
        def change(data):
            data["instances"][0]["dependencies"] = {
                "sha256": {
                    "git": "https://github.com/noir-lang/sha256",
                    "tag": "v0.3.0",
                }
            }
            data["instances"][0]["modules"] = ["profile"]

        out = self.manifest(change)
        directory = generate.entries(
            json.loads((GOLDEN / "input/use-cases.json.in").read_text())
        )[0]["directory"]
        self.assertIn(
            'sha256 = { git = "https://github.com/noir-lang/sha256", tag = "v0.3.0" }',
            out[f"{directory}/Nargo.toml"],
        )
        self.assertIn("mod test;\npub mod profile;\n", out[f"{directory}/src/main.nr"])

    def test_in_crate_family_input(self):
        # An OIDC account: its in-crate input implements the family's
        # provider trait, with no provider adapter crate.
        def change(data):
            row = data["instances"][0]
            row.pop("adapter")
            row["family"] = "oidc"

        out = self.manifest(change)
        directory = generate.entries(
            json.loads((GOLDEN / "input/use-cases.json.in").read_text())
        )[0]["directory"]
        main = out[f"{directory}/src/main.nr"]
        self.assertIn("use uc_family_oidc::OidcAccount;", main)
        self.assertIn("OidcAccount { input: auth }", main)
        self.assertIn("uc_family_oidc = {", out[f"{directory}/Nargo.toml"])

    def test_family_input_is_for_accounts_only(self):
        def change(data):
            row = data["instances"][0]
            row.pop("adapter")
            row["family"] = "oidc"
            row.pop("input_in_crate")

        with self.assertRaisesRegex(generate.ManifestError, "in-crate input"):
            self.manifest(change)

    def test_git_dependency_needs_git_and_tag(self):
        def change(data):
            data["instances"][0]["dependencies"] = {"sha256": {"git": "x"}}

        with self.assertRaisesRegex(generate.ManifestError, "needs git and tag"):
            self.manifest(change)

    def test_missing_marker_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = project_copy(directory)
            (root / "uniqueness/README.md").write_text("# no markers\n")
            with self.assertRaisesRegex(generate.ManifestError, "uniqueness/README.md"):
                generate.outputs(root)


class Packages(unittest.TestCase):
    def test_adapter_without_a_nargo_toml_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = project_copy(directory)
            (root / "adapters/google/Nargo.toml").unlink()
            with self.assertRaisesRegex(generate.ManifestError, "Missing adapters/google"):
                generate.outputs(root)


@unittest.skipUnless(nr_format.available(), "the nargo of Aztec 6.0.0 is not installed")
class FormatStability(unittest.TestCase):
    """`nargo fmt` with aztec/noirfmt.toml changes nothing in a generated
    file or in any Noir source of aztec/use-cases."""

    def test_generated_main_nr_is_what_nargo_fmt_writes(self):
        with tempfile.TemporaryDirectory() as name:
            root = project_copy(name)
            outputs = {
                path: content
                for path, content in generate.outputs(root).items()
                if path.endswith(".nr")
            }
            formatted = nr_format.format_sources(list(outputs.values()))
            for (path, content), expected in zip(outputs.items(), formatted):
                with self.subTest(path=path):
                    self.assertEqual(expected, content)

    def test_unparseable_noir_is_an_error_not_unchanged_output(self):
        # nargo exits 0 and leaves a file with a parse error alone.
        with self.assertRaisesRegex(RuntimeError, "nargo fmt failed"):
            nr_format.format_noir("pub fn (\n")

    def test_node_formatter_rejects_unparseable_noir_too(self):
        script = (
            'import { formatNoir } from "./nr_format.mjs";'
            'try { formatNoir("pub fn (\\n"); process.exit(0); }'
            "catch (e) { console.log(e.message); process.exit(3); }"
        )
        done = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            cwd=PROJECT / "scripts/fixtures/generators",
            capture_output=True,
            text=True,
        )
        self.assertEqual(done.returncode, 3, done.stderr)
        self.assertIn("nargo fmt failed", done.stdout)

    def test_committed_sources_are_fmt_clean(self):
        paths = sorted(
            path
            for path in PROJECT.rglob("*.nr")
            if not {"target", "node_modules", "scripts"} & set(path.relative_to(PROJECT).parts)
        )
        sources = [path.read_text() for path in paths]
        for path, source, formatted in zip(paths, sources, nr_format.format_sources(sources)):
            with self.subTest(path=str(path.relative_to(PROJECT))):
                self.assertEqual(formatted, source)


class RepositoryTree(unittest.TestCase):
    def test_committed_tree_matches_use_cases_json_and_lints_clean(self):
        drift, problems = generate.run(PROJECT, check=True)
        self.assertEqual(drift, [])
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
