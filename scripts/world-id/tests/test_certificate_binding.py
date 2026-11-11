"""Key-binding rule of recursive certificate callers; no compilation or proof.

common::certificate::verify grants authority only when its key hash is a compiled
constant, authenticated storage, or a public input that the outer verifier pins
(docs/world-id.md, "Recursive certificate boundary"). These checks read the entry-point sources and
the generator output. The in-circuit relation itself is covered by Noir tests.
"""

from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/world-id"))
from create_variant import create, render

VERIFY_CALLS = re.compile(r"\b(?:certificate::verify|verify_certificate)\s*\(")


def arguments(source, start):
    """Split the top-level arguments of the call whose '(' is at source[start]."""
    depth, current, result = 0, "", []
    for char in source[start:]:
        if char in "([{":
            depth += 1
            if depth == 1:
                continue
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                result.append(current.strip())
                return result
        elif char == "," and depth == 1:
            result.append(current.strip())
            current = ""
            continue
        current += char
    raise ValueError("Unbalanced call")


def public_main_parameters(source):
    match = re.search(r"fn main\s*\((.*?)\)\s*(?:->[^{]*)?\{", source, re.S)
    if not match:
        return set()
    return set(re.findall(r"(\w+)\s*:\s*pub\b", match.group(1)))


def key_sources(source):
    """Return the key-hash argument of every certificate verification call."""
    return [
        arguments(source, m.end() - 1)[3]
        for m in VERIFY_CALLS.finditer(source)
        if not source[: m.start()].rstrip().endswith("fn")
    ]


def authorised(argument, source):
    if re.fullmatch(r"self\.storage\.\w+\.read\(\)", argument):
        return True
    if re.fullmatch(r"[A-Z][A-Z0-9_]*", argument):
        return True  # compiled global
    return argument in public_main_parameters(source)


class KeyBindingTests(unittest.TestCase):
    def assert_bound(self, name, source):
        keys = key_sources(source)
        self.assertTrue(keys, name + " has no certificate verification call")
        for key in keys:
            self.assertTrue(
                authorised(key, source),
                f"{name}: producer key hash {key!r} is a private witness",
            )

    def test_producer_benchmarks_match_the_generated_producer(self):
        # The #[export] producer benchmarks are the generator's producer route
        # with the statement returned instead of compared with a public input.
        benchmarks = (ROOT / "noir/world_id_uniqueness/src/benchmarks.nr").read_text()
        for inputs in [4, 15]:
            outputs, info, _ = render(
                ROOT / "scratch", route="producer", backend="groth16", inputs=inputs
            )
            self.assertEqual(info["route"], "producer")
            producer = outputs["src/main.nr"]
            self.assertIn(
                "uniqueness::groth16::verify(key, public_inputs, proof, hints, authorized_key);",
                producer,
            )
            self.assertIn(f"key: uniqueness::groth16::RawVerificationKey<{inputs}>", producer)
            start = benchmarks.index(f"fn world_id_groth16_producer_{inputs}(")
            body = benchmarks[start : benchmarks.index("\n}\n", start)]
            self.assertIn(f"key: RawVerificationKey<{inputs}>", body)
            self.assertIn(f"hints: Hints<{inputs}>", body)
            self.assertIn(
                "crate::groth16::verify(key, public_inputs, proof, hints, authorized_key);", body
            )
            self.assertIn(
                "common::binding::groth16_statement(context, authorized_key, public_inputs)", body
            )
            self.assertIn(
                "common::binding::groth16_statement(context, authorized_key, public_inputs)",
                producer,
            )

    def test_private_key_hash_is_rejected_by_this_check(self):
        source = "fn main(s: pub Field, k: [Field; 115], p: [Field; 458], h: Field) { common::certificate::verify(k, p, s, h); }"
        with self.assertRaises(AssertionError):
            self.assert_bound("negative control", source)

    def test_generated_consumers_read_keys_from_storage(self):
        # A Groth16 producer compares the inner key with a private value and
        # binds it only through its public statement. The consumer must recompute
        # that statement with its own stored inner key.
        with tempfile.TemporaryDirectory() as tmp:
            aztec = Path(tmp) / "aztec"
            aztec.mkdir()
            (aztec / "Nargo.toml").write_text('[package]\nname="aztec"\n')
            for backend in ["groth16"]:
                dest = Path(tmp) / backend
                create(dest, route="consumer", backend=backend, inputs=4, aztec=aztec)
                source = (dest / "src/main.nr").read_text()
                self.assert_bound("generated " + backend, source)
                self.assertEqual(
                    key_sources(source), ["self.storage.producer_key.read()"]
                )
            statement = arguments(source, source.index("groth16_statement(") + 17)
            self.assertEqual(statement[1], "authorized_key")
            self.assertIn("let authorized_key = self.storage.inner_key.read();", source)
            self.assertNotIn("authorized_key: Field", source)
            producer = Path(tmp) / "producer"
            create(producer, route="producer", backend="groth16", inputs=4)
            source = (producer / "src/main.nr").read_text()
            self.assertIn(
                "statement == common::binding::groth16_statement(context, authorized_key, public_inputs)",
                source,
            )
            self.assertIn("statement: pub Field", source)


if __name__ == "__main__":
    unittest.main()
