#!/usr/bin/env python3
"""Create a separate producer, direct contract or small recursive contract.

No compilation or proving. Application semantics belong to the consumer:
generic variants return verified inputs and do not claim World ID validity.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AZTEC_DEPENDENCY = (
    'aztec = { git = "https://github.com/aztec-labs-eng/aztec-nr", tag = "v6.0.0", directory = "aztec" }\n'
)


# Every emitted line is already in the pinned `nargo fmt` style (100 columns,
# one parameter per line once a signature wraps), so formatting the checked-in
# examples does not change them and tests can compare bytes.
def _block(lines, indent):
    return "".join(" " * indent + line + "\n" for line in lines)


def _call(head, arguments, indent, tail=";"):
    """One call, wrapped one argument per line when it exceeds 100 columns."""
    flat = " " * indent + head + "(" + ", ".join(arguments) + ")" + tail
    if len(flat) <= 100:
        return [flat.strip()]
    return [head + "("] + ["    " + a + "," for a in arguments] + [")" + tail]


def render(
    destination, *, route, backend, inputs, aztec=None, library_root=ROOT
):
    """Return the variant files without writing them or requiring dependencies."""
    destination = Path(destination).resolve()
    library_root = Path(library_root).resolve()
    if route not in ["producer", "direct", "consumer"] or backend != "groth16":
        raise ValueError("Unsupported route/backend; only groth16 producer/direct/consumer")
    if not 1 <= inputs <= 256:
        raise ValueError("public input count must be 1..256")
    dependencies = {}

    def dep(name, path):
        dependencies[name] = Path(path).resolve()

    dep("common", library_root / "noir/world_id_common")
    fields, constructor, init = [], [], []
    if route != "consumer":
        dep("uniqueness", library_root / "noir/world_id_uniqueness")
    arguments = [
        f"key: uniqueness::groth16::RawVerificationKey<{inputs}>",
        "proof: [[u128; 3]; 8]",
        f"hints: uniqueness::groth16::Hints<{inputs}>",
        "authorized_key: Field",
    ]
    verify = _call(
        "uniqueness::groth16::verify",
        ["key", "public_inputs", "proof", "hints", "authorized_key"],
        4,
    )
    statement = (
        "common::binding::groth16_statement(context, authorized_key, public_inputs)"
    )
    if route == "producer":
        source = (
            f"// Bind a verified {inputs}-input Groth16 claim to an application-context statement.\n"
            "fn main(\n"
            + _block(
                ["statement: pub Field,", "context: [Field; 6],"]
                + [a + "," for a in arguments]
                + [f"public_inputs: [Field; {inputs}],"],
                4,
            )
            + ") {\n"
            + _block(verify, 4)
            + _block(
                _call(
                    "assert",
                    ["statement == " + statement, '"Wrong application statement"'],
                    4,
                ),
                4,
            )
            + "}\n"
        )
        kind = "bin"
    else:
        if aztec is not None:
            dep("aztec", aztec)
        if route == "consumer":
            arguments = [
                "key: [Field; common::certificate::VK_FIELDS]",
                "proof: [Field; common::certificate::PROOF_FIELDS]",
                "action: Field",
                "beneficiary: Field",
                "nonce: Field",
            ]
            # The statement binds this verifier's own address, not the
            # caller, and nothing here consumes the nonce.
            verify = [
                "// The context binds chain, version and this verifier's own address,",
                "// not the caller (msg_sender), and this function consumes no nonce.",
                "// Each caller of a shared verifier accepts the same certificate:",
                "// a calling application must bind itself and nullify the nonce.",
                "let context = [",
                "    self.context.chain_id(),",
                "    self.context.version(),",
                "    self.address.to_field(),",
                "    action,",
                "    beneficiary,",
                "    nonce,",
                "];",
            ]
            if backend == "groth16":
                verify.append("let authorized_key = self.storage.inner_key.read();")
            verify += _call(
                "common::certificate::verify",
                [
                    "key",
                    "proof",
                    statement,
                    "self.storage.producer_key.read()",
                ],
                8,
            )
            fields.append("producer_key: PublicImmutable<Field, Context>,")
            constructor.append("producer_key: Field")
            init += [
                "assert(producer_key != 0);",
                "self.storage.producer_key.initialize(producer_key);",
            ]
        if backend == "groth16":
            fields.append("inner_key: PublicImmutable<Field, Context>,")
            constructor.append("inner_key: Field")
            init += [
                "assert(inner_key != 0);",
                "self.storage.inner_key.initialize(inner_key);",
            ]
            if route == "direct":
                arguments = [
                    f"key: [[u128; 3]; {16 + 2 * inputs}]",
                    "proof: [[u128; 3]; 8]",
                    f"hints: [Field; {2799 + 4 * inputs}]",
                ]
                verify = _call(
                    "uniqueness::groth16::verify",
                    [
                        f"uniqueness::groth16::decode_key::<{inputs}>(key)",
                        "public_inputs",
                        "proof",
                        f"uniqueness::groth16::decode_hints::<{inputs}>(hints)",
                        "self.storage.inner_key.read()",
                    ],
                    8,
                )
        storage = ""
        if fields:
            storage = (
                "    #[storage]\n    struct Storage<Context> {\n"
                + _block(fields, 8)
                + "    }\n"
                + '    #[external("public")]\n    #[initializer]\n'
                + "    fn constructor("
                + ", ".join(constructor)
                + ") {\n"
                + _block(init, 8)
                + "    }\n"
            )
        source = (
            "use aztec::macros::aztec;\n#[aztec]\npub contract ProofVerifier {\n"
            "    use aztec::macros::{functions::{external, initializer}, storage::storage};\n"
            "    use aztec::state_vars::PublicImmutable;\n"
            "    use aztec::protocol::traits::ToField;\n"
            + storage
            + '    #[external("private")]\n    fn verify(\n'
            + _block(
                [a + "," for a in arguments] + [f"public_inputs: [Field; {inputs}],"],
                8,
            )
            + f"    ) -> [Field; {inputs}] {{\n"
            + _block(verify, 8)
            + "        public_inputs\n    }\n}\n"
        )
        kind = "contract"
    manifest = f'[package]\nname = "{backend}_{route}_{inputs}"\ntype = "{kind}"\nauthors = [""]\n\n[dependencies]\n'
    if kind == "contract" and aztec is None:
        manifest += AZTEC_DEPENDENCY
    for name, path in dependencies.items():
        manifest += (
            f"{name} = {{ path = {json.dumps(os.path.relpath(path, destination))} }}\n"
        )
    outputs = {"src/main.nr": source, "Nargo.toml": manifest}
    info = {
        "schema": "aztec-verifier-variant-v1",
        "backend": backend,
        "route": route,
        "public_inputs": inputs,
        "claim": "generic-proof-validity",
        "sources": {
            k: hashlib.sha256(v.encode()).hexdigest() for k, v in outputs.items()
        },
        "toolchain_profile": "aztec-v6.0.0",
    }
    outputs["variant.json"] = json.dumps(info, indent=2) + "\n"
    return outputs, info, dependencies


def create(destination, *, replace=False, **options):
    """Write a variant. An existing different file is kept unless replace=True."""
    destination = Path(destination).resolve()
    outputs, info, dependencies = render(destination, **options)
    for path in dependencies.values():
        if not (path / "Nargo.toml").is_file():
            raise ValueError("Missing dependency: " + str(path))
    for name, text in outputs.items():
        path = destination / name
        if not replace and path.exists() and path.read_text() != text:
            raise FileExistsError(path)
    for name, text in outputs.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return info


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("destination", type=Path)
    p.add_argument("--route", required=True, choices=["producer", "direct", "consumer"])
    p.add_argument("--backend", required=True, choices=["groth16"])
    p.add_argument("--inputs", required=True, type=int)
    p.add_argument(
        "--aztec",
        type=Path,
        help="Local aztec-nr package for contract routes (default: the v6.0.0 git dependency)",
    )
    p.add_argument("--library-root", type=Path, default=ROOT)
    p.add_argument(
        "--replace",
        action="store_true",
        help="Regenerate an existing variant in place (for example after a toolchain change)",
    )
    a = p.parse_args()
    print(json.dumps(create(**vars(a)), indent=2))


if __name__ == "__main__":
    main()
