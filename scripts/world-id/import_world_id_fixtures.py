#!/usr/bin/env python3
"""Extract public upstream test vectors and keys; never generate a proof."""

import hashlib
import json
from pathlib import Path
import re
import argparse

ROOT = Path(__file__).resolve().parents[2]
FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583
PINS = {
    "world-id-contracts": "f959f725c3ee2dec1ed24944d5b9593b68c7b8a4",
    "world-id-protocol": "46f6b43d231780e4fc0b5030bd71e846664532d1",
}

# Relation behind each trusted key. The importer binds a key only to the bytes of its
# Solidity verifier, so a key replaced after a new ceremony passes the source hash
# check once that hash is updated. These records name the relation the key is
# documented to encode, so a reviewer can compare them with a changed verifier.
# They come from an independent reproduction (circom2 0.2.23 = circom 2.2.3, --O2, on
# the 26 circom files of world-id-protocol at the pinned revision); this tool does not
# re-derive them. Hashes are full where the reproduction recorded them in full.
RELATIONS = {
    "nullifier-v4-key.json": {
        "circuit": "OPRFNullifierProof (src/main/OPRFNullifierProof.circom, world-id-protocol)",
        "publicInputs": 15,
        "compiler": "circom 2.2.3 (npm circom2 0.2.23) --r1cs --sym --wasm --O2",
        "ceremonyR1csSha256": "6e590ca8afb21f81460b7208f0cd830fad0da7b99f6368cc41dc8cb838e58bec",
        "ceremonyWasmSha256": "7b2abbd1ffc4075ca0380bd6890fb71a88431317f30f09f78f6ee90ef3fc7831",
        "trustedSetupCommit": "189abeaf (abbreviated; full commit not recorded)",
        "recordedPrefixes": {
            "finalZkeySha256": "cef08ef1",
            "arksZkeySha256": "4247e6bf",
            "ceremonyVkeySha256": "25e6ae6c",
            "transcriptCircuitHash": "8488f28e",
        },
        "keyEqualsCeremonyVkey": "alpha, beta, gamma, delta and all 16 IC points, per the reproduction",
    },
    "semaphore16-key.json": {
        "circuit": "Semaphore v3.15.2 depth 16 (circomlib 2.0.2)",
        "publicInputs": 4,
        "zkeyAndWasmSha256": "fixtures/world-id/aztec-foundation.json (provenance.zkeySha256, provenance.wasmSha256)",
        "npmPackages": "fixtures/world-id/aztec-foundation.json (provenance.packages)",
    },
}


def key_from_solidity(source, count):
    constants = {
        name: int(value, 0) if value.startswith("0x") else int(value)
        for name, value in re.findall(
            r"uint256 constant (\w+)\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)\s*;", source
        )
    }

    def g1(name):
        return [str(constants[name + "_X"]), str(constants[name + "_Y"]), "1"]

    def g2(name):
        return [
            [str(constants[name + "_NEG_X_" + str(i)]) for i in range(2)],
            [str((-constants[name + "_NEG_Y_" + str(i)]) % FQ) for i in range(2)],
            ["1", "0"],
        ]

    return {
        "protocol": "groth16",
        "curve": "bn128",
        "nPublic": count,
        "vk_alpha_1": g1("ALPHA"),
        "vk_beta_2": g2("BETA"),
        "vk_gamma_2": g2("GAMMA"),
        "vk_delta_2": g2("DELTA"),
        "IC": [g1("CONSTANT")] + [g1("PUB_" + str(i)) for i in range(count)],
    }


def extract():
    """Use pinned source bytes; a source archive does not need an upstream .git tree."""
    provenance = json.loads((ROOT / "fixtures/world-id/provenance.json").read_text())
    assert provenance["repositories"] == PINS, "Unexpected fixture source revisions"
    files = {}

    def read(repo, name):
        content = (ROOT / "fixtures/world-id/upstream" / repo / name).read_bytes()
        identifier = repo + "/" + name
        expected = provenance["sources"][identifier]
        assert hashlib.sha256(content).hexdigest() == expected["sha256"], identifier
        url = f"https://github.com/worldcoin/{repo}/blob/{PINS[repo]}/{name}"
        assert expected["url"] == url, identifier
        files[identifier] = {"sha256": expected["sha256"], "url": url}
        return content.decode()

    old = json.loads(read("world-id-contracts", "src/test/data/InclusionProof.json"))
    key = key_from_solidity(
        read("world-id-contracts", "src/test/SemaphoreVerifier16.sol"), 4
    )
    values = {"semaphore16-key.json": key, "semaphore16-inclusion.json": old}
    modern = read("world-id-protocol", "contracts/test/core/Verifier.t.sol")
    arrays = re.findall(r"\[\s*(0x[0-9a-fA-F]+(?:\s*,\s*0x[0-9a-fA-F]+)*)\s*\]", modern)
    assert len(arrays) == 2
    proof, inputs = [[v.strip() for v in array.split(",")] for array in arrays]
    assert len(proof) == 4 and len(inputs) == 15
    values["nullifier-v4.json"] = {"compressedProof": proof, "publicInputs": inputs}
    values["nullifier-v4-key.json"] = key_from_solidity(
        read("world-id-protocol", "contracts/src/core/Verifier.sol"), 15
    )
    values["provenance.json"] = {
        "repositories": PINS,
        "sources": files,
        "relations": RELATIONS,
        "notice": "Upstream test vectors, not production identity/root attestations. Semaphore fixture has depth 16. World ID 4 fixture uses 15-input nullifier circuit; it is a raw Groth16 vector (Verifier.t.sol testVerifyNullifier), not valid under the WorldIDVerifierV2 uniqueness policy (action top byte 0x15, non-Aztec signal, past expiry). Extraction un-negates Solidity G2 key Y coordinates; no trusted setup or proof is generated.",
    }
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Write nothing; fail if a fixture differs from its extraction",
    )
    args = parser.parse_args()
    out = ROOT / "fixtures/world-id"
    stale = []
    for name, data in extract().items():
        content = json.dumps(data, indent=2) + "\n"
        path = out / name
        if path.exists() and path.read_text() == content:
            continue
        stale.append(name)
        if not args.check:
            path.write_text(content)
    if args.check and stale:
        raise SystemExit("Stale World ID fixtures (rerun without --check): " + ", ".join(stale))
    print(("Checked " if args.check else "Wrote ") + str(out.relative_to(ROOT)))


if __name__ == "__main__":
    main()
