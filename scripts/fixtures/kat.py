#!/usr/bin/env python3
"""Write the end-to-end known-answer test modules from generated inputs.

Each entry of KATS names a benchmark function (an `#[export]` function in a
package's `src/benchmarks.nr`) and the input files the fixture generators write
for it under `<inputs>/<name>/`: `Prover.toml` and one TOML per further case.
Every case becomes a constrained `#[test]` in `<tests>/src/known_answer_tests.nr`
that passes the inputs, as Noir literals behind `std::hint::black_box`, to the
benchmark function: an accepted case asserts the known return value, a rejected
case is `#[test(should_fail_with = "<message>")]`.

The parameter types come from the ABI of the benchmark function: the script
copies the workspace, replaces each benchmark body with an empty one (so the
export compiles in seconds) and runs `nargo export` ($NARGO, else `nargo`).

scripts/fixtures/generate.py runs it; alone: kat.py <inputs dir> <noir workspace dir>.
"""

import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import tomllib

# name: the input directory and test-name prefix; package/function: the benchmark;
# tests: the package that holds the test module (default: package; a sibling
# `<package>_slow_tests` crate when the tests are too heavy for the package's own
# CI job, which then calls the package's public `benchmarks` module); returns: the
# known return value of the accepted cases, as a dotted input path, a function of
# the inputs, or UNCHECKED when no independent reference computes it (the test
# then checks acceptance only); rejects: case -> exact failure message; accepts:
# further accepted cases; untested: case -> why no test here, for an input a Noir
# test cannot pass (a BoundedVec longer than its capacity) or that fails only in
# an upstream assertion without a message, which an existing test of the package
# already rejects with a bare `should_fail`. The reason is written into the module.
KATS = []
UNCHECKED = object()


def kat(name, package, function, returns=None, rejects=None, accepts=(), untested=None, tests=None):
    KATS.append(
        dict(
            name=name,
            package=package,
            function=function,
            tests=tests or package,
            returns=returns,
            rejects=rejects or {},
            accepts=list(accepts),
            untested=untested or {},
        )
    )


def base64url_decoded(inputs, directory):
    """The decoded bytes of `encoded`, zero-padded to the 258-byte capacity."""
    encoded = inputs["encoded"]
    text = bytes(encoded["storage"][: encoded["len"]]).decode()
    decoded = list(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))
    return {"storage": decoded + [0] * (258 - len(decoded)), "len": len(decoded)}


MODULUS = "trusted_key.modulus_limbs"


def jpki_expiry(inputs, directory):
    """The earliest signed expiry, which the certificate generator records."""
    return int((directory / "expiry.txt").read_text())


# The Aadhaar nullifier is a Poseidon2 hash, which no reference here computes.
RSA_MISMATCH = "PKCS#1 v1.5: message hash mismatch"
kat(
    "aadhaar_secure_qr",
    "aadhaar_secure_qr",
    "aadhaar_secure_qr_verify",
    UNCHECKED,
    rejects={
        "ProverAlteredBirthYear": RSA_MISMATCH,
        "ProverBadSignature": RSA_MISMATCH,
        "ProverWrongKey": RSA_MISMATCH,
        "ProverLongNameNullifier": "Name exceeds supported length",
        "ProverMaximalLeapDayMinor": "Holder is younger than 18 on the issuance date",
        "ProverPhotoDelimiterAfterLength": "Photo delimiter is outside the signed data",
        "ProverPhotoDelimiterInPhoto": "Delimiter hints skip a delimiter",
        "ProverSkippedDelimiter": "Delimiter hints skip a delimiter",
        "ProverTooNew": "Aadhaar QR timestamp is in the future",
        "ProverTooOld": "Aadhaar QR is too old",
        "ProverWrongExpectedKey": "Wrong Aadhaar issuer key",
    },
    accepts=["ProverFreshBoundary", "ProverFutureBoundary", "ProverTrailingGarbage", "ProverYear2032"],
    untested={
        "ProverSignedLengthAboveCapacity": "its signed_data length exceeds the BoundedVec capacity,"
        " which only the ABI can encode (BoundedVec::from_parts asserts len <= capacity).",
    },
)
kat("alipay_v2", "alipay", "alipay_v2_response")
kat("alipay_v3", "alipay", "alipay_v3_response")
# The nullifier is the public signal of the saved Groth16 proof.
kat(
    "anon_aadhaar_v2",
    "anon_aadhaar_v2_auth",
    "anon_aadhaar_v2_verify",
    "signals.1",
    rejects={
        "ProverBadQuotient": "Quadratic expression hint has a nonzero remainder",
        "ProverQrInFuture": "QR timestamp is in the future",
        "ProverQrTooOld": "QR is too old",
        "ProverTimestampAlias": "QR timestamp exceeds u64",
        "ProverWrongAction": "Wrong action signal",
        "ProverWrongIssuer": "Wrong issuer key",
        "ProverWrongNullifierSeed": "Wrong nullifier seed",
    },
    # Each case runs the complete Groth16 verification (minutes per test).
    tests="anon_aadhaar_v2_auth_slow_tests",
)
kat("google", "oidc", "oidc_google", MODULUS)
kat("apple", "oidc", "oidc_apple", MODULUS)
kat("es256_jwt", "oidc", "oidc_es256_jwt")
kat("json_member_batch", "oidc", "oidc_json_member_batch")
kat("base64url", "base64url", "base64url_decode_344", base64url_decoded)
kat("ed25519", "ed25519_auth", "ed25519_verify_18", tests="ed25519_auth_slow_tests")
kat(
    "entra",
    "entra",
    "entra_verify",
    MODULUS,
    rejects={
        "Expired": "OIDC token expired",
        "Future": "OIDC token not active yet",
        "WrongAudience": "wrong OIDC audience",
        "WrongIssuer": "wrong OIDC issuer",
        "WrongNonce": "wrong OIDC nonce",
    },
    tests="entra_slow_tests",
)
kat("p256_black_box", "p256_auth", "p256_black_box_verify")
kat("facebook", "facebook", "facebook_verify", MODULUS)
OIDC_REJECTS = {
    "RejectExpiry": "OIDC token expired",
    "RejectIssuer": "wrong OIDC issuer",
    "Rejectaudience": "wrong OIDC audience",
    "Rejectnonce": "wrong OIDC nonce",
    "Rejectsubject": "wrong OIDC subject",
}
kat(
    "franceconnect_v1",
    "franceconnect",
    "franceconnect_v1_verify",
    rejects=OIDC_REJECTS
    | {
        "RejectDuplicateAcr": "duplicate required OIDC claim",
        "RejectLowAcr": "FranceConnect+ assurance below policy",
        "RejectMissingAcr": "missing required OIDC claim",
        "RejectUnknownAcr": "FranceConnect+ assurance below policy",
    },
    tests="franceconnect_slow_tests",
)
kat(
    "franceconnect_v2",
    "franceconnect",
    "franceconnect_v2_verify",
    rejects=OIDC_REJECTS
    | {
        "RejectDuplicateAcr": "duplicate required OIDC claim",
        "RejectMissingAcr": "missing required OIDC claim",
        "RejectUnknownAcr": "FranceConnect v2 assurance below policy",
    },
    tests="franceconnect_slow_tests",
)
kat(
    "govbr",
    "govbr",
    "govbr_verify",
    MODULUS,
    rejects=OIDC_REJECTS
    | {
        "RejectBronze": "gov.br assurance below policy",
        "RejectDuplicateLevel": "duplicate assurance level",
        "RejectDuplicateSubject": "duplicate OIDC claim",
        "RejectEnvironment": "wrong OIDC issuer",
        "RejectMissingLevel": "missing or unknown gov.br assurance level",
        "RejectShadowEscalation": "gov.br assurance below policy",
        "RejectUnknownLevel": "missing or unknown gov.br assurance level",
    },
    untested={
        "RejectWrongKey": "another signing key fails an unnamed constraint (\"Cannot satisfy constraint\")"
        " before the signature comparison, so no message names it.",
    },
    tests="govbr_slow_tests",
)
kat(
    "jpki",
    "jpki_auth",
    "jpki_authorise",
    jpki_expiry,
    rejects={
        "ExpiredOcsp": "expired OCSP response",
        "Revoked": "OCSP certificate is not good",
        "WrongPurpose": "wrong authentication certificate policy",
        "WrongRoot": "unapproved JPKI root",
        "WrongSerial": "OCSP serial mismatch",
        "WrongAction": RSA_MISMATCH,
        "WrongSignature": RSA_MISMATCH,
    },
    untested={
        "BadRedc": "a zero holder Barrett hint fails inside noir-bignum's unconstrained reduction"
        " (an unnamed assert, and a different failure under --force-brillig), so no message names it.",
    },
)
kat("kakao", "kakao", "kakao_verify", MODULUS)
kat("line", "line", "line_verify")
kat("linkedin", "linkedin", "linkedin_verify_bearer", MODULUS)
kat("miargentina", "miargentina", "miargentina_verify", MODULUS)
kat("peer_v4", "peer_v4_auth", "peer_v4_verify")
kat("philsys", "philsys_auth", "philsys_verify", tests="philsys_auth_slow_tests")
kat("reclaim", "reclaim_auth", "reclaim_verify_claim")
kat("singpass", "singpass_auth", "singpass_authorise")
kat("telegram", "telegram", "telegram_verify", MODULUS)
DIRECT_IDP = {"DirectWithIdp": "institutional idp must be empty in direct mode"}
kat(
    "university",
    "university_auth",
    "university_verify_login",
    MODULUS,
    rejects=DIRECT_IDP,
    accepts=["Direct"],
    tests="university_auth_slow_tests",
)
kat(
    "university_claims",
    "university_auth",
    "university_validate_login_claims",
    rejects=DIRECT_IDP,
    accepts=["Direct"],
    tests="university_auth_slow_tests",
)
kat("ethereum_personal_sign", "ethereum_auth", "ethereum_personal_sign")
kat("ethereum_secret_key", "ethereum_auth", "ethereum_secret_key")
kat("ethereum_siwe", "ethereum_auth", "ethereum_siwe")
kat("passkey", "passkey_auth", "passkey_webauthn")
kat("rsa_signature_compat", "zkemail", "zkemail_rsa_signature_compat")
kat("wechatpay_v3", "wechatpay", "wechatpay_v3_response")
kat("zupass_pod", "zupass", "zupass_pod_entry")


def nargo():
    return os.environ.get("NARGO", "nargo")


def strip_benchmark_bodies(text):
    """Return benchmarks.nr with the body of every exported function emptied."""
    out, i = [], 0
    for m in re.finditer(r"#\[export\]\s*(?:pub(?:\(crate\))?\s+)?fn\s+\w+\s*\(", text):
        if m.start() < i:
            continue
        depth, j = 1, m.end()
        while depth:
            depth += {"(": 1, ")": -1}.get(text[j], 0)
            j += 1
        k = text.index("{", j)
        depth, end = 1, k + 1
        while depth:
            depth += {"{": 1, "}": -1}.get(text[end], 0)
            end += 1
        out.append(text[i:m.start()])
        returns = "->" in text[j:k]
        out.append(text[m.start():k] + ("{ std::mem::zeroed() }" if returns else "{}"))
        i = end
    out.append(text[i:])
    if len(re.findall(r"^#\[export\]", text, re.M)) != len(out) // 2:
        raise SystemExit("an exported function was not recognised")
    return "".join(out)


def benchmark_abis(workspace, packages):
    """Return {function: abi} for the exported functions of `packages`."""
    abis = {}
    with tempfile.TemporaryDirectory(prefix="kat-abi-") as scratch:
        # Path dependencies reach outside the workspace (vendor/), so copy its parent.
        for top in ("noir", "vendor"):
            shutil.copytree(
                workspace.parent / top,
                Path(scratch) / top,
                ignore=shutil.ignore_patterns("target", "export"),
            )
        work = Path(scratch) / "noir"
        for package in packages:
            bench = work / package / "src/benchmarks.nr"
            bench.write_text(strip_benchmark_bodies(bench.read_text()))
        # The test modules being replaced need not compile.
        for module in work.glob("*/src/known_answer_tests.nr"):
            module.write_text("")
        for package in packages:
            subprocess.run(
                [nargo(), "export", "--silence-warnings", "--package", package],
                cwd=work,
                check=True,
            )
            for path in (work / "export").glob("*.json"):
                abis[path.stem] = json.loads(path.read_text())["abi"]
                path.unlink()
    return abis


BOUNDED_VEC = "std::collections::bounded_vec::BoundedVec"


def struct_path(path, deps):
    """A path to the struct named by ABI `path` from the benchmark package.

    ABI paths are relative to the package: `module::Name` for its own structs,
    `dependency::...::Name` for a dependency's, which this library re-exports at
    the dependency's root.
    """
    parts = path.split("::")
    if parts[0] in deps:
        return f"{parts[0]}::{parts[-1]}"
    if deps.outside:
        # A sibling test crate names the package's root re-export.
        return f"{deps.package}::{parts[-1]}"
    return "::".join(["crate"] + parts)


class Deps(set):
    """The dependency names of the benchmark package, and where the tests live."""

    def __init__(self, names, package, outside):
        super().__init__(names)
        self.package, self.outside = package, outside


def scalar(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and re.fullmatch(r"-?(0x[0-9a-fA-F]+|[0-9]+)", value):
        return value
    raise ValueError(f"not a numeric input: {value!r}")


def literal(typ, value, deps):
    kind = typ["kind"]
    if kind in ("field", "integer"):
        return scalar(value)
    if kind == "boolean":
        if isinstance(value, bool):
            return "true" if value else "false"
        if value in (0, 1, "0", "1"):
            return "true" if int(value) else "false"
        raise ValueError(f"not a boolean input: {value!r}")
    if kind == "array":
        if len(value) != typ["length"]:
            raise ValueError(f"array length {len(value)} != {typ['length']}")
        return "[" + ", ".join(literal(typ["type"], v, deps) for v in value) + "]"
    if kind == "string":
        return json.dumps(value)
    if kind == "tuple":
        return "(" + ", ".join(literal(t, v, deps) for t, v in zip(typ["fields"], value)) + ")"
    if kind == "struct":
        fields = {f["name"]: f["type"] for f in typ["fields"]}
        if set(value) != set(fields):
            raise ValueError(f"fields {sorted(value)} != {sorted(fields)} of {typ['path']}")
        if typ["path"] == BOUNDED_VEC:
            storage = literal(fields["storage"], value["storage"], deps)
            return f"BoundedVec::from_parts({storage}, {scalar(value['len'])})"
        body = ", ".join(
            f"{f['name']}: {literal(f['type'], value[f['name']], deps)}" for f in typ["fields"]
        )
        return f"{struct_path(typ['path'], deps)} {{ {body} }}"
    raise ValueError(f"unsupported ABI type {kind}")


def lookup(inputs, dotted):
    value = inputs
    for part in dotted.split("."):
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def snake(case):
    case = re.sub(r"^Reject(?=[a-z])", "Reject_", case.removeprefix("Prover"))
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", case).lower()


def test_function(entry, case, inputs, abi, deps, directory):
    params = abi["parameters"]
    names = [p["name"] for p in params]
    if set(inputs) != set(names):
        raise ValueError(f"{entry['name']}/{case}: inputs {sorted(inputs)} != {sorted(names)}")
    args = ",\n".join(
        f"std::hint::black_box({literal(p['type'], inputs[p['name']], deps)})" for p in params
    )
    call = f"{entry['function']}(\n{args},\n)"
    rejected = case in entry["rejects"]
    test_name = f"{entry['name']}_known_answer" if case == "Prover" else f"{entry['name']}_{snake(case)}"
    if rejected:
        message = entry["rejects"][case].replace("\\", "\\\\").replace('"', '\\"')
        return f'#[test(should_fail_with = "{message}")]\nfn {test_name}() {{\n    let _ = {call};\n}}\n'
    returns = abi.get("return_type")
    known = entry["returns"]
    if known is UNCHECKED or (returns is None and known is None):
        return f"#[test]\nfn {test_name}() {{\n    let _ = {call};\n}}\n"
    if returns is None or known is None:
        raise ValueError(f"{entry['name']}: return value and known answer must both be given")
    value = known(inputs, directory) if callable(known) else lookup(inputs, known)
    expected = literal(returns["abi_type"], value, deps)
    return f"#[test]\nfn {test_name}() {{\n    let result = {call};\n    assert(result == {expected});\n}}\n"


HEADER = """// Generated by scripts/fixtures/generate.py from the fixture material; do not edit.
// End-to-end known-answer tests: each passes its inputs, as constrained
// witnesses, to a benchmark function, which runs the complete relation.
"""


def modules(inputs_dir, workspace, abis):
    """Return {tests package: module text}."""
    out = {}
    for entry in KATS:
        directory = inputs_dir / entry["name"]
        cases = sorted(p.stem for p in directory.glob("*.toml"))
        known = {"Prover", *entry["rejects"], *entry["accepts"], *entry["untested"]}
        if set(cases) != known:
            raise SystemExit(f"{entry['name']}: cases {cases} != declared {sorted(known)}")
        cases.remove("Prover")
        vectors = directory / "vectors.json"
        if vectors.exists():
            # A generator's own expectations must agree with the exact messages here.
            for case in json.loads(vectors.read_text())["cases"]:
                if case["name"] in entry["untested"]:
                    continue
                reason = case.get("reason")
                if reason is not None and reason not in entry["rejects"].get(case["name"], ""):
                    raise SystemExit(f"{entry['name']}/{case['name']}: {reason!r} is not the declared message")
                if case.get("success") and case["name"] not in entry["accepts"]:
                    raise SystemExit(f"{entry['name']}/{case['name']}: the generator expects success")
        abi = abis[entry["function"]]
        manifest = tomllib.loads((workspace / entry["package"] / "Nargo.toml").read_text())
        deps = Deps(manifest.get("dependencies", {}), entry["package"], entry["tests"] != entry["package"])
        tests = []
        for case, reason in sorted(entry["untested"].items()):
            cases.remove(case)
            note = f"No test for the {case} input of {entry['name']}: {reason}"
            tests.append("".join(f"// {line}\n" for line in textwrap.wrap(note, 96)))
        for case in ["Prover"] + cases:
            inputs = tomllib.loads((directory / f"{case}.toml").read_text())
            tests.append(test_function(entry, case, inputs, abi, deps, directory))
        prefix = "crate" if entry["tests"] == entry["package"] else entry["package"]
        use = f"use {prefix}::benchmarks::{entry['function']};\n"
        out.setdefault(entry["tests"], []).append((use, tests))
    return {
        package: HEADER + "\n" + "".join(sorted(u for u, _ in parts)) + "\n" + "\n".join(t for _, ts in parts for t in ts)
        for package, parts in out.items()
    }


def write_modules(inputs_dir, workspace):
    """Write every known-answer test module from the inputs under `inputs_dir`."""
    abis = benchmark_abis(workspace, sorted({e["package"] for e in KATS}))
    for package, text in modules(inputs_dir, workspace, abis).items():
        (workspace / package / "src/known_answer_tests.nr").write_text(text)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    write_modules(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())


if __name__ == "__main__":
    main()
