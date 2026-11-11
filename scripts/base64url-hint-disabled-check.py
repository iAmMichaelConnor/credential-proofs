#!/usr/bin/env python3
"""Show that the constraints, not only a Brillig hint, reject non-URL-safe input.

In an honest run, `decode_canonical` rejects `+`, `/`, `=` and nonzero
inactive storage first in the unconstrained `__validate_decoded` of the pinned
noir_base64 v0.5.1 ("DecodeError: invalid symbol"). That shows only that hint
generation rejects them. This tool copies this package and the
pinned noir_base64 source into a fresh directory, replaces the body of
`__validate_decoded` with nothing (every constrained line stays byte-identical),
and runs `nargo test` on tests that expect the constrained failure messages.
A valid input must still decode in the patched copy.

Usage (from anywhere; execution only, no proof):
  python3 scripts/base64url-hint-disabled-check.py --out <fresh dir>

It needs the pinned noir_base64 v0.5.1 in nargo's git cache
($HOME/nargo/github.com/noir-lang/noir_base64/v0.5.1); `nargo check` in this
package fetches it.
"""

import argparse
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys

WORKSPACE = pathlib.Path(__file__).resolve().parents[1]
PACKAGE = WORKSPACE / "noir/base64url"
UPSTREAM = pathlib.Path.home() / "nargo/github.com/noir-lang/noir_base64/v0.5.1"
# SHA-256 of the pinned src/decoder.nr (noir_base64 v0.5.1) before the patch.
DECODER_SHA256 = "e860a6493101d300abc865fd45f046340d9064731434413e6d915b34001dcb4e"
DEPENDENCY = (
    'base64 = { git = "https://github.com/noir-lang/noir_base64", tag = "v0.5.1" }'
)

HINT = """unconstrained fn __validate_decoded(decoded: Field, input_byte: u8, offset: u32) {
    assert(
        decoded != INVALID_DECODE_VALUE,
        f"DecodeError: invalid symbol {input_byte}, offset {offset}.",
    );
}"""
NO_HINT = """unconstrained fn __validate_decoded(decoded: Field, input_byte: u8, offset: u32) {
    let _ = (decoded, input_byte, offset);
}"""

# Each case fails in a constraint of the pinned decoder once the hint is gone:
# an invalid lookup adds -2^32 to the validity accumulator, whose 32-bit range
# check (decoder.nr, `validity_check.assert_max_bit_size::<32>()`) fails.
# The only other 32-bit check, on `decode_index`, cannot fail: the index is at
# most 767.
# A capacity of 344 (the JOSE signature size) also exercises the full 40-symbol
# chunk path, where the 30-byte decomposition of the packed chunk fails first.
TESTS = """
mod hint_disabled_tests {
    use crate::decode_canonical;

    fn padded<let L: u32>(bytes: [u8; L], len: u32) -> BoundedVec<u8, 344> {
        let mut storage = [65; 344];
        for i in 0..L {
            storage[i] = bytes[i];
        }
        for i in L..344 {
            if i >= len {
                storage[i] = 0;
            }
        }
        BoundedVec::from_parts(storage, len)
    }

    #[test]
    fn valid_input_still_decodes() {
        let d = decode_canonical(BoundedVec::from_parts([95u8, 119], 2), "canonical");
        assert(d.len() == 1);
        assert(d.storage()[0] == 255);
    }

    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn standard_plus() {
        let _d = decode_canonical(BoundedVec::from_parts([43u8, 65, 65, 65], 4), "canonical");
    }

    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn standard_slash() {
        let _d = decode_canonical(BoundedVec::from_parts([47u8, 65, 65, 65], 4), "canonical");
    }

    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn padding() {
        let _d = decode_canonical(BoundedVec::from_parts([65u8, 65, 61, 61], 4), "canonical");
    }

    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn nonzero_inactive_storage() {
        let _d = decode_canonical(BoundedVec::from_parts([95u8, 119, 65, 0], 2), "canonical");
    }

    #[test(should_fail_with = "Field failed to decompose into specified 30 limbs")]
    fn standard_plus_in_full_chunk() {
        let _d = decode_canonical(padded([43u8, 65, 65, 65], 344), "canonical");
    }

    #[test(should_fail_with = "Field failed to decompose into specified 30 limbs")]
    fn nonzero_inactive_storage_in_full_chunk() {
        let mut input = padded([95u8, 119], 2);
        let mut storage = input.storage();
        storage[2] = 65;
        input = BoundedVec::from_parts(storage, 2);
        let _d = decode_canonical(input, "canonical");
    }
}
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--out", required=True, type=pathlib.Path, help="fresh output directory"
    )
    parser.add_argument(
        "--nargo",
        default=os.environ.get("NARGO", "nargo"),
        help="nargo binary ($NARGO, else nargo on PATH)",
    )
    args = parser.parse_args()
    if args.out.exists():
        parser.error(f"{args.out} exists; give a fresh directory")
    if not (UPSTREAM / "Nargo.toml").is_file():
        parser.error(f"{UPSTREAM} is missing; run `nargo check` in {PACKAGE} first")

    dependency = args.out / "noir_base64"
    shutil.copytree(
        UPSTREAM, dependency, ignore=shutil.ignore_patterns("target", ".git")
    )
    decoder = dependency / "src/decoder.nr"
    if hashlib.sha256(decoder.read_bytes()).hexdigest() != DECODER_SHA256:
        raise SystemExit(f"{decoder} is not the pinned v0.5.1 decoder")
    source = decoder.read_text()
    if source.count(HINT) != 1:
        raise SystemExit("the pinned __validate_decoded body changed; review this tool")
    decoder.write_text(source.replace(HINT, NO_HINT))

    package = args.out / "base64url"
    shutil.copytree(PACKAGE, package, ignore=shutil.ignore_patterns("target", "tools"))
    manifest = package / "Nargo.toml"
    text = manifest.read_text()
    if text.count(DEPENDENCY) != 1:
        raise SystemExit("the base64 dependency line changed; review this tool")
    manifest.write_text(
        text.replace(DEPENDENCY, 'base64 = { path = "../noir_base64" }')
    )
    library = package / "src/lib.nr"
    # The package's own negatives expect the removed hint's message; run only
    # the hint-disabled tests.
    library.write_text(library.read_text() + TESTS)

    result = subprocess.run(
        [args.nargo, "test", "--silence-warnings", "hint_disabled_tests"],
        cwd=package,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    (args.out / "nargo-test.log").write_text(result.stdout)
    sys.stdout.write(re.sub(r"\x1b\[[0-9;]*m", "", result.stdout))
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
