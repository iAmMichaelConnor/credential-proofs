//! Canonical unpadded RFC 4648 base64url decoding over the Git-pinned
//! `noir_base64` v0.5.1 URL decoder, which constrains alphabet membership and
//! rejects standard `+`/`/`, padding and nonzero inactive storage.
//!
//! `decode_canonical` adds the active-length check, rejects lengths congruent to
//! 1 mod 4, and requires the unused tail bits of a final sextet to be zero.
//! Empty input (including capacity 0) is valid: protocol consumers enforce
//! their own nonempty and decoded-size rules and authenticate the original
//! signed bytes. Re-encoding is deliberately not used: that release's variable
//! encoder inverts the alphabet after the first position and rejected valid
//! JOSE signatures beginning `-` or `_`.
//!
//! The negative tests fail first in the decoder's unconstrained hint
//! ("DecodeError: invalid symbol"); `scripts/base64url-hint-disabled-check.py`
//! shows that the constraints reject the same inputs with the hint removed.
use base64::BASE64_URL_DECODER;
/// Decode RFC4648 URL-safe, unpadded canonical bytes. The pinned decoder's
/// invalid-character accumulator requires active length below2^24.
pub fn decode_canonical<let N: u32, let E: u32>(
    input: BoundedVec<u8, N>,
    error: str<E>,
) -> BoundedVec<u8, ((N + 3) / 4) * 3> {
    assert(input.len() <= N, error);
    assert(input.len() < 16777216, "base64url decoder requires active length below2^24");
    let remainder = input.len() % 4;
    assert(remainder != 1, error);
    if N > 0 {
        if input.len() > 0 {
            let last = input.storage()[input.len() - 1];
            if remainder == 2 {
                assert((last == 65) | (last == 81) | (last == 103) | (last == 119), error);
            } else if remainder == 3 {
                let mut allowed = false;
                for b in "AEIMQUYcgkosw048".as_bytes() {
                    allowed = allowed | (last == b);
                }
                assert(allowed, error);
            }
        }
        BASE64_URL_DECODER::decode_var::<N, ((N + 3) / 4) * 3>(input)
    } else {
        BoundedVec::from_parts([0; ((N + 3) / 4) * 3], 0)
    }
}
#[test]
fn leading_underscore() {
    let decoded = decode_canonical(
        BoundedVec::from_parts([95u8, 119], 2),
        "non-canonical JOSE signature encoding",
    );
    assert(decoded.len() == 1);
    assert(decoded.storage()[0] == 255);
}
#[test]
fn capacity_zero() {
    let decoded = decode_canonical(BoundedVec::from_parts([0u8; 0], 0), "canonical");
    assert(decoded.len() == 0);
}
#[test]
fn all_first_and_second_sextets() {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".as_bytes();
    for i in 0..64 {
        let a = decode_canonical(
            BoundedVec::from_parts([alphabet[i], 65, 65, 65], 4),
            "canonical",
        );
        assert(a.len() == 3);
        assert(a.storage()[0] == (i * 4) as u8);
        assert(a.storage()[1] == 0);
        assert(a.storage()[2] == 0);
        let b = decode_canonical(
            BoundedVec::from_parts([65, alphabet[i], 65, 65], 4),
            "canonical",
        );
        assert(b.len() == 3);
        assert(b.storage()[0] == (i / 16) as u8);
        assert(b.storage()[1] == ((i % 16) * 16) as u8);
        assert(b.storage()[2] == 0);
    }
}
#[test]
fn every_valid_two_character_tail() {
    let tails = "AQgw".as_bytes();
    for i in 0..4 {
        let d = decode_canonical(BoundedVec::from_parts([65, tails[i]], 2), "canonical");
        assert(d.len() == 1);
        assert(d.storage()[0] == i as u8);
    }
}
#[test]
fn every_valid_three_character_tail() {
    let tails = "AEIMQUYcgkosw048".as_bytes();
    for i in 0..16 {
        let d = decode_canonical(BoundedVec::from_parts([65, 65, tails[i]], 3), "canonical");
        assert(d.len() == 2);
        assert(d.storage()[0] == 0);
        assert(d.storage()[1] == i as u8);
    }
}
#[test]
fn empty_nonzero_capacity() {
    let d = decode_canonical(BoundedVec::from_parts([0u8; 8], 0), "canonical");
    assert(d.len() == 0);
}
#[test(should_fail_with = "canonical")]
fn reject_length_one() {
    let _d = decode_canonical(BoundedVec::from_parts([65u8], 1), "canonical");
}
#[test(should_fail_with = "canonical")]
fn reject_two_character_tail_alias() {
    let _d = decode_canonical(BoundedVec::from_parts([95u8, 120], 2), "canonical");
}
#[test(should_fail_with = "canonical")]
fn reject_three_character_tail_alias() {
    let _d = decode_canonical(BoundedVec::from_parts([65u8, 65, 66], 3), "canonical");
}
// The next four inputs fail first in the pinned decoder's unconstrained
// `__validate_decoded` hint, so these tests show only that hint generation
// rejects them. scripts/base64url-hint-disabled-check.py removes that hint and shows that
// the constraints reject the same inputs.
#[test(should_fail_with = "DecodeError: invalid symbol")]
fn reject_standard_plus() {
    let _d = decode_canonical(BoundedVec::from_parts([43u8, 65, 65, 65], 4), "canonical");
}
#[test(should_fail_with = "DecodeError: invalid symbol")]
fn reject_standard_slash() {
    let _d = decode_canonical(BoundedVec::from_parts([47u8, 65, 65, 65], 4), "canonical");
}
#[test(should_fail_with = "DecodeError: invalid symbol")]
fn reject_padding() {
    let _d = decode_canonical(BoundedVec::from_parts([65u8, 65, 61, 61], 4), "canonical");
}
#[test(should_fail_with = "DecodeError: invalid symbol")]
fn reject_nonzero_inactive_storage() {
    let _d = decode_canonical(BoundedVec::from_parts([95u8, 119, 65, 0], 2), "canonical");
}
mod benchmarks;
mod known_answer_tests;
