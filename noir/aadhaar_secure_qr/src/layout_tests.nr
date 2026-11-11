//! Layout, hint, calendar and freshness relations without the signature.
//! These tests change bytes of the upstream test vector and call the parser
//! directly, so each case reaches the relation it names. Changed bytes would
//! fail the signature in `verify`; tests.nr covers that path.

use crate::{IDENTITY_DOMAIN, layout::parse, MAX_STATE_BYTES, SecureQr, SecureQrInput, vectors};
use poseidon::poseidon2::Poseidon2;

global ISSUED: u64 = 1713557752;

fn parsed(input: SecureQrInput<vectors::N>) -> SecureQr<vectors::N> {
    parse(input.signed_data, input.delimiters, 0)
}

fn with_bytes<let K: u32>(offset: u32, bytes: [u8; K]) -> SecureQrInput<vectors::N> {
    let mut input = vectors::upstream();
    let mut storage = input.signed_data.storage();
    for i in 0..K {
        storage[offset + i] = bytes[i];
    }
    input.signed_data = BoundedVec::from_parts(storage, input.signed_data.len());
    input
}

/// Reference-id timestamp YYYYMMDDhhmmssSSS starts at byte 9.
fn stamped<let K: u32>(stamp: str<K>) -> SecureQr<vectors::N> {
    parsed(with_bytes(9, stamp.as_bytes()))
}

/// Timestamp at byte 9 and date of birth DD-MM-YYYY at byte 39.
fn stamped_born<let K: u32, let L: u32>(stamp: str<K>, born: str<L>) -> SecureQr<vectors::N> {
    let mut input = with_bytes(9, stamp.as_bytes());
    let mut storage = input.signed_data.storage();
    let bytes = born.as_bytes();
    for i in 0..L {
        storage[39 + i] = bytes[i];
    }
    input.signed_data = BoundedVec::from_parts(storage, input.signed_data.len());
    parsed(input)
}

/// Insert one byte before `position`, moving later bytes and hints up.
fn inserted(position: u32, byte: u8) -> SecureQrInput<vectors::N> {
    let mut input = vectors::upstream();
    let length = input.signed_data.len();
    let old = input.signed_data.storage();
    let mut storage = [0; vectors::N];
    for i in 0..vectors::N {
        if i < position {
            storage[i] = old[i];
        } else if i == position {
            storage[i] = byte;
        } else {
            storage[i] = old[i - 1];
        }
    }
    input.signed_data = BoundedVec::from_parts(storage, length + 1);
    for k in 0..18 {
        if input.delimiters[k] >= position {
            input.delimiters[k] += 1;
        }
    }
    input
}

/// Replace field `k` (1-based, between hints k-1 and k) of the upstream
/// vector with `value`, moving later bytes and hints.
fn with_field<let K: u32>(k: u32, value: [u8; K]) -> SecureQrInput<vectors::N> {
    let mut input = vectors::upstream();
    let length = input.signed_data.len();
    let old = input.signed_data.storage();
    let start = input.delimiters[k - 1] + 1;
    let old_length = input.delimiters[k] - start;
    let mut storage = [0; vectors::N];
    for i in 0..vectors::N {
        if i < start {
            storage[i] = old[i];
        } else if i < start + K {
            storage[i] = value[i - start];
        } else if i + old_length < vectors::N + K {
            storage[i] = old[i + old_length - K];
        }
    }
    input.signed_data = BoundedVec::from_parts(storage, length + K - old_length);
    for j in 0..18 {
        if j >= k {
            input.delimiters[j] = input.delimiters[j] + K - old_length;
        }
    }
    input
}

fn next_photo_delimiter(input: SecureQrInput<vectors::N>) -> u32 {
    let storage = input.signed_data.storage();
    let mut found = 0;
    for i in 0..vectors::N {
        if (found == 0) & (i > input.delimiters[17]) & (storage[i] == 255) {
            found = i;
        }
    }
    found
}

// Hints.

#[test]
fn upstream_hints_parse() {
    let qr = parsed(vectors::upstream());
    assert_eq(qr.issued_at(), ISSUED);
}

#[test(should_fail_with = "Delimiter hints skip a delimiter")]
fn rejects_a_skipped_delimiter() {
    let mut input = vectors::upstream();
    let next = next_photo_delimiter(input);
    let d = input.delimiters;
    for k in 5..17 {
        input.delimiters[k] = d[k + 1];
    }
    input.delimiters[17] = next;
    let _ = parsed(input);
}

#[test(should_fail_with = "Delimiter hints skip a delimiter")]
fn rejects_a_photo_delimiter_inside_the_photo() {
    let mut input = vectors::upstream();
    input.delimiters[17] = next_photo_delimiter(input);
    let _ = parsed(input);
}

#[test(should_fail_with = "Delimiter hints skip a delimiter")]
fn rejects_a_delimiter_byte_inside_a_field() {
    // A 255 inside the name makes the hints no longer the first 18.
    let _ = parsed(with_bytes(30, [255]));
}

#[test(should_fail_with = "Delimiter hint is not 255")]
fn rejects_a_hint_on_a_non_delimiter_byte() {
    let mut input = vectors::upstream();
    input.delimiters[5] += 1;
    let _ = parsed(input);
}

#[test(should_fail_with = "Delimiter hints must increase")]
fn rejects_swapped_hints() {
    let mut input = vectors::upstream();
    let d = input.delimiters;
    input.delimiters[6] = d[7];
    input.delimiters[7] = d[6];
    let _ = parsed(input);
}

#[test(should_fail_with = "Delimiter hints must increase")]
fn rejects_a_repeated_hint() {
    let mut input = vectors::upstream();
    input.delimiters[7] = input.delimiters[6];
    let _ = parsed(input);
}

#[test(should_fail_with = "Photo delimiter is outside the signed data")]
fn rejects_a_photo_delimiter_after_the_signed_length() {
    let mut input = vectors::upstream();
    let length = input.signed_data.len();
    let mut storage = input.signed_data.storage();
    storage[length] = 255;
    input.signed_data = BoundedVec::from_parts(storage, length);
    input.delimiters[17] = length;
    let _ = parsed(input);
}

// Fixed V2 prefix.

#[test(should_fail_with = "Not a Secure QR V2 payload")]
fn rejects_another_version_marker() {
    let _ = parsed(with_bytes(1, [49]));
}

#[test(should_fail_with = "Unexpected Secure QR V2 layout")]
fn rejects_a_moved_reference_id_delimiter() {
    let mut input = vectors::upstream();
    input.delimiters[2] = 25;
    let _ = parsed(input);
}

#[test(should_fail_with = "Invalid email/mobile indicator")]
fn rejects_an_out_of_range_indicator() {
    let _ = parsed(with_bytes(3, [52]));
}

#[test(should_fail_with = "Expected an ASCII digit")]
fn rejects_a_non_digit_aadhaar_digit() {
    let _ = parsed(with_bytes(5, [65]));
}

// Issuance time: exact Gregorian seconds in IST. Oracles: Python
// calendar.timegm(...) - 19800.

#[test]
fn year_2032_after_leap_day() {
    assert_eq(stamped("20320301120000000").issued_at(), 1961735400);
}

#[test]
fn leap_day_2032() {
    assert_eq(stamped("20320229120000000").issued_at(), 1961649000);
}

#[test]
fn year_2033_and_later() {
    assert_eq(stamped("20330101120000000").issued_at(), 1988173800);
    assert_eq(stamped("21000301000000000").issued_at(), 4107522600);
    assert_eq(stamped("99991231235959999").issued_at(), 253402280999);
}

#[test]
fn minutes_and_seconds_are_kept() {
    // Upstream truncates this to 01:00 IST.
    assert_eq(stamped("20240420014552930").issued_at(), 1713557752);
    assert_eq(stamped("20240420010000000").issued_at(), 1713557752 - 45 * 60 - 52);
}

#[test]
fn unix_epoch_in_ist() {
    assert_eq(stamped("19700101053000000").issued_at(), 0);
}

#[test(should_fail_with = "QR timestamp precedes the Unix epoch")]
fn rejects_a_time_before_the_unix_epoch() {
    let _ = stamped("19700101052959999");
}

#[test(should_fail_with = "invalid UTC day")]
fn rejects_29_february_2100() {
    let _ = stamped("21000229000000000");
}

#[test(should_fail_with = "invalid UTC day")]
fn rejects_29_february_2023() {
    let _ = stamped("20230229000000000");
}

#[test(should_fail_with = "invalid UTC month")]
fn rejects_month_13() {
    let _ = stamped("20241301000000000");
}

#[test(should_fail_with = "invalid UTC day")]
fn rejects_day_zero() {
    let _ = stamped("20240400000000000");
}

#[test(should_fail_with = "invalid UTC time of day")]
fn rejects_hour_24() {
    let _ = stamped("20240420240000000");
}

#[test(should_fail_with = "invalid UTC time of day")]
fn rejects_minute_60() {
    let _ = stamped("20240420016000000");
}

#[test(should_fail_with = "invalid UTC time of day")]
fn rejects_second_60() {
    let _ = stamped("20240420010060000");
}

#[test(should_fail_with = "Expected an ASCII digit")]
fn rejects_non_digit_milliseconds() {
    let _ = stamped("2024042001455293X");
}

// Age on the IST issuance date.

#[test]
fn age_uses_the_ist_date_at_midnight() {
    // 2024-04-20 00:10 IST is still 19 April in UTC.
    let qr = stamped_born("20240420001000000", "20-04-2006");
    assert_eq(qr.issued_at(), 1713552000);
    assert(qr.age_at_least(18));
    assert(!stamped_born("20240420001000000", "21-04-2006").age_at_least(18));
}

#[test]
fn leap_day_birthday() {
    assert(!stamped_born("20220228235959999", "29-02-2004").age_at_least(18));
    assert(stamped_born("20220301000000000", "29-02-2004").age_at_least(18));
    assert(stamped_born("20240229000000000", "29-02-2004").age_at_least(20));
    assert(!stamped_born("20240228000000000", "29-02-2004").age_at_least(20));
}

#[test]
fn birth_after_issuance_is_not_an_age() {
    let qr = stamped_born("20240420014552930", "01-01-2030");
    assert(!qr.age_at_least(0));
}

#[test(should_fail_with = "Date of birth must be DD-MM-YYYY")]
fn rejects_an_iso_birth_date() {
    let _ = stamped_born("20240420014552930", "1984-01-01");
}

#[test(should_fail_with = "Invalid birth month")]
fn rejects_birth_month_13() {
    let _ = stamped_born("20240420014552930", "01-13-1984");
}

#[test(should_fail_with = "Invalid birth day")]
fn rejects_birth_day_zero() {
    let _ = stamped_born("20240420014552930", "00-01-1984");
}

#[test(should_fail_with = "Date of birth must be DD-MM-YYYY")]
fn rejects_a_longer_birth_field() {
    // One more byte inside the date of birth field.
    let _ = parsed(inserted(45, 48));
}

// Optional attributes.

#[test(should_fail_with = "Gender must be one byte")]
fn rejects_a_two_byte_gender() {
    let qr = parsed(inserted(50, 77));
    let _ = qr.gender();
}

#[test(should_fail_with = "PIN code must have six digits")]
fn rejects_a_seven_digit_pin_code() {
    let qr = parsed(inserted(98, 49));
    let _ = qr.pincode();
}

#[test(should_fail_with = "Expected an ASCII digit")]
fn rejects_a_non_digit_pin_code() {
    let _ = parsed(with_bytes(100, [88])).pincode();
}

#[test]
fn accepts_a_state_of_maximal_length() {
    let state = parsed(with_field(13, [83; MAX_STATE_BYTES])).state();
    assert_eq(state.len(), MAX_STATE_BYTES);
    for i in 0..MAX_STATE_BYTES {
        assert_eq(state.get(i), 83);
    }
}

#[test(should_fail_with = "State exceeds supported length")]
fn rejects_a_state_one_byte_too_long() {
    let qr = parsed(with_field(13, [83; MAX_STATE_BYTES + 1]));
    // Parsing and the other attributes do not depend on the state length.
    assert_eq(qr.pincode(), 110051);
    let _ = qr.state();
}

#[test]
fn accepts_an_empty_state() {
    assert_eq(parsed(with_field(13, [])).state().len(), 0);
}

// Name length. Only the identity commitment reads the name.

#[test]
fn an_empty_name_parses_and_commits() {
    let qr = parsed(with_field(3, []));
    assert_eq(qr.delimiters[3], 27);
    assert(qr.age_at_least(40));
    let expected = Poseidon2::hash([IDENTITY_DOMAIN, 2697, 1984, 1, 1, 0, 0, 0, 0, 0, 0], 11);
    assert_eq(qr.identity_commitment(), expected);
}

#[test]
fn a_long_name_still_allows_attribute_checks() {
    let qr = parsed(with_field(3, [78; 300]));
    assert_eq(qr.issued_at(), ISSUED);
    assert(qr.age_at_least(18));
    assert_eq(qr.gender(), 77);
    assert_eq(qr.pincode(), 110051);
    assert_eq(qr.state().len(), 5);
}

#[test(should_fail_with = "Name exceeds supported length")]
fn a_long_name_has_no_identity_commitment() {
    let _ = parsed(with_field(3, [78; 156])).identity_commitment();
}

// Freshness against a trusted `now`.

#[test]
fn freshness_boundaries_are_inclusive() {
    let qr = parsed(vectors::upstream());
    qr.assert_fresh(ISSUED, 0, 0);
    qr.assert_fresh(ISSUED + 10800, 10800, 900);
    qr.assert_fresh(ISSUED - 900, 10800, 900);
    qr.assert_fresh(18446744073709551615, 18446744073709551615, 0);
    qr.assert_fresh(0, 0, 18446744073709551615);
}

#[test(should_fail_with = "Aadhaar QR is too old")]
fn rejects_one_second_too_old() {
    parsed(vectors::upstream()).assert_fresh(ISSUED + 10801, 10800, 900);
}

#[test(should_fail_with = "Aadhaar QR timestamp is in the future")]
fn rejects_one_second_too_far_in_the_future() {
    parsed(vectors::upstream()).assert_fresh(ISSUED - 901, 10800, 900);
}
