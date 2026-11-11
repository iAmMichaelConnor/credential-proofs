//! The pinned circuit's timestamp signal, read back as an issuance hour.
//!
//! Upstream `DigitBytesToTimestamp(2032)` (packages/circuits/src/utils/
//! pack.circom at 4dad918) adds a leap day only for the leap years 1972 to
//! 2028 (`maxLeapYears = (2032 - 1972) \ 4 = 15`). For an issuance from
//! 2032-03-01 to 2032-12-31 IST it omits 2032-02-29, so `signals[2]` is 86400 s
//! before the true start of the issuance hour. Issuances on 2032-02-29 and on
//! 2032-03-01 can give the same signal. The official witness generator refuses
//! years after 2032 (`assert(year <= maxYears)`, which is not a constraint); a
//! patched generator with the same key gives signals that are early by one
//! more day for each later leap year.

/// Unix time of 2032-02-29 00:00 IST. A signal below this is exact.
pub global LEAP_DAY_2032_START: u64 = 1961605800;
/// Unix time of 2032-03-01 00:00 IST. A signal from here to
/// `MAX_TIMESTAMP_SIGNAL` is exactly one day early.
pub global MARCH_2032_START: u64 = LEAP_DAY_2032_START + 86400;
/// The largest signal that the official witness generator gives: an issuance
/// at 2032-12-31 23:00 IST, reported one day early.
pub global MAX_TIMESTAMP_SIGNAL: u64 = 1988040600;

/// Returns `(earliest, latest)`: the inclusive range of Unix start times of
/// the IST issuance hour that the circuit's timestamp signal can stand for.
/// The two are equal except for a signal on 2032-02-29 IST, which can stand
/// for that day or the next. Use `earliest` for a "not too old" bound and
/// `latest` for a "not in the future" bound to accept only QRs whose every
/// possible issuance hour lies in the window. A signal above
/// `MAX_TIMESTAMP_SIGNAL` (a year after 2032, only from a patched witness
/// generator) is rejected, because its error grows with each later leap year.
pub fn issuance_hour_bounds(signal: u64) -> (u64, u64) {
    assert(
        signal <= MAX_TIMESTAMP_SIGNAL,
        "QR timestamp is after 2032, outside the official prover's range",
    );
    if signal < LEAP_DAY_2032_START {
        (signal, signal)
    } else if signal < MARCH_2032_START {
        (signal, signal + 86400)
    } else {
        (signal + 86400, signal + 86400)
    }
}

// Vectors: `signals[2]` from the official v2 witness generator (aadhaar-
// verifier.wasm SHA-256 4894923663fa...0d4f, snarkjs wtns.calculate, no
// proof) for QRs with these IST issuance hours.
// The true hour starts are Date.UTC(year, month - 1, day, hour) / 1000 -
// 19800.
global OFFICIAL_2031_12_31_23: u64 = 1956504600; // exact (diff 0)
global OFFICIAL_2032_02_29_12: u64 = 1961649000; // exact (diff 0)
global OFFICIAL_2032_03_01_12: u64 = 1961649000; // true 1961735400
global OFFICIAL_2032_12_31_23: u64 = 1988040600; // true 1988127000

#[test]
fn constants_match_the_official_vectors() {
    // 2032-02-29 00:00 IST is midnight IST, 12 hours before the 12:00 vector.
    assert_eq((LEAP_DAY_2032_START + 19800) % 86400, 0);
    assert_eq(LEAP_DAY_2032_START + 12 * 3600, OFFICIAL_2032_02_29_12);
    assert_eq(MAX_TIMESTAMP_SIGNAL, OFFICIAL_2032_12_31_23);
}

#[test]
fn exact_before_the_2032_leap_day() {
    assert_eq(issuance_hour_bounds(OFFICIAL_2031_12_31_23), (1956504600, 1956504600));
    let last = LEAP_DAY_2032_START - 3600;
    assert_eq(issuance_hour_bounds(last), (last, last));
}

#[test]
fn leap_day_signal_stands_for_two_days() {
    // 2032-02-29 12:00 and 2032-03-01 12:00 IST give the same signal.
    assert_eq(OFFICIAL_2032_02_29_12, OFFICIAL_2032_03_01_12);
    assert_eq(issuance_hour_bounds(OFFICIAL_2032_03_01_12), (1961649000, 1961735400));
    let first = LEAP_DAY_2032_START;
    assert_eq(issuance_hour_bounds(first), (first, first + 86400));
}

#[test]
fn one_day_early_from_march_2032() {
    assert_eq(
        issuance_hour_bounds(MARCH_2032_START),
        (MARCH_2032_START + 86400, MARCH_2032_START + 86400),
    );
    assert_eq(issuance_hour_bounds(OFFICIAL_2032_12_31_23), (1988127000, 1988127000));
}

#[test(should_fail_with = "QR timestamp is after 2032, outside the official prover's range")]
fn rejects_a_signal_after_2032() {
    // 2033-01-01 00:00 IST from a patched generator: one hour above the last
    // official signal.
    let _ = issuance_hour_bounds(MAX_TIMESTAMP_SIGNAL + 3600);
}
