/// Exact UTC seconds of an RFC 3339 `YYYY-MM-DDTHH:MM:SSZ` string, restricted to
/// years 1970..9999 (no leap seconds). Calendar validation precedes arithmetic, so
/// no subtraction can underflow. Used by the x509 component, Aadhaar
/// Secure QR and the SIWE account.
pub fn utc_to_unix(date: [u8; 20]) -> u64 {
    for i in 0..20 {
        if (i == 4) | (i == 7) {
            assert_eq(date[i], 45);
        } else if i == 10 {
            assert_eq(date[i], 84);
        } else if (i == 13) | (i == 16) {
            assert_eq(date[i], 58);
        } else if i == 19 {
            assert_eq(date[i], 90);
        } else {
            assert((date[i] >= 48) & (date[i] <= 57), "UTC time field is not a digit");
        }
    }
    let year = (date[0] - 48) as u64 * 1000
        + (date[1] - 48) as u64 * 100
        + (date[2] - 48) as u64 * 10
        + (date[3] - 48) as u64;
    let month = (date[5] - 48) as u64 * 10 + (date[6] - 48) as u64;
    let day = (date[8] - 48) as u64 * 10 + (date[9] - 48) as u64;
    let hour = (date[11] - 48) as u64 * 10 + (date[12] - 48) as u64;
    let minute = (date[14] - 48) as u64 * 10 + (date[15] - 48) as u64;
    let second = (date[17] - 48) as u64 * 10 + (date[18] - 48) as u64;
    assert(year >= 1970, "UTC year before 1970");
    assert((month >= 1) & (month <= 12), "invalid UTC month");
    let leap = (year % 4 == 0) & ((year % 100 != 0) | (year % 400 == 0));
    let lengths: [u64; 12] =
        [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    assert((day >= 1) & (day <= lengths[(month - 1) as u32]), "invalid UTC day");
    assert((hour < 24) & (minute < 60) & (second < 60), "invalid UTC time of day");
    let previous_year = year - 1;
    let leap_days = previous_year / 4 - 1969 / 4 - (previous_year / 100 - 1969 / 100)
        + (previous_year / 400 - 1969 / 400);
    let mut days = (year - 1970) * 365 + leap_days + day - 1;
    for m in 0..12 {
        if ((m + 1) as u64) < month {
            days += lengths[m];
        }
    }
    days * 86400 + hour * 3600 + minute * 60 + second
}

#[test]
fn unix_calendar_boundaries() {
    assert_eq(utc_to_unix("1970-01-01T00:00:00Z".as_bytes()), 0);
    assert_eq(utc_to_unix("2000-02-29T12:34:56Z".as_bytes()), 951827696);
    assert_eq(utc_to_unix("2100-03-01T00:00:00Z".as_bytes()), 4107542400);
}

#[test(should_fail_with = "invalid UTC day")]
fn reject_century_non_leap_day() {
    let _ = utc_to_unix("2100-02-29T00:00:00Z".as_bytes());
}

/// Last inclusive transaction timestamp for exclusive signed expiry and inclusive
/// max-age. Saturating addition preserves valid near-u64-boundary policies.
/// Caller separately checks issued<=anchor and anchor<=returned deadline.
pub fn expiry_and_max_age_deadline(issued: u64, expires: u64, max_age: u64) -> u64 {
    assert(expires > 0, "expiry must be positive");
    let remaining = 18446744073709551615 - issued;
    let capped_age = if max_age > remaining {
        remaining
    } else {
        max_age
    };
    let freshness_end = issued + capped_age;
    let expiry_end = expires - 1;
    if freshness_end < expiry_end {
        freshness_end
    } else {
        expiry_end
    }
}
#[test]
fn expiry_age_inclusion_boundaries() {
    assert(expiry_and_max_age_deadline(100, 1000, 20) == 120);
    assert(expiry_and_max_age_deadline(100, 120, 20) == 119);
    assert(expiry_and_max_age_deadline(100, 1000, 0) == 100);
    assert(
        expiry_and_max_age_deadline(18446744073709551610, 18446744073709551615, 100)
            == 18446744073709551614,
    );
    assert(
        expiry_and_max_age_deadline(0, 18446744073709551615, 18446744073709551615)
            == 18446744073709551614,
    );
}
#[test(should_fail_with = "expiry must be positive")]
fn reject_zero_inclusion_expiry() {
    let _deadline = expiry_and_max_age_deadline(0, 0, 0);
}
