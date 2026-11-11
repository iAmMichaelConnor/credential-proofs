//! Calendar handling. Issuance time uses the shared auth_time Gregorian
//! conversion, which has no year ceiling (upstream stops at 2032).

use crate::{Date, IST_OFFSET_SECONDS};
use auth_time::utc_to_unix;

pub(crate) fn digit(byte: u8) -> u32 {
    assert((byte >= 48) & (byte <= 57), "Expected an ASCII digit");
    (byte - 48) as u32
}

pub(crate) fn digits<let K: u32>(bytes: [u8; K]) -> u32 {
    let mut value = 0;
    for i in 0..K {
        value = value * 10 + digit(bytes[i]);
    }
    value
}

/// Convert the 14 digits YYYYMMDDhhmmss of an IST wall-clock time to Unix
/// seconds and the IST calendar date. auth_time checks digits, month,
/// days in the month (leap years included), hour < 24, minute < 60 and
/// second < 60.
pub(crate) fn ist_timestamp(t: [u8; 14]) -> (u64, Date) {
    let rfc3339: [u8; 20] = [
        t[0], t[1], t[2], t[3], 45, t[4], t[5], 45, t[6], t[7], 84, t[8], t[9], 58, t[10], t[11],
        58, t[12], t[13], 90,
    ];
    let wall_clock = utc_to_unix(rfc3339);
    assert(wall_clock >= IST_OFFSET_SECONDS, "QR timestamp precedes the Unix epoch");
    let date = Date {
        year: digits([t[0], t[1], t[2], t[3]]),
        month: digits([t[4], t[5]]),
        day: digits([t[6], t[7]]),
    };
    (wall_clock - IST_OFFSET_SECONDS, date)
}

/// Parse a DD-MM-YYYY date of birth. The month must be 1 to 12 and the day
/// 1 to 31; the signed value is otherwise taken as UIDAI wrote it.
pub(crate) fn date_of_birth(b: [u8; 10]) -> Date {
    assert((b[2] == 45) & (b[5] == 45), "Date of birth must be DD-MM-YYYY");
    let date = Date {
        year: digits([b[6], b[7], b[8], b[9]]),
        month: digits([b[3], b[4]]),
        day: digits([b[0], b[1]]),
    };
    assert((date.month >= 1) & (date.month <= 12), "Invalid birth month");
    assert((date.day >= 1) & (date.day <= 31), "Invalid birth day");
    date
}

/// (birth.year + years, birth.month, birth.day) <= on, lexicographically.
/// No subtraction, so a birth date after `on` gives false, not an underflow.
pub(crate) fn age_at_least(birth: Date, on: Date, years: u32) -> bool {
    let year = birth.year + years;
    let same_year_reached =
        (birth.month < on.month) | ((birth.month == on.month) & (birth.day <= on.day));
    (year < on.year) | ((year == on.year) & same_year_reached)
}
