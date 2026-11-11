//! Secure QR V2 layout. Field k (1-based, as in upstream constants.circom)
//! lies between delimiters k-1 and k (0-based hints):
//! 0 "V2" | 1 email/mobile indicator | 2 reference id | 3 name | 4 date of
//! birth | 5 gender | 6-10 address | 11 PIN code | 12 post office | 13 state |
//! 14-16 address | 17 last four mobile digits | after delimiter 17: photo.
//! Only bytes before the photo delimiter are delimiters; the photo may
//! contain 255.

use crate::{date, DELIMITERS, SecureQr};

/// Check the delimiter hints and the fixed V2 prefix, then extract the
/// issuance time, date of birth and Aadhaar digits. The signature must be
/// checked separately (`verify` does this first).
pub(crate) fn parse<let N: u32>(
    data: BoundedVec<u8, N>,
    d: [u32; DELIMITERS],
    issuer_key_hash: Field,
) -> SecureQr<N> {
    let length = data.len();
    assert(length <= N, "Signed data exceeds capacity");
    let bytes = data.storage();

    // Fixed V2 prefix: "V2", 255, one indicator digit, 255, a 21-digit
    // reference id (4 Aadhaar digits and YYYYMMDDhhmmssSSS in IST), 255.
    assert((bytes[0] == 86) & (bytes[1] == 50), "Not a Secure QR V2 payload");
    assert((d[0] == 2) & (d[1] == 4) & (d[2] == 26), "Unexpected Secure QR V2 layout");
    assert((bytes[2] == 255) & (bytes[4] == 255) & (bytes[26] == 255), "Delimiter hint is not 255");

    // Hints are strictly increasing, inside the signed bytes, and each one is
    // a delimiter byte.
    for k in 0..DELIMITERS - 1 {
        assert(d[k] < d[k + 1], "Delimiter hints must increase");
    }
    let photo_delimiter = d[DELIMITERS - 1];
    assert(photo_delimiter < length, "Photo delimiter is outside the signed data");
    for k in 3..DELIMITERS {
        assert(bytes[d[k]] == 255, "Delimiter hint is not 255");
    }
    // Exactly 17 bytes equal to 255 lie before the photo delimiter, so the
    // hints are the first 18 occurrences and no delimiter was skipped.
    let mut before_photo: Field = 0;
    for i in 0..N {
        let counted = (i < photo_delimiter) & (bytes[i] == 255);
        before_photo += counted as Field;
    }
    assert(before_photo == (DELIMITERS - 1) as Field, "Delimiter hints skip a delimiter");

    assert((bytes[3] >= 48) & (bytes[3] <= 51), "Invalid email/mobile indicator");
    let aadhaar_last4 = date::digits([bytes[5], bytes[6], bytes[7], bytes[8]]);
    let mut stamp = [0; 14];
    for i in 0..14 {
        stamp[i] = bytes[9 + i];
    }
    let _milliseconds = date::digits([bytes[23], bytes[24], bytes[25]]);
    let (issued_at, issued_ist) = date::ist_timestamp(stamp);

    // The name length is checked only where the name is used
    // (`identity_commitment`), so attribute checks accept any name length.
    assert(d[4] == d[3] + 11, "Date of birth must be DD-MM-YYYY");
    let mut dob = [0; 10];
    for i in 0..10 {
        dob[i] = bytes[d[3] + 1 + i];
    }
    let birth = date::date_of_birth(dob);

    SecureQr { data, delimiters: d, issuer_key_hash, issued_at, issued_ist, birth, aadhaar_last4 }
}
