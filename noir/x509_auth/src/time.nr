use crate::der::Tlv;
fn pair<let N: u32>(data: BoundedVec<u8, N>, p: u32) -> u8 {
    let a = data.storage()[p];
    let b = data.storage()[p + 1];
    assert((a >= 48) & (a <= 57) & (b >= 48) & (b <= 57), "invalid DER time digit");
    (a - 48) * 10 + b - 48
}
/// X.509 UTC/GeneralizedTime with seconds, Z, and no fractions or offsets.
pub fn unix<let N: u32>(data: BoundedVec<u8, N>, node: Tlv) -> u64 {
    let utc = node.tag == 23;
    assert(utc | (node.tag == 24), "invalid DER time tag");
    assert(node.len == if utc { 13 } else { 15 }, "invalid DER time length");
    assert(data.storage()[node.end - 1] == 90, "DER time must use Z");
    let mut year = pair(data, node.content) as u32;
    let mut p = node.content + 2;
    if utc {
        year += if year < 50 { 2000 } else { 1900 };
    } else {
        year = year * 100 + pair(data, p) as u32;
        p += 2;
    }
    let month = pair(data, p);
    let day = pair(data, p + 2);
    let hour = pair(data, p + 4);
    let minute = pair(data, p + 6);
    let second = pair(data, p + 8);
    let date = [
        (year / 1000) as u8 + 48,
        ((year / 100) % 10) as u8 + 48,
        ((year / 10) % 10) as u8 + 48,
        (year % 10) as u8 + 48,
        45,
        month / 10 + 48,
        month % 10 + 48,
        45,
        day / 10 + 48,
        day % 10 + 48,
        84,
        hour / 10 + 48,
        hour % 10 + 48,
        58,
        minute / 10 + 48,
        minute % 10 + 48,
        58,
        second / 10 + 48,
        second % 10 + 48,
        90,
    ];
    auth_time::utc_to_unix(date)
}
/// 2050-01-01T00:00:00Z.
global GENERALIZED_TIME_FROM: u64 = 2524608000;
/// Certificate Validity time (RFC 5280 4.1.2.5): UTCTime for years through 2049
/// and GeneralizedTime for 2050 and later. UTCTime years 50-99 map to 1950-1999,
/// but `auth_time` rejects years before 1970, so certificate times before 1970
/// are deliberately unsupported. OCSP times (RFC 6960) use `unix` directly,
/// because they are GeneralizedTime for every year.
pub fn validity_unix<let N: u32>(data: BoundedVec<u8, N>, node: Tlv) -> u64 {
    let time = unix(data, node);
    assert(
        (node.tag == 23) | (time >= GENERALIZED_TIME_FROM),
        "GeneralizedTime before 2050 in certificate validity",
    );
    time
}
fn time_tlv<let L: u32, let M: u32>(tag: u8, text: str<L>) -> BoundedVec<u8, M> {
    let bytes = text.as_bytes();
    let mut out = [0; M];
    out[0] = tag;
    out[1] = L as u8;
    for i in 0..L {
        out[2 + i] = bytes[i];
    }
    BoundedVec::from_array(out)
}
#[test]
fn validity_utc_time_through_2049() {
    let data: BoundedVec<u8, 15> = time_tlv(23, "491231235959Z");
    assert_eq(validity_unix(data, crate::der::read(data, 0, 15)), GENERALIZED_TIME_FROM - 1);
}
#[test]
fn validity_generalized_time_from_2050() {
    let data: BoundedVec<u8, 17> = time_tlv(24, "20500101000000Z");
    assert_eq(validity_unix(data, crate::der::read(data, 0, 17)), GENERALIZED_TIME_FROM);
}
#[test(should_fail_with = "GeneralizedTime before 2050 in certificate validity")]
fn validity_rejects_generalized_time_2049() {
    let data: BoundedVec<u8, 17> = time_tlv(24, "20491231235959Z");
    let _ = validity_unix(data, crate::der::read(data, 0, 17));
}
#[test]
fn ocsp_time_keeps_generalized_time_before_2050() {
    let data: BoundedVec<u8, 17> = time_tlv(24, "20300101000000Z");
    assert_eq(unix(data, crate::der::read(data, 0, 17)), 1893456000);
}
// UTCTime 69 maps to 1969; every other field is valid.
#[test(should_fail_with = "UTC year before 1970")]
fn validity_rejects_utc_time_before_1970() {
    let data: BoundedVec<u8, 15> = time_tlv(23, "691231235959Z");
    let _ = validity_unix(data, crate::der::read(data, 0, 15));
}
#[test]
fn utc_generalized_agree() {
    let a = BoundedVec::<u8, 15>::from_array([
        23, 13, 50, 54, 49, 48, 50, 50, 49, 50, 48, 48, 48, 48, 90,
    ]);
    let b = BoundedVec::<u8, 17>::from_array([
        24, 15, 50, 48, 50, 54, 49, 48, 50, 50, 49, 50, 48, 48, 48, 48, 90,
    ]);
    assert(unix(a, crate::der::read(a, 0, 15)) == unix(b, crate::der::read(b, 0, 17)));
}
