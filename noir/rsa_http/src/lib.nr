//! RSA-2048/SHA256 response envelope: timestamp LF nonce LF raw-body LF.
//! Timestamp units are fixed by the provider wrapper and trusted clock.
//!
//! `verify_response` checks an RSA-2048 PKCS#1 v1.5 SHA-256 signature over the
//! exact bytes and returns the digest. The timestamp is canonical decimal (at
//! most u64), not after `now` and at most `max_age` old, in the provider's unit
//! (Alipay v3 milliseconds, WeChat Pay v3 seconds: use the provider wrapper).
//! The nonce is 1 to 128 bytes of printable ASCII; the body is nonempty and
//! signed as supplied, never reserialised.
//!
//! Caller obligations: `key` is the provider's authenticated platform key, not
//! a key or certificate the response names; `now` is trusted. This verifies the
//! envelope only: it reads no response claims and does not bind the request
//! (URL, method, body), and the response nonce is the provider's, not a caller
//! challenge.
pub use rsa_signature::RSAPubkey;

pub fn verify_response<let N: u32>(
    timestamp: BoundedVec<u8, 20>,
    nonce: BoundedVec<u8, 128>,
    body: BoundedVec<u8, N>,
    signature: [Field; 18],
    key: RSAPubkey<18>,
    now: u64,
    max_age: u64,
) -> [u8; 32] {
    let issued = parse_timestamp(timestamp);
    assert(issued <= now, "future response timestamp");
    assert(now - issued <= max_age, "stale response");
    assert((nonce.len() > 0) & (nonce.len() <= 128), "invalid response nonce length");
    assert((body.len() > 0) & (body.len() <= N), "invalid response length");
    let mut signed_storage = [0; N + 151];
    let mut signed_len = 0;
    for i in 0..20 {
        if i < timestamp.len() {
            signed_storage[signed_len] = timestamp.storage()[i];
            signed_len += 1;
        }
    }
    signed_storage[signed_len] = 10;
    signed_len += 1;
    for i in 0..128 {
        if i < nonce.len() {
            let c = nonce.storage()[i];
            assert((c >= 33) & (c <= 126), "invalid response nonce byte");
            signed_storage[signed_len] = c;
            signed_len += 1;
        }
    }
    signed_storage[signed_len] = 10;
    signed_len += 1;
    for i in 0..N {
        if i < body.len() {
            signed_storage[signed_len] = body.storage()[i];
            signed_len += 1;
        }
    }
    signed_storage[signed_len] = 10;
    signed_len += 1;
    assert(signed_len <= N + 151, "signed response exceeds capacity");
    let signed = BoundedVec::from_parts(signed_storage, signed_len);
    key.verify_rsa_sha256_pkcs1v15(signed, signature)
}

fn parse_timestamp(timestamp: BoundedVec<u8, 20>) -> u64 {
    assert((timestamp.len() > 0) & (timestamp.len() <= 20), "invalid timestamp length");
    assert((timestamp.len() == 1) | (timestamp.storage()[0] != 48), "noncanonical timestamp");
    let mut value: u64 = 0;
    for i in 0..20 {
        if i < timestamp.len() {
            let c = timestamp.storage()[i];
            assert((c >= 48) & (c <= 57), "timestamp must be decimal");
            let digit = (c - 48) as u64;
            assert(value <= (18446744073709551615 - digit) / 10, "timestamp exceeds u64");
            value = value * 10 + digit;
        }
    }
    value
}

#[test]
fn timestamp_boundaries() {
    assert_eq(parse_timestamp(BoundedVec::from_array("0".as_bytes())), 0);
    assert_eq(
        parse_timestamp(BoundedVec::from_array("18446744073709551615".as_bytes())),
        18446744073709551615,
    );
}

#[test(should_fail_with = "timestamp exceeds u64")]
fn reject_timestamp_alias() {
    let _ = parse_timestamp(BoundedVec::from_array("18446744073709551616".as_bytes()));
}
