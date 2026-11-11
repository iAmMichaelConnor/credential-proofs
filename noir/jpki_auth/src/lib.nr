//! JPKI (Japanese My Number card) holder authentication.
//!
//! `authorise` verifies an RSA-2048/SHA-256 holder signature over the 128-byte
//! `challenge(account, action, session)` and returns the earliest signed expiry.
//! It proves possession of the enrolled card authentication key; it discloses
//! no My Number, name, address, birth date or nationality.
//! - Chain: the holder certificate is issued directly by the pinned root, has
//!   digitalSignature without CA usages and the card policy
//!   `1.2.392.200149.8.5.1.3.30`, and its SPKI SHA-256 equals the enrolled value.
//! - Anchors: class 0 accepts only the JPKI user-authentication roots CA03
//!   (2023, DER SHA-256 `64114f29...c322b5`) and CA02 (2019, `0d98de47...1fade6`),
//!   matched against JPKI's published fingerprint table; class 1 is an explicit
//!   local-test namespace that enrolment must choose deliberately.
//! - Revocation is mandatory: one signed `good` OCSP SingleResponse (profile in
//!   `x509_auth::ocsp`) from the issuer or a directly issued responder with
//!   OCSPSigning and id-pkix-ocsp-nocheck, thisUpdate at most `max_ocsp_age`
//!   (at most one day) old and nextUpdate after `now`. Certificate and responder
//!   validity also bound the returned expiry.
//! - Capacities: certificates and responder certificates up to 2048 bytes, OCSP
//!   up to 4096 bytes.
//! `AuthPolicy` is immutable account enrolment and `now` a trusted time. This is
//! a standards profile; local fixtures use a synthetic authority, and live JPKI
//! OCSP interoperability is not claimed.
use sha256::sha256_var;
use x509_auth::{certificate::{hash_tlv, parse, verify_signature}, crypto::Rsa2048Key};
pub struct AuthInput {
    pub root: BoundedVec<u8, 2048>,
    pub certificate: BoundedVec<u8, 2048>,
    pub responder: BoundedVec<u8, 2048>,
    pub ocsp: BoundedVec<u8, 4096>,
    pub holder_signature: [u8; 256],
    pub root_redc: [u128; 18],
    pub holder_redc: [u128; 18],
    pub responder_redc: [u128; 18],
}
pub struct AuthPolicy {
    /// 0 = official JPKI user-authentication CA02 or CA03; 1 = explicit local test root.
    pub anchor_class: u8,
    pub root_sha256: [u8; 32],
    pub holder_spki_sha256: [u8; 32],
    pub max_ocsp_age: u64,
}
pub fn official_root_sha256() -> [u8; 32] {
    [
        0x64, 0x11, 0x4f, 0x29, 0x62, 0x0c, 0x24, 0xed, 0x26, 0x31, 0xd4, 0x64, 0x76, 0xa0, 0x40,
        0xe7, 0xee, 0x74, 0x0d, 0x95, 0x60, 0x89, 0xc0, 0x0b, 0x03, 0x6a, 0x6a, 0x81, 0x18, 0xc3,
        0x22, 0xb5,
    ]
}
pub fn official_root_2019_sha256() -> [u8; 32] {
    [
        0x0d, 0x98, 0xde, 0x47, 0xfc, 0x11, 0xb7, 0xf6, 0x71, 0x26, 0x87, 0x4b, 0x70, 0x28, 0xb6,
        0x02, 0x6a, 0x80, 0x3d, 0x26, 0x38, 0xd6, 0xed, 0xfe, 0x53, 0x17, 0x69, 0x53, 0x96, 0x1f,
        0xad, 0xe6,
    ]
}
/// Domain-separated fixed-length challenge: domain || account || action || session.
pub fn challenge(account: [u8; 32], action: [u8; 32], session: [u8; 32]) -> [u8; 128] {
    let domain = "MIKE_JPKI_CARD_AUTH_V1__________".as_bytes();
    let mut bytes = [0; 128];
    for i in 0..32 {
        bytes[i] = domain[i];
        bytes[32 + i] = account[i];
        bytes[64 + i] = action[i];
        bytes[96 + i] = session[i];
    }
    bytes
}
/// Returns the earliest signed expiry. Policy is immutable account enrollment.
/// Synthetic roots are explicitly class1; production enrollment must choose0.
pub fn authorise(
    input: AuthInput,
    policy: AuthPolicy,
    account: [u8; 32],
    action: [u8; 32],
    session: [u8; 32],
    now: u64,
) -> u64 {
    assert(policy.anchor_class <= 1, "unknown JPKI trust class");
    if policy.anchor_class == 0 {
        assert(
            (policy.root_sha256 == official_root_sha256())
                | (policy.root_sha256 == official_root_2019_sha256()),
            "unapproved JPKI root",
        );
    }
    assert(
        sha256_var(input.root.storage(), input.root.len()) == policy.root_sha256,
        "root pin mismatch",
    );
    assert(
        (policy.max_ocsp_age > 0) & (policy.max_ocsp_age <= 86400),
        "invalid OCSP freshness policy",
    );
    let root = parse(input.root);
    let leaf = parse(input.certificate);
    assert((now >= root.not_before) & (now < root.not_after), "root outside validity");
    assert(
        hash_tlv(input.root, root.subject) == hash_tlv(input.root, root.issuer),
        "root is not self-issued",
    );
    assert(
        hash_tlv(input.certificate, leaf.issuer) == hash_tlv(input.root, root.subject),
        "holder issuer mismatch",
    );
    assert(
        x509_auth::certificate::hash_spki(input.certificate, leaf) == policy.holder_spki_sha256,
        "holder key mismatch",
    );
    let policy_oid = BoundedVec::<u8, 32>::from_array([42, 131, 8, 140, 155, 85, 8, 5, 1, 3, 30]);
    x509_auth::extensions::purpose(input.root, root.extensions, 0, policy_oid);
    x509_auth::extensions::purpose(input.certificate, leaf.extensions, 1, policy_oid);
    let root_key = Rsa2048Key { modulus: root.modulus, redc: input.root_redc };
    verify_signature(input.certificate, leaf, root_key, now);
    // An issuer-signed response needs no delegated certificate. Otherwise require
    // a directly root-issued responder with OCSPSigning + id-pkix-ocsp-nocheck.
    let direct = input.responder.len() == 0;
    let responder_data = if direct { input.root } else { input.responder };
    let responder = parse(responder_data);
    let mut signer = root_key;
    if !direct {
        assert(
            hash_tlv(responder_data, responder.issuer) == hash_tlv(input.root, root.subject),
            "OCSP signer issuer mismatch",
        );
        x509_auth::extensions::purpose(responder_data, responder.extensions, 2, policy_oid);
        verify_signature(responder_data, responder, root_key, now);
        signer = Rsa2048Key { modulus: responder.modulus, redc: input.responder_redc };
    }
    let ocsp_expiry = x509_auth::ocsp::good(
        input.ocsp,
        input.certificate,
        leaf,
        input.root,
        root,
        responder_data,
        responder,
        signer,
        now,
        policy.max_ocsp_age,
    );
    let message = challenge(account, action, session);
    x509_auth::crypto::verify_digest(
        Rsa2048Key { modulus: leaf.modulus, redc: input.holder_redc },
        sha256::digest(message),
        input.holder_signature,
    );
    let mut expiry = leaf.not_after;
    if root.not_after < expiry {
        expiry = root.not_after;
    }
    if responder.not_after < expiry {
        expiry = responder.not_after;
    }
    if ocsp_expiry < expiry {
        expiry = ocsp_expiry;
    }
    expiry
}
mod benchmarks;
mod known_answer_tests;
