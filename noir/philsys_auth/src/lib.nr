//! Legacy PSA PhilID JSON QR, strict prime-subgroup Ed25519 profile.
//! Verifies issuer authenticity only; it does not prove rightful-holder status.
//!
//! `AuthInput::verify` checks the PSA Ed25519 signature (the strict `ed25519_auth`
//! profile) over the official `formatVersion1` serialization reconstructed from
//! the fields (raw QR whitespace and order are not signed) and binds its SHA-256
//! to the consumer-enrolled credential digest. Supported: the old PhilID JSON
//! with `Issuer: PSA`, `alg: EDDSA`, each string at most 64 Latin1 bytes without
//! quotes, backslashes or control bytes, fields in their signed spelling (`?`
//! for ñ/Ñ, as the host importer emits). Current COSE/ePhilID and Digital
//! National ID are different formats and are not interpreted as this profile.
//! It proves nothing about current activation, revocation, biometrics or holder
//! control: a static QR can be copied, so this is never account ownership. The
//! issuer key comes from an authenticated registry (public source:
//! verify.philsys.gov.ph). The upstream SHA-512 encoding path emits an
//! unsuppressed manual-constraint diagnostic; a bounded review of the hints
//! found no missing relation for the current callers, which is not a proof.
use ed25519_auth::PointHint;
use sha256::sha256_var;

/// Latin1 demographic fields in their signed spelling. The official verifier
/// signs ñ and Ñ as `?`, so the issuer cannot tell them from a literal `?`.
/// Each field must hold the signed bytes: `value` rejects ñ (241) and Ñ (209),
/// so every signed message has exactly one encoding in these fields.
pub struct AuthInput {
    pub date_issued: BoundedVec<u8, 64>,
    pub suffix: BoundedVec<u8, 64>,
    pub last_name: BoundedVec<u8, 64>,
    pub first_name: BoundedVec<u8, 64>,
    pub middle_name: BoundedVec<u8, 64>,
    pub sex: BoundedVec<u8, 64>,
    pub blood_finger: BoundedVec<u8, 64>,
    pub date_of_birth: BoundedVec<u8, 64>,
    pub place_of_birth: BoundedVec<u8, 64>,
    pub pcn: BoundedVec<u8, 64>,
    pub signature: [u8; 64],
    pub issuer_hint: PointHint,
    pub signature_hint: PointHint,
}
pub struct AuthPolicy {
    /// Authenticated issuer registry key, never supplied by the QR itself.
    pub issuer_key: [u8; 32],
    /// SHA256 of exact official signed serialization, enrolled by consumer.
    pub credential_digest: [u8; 32],
}
fn literal<let N: u32>(mut out: BoundedVec<u8, 1024>, bytes: [u8; N]) -> BoundedVec<u8, 1024> {
    out.extend_from_array(bytes);
    out
}
/// Appends one field. The serialization is injective: JSON-breaking bytes are
/// rejected, and so are ñ (241) and Ñ (209), which the issuer signs as `?`
/// (63). A field therefore holds exactly the signed bytes.
fn value(mut out: BoundedVec<u8, 1024>, field: BoundedVec<u8, 64>) -> BoundedVec<u8, 1024> {
    assert(field.len() <= 64, "PhilSys field exceeds capacity");
    for i in 0..64 {
        if i < field.len() {
            let b = field.storage()[i];
            assert(
                (b >= 32) & (b != 34) & (b != 92) & (b != 127),
                "PhilSys field contains unsupported JSON character",
            );
            assert((b != 241) & (b != 209), "PhilSys field must spell an enye as the signed ?");
            out.push(b);
        }
    }
    out
}
impl AuthInput {
    pub fn signed_message(self) -> BoundedVec<u8, 1024> {
        let mut out = BoundedVec::new();
        out = literal(out, "{\n  \"DateIssued\": \"".as_bytes());
        out = value(out, self.date_issued);
        out = literal(
            out,
            "\",\n  \"Issuer\": \"PSA\",\n  \"subject\": {\n    \"Suffix\": \"".as_bytes(),
        );
        out = value(out, self.suffix);
        out = literal(out, "\",\n    \"lName\": \"".as_bytes());
        out = value(out, self.last_name);
        out = literal(out, "\",\n    \"fName\": \"".as_bytes());
        out = value(out, self.first_name);
        out = literal(out, "\",\n    \"mName\": \"".as_bytes());
        out = value(out, self.middle_name);
        out = literal(out, "\",\n    \"sex\": \"".as_bytes());
        out = value(out, self.sex);
        out = literal(out, "\",\n    \"BF\": \"".as_bytes());
        out = value(out, self.blood_finger);
        out = literal(out, "\",\n    \"DOB\": \"".as_bytes());
        out = value(out, self.date_of_birth);
        out = literal(out, "\",\n    \"POB\": \"".as_bytes());
        out = value(out, self.place_of_birth);
        out = literal(out, "\",\n    \"PCN\": \"".as_bytes());
        out = value(out, self.pcn);
        literal(out, "\"\n  },\n  \"alg\": \"EDDSA\"\n}".as_bytes())
    }
    /// Verifies PSA issuer authenticity and the consumer-enrolled credential
    /// digest. This does not prove that the presenter is the rightful holder or
    /// that the credential remains active.
    pub fn verify(self, policy: AuthPolicy) {
        let message = self.signed_message();
        assert(
            sha256_var(message.storage(), message.len()) == policy.credential_digest,
            "wrong enrolled PhilSys credential",
        );
        ed25519_auth::verify(
            policy.issuer_key,
            self.signature,
            message,
            self.issuer_hint,
            self.signature_hint,
        );
    }
}

mod fixture;
mod verification_tests;

mod serialization_tests;
mod serialization_vectors;
pub mod benchmarks;
