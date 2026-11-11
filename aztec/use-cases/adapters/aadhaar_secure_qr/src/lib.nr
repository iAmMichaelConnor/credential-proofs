//! Native Aadhaar Secure QR adapter: a UIDAI-signed Secure QR (V2 layout) as
//! attribute evidence (`uc_attribute_gate::AttributeEvidence`). The QR is
//! verified by `aadhaar_secure_qr` inside the gate's private function:
//! RSA-2048 PKCS#1 v1.5 SHA-256 under the issuer key whose hash the terms
//! pin, the signed layout, and the issuance time.
//!
//! What it proves (category 6, a static document): "someone holds a QR that
//! UIDAI signed for a person who had reached 18 years on the issuance date,
//! issued at most `max_age` seconds before the anchor block". UIDAI signs no
//! value that the holder chooses at use time, and hotels, banks and KYC
//! services routinely receive copies. So the claim is labelled
//! `ALSO_COPY_HOLDER` and `SET_BY_NONE`: anyone with a copy can make the same
//! presentation, from any account. The gate accepts it only with
//! `allow_unbound`, and the core caps the terms' `max_age` at
//! `MAX_BEARER_AGE`.
//!
//! Subject: one id per signed QR (`credential_id`), not per person. A new QR
//! download gives a new id. Per-person uniqueness is the uniqueness use
//! case; this adapter does not use the library's demographic nullifier.
//!
//! Privacy rule of the library: never publish `issued_at` or a value derived
//! from it (UIDAI logs QR downloads). The adapter therefore checks the QR age
//! itself (`assert_fresh` against the anchor block timestamp, with the pinned
//! `max_age` and `MAX_FUTURE`) and reports the anchor timestamp as
//! `issued_at`. The core then limits inclusion to the anchor timestamp plus
//! the terms' `max_age`, and the adapter limits it to the anchor timestamp
//! plus `MAX_BEARER_AGE - max_age`. Both limits depend only on the anchor and
//! pinned values, not on the QR time. Since the QR is at most `max_age` old
//! at the anchor block, it is at most `MAX_BEARER_AGE` old (the copy-holder
//! ceiling of `uc_trust`) when the transaction is included. The adapter
//! refuses a pinned `max_age` above `MAX_BEARER_AGE - MIN_INCLUSION_WINDOW`:
//! such a pin leaves less than `MIN_INCLUSION_WINDOW` after the anchor for
//! inclusion (none at `MAX_BEARER_AGE`), and a transaction anchored to an
//! older block has less still.
use aadhaar_secure_qr::{DELIMITERS, issuer_key_hash, KEY_LIMBS, SecureQrInput, UPSTREAM_MAX_SIGNED_BYTES};
use aztec::{
    context::PrivateContext,
    protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}},
};
use std::meta::derive;
use uc_attribute_gate::{AttributeClaim, AttributeEvidence, KIND_AGE_AT_LEAST_18};
use uc_trust::{ALSO_COPY_HOLDER, ANCHOR_NONE, Binding, MAX_BEARER_AGE, SET_BY_NONE, SOURCE_DOCUMENT_ISSUER, Trust};

mod tests;

/// The attribute-gating scheme id of the native Secure QR.
pub global SCHEME_AADHAAR_SECURE_QR: u32 = 70;

pub global DOMAIN_AADHAAR_ISSUER: Field = comptime { poseidon2_hash_bytes("MIKE_UC_AADHAAR_QR_ISSUER_V1".as_bytes()) };
pub global DOMAIN_AADHAAR_CREDENTIAL: Field =
    comptime { poseidon2_hash_bytes("MIKE_UC_AADHAAR_QR_CREDENTIAL_V1".as_bytes()) };

/// Signed-byte capacity: the upstream limit (1536 SHA-256-padded bytes).
pub global N: u32 = UPSTREAM_MAX_SIGNED_BYTES;

/// Accepted issuance time after the anchor block, for anchor lag and clock
/// skew (the library's recommended policy).
pub global MAX_FUTURE: u64 = 900;

/// The shortest inclusion window, after the anchor timestamp, that a pinned
/// `max_age` must leave: `max_age <= MAX_BEARER_AGE - MIN_INCLUSION_WINDOW`
/// (13800 s). Ten minutes, for proving and inclusion.
pub global MIN_INCLUSION_WINDOW: u64 = 600;

/// The age that `KIND_AGE_AT_LEAST_18` reports: inclusive, on the issuance
/// date in IST (`SecureQr::age_at_least`). Upstream `ageAbove18` means more
/// than 18 whole years instead.
pub global ADULT_YEARS: u32 = 18;

/// A decompressed Secure QR and the maximum age that the terms accept.
/// Every field is prover-supplied: the library checks the signature, the
/// layout and the delimiter hints, and `issuer()` puts the modulus and
/// `max_age` into `Trust.issuer`, which the terms pin.
#[derive(Serialize, Deserialize)]
pub struct AadhaarSecureQr {
    /// Decompressed payload without the trailing 256-byte signature.
    pub signed_data: BoundedVec<u8, N>,
    /// RSA-2048 signature, modulus and Barrett parameter, 18 x 120-bit limbs.
    pub signature: [Field; KEY_LIMBS],
    pub modulus: [Field; KEY_LIMBS],
    pub redc: [Field; KEY_LIMBS],
    /// Hint: the indices of the first 18 bytes equal to 255.
    pub delimiters: [u32; DELIMITERS],
    /// Maximum QR age at the anchor block, in seconds, inclusive from zero to
    /// `MAX_BEARER_AGE - MIN_INCLUSION_WINDOW`. Zero still allows issuance
    /// up to `MAX_FUTURE` seconds after the anchor.
    pub max_age: u64,
}

/// The trust root of a deployment: the UIDAI key (its upstream-compatible
/// hash) and the maximum QR age.
pub fn issuer_pin(key_hash: Field, max_age: u64) -> Field {
    poseidon2_hash([DOMAIN_AADHAAR_ISSUER, key_hash, max_age as Field])
}

/// One id per signed QR: the issuer key hash and the signature, which the
/// RSA check binds to the signed bytes. It does not depend on the issuance
/// time, so publishing the gate nullifier reveals no time. Anyone who holds
/// a copy of the QR can compute it.
pub fn credential_id(key_hash: Field, signature: [Field; KEY_LIMBS]) -> Field {
    poseidon2_hash(
        [DOMAIN_AADHAAR_CREDENTIAL, key_hash, poseidon2_hash(signature)],
    )
}

/// The published upstream test key (`testPublicKey.pem`). Never pin it
/// outside tests: anyone can sign a QR for any identity with it.
pub use aadhaar_secure_qr::UPSTREAM_TEST_ISSUER_KEY_HASH;

impl AadhaarSecureQr {
    /// The upstream-compatible hash of the supplied modulus.
    pub fn key_hash(self) -> Field {
        issuer_key_hash(self.modulus)
    }

    pub fn issuer(self) -> Field {
        issuer_pin(self.key_hash(), self.max_age)
    }

    /// The subject that `verify` reports for this QR.
    pub fn credential_id(self) -> Field {
        credential_id(self.key_hash(), self.signature)
    }
}

impl AttributeEvidence for AadhaarSecureQr {
    let SCHEME: u32 = 70;

    fn verify(self, context: &mut PrivateContext, _binding: Field) -> AttributeClaim {
        // A QR has no free signed field: the caller binding cannot enter it.
        // MAX_BEARER_AGE (14400) > MIN_INCLUSION_WINDOW (600): no underflow.
        assert(
            self.max_age <= MAX_BEARER_AGE - MIN_INCLUSION_WINDOW,
            "Aadhaar QR maximum age leaves too short an inclusion window",
        );
        let key_hash = issuer_key_hash(self.modulus);
        let qr = aadhaar_secure_qr::verify(
            SecureQrInput {
                signed_data: self.signed_data,
                signature: self.signature,
                modulus: self.modulus,
                redc: self.redc,
                delimiters: self.delimiters,
            },
            key_hash,
        );
        let now = context.get_anchor_block_header().timestamp();
        qr.assert_fresh(now, self.max_age, MAX_FUTURE);
        // The QR is at most `max_age` old at the anchor block, so this keeps it
        // at most `MAX_BEARER_AGE` old at inclusion, from the anchor alone.
        context.set_expiration_timestamp(now + (MAX_BEARER_AGE - self.max_age));
        AttributeClaim {
            trust: Trust {
                source: SOURCE_DOCUMENT_ISSUER,
                issuer: issuer_pin(key_hash, self.max_age),
                anchor_kind: ANCHOR_NONE,
                anchor: 0,
                finality: 0,
                also_authorised: ALSO_COPY_HOLDER,
            },
            kind: KIND_AGE_AT_LEAST_18,
            value: qr.age_at_least(ADULT_YEARS) as Field,
            subject: credential_id(key_hash, self.signature),
            binding: Binding { value: 0, set_by: SET_BY_NONE },
            // The anchor time, not the QR time (privacy rule, see above).
            issued_at: now,
        }
    }
}
