//! PhilSys adapter: a legacy PhilID JSON QR signed by the Philippine
//! Statistics Authority (PSA) as attribute evidence
//! (`uc_attribute_gate::AttributeEvidence`). `philsys_auth` rebuilds the
//! official signed serialization from the fields, checks its SHA-256 against
//! `credential_digest` and the strict prime-subgroup Ed25519 signature under
//! the issuer key that the terms pin.
//!
//! What it proves (category 6, a static document): "a PhilID QR with these
//! fields exists and the pinned key signed it" (`KIND_ISSUER_AUTHENTIC`,
//! value 1). It does not prove that the presenter is the holder, that the
//! card is still active, or any biometric. The QR is printed on the card and
//! is copied by anyone who sees or scans it, so the claim is labelled
//! `ALSO_COPY_HOLDER` and `SET_BY_NONE`, and the gate accepts it only with
//! `allow_unbound`.
//!
//! The legacy QR carries `DateIssued`, a card issuance date, not a
//! presentation time; it says nothing about how old a copy is. The adapter
//! reports `issued_at = 0` (undated), so the gate accepts it only with
//! `allow_undated`, and an old copy works as well as a new one.
//!
//! Subject: one id per signed serialization (`credential_id`), not per
//! person. The library's `credential_digest` is the SHA-256 that the old
//! account enrolled; here it is a prover-supplied value that the library
//! checks against the signed bytes, so it costs no second hash.
use aztec::{
    context::PrivateContext,
    protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}},
};
use ed25519_auth::PointHint;
use philsys_auth::{AuthInput, AuthPolicy};
use std::meta::derive;
use uc_attribute_gate::{AttributeClaim, AttributeEvidence, KIND_ISSUER_AUTHENTIC};
use uc_trust::{ALSO_COPY_HOLDER, ANCHOR_NONE, Binding, bytes::halves, SET_BY_NONE, SOURCE_DOCUMENT_ISSUER, Trust};

mod fixture;
mod tests;

/// The attribute-gating scheme id of the legacy PhilID QR.
pub global SCHEME_PHILSYS: u32 = 71;

pub global DOMAIN_PHILSYS_ISSUER: Field = comptime { poseidon2_hash_bytes("MIKE_UC_PHILSYS_ISSUER_V1".as_bytes()) };
pub global DOMAIN_PHILSYS_CREDENTIAL: Field =
    comptime { poseidon2_hash_bytes("MIKE_UC_PHILSYS_CREDENTIAL_V1".as_bytes()) };

/// An Ed25519 point hint (`ed25519_auth::PointHint`, which has no
/// serialisation for a function ABI). Hints steer witness generation; the
/// library checks the points they give.
#[derive(Serialize, Deserialize)]
pub struct Point {
    pub x_limbs: [u128; 3],
    pub y_limbs: [u128; 3],
}

impl Point {
    fn hint(self) -> PointHint {
        PointHint { x_limbs: self.x_limbs, y_limbs: self.y_limbs }
    }
}

/// The QR fields in the official order (Latin-1 bytes, at most 64 each), the
/// signature with its point hints, the issuer key that the terms pin, and the
/// SHA-256 of the official signed serialization.
#[derive(Serialize, Deserialize)]
pub struct PhilsysQr {
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
    pub issuer_hint: Point,
    pub signature_hint: Point,
    /// The PSA Ed25519 public key; it enters `Trust.issuer`.
    pub issuer_key: [u8; 32],
    /// SHA-256 of the signed serialization; the library checks it.
    pub credential_digest: [u8; 32],
}

/// The trust root of a deployment: the PSA Ed25519 key.
pub fn issuer_pin(issuer_key: [u8; 32]) -> Field {
    let (high, low) = halves(issuer_key);
    poseidon2_hash([DOMAIN_PHILSYS_ISSUER, high, low])
}

/// One id per signed serialization. Anyone who holds a copy can compute it.
pub fn credential_id(issuer_key: [u8; 32], digest: [u8; 32]) -> Field {
    let (key_high, key_low) = halves(issuer_key);
    let (high, low) = halves(digest);
    poseidon2_hash([DOMAIN_PHILSYS_CREDENTIAL, key_high, key_low, high, low])
}

impl PhilsysQr {
    pub fn issuer(self) -> Field {
        issuer_pin(self.issuer_key)
    }

    /// Verifies the QR and returns its claim. It reads no context, so
    /// `verify` is this function; tests can also run it before a TXE
    /// session exists (the Brillig Ed25519 check takes minutes).
    pub fn claim(self) -> AttributeClaim {
        // The QR has no free signed field: the caller binding cannot enter it.
        AuthInput {
            date_issued: self.date_issued,
            suffix: self.suffix,
            last_name: self.last_name,
            first_name: self.first_name,
            middle_name: self.middle_name,
            sex: self.sex,
            blood_finger: self.blood_finger,
            date_of_birth: self.date_of_birth,
            place_of_birth: self.place_of_birth,
            pcn: self.pcn,
            signature: self.signature,
            issuer_hint: self.issuer_hint.hint(),
            signature_hint: self.signature_hint.hint(),
        }
            .verify(AuthPolicy { issuer_key: self.issuer_key, credential_digest: self.credential_digest });
        AttributeClaim {
            trust: Trust {
                source: SOURCE_DOCUMENT_ISSUER,
                issuer: issuer_pin(self.issuer_key),
                anchor_kind: ANCHOR_NONE,
                anchor: 0,
                finality: 0,
                also_authorised: ALSO_COPY_HOLDER,
            },
            kind: KIND_ISSUER_AUTHENTIC,
            value: 1,
            subject: credential_id(self.issuer_key, self.credential_digest),
            binding: Binding { value: 0, set_by: SET_BY_NONE },
            issued_at: 0,
        }
    }
}

impl AttributeEvidence for PhilsysQr {
    let SCHEME: u32 = 71;

    fn verify(self, _context: &mut PrivateContext, _binding: Field) -> AttributeClaim {
        self.claim()
    }
}
