//! Zupass POD adapter: one numeric entry of a POD that a pinned issuer
//! signed, as attribute evidence (`uc_attribute_gate::AttributeEvidence`),
//! without a holder signature. `zupass::assert_pod_signature` checks the
//! issuer's EdDSA-Poseidon (Baby Jubjub) signature over the POD's content id
//! (its LeanIMT root), and `zupass::assert_entry` checks the entry's
//! name/value pair in that tree.
//!
//! What it proves (category 6 without the holder key): "a POD that the
//! pinned issuer signed has entry `name` with numeric value `value`". A POD
//! is a file that its holder can copy and share, and the issuer can sign any
//! POD. Without a holder signature nothing ties the presenter to the POD, so
//! the claim is labelled `ALSO_COPY_HOLDER` and `SET_BY_NONE`, and the gate
//! accepts it only with `allow_unbound`. The holder-bound POD (category 2,
//! with `zupass::assert_holder_login`) is a different scheme.
//!
//! A POD carries no time unless an entry says so; this adapter reads none and
//! reports `issued_at = 0` (undated), so the gate accepts it only with
//! `allow_undated`. The entry name is part of `Trust.issuer`, so the terms pin
//! the issuer key and which entry the value comes from.
//!
//! Subject: one id per POD (`pod_id`: issuer key and content id). Proving
//! another entry of the same POD gives the same subject.
//!
//! Holder-bound gate (`ZupassHolderEntry`, category 2) composes this numeric
//! entry with a holder-key entry of the same issuer-signed POD. The holder
//! signs the GATE-domain caller/choice binding and stated authorization time.
//! Its trust pin covers both entry names; its subject stays the ticket POD,
//! not the login identity. The timestamp does not date or expire the ticket.
//!
//! Login link (`ZupassHolderLogin`, category 2): a POD that the pinned
//! issuer signed names a holder EdDSA-Poseidon key in the entry that the
//! terms pin, and that holder key signs the holder login POD
//! {`_aztec_link_v1_challenge`: challenge, `_aztec_link_v1_issued_at`:
//! issued_at} (`zupass::assert_holder_login`). A holder signature
//! carries no time, so the holder states one and signs it with the
//! challenge. The challenge already commits to the chain, this contract, the
//! caller and the round, and the terms' `max_age` bounds the age of the
//! signed issue time, so the POD has no account, action or expiry entry. The
//! claim has
//! source `SOURCE_CERTIFIED_KEY`, issuer `holder_issuer_pin` (issuer key and
//! holder entry name), no co-authority, binding `SET_BY_HOLDER` and identity
//! `holder_id` (the holder key). The issuer can certify keys that it holds,
//! but cannot sign for a holder key that it does not hold. The holder key is
//! the Zupass identity key, the same in every app; any POD of the issuer
//! that names it gives the same identity. A raw field signature by the
//! holder key (for example over the challenge) is not a link signature; a
//! raw signer over a POD root (`signPODRoot`) still is, and holder software
//! must not sign a POD with the `_aztec_link_v1_` entry names for another
//! party.
use aztec::{
    context::PrivateContext,
    protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}},
};
use std::meta::derive;
use uc_attribute_gate::{AttributeClaim, AttributeEvidence, KIND_POD_ENTRY};
use uc_login_link::{LinkClaim, LoginLink};
use uc_trust::{
    ALSO_COPY_HOLDER, ANCHOR_NONE, Binding, SET_BY_HOLDER, SET_BY_NONE, SOURCE_CERTIFIED_KEY, SOURCE_DOCUMENT_ISSUER,
    Trust,
};
use zupass::{
    assert_entry, assert_holder_login, assert_pod_signature, HolderLogin, numeric_value_hash, PublicKey, Signature,
};

mod tests;

/// The attribute-gating scheme id of a POD without a holder signature (the
/// holder-bound Zupass schemes use id 7).
pub global SCHEME_ZUPASS_POD: u32 = 72;

pub global DOMAIN_POD_ISSUER: Field = comptime { poseidon2_hash_bytes("MIKE_UC_POD_ISSUER_V1".as_bytes()) };
pub global DOMAIN_POD_ID: Field = comptime { poseidon2_hash_bytes("MIKE_UC_POD_ID_V1".as_bytes()) };
pub global DOMAIN_POD_HOLDER_ISSUER: Field =
    comptime { poseidon2_hash_bytes("MIKE_UC_POD_HOLDER_ISSUER_V1".as_bytes()) };
pub global DOMAIN_POD_HOLDER: Field = comptime { poseidon2_hash_bytes("MIKE_UC_POD_HOLDER_V1".as_bytes()) };

/// The login-link scheme id: the holder-bound Zupass account's id.
pub global SCHEME_ZUPASS: u32 = 7;

/// LeanIMT sibling capacity: PODs with up to 256 entries.
pub global POD_DEPTH: u32 = 8;

/// The largest accepted entry value. A POD `int` is a signed 64-bit integer;
/// the gate compares field values as integers, so negative values, which
/// would read as values near the field modulus, are refused.
pub global MAX_ENTRY_VALUE: Field = 0x7fffffffffffffff;

/// One numeric POD entry with its issuer signature and entry proof.
#[derive(Serialize, Deserialize)]
pub struct ZupassPodEntry {
    /// The issuer's Baby Jubjub public key; it enters `Trust.issuer`.
    pub issuer_x: Field,
    pub issuer_y: Field,
    /// EdDSA-Poseidon signature over `content_id`.
    pub signature_rx: Field,
    pub signature_ry: Field,
    pub signature_s: Field,
    /// The POD's LeanIMT root.
    pub content_id: Field,
    /// The POD name hash of the entry (`zupass::bytes_hash` of the name); it
    /// enters `Trust.issuer`.
    pub name_hash: Field,
    /// The entry's value. `@pcd/pod` hashes `int`, `cryptographic`,
    /// `boolean` and `date` values alike, so the type is not proven; the
    /// pinned entry name's schema must make it an `int`.
    pub value: Field,
    /// LeanIMT proof of the name/value pair: supplied upper siblings.
    pub depth: u32,
    pub indices: [bool; POD_DEPTH],
    pub siblings: [Field; POD_DEPTH],
}

/// The trust root of a deployment: the issuer key and the entry name.
pub fn issuer_pin(issuer_x: Field, issuer_y: Field, name_hash: Field) -> Field {
    poseidon2_hash([DOMAIN_POD_ISSUER, issuer_x, issuer_y, name_hash])
}

/// One id per POD of an issuer. Anyone who holds a copy can compute it.
pub fn pod_id(issuer_x: Field, issuer_y: Field, content_id: Field) -> Field {
    poseidon2_hash([DOMAIN_POD_ID, issuer_x, issuer_y, content_id])
}

impl ZupassPodEntry {
    pub fn issuer(self) -> Field {
        issuer_pin(self.issuer_x, self.issuer_y, self.name_hash)
    }
}

impl AttributeEvidence for ZupassPodEntry {
    let SCHEME: u32 = 72;

    fn verify(self, _context: &mut PrivateContext, _binding: Field) -> AttributeClaim {
        // A POD has no free signed field: the caller binding cannot enter it.
        assert(!MAX_ENTRY_VALUE.lt(self.value), "POD value out of range");
        assert_pod_signature(
            self.content_id,
            PublicKey { x: self.issuer_x, y: self.issuer_y },
            Signature { rx: self.signature_rx, ry: self.signature_ry, s: self.signature_s },
        );
        assert_entry(
            self.content_id,
            self.name_hash,
            numeric_value_hash(self.value),
            self.depth,
            self.indices,
            self.siblings,
        );
        AttributeClaim {
            trust: Trust {
                source: SOURCE_DOCUMENT_ISSUER,
                issuer: issuer_pin(self.issuer_x, self.issuer_y, self.name_hash),
                anchor_kind: ANCHOR_NONE,
                anchor: 0,
                finality: 0,
                also_authorised: ALSO_COPY_HOLDER,
            },
            kind: KIND_POD_ENTRY,
            value: self.value,
            subject: pod_id(self.issuer_x, self.issuer_y, self.content_id),
            binding: Binding { value: 0, set_by: SET_BY_NONE },
            issued_at: 0,
        }
    }
}

/// A POD that names a holder key, and that key's signature on the holder
/// login POD of the link challenge and the stated issue time. The issuer
/// key and the holder entry name enter the trust issuer, which the terms
/// pin; the holder key is the identity.
#[derive(Serialize, Deserialize)]
pub struct ZupassHolderLogin {
    /// The issuer's Baby Jubjub public key and its EdDSA-Poseidon signature
    /// over `content_id`.
    pub issuer_x: Field,
    pub issuer_y: Field,
    pub issuer_rx: Field,
    pub issuer_ry: Field,
    pub issuer_s: Field,
    /// The POD's LeanIMT root.
    pub content_id: Field,
    /// The POD name hash of the entry that holds the holder key.
    pub holder_name_hash: Field,
    /// The holder's Baby Jubjub public key (the entry's value).
    pub holder_x: Field,
    pub holder_y: Field,
    /// LeanIMT proof of the holder entry: supplied upper siblings.
    pub depth: u32,
    pub indices: [bool; POD_DEPTH],
    pub siblings: [Field; POD_DEPTH],
    /// The issue time that the holder signs with the challenge (Unix s).
    pub issued_at: u64,
    /// The holder's EdDSA-Poseidon signature on the holder login POD.
    pub holder_rx: Field,
    pub holder_ry: Field,
    pub holder_s: Field,
}

/// The trust root of a holder-bound login: the issuer key and the name of
/// the entry that holds the holder key.
pub fn holder_issuer_pin(issuer_x: Field, issuer_y: Field, holder_name_hash: Field) -> Field {
    poseidon2_hash(
        [DOMAIN_POD_HOLDER_ISSUER, issuer_x, issuer_y, holder_name_hash],
    )
}

/// The identity of a Zupass holder: the holder key.
pub fn holder_id(holder_x: Field, holder_y: Field) -> Field {
    poseidon2_hash([DOMAIN_POD_HOLDER, holder_x, holder_y])
}

impl ZupassHolderLogin {
    pub fn issuer(self) -> Field {
        holder_issuer_pin(self.issuer_x, self.issuer_y, self.holder_name_hash)
    }

    pub fn identity(self) -> Field {
        holder_id(self.holder_x, self.holder_y)
    }
}

impl LoginLink for ZupassHolderLogin {
    let SCHEME: u32 = 7;

    fn verify(self, _context: &mut PrivateContext, challenge: Field) -> LinkClaim {
        assert_holder_login(
            self.content_id,
            PublicKey { x: self.issuer_x, y: self.issuer_y },
            Signature { rx: self.issuer_rx, ry: self.issuer_ry, s: self.issuer_s },
            PublicKey { x: self.holder_x, y: self.holder_y },
            self.holder_name_hash,
            self.depth,
            self.indices,
            self.siblings,
            HolderLogin { challenge, issued_at: self.issued_at },
            Signature { rx: self.holder_rx, ry: self.holder_ry, s: self.holder_s },
        );
        LinkClaim {
            trust: Trust {
                source: SOURCE_CERTIFIED_KEY,
                issuer: self.issuer(),
                anchor_kind: ANCHOR_NONE,
                anchor: 0,
                finality: 0,
                also_authorised: 0,
            },
            identity: self.identity(),
            binding: Binding { value: challenge, set_by: SET_BY_HOLDER },
            issued_at: self.issued_at,
            expires_at: 0,
            bearer: false,
        }
    }
}

/// A numeric ticket entry and a holder entry of the same issuer-signed POD.
/// The holder signs the gate's domain-separated caller/choice binding and
/// stated authorization time using the existing reserved HolderLogin schema.
/// This time says nothing about ticket issuance, expiration or revocation.
#[derive(Serialize, Deserialize)]
pub struct ZupassHolderEntry {
    pub entry: ZupassPodEntry,
    pub holder: ZupassHolderLogin,
}

pub global DOMAIN_POD_HOLDER_ENTRY: Field = comptime { poseidon2_hash_bytes("MIKE_UC_POD_HOLDER_ENTRY_V1".as_bytes()) };

/// Pin the issuer key and both entry names. The issuer's schema must mean
/// a nonnegative int for the numeric entry and a holder key for the other.
pub fn holder_entry_issuer_pin(issuer_x: Field, issuer_y: Field, name_hash: Field, holder_name_hash: Field) -> Field {
    poseidon2_hash(
        [DOMAIN_POD_HOLDER_ENTRY, issuer_x, issuer_y, name_hash, holder_name_hash],
    )
}

impl ZupassHolderEntry {
    pub fn issuer(self) -> Field {
        holder_entry_issuer_pin(
            self.entry.issuer_x,
            self.entry.issuer_y,
            self.entry.name_hash,
            self.holder.holder_name_hash,
        )
    }
}

impl AttributeEvidence for ZupassHolderEntry {
    let SCHEME: u32 = 7;

    fn verify(self, context: &mut PrivateContext, binding: Field) -> AttributeClaim {
        assert_eq(self.entry.issuer_x, self.holder.issuer_x, "Different POD issuers");
        assert_eq(self.entry.issuer_y, self.holder.issuer_y, "Different POD issuers");
        assert_eq(self.entry.content_id, self.holder.content_id, "Different POD roots");
        let entry = self.entry.verify(context, binding);
        let holder = self.holder.verify(context, binding);
        AttributeClaim {
            trust: Trust {
                source: SOURCE_CERTIFIED_KEY,
                issuer: self.issuer(),
                anchor_kind: ANCHOR_NONE,
                anchor: 0,
                finality: 0,
                also_authorised: 0,
            },
            kind: entry.kind,
            value: entry.value,
            // One use of this ticket POD, not one use per key or person.
            subject: entry.subject,
            binding: holder.binding,
            issued_at: holder.issued_at,
        }
    }
}
