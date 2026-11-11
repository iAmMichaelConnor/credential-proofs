//! JPKI adapter: a signature by the user-authentication key of a My Number
//! card, certified by the JPKI user-authentication CA, as login-link
//! evidence (`uc_login_link::LoginLink`, category 2).
//!
//! `jpki_auth::authorise` (noir/jpki_auth) checks
//! the root against its pinned SHA-256 (anchor class 0 accepts only the
//! official 2019 and 2023 roots; class 1 is a local test root), the holder
//! certificate under that root with the JPKI card policy, a fresh `good`
//! OCSP response at the anchor time, that the certificate's key hashes to
//! `holder_spki_sha256`, and the card's RSA-2048 signature over the fixed
//! challenge `MIKE_JPKI_CARD_AUTH_V1 || account || action || session`. It
//! returns the earliest end of the certificate, root, responder and OCSP
//! validity. The adapter passes this contract's address as `account` and
//! `uc_login_link::timed_challenge(challenge, issued_at)` as `action`: the
//! card signature carries no time, so the holder states one and signs it
//! with the challenge. `session` is a value the signer chose; the link does
//! not read it.
//!
//! Claim:
//! - trust: source `SOURCE_CERTIFIED_KEY`, issuer `jpki_pin` (anchor class,
//!   root and maximum OCSP age), no co-authority: the identity is the card
//!   key, so the CA cannot produce a link for a key that it does not hold.
//! - identity: the SHA-256 of the holder certificate's public key
//!   (`card_key_id`). JPKI user-authentication certificates carry no name,
//!   My Number or other personal attribute, so the key is the only
//!   identifier. It is per card and changes when the card or its
//!   certificate is renewed (about every five years).
//! - binding: the link challenge, set by the holder (`SET_BY_HOLDER`).
//! - issued at: the time that the holder signed; expires at: the end of the
//!   certificate, root, responder and OCSP validity.
use aztec::{
    context::PrivateContext,
    protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize, ToField}},
};
use std::meta::derive;
use uc_login_link::{LinkClaim, LoginLink, timed_challenge};
use uc_trust::{ANCHOR_NONE, Binding, bytes::halves, SET_BY_HOLDER, SOURCE_CERTIFIED_KEY, Trust};

mod tests;

/// The JPKI scheme id.
pub global SCHEME_JPKI: u32 = 16;

pub global DOMAIN_JPKI_ROOT: Field = comptime { poseidon2_hash_bytes("MIKE_UC_JPKI_ROOT_V1".as_bytes()) };
pub global DOMAIN_JPKI_CARD_KEY: Field = comptime { poseidon2_hash_bytes("MIKE_UC_JPKI_CARD_KEY_V1".as_bytes()) };

/// A JPKI card signature with its certificate chain and OCSP response. The
/// anchor class, root hash and OCSP age enter the trust issuer, which the
/// terms pin; the holder key hash is the identity.
#[derive(Serialize, Deserialize)]
pub struct JpkiLogin {
    /// 0: an official JPKI user-authentication root; 1: a local test root.
    pub anchor_class: u8,
    pub root_sha256: [u8; 32],
    /// The SHA-256 of the holder certificate's SubjectPublicKeyInfo.
    pub holder_spki_sha256: [u8; 32],
    /// Maximum OCSP `thisUpdate` age, seconds (at most one day).
    pub max_ocsp_age: u64,
    pub root: BoundedVec<u8, 2048>,
    pub certificate: BoundedVec<u8, 2048>,
    /// Empty when the root signs the OCSP response itself.
    pub responder: BoundedVec<u8, 2048>,
    pub ocsp: BoundedVec<u8, 4096>,
    pub holder_signature: [u8; 256],
    pub root_redc: [u128; 18],
    pub holder_redc: [u128; 18],
    pub responder_redc: [u128; 18],
    pub session: [u8; 32],
    /// The issue time that the holder signs with the challenge (Unix s).
    pub issued_at: u64,
}

/// The trust root of a deployment: anchor class, root and OCSP age.
pub fn jpki_pin(anchor_class: u8, root_sha256: [u8; 32], max_ocsp_age: u64) -> Field {
    let (high, low) = halves(root_sha256);
    poseidon2_hash(
        [DOMAIN_JPKI_ROOT, anchor_class as Field, high, low, max_ocsp_age as Field],
    )
}

/// The identity of a JPKI card: its authentication key's SPKI hash.
pub fn card_key_id(holder_spki_sha256: [u8; 32]) -> Field {
    let (high, low) = halves(holder_spki_sha256);
    poseidon2_hash([DOMAIN_JPKI_CARD_KEY, high, low])
}

impl JpkiLogin {
    /// The trust issuer that this input pins.
    pub fn issuer(self) -> Field {
        jpki_pin(self.anchor_class, self.root_sha256, self.max_ocsp_age)
    }

    pub fn identity(self) -> Field {
        card_key_id(self.holder_spki_sha256)
    }
}

impl LoginLink for JpkiLogin {
    let SCHEME: u32 = 16;

    fn verify(self, context: &mut PrivateContext, challenge: Field) -> LinkClaim {
        let expires_at = jpki_auth::authorise(
            jpki_auth::AuthInput {
                root: self.root,
                certificate: self.certificate,
                responder: self.responder,
                ocsp: self.ocsp,
                holder_signature: self.holder_signature,
                root_redc: self.root_redc,
                holder_redc: self.holder_redc,
                responder_redc: self.responder_redc,
            },
            jpki_auth::AuthPolicy {
                anchor_class: self.anchor_class,
                root_sha256: self.root_sha256,
                holder_spki_sha256: self.holder_spki_sha256,
                max_ocsp_age: self.max_ocsp_age,
            },
            context.this_address().to_field().to_be_bytes::<32>(),
            timed_challenge(challenge, self.issued_at).to_be_bytes::<32>(),
            self.session,
            context.get_anchor_block_header().timestamp(),
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
            expires_at,
            bearer: false,
        }
    }
}
