//! Passkey adapter: a WebAuthn assertion under a P-256 key as login-link
//! evidence (`uc_login_link::LoginLink`, category 1).
//!
//! `passkey::webauthn::assert_valid_webauthn`
//! (noir/passkey_auth) checks the P-256 signature
//! over the authenticator data and the client data hash, the RP ID hash, the
//! flags (user presence; user verification when the input requires it), the
//! exact origin and that the client data challenge is the signed value. A
//! WebAuthn assertion carries no time, so the signed value is
//! `uc_login_link::timed_challenge(challenge, issued_at)`: the holder states
//! the issue time and signs it with the link challenge.
//!
//! Claim:
//! - trust: source `SOURCE_USER_KEY`, no co-authority. The issuer is not a
//!   key: it pins the relying party (`rp_pin`: RP ID, origin and the
//!   user-verification requirement), so the terms decide which site's
//!   passkeys can link.
//! - identity: the public key (`key_id`). A passkey is one credential at
//!   one relying party, so the identity is per credential and per RP; it is
//!   stable while the credential exists. Anyone can make a P-256 key and
//!   sign an assertion with it: the link shows control of the key, and only
//!   the relying party's registration records say whose passkey it is.
//! - binding: the link challenge, set by the holder (`SET_BY_HOLDER`).
//! - issued at: the time that the holder signed; expires at: none (0).
use aztec::{
    context::PrivateContext,
    protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}},
};
use passkey::webauthn::{assert_valid_webauthn, PasskeyPublicKey, WebAuthnAssertion, WebAuthnPolicy};
use std::meta::derive;
use uc_login_link::{LinkClaim, LoginLink, timed_challenge};
use uc_trust::{ANCHOR_NONE, Binding, bytes::{halves, prefix_hash}, SET_BY_HOLDER, SOURCE_USER_KEY, Trust};

mod tests;

/// The passkey scheme id.
pub global SCHEME_PASSKEY: u32 = 1;

pub global DOMAIN_PASSKEY_RP: Field = comptime { poseidon2_hash_bytes("MIKE_UC_PASSKEY_RP_V1".as_bytes()) };
pub global DOMAIN_PASSKEY_KEY: Field = comptime { poseidon2_hash_bytes("MIKE_UC_PASSKEY_KEY_V1".as_bytes()) };

/// Capacities of the RP ID, the origin and the client data JSON.
pub global MAX_RP_ID: u32 = 64;
pub global MAX_ORIGIN: u32 = 128;
pub global MAX_CLIENT_DATA: u32 = 256;

/// A WebAuthn assertion with the key and the relying party it must verify
/// under. The key is the identity; the relying party enters the trust issuer,
/// which the terms pin.
#[derive(Serialize, Deserialize)]
pub struct PasskeyLogin {
    /// P-256 public key, 32-byte big-endian coordinates.
    pub key_x: [u8; 32],
    pub key_y: [u8; 32],
    /// The RP ID (no scheme or port) and the exact origin, zero-padded.
    pub rp_id: [u8; MAX_RP_ID],
    pub rp_id_len: u32,
    pub origin: [u8; MAX_ORIGIN],
    pub origin_len: u32,
    pub require_user_verification: bool,
    /// The issue time that the holder signs with the challenge (Unix s).
    pub issued_at: u64,
    pub authenticator_data: [u8; 37],
    pub client_data_json: [u8; MAX_CLIENT_DATA],
    pub client_data_json_len: u32,
    /// P-256 signature, r || s.
    pub signature: [u8; 64],
}

/// The relying party that a deployment accepts: RP ID, origin and whether
/// user verification is required.
pub fn rp_pin(
    rp_id: [u8; MAX_RP_ID],
    rp_id_len: u32,
    origin: [u8; MAX_ORIGIN],
    origin_len: u32,
    require_user_verification: bool,
) -> Field {
    poseidon2_hash([
        DOMAIN_PASSKEY_RP,
        prefix_hash(rp_id, rp_id_len),
        prefix_hash(origin, origin_len),
        require_user_verification as Field,
    ])
}

/// The identity of a passkey: its public key.
pub fn key_id(key_x: [u8; 32], key_y: [u8; 32]) -> Field {
    let (x_high, x_low) = halves(key_x);
    let (y_high, y_low) = halves(key_y);
    poseidon2_hash([DOMAIN_PASSKEY_KEY, x_high, x_low, y_high, y_low])
}

impl PasskeyLogin {
    /// The trust issuer that this input pins: the relying party.
    pub fn issuer(self) -> Field {
        rp_pin(
            self.rp_id,
            self.rp_id_len,
            self.origin,
            self.origin_len,
            self.require_user_verification,
        )
    }

    pub fn identity(self) -> Field {
        key_id(self.key_x, self.key_y)
    }
}

impl LoginLink for PasskeyLogin {
    let SCHEME: u32 = 1;

    fn verify(self, _context: &mut PrivateContext, challenge: Field) -> LinkClaim {
        assert_valid_webauthn(
            PasskeyPublicKey { x: self.key_x, y: self.key_y },
            timed_challenge(challenge, self.issued_at),
            WebAuthnPolicy {
                rp_id: self.rp_id,
                rp_id_len: self.rp_id_len,
                origin: self.origin,
                origin_len: self.origin_len,
                require_user_verification: self.require_user_verification,
            },
            WebAuthnAssertion {
                authenticator_data: self.authenticator_data,
                client_data_json: self.client_data_json,
                client_data_json_len: self.client_data_json_len,
                signature: self.signature,
            },
        );
        LinkClaim {
            trust: Trust {
                source: SOURCE_USER_KEY,
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
