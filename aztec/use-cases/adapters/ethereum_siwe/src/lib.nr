//! Sign-In with Ethereum adapter: an EIP-4361 message signed with
//! `personal_sign` as login-link evidence (`uc_login_link::LoginLink`,
//! category 1).
//!
//! `ethereum::siwe::build_siwe_message` (noir/ethereum_auth) rebuilds the library's canonical
//! SIWE profile (domain, address,
//! URI, version 1, chain id, nonce, issued at, expiration time; no statement,
//! request id, not-before or resources) and checks that the times are real
//! UTC times with `issued_at <= current_time < expiration_time`.
//! `ethereum::eip191::verify_personal_sign` checks the secp256k1 signature
//! over the EIP-191 digest and that the supplied key hashes to the address.
//! The adapter sets the nonce to the lowercase hex of the link challenge and
//! requires `current_time` to be the anchor block time. Only externally owned
//! accounts sign this way: contract wallets (EIP-1271) are not supported.
//!
//! Claim:
//! - trust: source `SOURCE_USER_KEY`, no co-authority. The issuer is not a
//!   key: it pins the relying party (`siwe_pin`: domain, URI and chain id),
//!   so a message that a wallet showed for another site does not link.
//! - identity: the Ethereum address (`address_id`), the same in every app
//!   and stable while the key exists. Anyone can make a key: the link shows
//!   control of the address, nothing about its owner.
//! - binding: the link challenge, set by the holder (`SET_BY_HOLDER`).
//! - issued at: the message's `Issued At`; expires at: its `Expiration
//!   Time`. The holder's wallet writes both and the holder signs them.
use aztec::{
    context::PrivateContext,
    protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}},
};
use ethereum::{eip191::verify_personal_sign, siwe::{build_siwe_message, SiweContext}};
use std::meta::derive;
use time::utc_to_unix;
use uc_login_link::{LinkClaim, LoginLink};
use uc_trust::{ANCHOR_NONE, Binding, bytes::prefix_hash, field_hex, SET_BY_HOLDER, SOURCE_USER_KEY, Trust};

mod tests;

/// The SIWE scheme id.
pub global SCHEME_ETHEREUM_SIWE: u32 = 5;

pub global DOMAIN_SIWE_RP: Field = comptime { poseidon2_hash_bytes("MIKE_UC_SIWE_RP_V1".as_bytes()) };
pub global DOMAIN_ETHEREUM_ADDRESS: Field = comptime { poseidon2_hash_bytes("MIKE_UC_ETHEREUM_ADDRESS_V1".as_bytes()) };

/// Capacities of the domain and URI, and of the rebuilt message.
pub global MAX_SIWE_DOMAIN: u32 = 128;
pub global MAX_SIWE_URI: u32 = 128;
pub global MAX_SIWE_MESSAGE: u32 = 640;

/// A SIWE message's fields and its signature. The domain, URI and chain id
/// enter the trust issuer, which the terms pin; the address is the identity.
#[derive(Serialize, Deserialize)]
pub struct SiweLogin {
    pub address: [u8; 20],
    pub domain: [u8; MAX_SIWE_DOMAIN],
    pub domain_len: u32,
    pub uri: [u8; MAX_SIWE_URI],
    pub uri_len: u32,
    pub chain_id: u64,
    /// Uncompressed secp256k1 key of the address, big-endian coordinates.
    pub public_key_x: [u8; 32],
    pub public_key_y: [u8; 32],
    /// r || s (low s).
    pub signature: [u8; 64],
    /// `YYYY-MM-DDTHH:MM:SSZ`.
    pub issued_at: [u8; 20],
    pub expiration_time: [u8; 20],
    /// Must be the anchor block time.
    pub current_time: [u8; 20],
}

/// The relying party that a deployment accepts: domain, URI and chain id.
pub fn siwe_pin(
    domain: [u8; MAX_SIWE_DOMAIN],
    domain_len: u32,
    uri: [u8; MAX_SIWE_URI],
    uri_len: u32,
    chain_id: u64,
) -> Field {
    poseidon2_hash(
        [DOMAIN_SIWE_RP, prefix_hash(domain, domain_len), prefix_hash(uri, uri_len), chain_id as Field],
    )
}

/// The identity of an Ethereum account: its 20-byte address.
pub fn address_id(address: [u8; 20]) -> Field {
    let mut value: Field = 0;
    for i in 0..20 {
        value = value * 256 + address[i] as Field;
    }
    poseidon2_hash([DOMAIN_ETHEREUM_ADDRESS, value])
}

impl SiweLogin {
    /// The trust issuer that this input pins: the relying party.
    pub fn issuer(self) -> Field {
        siwe_pin(
            self.domain,
            self.domain_len,
            self.uri,
            self.uri_len,
            self.chain_id,
        )
    }

    pub fn identity(self) -> Field {
        address_id(self.address)
    }

    /// Verifies the message at the anchor time `now` with `challenge` as
    /// its nonce. Returns (issued at, expiration time) in Unix seconds.
    pub fn verify_message(self, challenge: Field, now: u64) -> (u64, u64) {
        assert(utc_to_unix(self.current_time) == now, "SIWE current time is not the anchor time");
        let message = build_siwe_message::<MAX_SIWE_MESSAGE, MAX_SIWE_DOMAIN, MAX_SIWE_URI, 64>(
            self.address,
            SiweContext {
                domain: self.domain,
                domain_len: self.domain_len,
                uri: self.uri,
                uri_len: self.uri_len,
                chain_id: self.chain_id,
                nonce: field_hex(challenge),
                nonce_len: 64,
                issued_at: self.issued_at,
                expiration_time: self.expiration_time,
                current_time: self.current_time,
            },
        );
        assert(
            verify_personal_sign(
                message.bytes,
                message.len,
                self.public_key_x,
                self.public_key_y,
                self.signature,
                self.address,
            ),
            "SIWE signature does not verify",
        );
        (utc_to_unix(self.issued_at), utc_to_unix(self.expiration_time))
    }
}

impl LoginLink for SiweLogin {
    let SCHEME: u32 = 5;

    fn verify(self, context: &mut PrivateContext, challenge: Field) -> LinkClaim {
        let (issued_at, expires_at) = self.verify_message(challenge, context.get_anchor_block_header().timestamp());
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
            issued_at,
            expires_at,
            bearer: false,
        }
    }
}
