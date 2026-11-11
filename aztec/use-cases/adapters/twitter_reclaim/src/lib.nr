//! Reclaim adapter: a Reclaim claim, signed by a pinned attestor, as event
//! evidence (`uc_event_proof::EventEvidence`). The event is "the attestor
//! reports that provider P with exact parameters M was satisfied", for
//! example that an HTTP response from a Twitter/X URL matched the
//! parameters' response rules.
//!
//! `reclaim_auth::verify_claim` (noir/reclaim_auth)
//! checks that the identifier is Keccak-256 of `provider\nparameters\ncontext`,
//! that the parameters hash to `parameters_hash`, that the claim epoch is the
//! pinned epoch, that the claim time is not after the anchor block, and the
//! attestor's EIP-191 signature over `identifier\nowner\ntimestamp\nepoch`
//! under the supplied key and its address. The adapter passes the claim's
//! own context as the expected context: an event binds no caller value, and
//! the event data commits to the context instead. The library's own age
//! limit is set to its maximum; the event core applies the terms' `max_age`.
//!
//! Event:
//! - trust: source `SOURCE_ATTESTOR`, issuer `attestor_issuer(key, epoch)`,
//!   no anchor, and `ALSO_ATTESTOR`: the attestor can sign a claim for a fact
//!   that it did not observe. The attestor is part of the authority.
//! - event id: the claim identifier. One identifier is one event, whatever
//!   owner, time or epoch signs it.
//! - kind: (provider, parameters hash); subject: none (0); data: the claim
//!   context, which the claim requester chose; occurred at: the claim time.
//!
//! Login link (`ReclaimHandleLogin`, `uc_login_link::LoginLink`): a claim
//! whose parameters are a pinned template with an X handle in one place,
//! `parameters_prefix || handle || parameters_suffix`, and whose context is
//! exactly `{"contextAddress":"0x<caller>","contextMessage":"<challenge
//! hex>","extractedParameters":{"username":"<handle>"},"providerHash":
//! "0x<provider hash>","reclaimSessionId":"<session>"}`. The handle comes
//! from the parameters, which the attestor checked against the response,
//! not from `extractedParameters` alone: the attestor keeps a
//! caller-supplied `extractedParameters` when its rules capture nothing.
//! The claim:
//! - trust: source `SOURCE_ATTESTOR`, issuer `handle_issuer_pin` (attestor
//!   key and epoch, provider, template and the prover-written provider-hash
//!   label), and
//!   `ALSO_ATTESTOR`: the attestor can sign a claim for any handle.
//! - identity: the handle, lowercased (`handle_id`). X handles are
//!   case-insensitive, can be renamed and can later belong to another
//!   account, so the identity is the handle at login time, not the account.
//! - binding: the link challenge, in the context that the prover writes
//!   (`SET_BY_PROVER`).
//! - issued at: the claim time (the attestor signs it); expires at: none.
//!
//! The template decides what the attestor checked. Only a template whose
//! request returns the logged-in account's own handle, and whose response
//! rule matches that handle exactly, makes the claim mean "the prover
//! controls this X account". The terms pin the template, and the deployer
//! must review it. The repository has no reviewed X template.
use aztec::{
    context::PrivateContext,
    protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize, ToField}},
};
use reclaim_auth::{ReclaimClaim, ReclaimPolicy, verify_claim};
use std::meta::derive;
use uc_event_proof::{Event, EventEvidence};
use uc_login_link::{LinkClaim, LoginLink};
use uc_trust::{
    ALSO_ATTESTOR,
    ANCHOR_NONE,
    Binding,
    bytes::{bytes_hash, halves, prefix_hash},
    field_hex,
    SET_BY_PROVER,
    SOURCE_ATTESTOR,
    Trust,
};

mod tests;

/// The Reclaim scheme id.
pub global SCHEME_TWITTER_RECLAIM: u32 = 9;

pub global DOMAIN_RECLAIM_ATTESTOR: Field = comptime { poseidon2_hash_bytes("MIKE_UC_RECLAIM_ATTESTOR_V1".as_bytes()) };
pub global DOMAIN_RECLAIM_EVENT: Field = comptime { poseidon2_hash_bytes("MIKE_UC_RECLAIM_EVENT_V1".as_bytes()) };
pub global DOMAIN_RECLAIM_KIND: Field = comptime { poseidon2_hash_bytes("MIKE_UC_RECLAIM_KIND_V1".as_bytes()) };
pub global DOMAIN_RECLAIM_CONTEXT: Field = comptime { poseidon2_hash_bytes("MIKE_UC_RECLAIM_CONTEXT_V1".as_bytes()) };
pub global DOMAIN_RECLAIM_HANDLE_ISSUER: Field =
    comptime { poseidon2_hash_bytes("MIKE_UC_RECLAIM_HANDLE_ISSUER_V1".as_bytes()) };
pub global DOMAIN_X_HANDLE: Field = comptime { poseidon2_hash_bytes("MIKE_UC_X_HANDLE_V1".as_bytes()) };

/// Claim segment capacities (the Twitter/X account's provider and
/// parameter capacities; a 512-byte context).
pub global MAX_PROVIDER: u32 = 8;
pub global MAX_PARAMETERS: u32 = 1024;
pub global MAX_CONTEXT: u32 = 512;
/// Login-link capacities: each template part, an X handle (1 to 15 of
/// `[A-Za-z0-9_]`) and a Reclaim session id (1 to 128 of `[A-Za-z0-9_-]`).
pub global MAX_TEMPLATE: u32 = 512;
pub global MAX_HANDLE: u32 = 15;
pub global MAX_SESSION: u32 = 128;

/// A Reclaim claim envelope with the attestor key it must verify under.
/// The key, epoch and parameters hash are not trusted by themselves: they
/// enter the trust issuer and the event kind, which the terms pin.
#[derive(Serialize, Deserialize)]
pub struct ReclaimObservation {
    /// The attestor's uncompressed secp256k1 key and its Ethereum address.
    pub attestor_x: [u8; 32],
    pub attestor_y: [u8; 32],
    pub attestor_address: [u8; 20],
    pub epoch: u32,
    pub provider: [u8; MAX_PROVIDER],
    pub provider_len: u32,
    pub parameters: [u8; MAX_PARAMETERS],
    pub parameters_len: u32,
    /// Keccak-256 of the parameters bytes.
    pub parameters_hash: [u8; 32],
    pub context: [u8; MAX_CONTEXT],
    pub context_len: u32,
    /// The claim owner, `0x` and 40 lowercase hex digits.
    pub owner: [u8; 42],
    pub timestamp_s: u32,
    pub identifier: [u8; 32],
    /// r || s || v.
    pub signature: [u8; 65],
}

/// The trust issuer of an attestor key in one epoch. The address is a
/// function of the key, which `verify_claim` checks.
pub fn attestor_issuer(x: [u8; 32], y: [u8; 32], epoch: u32) -> Field {
    let (x_high, x_low) = halves(x);
    let (y_high, y_low) = halves(y);
    poseidon2_hash(
        [DOMAIN_RECLAIM_ATTESTOR, x_high, x_low, y_high, y_low, epoch as Field],
    )
}

/// The event kind of a claim: its provider and exact parameters.
pub fn claim_kind(provider: [u8; MAX_PROVIDER], provider_len: u32, parameters_hash: [u8; 32]) -> Field {
    let (high, low) = halves(parameters_hash);
    poseidon2_hash(
        [DOMAIN_RECLAIM_KIND, prefix_hash(provider, provider_len), high, low],
    )
}

/// The event data of a claim: its context.
pub fn claim_context(context: [u8; MAX_CONTEXT], context_len: u32) -> Field {
    poseidon2_hash([DOMAIN_RECLAIM_CONTEXT, prefix_hash(context, context_len)])
}

impl ReclaimObservation {
    /// The trust issuer that this input pins.
    pub fn issuer(self) -> Field {
        attestor_issuer(self.attestor_x, self.attestor_y, self.epoch)
    }

    pub fn kind(self) -> Field {
        claim_kind(self.provider, self.provider_len, self.parameters_hash)
    }

    /// Verifies the claim at time `now` (the anchor block time) and returns
    /// the event.
    pub fn verify_observation(self, now: u64) -> Event {
        let identifier = verify_claim(
            ReclaimClaim::<MAX_PROVIDER, MAX_PARAMETERS, MAX_CONTEXT> {
                provider: self.provider,
                provider_len: self.provider_len,
                parameters: self.parameters,
                parameters_len: self.parameters_len,
                context: self.context,
                context_len: self.context_len,
                owner: self.owner,
                timestamp_s: self.timestamp_s,
                epoch: self.epoch,
                identifier: self.identifier,
                signature: self.signature,
            },
            ReclaimPolicy::<MAX_PROVIDER> {
                provider: self.provider,
                provider_len: self.provider_len,
                parameters_hash: self.parameters_hash,
                attestor_x: self.attestor_x,
                attestor_y: self.attestor_y,
                attestor_address: self.attestor_address,
                expected_epoch: self.epoch,
                max_age_seconds: 0xffffffff,
            },
            self.context,
            self.context_len,
            now,
        );
        let (id_high, id_low) = halves(identifier);
        Event {
            trust: Trust {
                source: SOURCE_ATTESTOR,
                issuer: self.issuer(),
                anchor_kind: ANCHOR_NONE,
                anchor: 0,
                finality: 0,
                also_authorised: ALSO_ATTESTOR,
            },
            event_id: poseidon2_hash([DOMAIN_RECLAIM_EVENT, id_high, id_low]),
            kind: self.kind(),
            subject: 0,
            data: claim_context(self.context, self.context_len),
            occurred_at: self.timestamp_s as u64,
        }
    }
}

impl EventEvidence for ReclaimObservation {
    let SCHEME: u32 = 9;

    fn verify(self, context: &mut PrivateContext) -> Event {
        self.verify_observation(context.get_anchor_block_header().timestamp())
    }
}

/// A Reclaim claim that names an X handle, with the attestor key, the
/// parameters template and the provider hash it must verify under. They
/// enter the trust issuer, which the terms pin; the handle is the identity.
/// The parameters and the context are rebuilt from these fields.
#[derive(Serialize, Deserialize)]
pub struct ReclaimHandleLogin {
    pub attestor_x: [u8; 32],
    pub attestor_y: [u8; 32],
    pub attestor_address: [u8; 20],
    pub epoch: u32,
    pub provider: [u8; MAX_PROVIDER],
    pub provider_len: u32,
    /// The parameters are `parameters_prefix || handle || parameters_suffix`.
    pub parameters_prefix: BoundedVec<u8, MAX_TEMPLATE>,
    pub parameters_suffix: BoundedVec<u8, MAX_TEMPLATE>,
    /// Keccak-256 of the parameters (`verify_claim` checks it).
    pub parameters_hash: [u8; 32],
    /// The context's `providerHash`. The prover writes it and the attestor
    /// does not check it: pinning it selects a label, not what was observed.
    pub provider_hash: [u8; 32],
    pub handle: BoundedVec<u8, MAX_HANDLE>,
    pub session: BoundedVec<u8, MAX_SESSION>,
    /// The claim owner, `0x` and 40 lowercase hex digits.
    pub owner: [u8; 42],
    pub timestamp_s: u32,
    pub identifier: [u8; 32],
    /// r || s || v.
    pub signature: [u8; 65],
}

/// The trust root of a handle login: attestor key and epoch, provider,
/// parameters template and provider hash.
pub fn handle_issuer_pin(
    attestor_x: [u8; 32],
    attestor_y: [u8; 32],
    epoch: u32,
    provider: [u8; MAX_PROVIDER],
    provider_len: u32,
    parameters_prefix: BoundedVec<u8, MAX_TEMPLATE>,
    parameters_suffix: BoundedVec<u8, MAX_TEMPLATE>,
    provider_hash: [u8; 32],
) -> Field {
    let (high, low) = halves(provider_hash);
    poseidon2_hash([
        DOMAIN_RECLAIM_HANDLE_ISSUER,
        attestor_issuer(attestor_x, attestor_y, epoch),
        prefix_hash(provider, provider_len),
        bytes_hash(parameters_prefix),
        bytes_hash(parameters_suffix),
        high,
        low,
    ])
}

fn is_handle_byte(c: u8) -> bool {
    ((c >= 48) & (c <= 57)) | ((c >= 65) & (c <= 90)) | ((c >= 97) & (c <= 122)) | (c == 95)
}

/// The identity of an X handle: the handle in lowercase, so that case
/// variants of one handle are one identity. Checks the handle's bytes.
pub fn handle_id(handle: BoundedVec<u8, MAX_HANDLE>) -> Field {
    assert(handle.len() > 0, "Empty X handle");
    let mut lower: BoundedVec<u8, MAX_HANDLE> = BoundedVec::new();
    for i in 0..MAX_HANDLE {
        if i < handle.len() {
            let c = handle.get_unchecked(i);
            assert(is_handle_byte(c), "Unsupported X handle byte");
            lower.push(if (c >= 65) & (c <= 90) { c + 32 } else { c });
        }
    }
    poseidon2_hash([DOMAIN_X_HANDLE, bytes_hash(lower)])
}

fn assert_session(session: BoundedVec<u8, MAX_SESSION>) {
    assert(session.len() > 0, "Empty Reclaim session id");
    for i in 0..MAX_SESSION {
        if i < session.len() {
            let c = session.get_unchecked(i);
            assert(is_handle_byte(c) | (c == 45), "Unsupported Reclaim session byte");
        }
    }
}

fn append_literal<let N: u32, let M: u32>(out: &mut BoundedVec<u8, N>, value: str<M>) {
    let bytes = value.as_bytes();
    for i in 0..M {
        out.push(bytes[i]);
    }
}

fn append_bytes<let N: u32, let M: u32>(out: &mut BoundedVec<u8, N>, value: BoundedVec<u8, M>) {
    for i in 0..M {
        if i < value.len() {
            out.push(value.get_unchecked(i));
        }
    }
}

fn append_hex<let N: u32>(out: &mut BoundedVec<u8, N>, value: [u8; 32]) {
    let alphabet = "0123456789abcdef".as_bytes();
    for i in 0..32 {
        out.push(alphabet[(value[i] >> 4) as u32]);
        out.push(alphabet[(value[i] & 15) as u32]);
    }
}

impl ReclaimHandleLogin {
    /// The trust issuer that this input pins.
    pub fn issuer(self) -> Field {
        handle_issuer_pin(
            self.attestor_x,
            self.attestor_y,
            self.epoch,
            self.provider,
            self.provider_len,
            self.parameters_prefix,
            self.parameters_suffix,
            self.provider_hash,
        )
    }

    pub fn identity(self) -> Field {
        handle_id(self.handle)
    }

    /// The claim parameters: the template with the handle in place.
    pub fn parameters(self) -> BoundedVec<u8, MAX_PARAMETERS> {
        assert(
            self.parameters_prefix.len() + self.handle.len() + self.parameters_suffix.len() <= MAX_PARAMETERS,
            "Template too long",
        );
        let mut parameters = BoundedVec::new();
        append_bytes(&mut parameters, self.parameters_prefix);
        append_bytes(&mut parameters, self.handle);
        append_bytes(&mut parameters, self.parameters_suffix);
        parameters
    }

    /// The exact claim context for `caller` and `challenge`.
    pub fn context(self, caller: Field, challenge: Field) -> BoundedVec<u8, MAX_CONTEXT> {
        let mut context = BoundedVec::new();
        append_literal(&mut context, "{\"contextAddress\":\"0x");
        append_hex(&mut context, caller.to_be_bytes::<32>());
        append_literal(&mut context, "\",\"contextMessage\":\"");
        let hex = field_hex(challenge);
        for i in 0..64 {
            context.push(hex[i]);
        }
        append_literal(&mut context, "\",\"extractedParameters\":{\"username\":\"");
        append_bytes(&mut context, self.handle);
        append_literal(&mut context, "\"},\"providerHash\":\"0x");
        append_hex(&mut context, self.provider_hash);
        append_literal(&mut context, "\",\"reclaimSessionId\":\"");
        append_bytes(&mut context, self.session);
        append_literal(&mut context, "\"}");
        context
    }

    /// Verifies the claim for `caller` and `challenge` at time `now` (the
    /// anchor block time) and returns the claim time. The handle and the
    /// session are checked first, so neither can end a JSON string in the
    /// parameters or the context.
    pub fn verify_login(self, caller: Field, challenge: Field, now: u64) -> u64 {
        let _ = handle_id(self.handle);
        assert_session(self.session);
        let parameters = self.parameters();
        let context = self.context(caller, challenge);
        let _ = verify_claim(
            ReclaimClaim::<MAX_PROVIDER, MAX_PARAMETERS, MAX_CONTEXT> {
                provider: self.provider,
                provider_len: self.provider_len,
                parameters: parameters.storage(),
                parameters_len: parameters.len(),
                context: context.storage(),
                context_len: context.len(),
                owner: self.owner,
                timestamp_s: self.timestamp_s,
                epoch: self.epoch,
                identifier: self.identifier,
                signature: self.signature,
            },
            ReclaimPolicy::<MAX_PROVIDER> {
                provider: self.provider,
                provider_len: self.provider_len,
                parameters_hash: self.parameters_hash,
                attestor_x: self.attestor_x,
                attestor_y: self.attestor_y,
                attestor_address: self.attestor_address,
                expected_epoch: self.epoch,
                max_age_seconds: 0xffffffff,
            },
            context.storage(),
            context.len(),
            now,
        );
        self.timestamp_s as u64
    }
}

impl LoginLink for ReclaimHandleLogin {
    let SCHEME: u32 = 9;

    fn verify(self, context: &mut PrivateContext, challenge: Field) -> LinkClaim {
        let caller = uc_trust::msg_sender(*context).to_field();
        let issued_at = self.verify_login(caller, challenge, context.get_anchor_block_header().timestamp());
        LinkClaim {
            trust: Trust {
                source: SOURCE_ATTESTOR,
                issuer: self.issuer(),
                anchor_kind: ANCHOR_NONE,
                anchor: 0,
                finality: 0,
                also_authorised: ALSO_ATTESTOR,
            },
            identity: self.identity(),
            binding: Binding { value: challenge, set_by: SET_BY_PROVER },
            issued_at,
            expires_at: 0,
            bearer: false,
        }
    }
}
