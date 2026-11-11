//! Shared trust vocabulary and rules for the use-case cores (`uc_*`).
//!
//! Every claim that an adapter returns carries a `Trust` (who produced the
//! evidence and who else could have produced it) and, where the credential
//! binds a value, a `Binding` (the value and who chose it). The cores enforce
//! contract terms on these fields, so evidence with different trust is never
//! interchangeable. The fields are the adapter's labels: the cores cannot
//! detect a wrong label, so adapter review checks them. This crate imports
//! no scheme library and holds no state.
use aztec::{
    context::PrivateContext,
    oracle::get_contract_instance::get_contract_instance,
    protocol::{address::AztecAddress, hash::poseidon2_hash, traits::{Deserialize, Serialize, ToField}},
};
use std::meta::derive;

pub mod bytes;
mod tests;

/// Who signed or produced the evidence (`Trust.source`).
pub global SOURCE_USER_KEY: u8 = 1; // category 1: the user's own key
pub global SOURCE_CERTIFIED_KEY: u8 = 2; // category 2: a user key that an authority certified
pub global SOURCE_IDENTITY_PROVIDER: u8 = 3; // category 3: OIDC IdP, DKIM mail domain
pub global SOURCE_ATTESTOR: u8 = 4; // category 4: an attestor or notary
pub global SOURCE_PLATFORM: u8 = 5; // category 5: a payment platform key
pub global SOURCE_DOCUMENT_ISSUER: u8 = 6; // category 6: the issuer of a static document
pub global SOURCE_CHAIN: u8 = 7; // blockchain state or events
pub global SOURCE_PROOF_SYSTEM: u8 = 8; // a proof under a root (World ID, ProveKit)

/// How a chain root or checkpoint reaches Aztec (`Trust.anchor_kind`).
pub global ANCHOR_NONE: u8 = 0; // not chain evidence
pub global ANCHOR_PINNED: u8 = 1; // a deployer-set root or checkpoint
pub global ANCHOR_REGISTRY: u8 = 2; // a root registry; the registry identity is `Trust.issuer`
pub global ANCHOR_L1_MESSAGE: u8 = 3; // a root relayed by an L1 portal (not implemented)
pub global ANCHOR_LIGHT_CLIENT: u8 = 4; // consensus verified in circuit (not implemented)

/// Who chose the value that the credential binds (`Binding.set_by`).
pub global SET_BY_NONE: u8 = 0; // no free signed field (LinkedIn, PhilSys)
pub global SET_BY_HOLDER: u8 = 1; // the holder's key or secret proves the choice
pub global SET_BY_CLIENT: u8 = 2; // the OIDC client operator picks the nonce
pub global SET_BY_SENDER: u8 = 3; // the mailbox sender writes the body
pub global SET_BY_PROVER: u8 = 4; // any prover (Aadhaar signal, Reclaim context)
pub global SET_BY_MERCHANT: u8 = 5; // the merchant (WeChat attach, out_trade_no)
pub global SET_BY_PAYER: u8 = 6; // the payer (Peer payerCommitment)

/// Bitmask of parties other than the holder that can produce valid evidence
/// (`Trust.also_authorised`).
pub global ALSO_IDP: u8 = 1;
pub global ALSO_CLIENT_OPERATOR: u8 = 2;
pub global ALSO_MAIL_OPERATOR: u8 = 4;
pub global ALSO_ATTESTOR: u8 = 8;
pub global ALSO_MERCHANT: u8 = 16;
pub global ALSO_COPY_HOLDER: u8 = 32; // anyone who received a copy (bearer)

/// `Trust.finality` for evidence whose anchor is final by construction.
pub global FINAL_BY_ANCHOR: u32 = 0xffffffff;

/// Freshness ceiling, in seconds, for evidence that copy holders also have:
/// the upstream AnonAadhaarVote 3 hours plus one hour of IST-hour truncation.
pub global MAX_BEARER_AGE: u64 = 14400;

global U64_MAX: u64 = 0xffffffffffffffff;

/// Who produced the evidence, and who else could have produced it.
#[derive(Eq, Serialize, Deserialize)]
pub struct Trust {
    /// `SOURCE_*`.
    pub source: u8,
    /// Adapter-defined trust pin: trusted key, authority, registry, chain or
    /// relying party (for example passkey RP ID/origin or SIWE domain/URI/chain).
    /// User-key evidence can carry a relying-party pin; see the adapter.
    pub issuer: Field,
    /// `ANCHOR_*`; `ANCHOR_NONE` for evidence that is not chain evidence.
    pub anchor_kind: u8,
    /// Authenticated root, header hash or checkpoint; 0 otherwise.
    pub anchor: Field,
    /// Blocks below the anchor, or `FINAL_BY_ANCHOR`; 0 for evidence that is not chain evidence.
    pub finality: u32,
    /// `ALSO_*` bitmask.
    pub also_authorised: u8,
}

/// The value a credential binds, and who chose it.
#[derive(Eq, Serialize, Deserialize)]
pub struct Binding {
    /// What the credential binds (action hash, link challenge, caller binding, order reference).
    pub value: Field,
    /// `SET_BY_*`.
    pub set_by: u8,
}

/// The trust that contract terms accept. Every field is compared with the
/// claim's `Trust` by `assert_trust_accepted`.
#[derive(Eq, Serialize, Deserialize)]
pub struct TrustPolicy {
    pub source: u8,
    pub issuer: Field,
    pub anchor_kind: u8,
    /// Required anchor for every kind except `ANCHOR_REGISTRY`, whose adapter
    /// proves membership in the registry that `issuer` names.
    pub anchor: Field,
    pub min_finality: u32,
    /// `ALSO_*` bits that the terms refuse (for example `ALSO_COPY_HOLDER`).
    pub refuse_also: u8,
}

/// Rejects evidence whose trust differs from the accepted policy.
pub fn assert_trust_accepted(trust: Trust, accepted: TrustPolicy) {
    assert(trust.source == accepted.source, "Untrusted evidence source");
    assert(trust.issuer == accepted.issuer, "Untrusted issuer");
    assert(trust.anchor_kind == accepted.anchor_kind, "Untrusted anchor kind");
    assert(accepted.anchor_kind <= ANCHOR_REGISTRY, "Anchor kind not implemented");
    if accepted.anchor_kind != ANCHOR_REGISTRY {
        assert(trust.anchor == accepted.anchor, "Untrusted anchor");
    }
    assert(trust.finality >= accepted.min_finality, "Insufficient finality");
    assert((trust.also_authorised & accepted.refuse_also) == 0, "Refused co-authority");
}

/// A nullifier for `id` in a use-case domain and an app scope. The preimage
/// has three elements and starts with a hashed domain tag, so it cannot equal
/// the two-element account transaction nullifier or an untagged bytes hash
///. Aztec silos every nullifier by contract address.
pub fn scoped_nullifier(domain: Field, scope: Field, id: Field) -> Field {
    poseidon2_hash([domain, scope, id])
}

/// The last inclusive timestamp at which a transaction may use evidence
/// issued at `issued_at` under `max_age`. Rejects evidence issued after the
/// anchor block and evidence that is already too old at the anchor block.
/// Saturating addition keeps policies near the u64 boundary valid.
pub fn assert_fresh(issued_at: u64, anchor_timestamp: u64, max_age: u64) -> u64 {
    assert(issued_at <= anchor_timestamp, "Evidence issued after the anchor block");
    let remaining = U64_MAX - issued_at;
    let age = if max_age > remaining {
        remaining
    } else {
        max_age
    };
    let deadline = issued_at + age;
    assert(anchor_timestamp <= deadline, "Evidence too old");
    deadline
}

/// Applies `assert_fresh` at the anchor block and limits the transaction's
/// inclusion to the freshness deadline.
pub fn require_fresh(context: &mut PrivateContext, issued_at: u64, max_age: u64) {
    let deadline = assert_fresh(
        issued_at,
        context.get_anchor_block_header().timestamp(),
        max_age,
    );
    context.set_expiration_timestamp(deadline);
}

/// As `require_fresh`; `issued_at == 0` marks evidence that carries no time,
/// which the terms must accept explicitly. Undated evidence gets no freshness
/// deadline and no bearer ceiling: only the protocol's maximum transaction
/// lifetime limits inclusion, and an old copy works as well as a new one.
pub fn require_fresh_or_undated(context: &mut PrivateContext, issued_at: u64, max_age: u64, allow_undated: bool) {
    if issued_at == 0 {
        assert(allow_undated, "Undated evidence not accepted");
    } else {
        require_fresh(context, issued_at, max_age);
    }
}

/// Rejects a credential whose own exclusive expiry has passed at the anchor
/// block and limits inclusion to strictly before it. `expires_at == 0` means
/// the credential carries no expiry.
pub fn require_unexpired(context: &mut PrivateContext, expires_at: u64) {
    if expires_at != 0 {
        assert(context.get_anchor_block_header().timestamp() < expires_at, "Evidence expired");
        context.set_expiration_timestamp(expires_at - 1);
    }
}

/// The freshness ceiling that applies to evidence with this trust: evidence
/// whose `also_authorised` includes `ALSO_COPY_HOLDER` is capped at
/// `MAX_BEARER_AGE`. The cap depends on the adapter's label: an adapter that
/// omits the bit gets the terms' `max_age`, and `TrustPolicy` cannot require
/// an exact `also_authorised` value (only refuse bits). Adapter review must
/// check the label. Undated evidence has no ceiling (`require_fresh_or_undated`).
pub fn effective_max_age(max_age: u64, trust: Trust) -> u64 {
    if ((trust.also_authorised & ALSO_COPY_HOLDER) != 0) & (max_age > MAX_BEARER_AGE) {
        MAX_BEARER_AGE
    } else {
        max_age
    }
}

/// Binding rule of the restricted-payload use cases (U1b). Evidence with a
/// free signed field must bind `expected`. Evidence with no free field is
/// accepted only when the terms allow unbound evidence.
pub fn assert_binding(binding: Binding, expected: Field, allow_unbound: bool) {
    if binding.set_by == SET_BY_NONE {
        assert(allow_unbound, "Unbound evidence not accepted");
    } else {
        assert(binding.value == expected, "Evidence bound to another value");
    }
}

/// A free argument (for example a vote choice) is taken only from evidence
/// whose bound value the holder, the holder's OIDC client or the mailbox
/// sender chose. Prover-set, merchant-set and unbound evidence is refused,
/// because a copy holder or a third party could pick the argument.
pub fn assert_choice_allowed(binding: Binding) {
    let set_by = binding.set_by;
    assert(
        (set_by == SET_BY_HOLDER) | (set_by == SET_BY_CLIENT) | (set_by == SET_BY_SENDER),
        "A free choice needs holder-chosen evidence",
    );
}

/// The value that evidence must bind so that it is good only for this caller
/// of this contract on this chain (the AnonAadhaarVote `signal = msg.sender`
/// pattern, against proof theft).
pub fn caller_binding(
    domain: Field,
    chain_id: Field,
    version: Field,
    this_address: AztecAddress,
    sender: AztecAddress,
) -> Field {
    poseidon2_hash(
        [domain, chain_id, version, this_address.to_field(), sender.to_field()],
    )
}

/// As `caller_binding`, also binding a free argument chosen by the holder.
pub fn caller_choice_binding(
    domain: Field,
    chain_id: Field,
    version: Field,
    this_address: AztecAddress,
    sender: AztecAddress,
    choice: Field,
) -> Field {
    poseidon2_hash(
        [domain, chain_id, version, this_address.to_field(), sender.to_field(), choice],
    )
}

/// The calling contract. A use-case entrypoint is never the first call of a
/// transaction (the account contract is), so a missing caller is rejected.
pub fn msg_sender(context: PrivateContext) -> AztecAddress {
    let sender = context.maybe_msg_sender();
    assert(sender.is_some(), "No caller");
    sender.unwrap_unchecked()
}

/// The contract instance's `immutables_hash` value for these terms.
pub fn terms_commitment(domain: Field, scheme: Field, terms_hash: Field) -> Field {
    poseidon2_hash([domain, scheme, terms_hash])
}

/// The contract address commits to its terms. Supplied terms become trusted
/// only after this check.
pub fn bind_terms(context: &mut PrivateContext, domain: Field, scheme: Field, terms_hash: Field) {
    let instance = get_contract_instance(context.this_address());
    assert_eq(instance.immutables_hash, terms_commitment(domain, scheme, terms_hash), "Wrong terms");
}

/// Canonical lowercase hex of a field, without 0x (OIDC and SIWE nonces).
pub fn field_hex(value: Field) -> [u8; 64] {
    let bytes = value.to_be_bytes::<32>();
    let alphabet = "0123456789abcdef".as_bytes();
    let mut out = [0; 64];
    for i in 0..32 {
        out[2 * i] = alphabet[(bytes[i] >> 4) as u32];
        out[2 * i + 1] = alphabet[(bytes[i] & 15) as u32];
    }
    out
}
