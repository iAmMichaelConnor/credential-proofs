//! Native Zupass POD signature and entry verification, for private composition.
//! The caller anchors the issuer, content claims and transaction context.
//!
//! Entry points: `assert_pod_signature` (issuer EdDSA-Poseidon signature over a
//! content ID), `assert_named_entry` / `assert_entry` (LeanIMT membership),
//! `assert_certified_holder`, `assert_holder_approval` and
//! `assert_holder_login` (holder-key signatures over fixed-schema PODs).
//! Holder software must never sign, for another party, a POD with an
//! `_aztec_auth_v1_*` or `_aztec_link_v1_*` entry or a raw field: such a signer
//! is an approval or login oracle. Moduli, the backend premise and the hazards
//! are in `docs/zupass.md`.
use edwards::{bjj::BabyJubJub, CurveTrait, ScalarField};
use poseidon::poseidon::bn254::{hash_1, hash_2, hash_5};

pub global SUBGROUP_ORDER: Field =
    2736030358979909402780800718157159386076813972158567259200215660948447373041;

pub struct PublicKey {
    pub x: Field,
    pub y: Field,
}
pub struct Signature {
    pub rx: Field,
    pub ry: Field,
    pub s: Field,
}

// The EdDSA scalar is checked below against l < 2^252, so a 63-nibble
// ScalarField reconstructs it exactly. In the compiled circuit the 4-bit
// bound on each slice is the memory bound of mul's 16-entry table reads,
// enforced by the backend: docs/zupass.md#backend-and-compiler-premises.
fn multiply_signature_scalar(point: BabyJubJub, scalar: Field) -> BabyJubJub {
    point.mul(ScalarField::<63>::from(scalar))
}

fn multiply_challenge(point: BabyJubJub, challenge: Field) -> BabyJubJub {
    // The challenge spans the whole field. A canonical bitwise ladder covers
    // that domain without a decomposition hint (docs/zupass.md).
    let bits = challenge.to_le_bits::<254>();
    let mut acc = BabyJubJub::zero();
    for i in 0..254 {
        acc = acc.dbl();
        let added = acc + point;
        acc = if bits[253 - i] { added } else { acc };
    }
    acc
}

/// Verify the exact EdDSA-Poseidon equation used by @pcd/pod.
/// `issuer` must be a trusted key from account state, not an arbitrary witness.
pub fn assert_pod_signature(content_id: Field, issuer: PublicKey, signature: Signature) {
    let a = BabyJubJub::new(issuer.x, issuer.y);
    let r = BabyJubJub::new(signature.rx, signature.ry);
    let h = hash_5([r.x, r.y, a.x, a.y, content_id]);
    assert_pod_signature_points(a, r, signature.s, h);
}

/// Constrain the scalar-multiplication equation after the caller supplies the
/// challenge. Use `assert_pod_signature` in applications so h is bound to the
/// POD transcript; this lower-level relation is useful for private composition
/// and component measurement but does not itself bind `h` to a hash preimage.
pub fn assert_pod_signature_equation(issuer: PublicKey, signature: Signature, challenge: Field) {
    let a = BabyJubJub::new(issuer.x, issuer.y);
    let r = BabyJubJub::new(signature.rx, signature.ry);
    assert_pod_signature_points(a, r, signature.s, challenge);
}

fn assert_pod_signature_points(a: BabyJubJub, r: BabyJubJub, scalar: Field, challenge: Field) {
    assert(scalar.lt(SUBGROUP_ORDER), "Noncanonical EdDSA scalar");
    let a8 = a.dbl().dbl().dbl();
    assert(!a8.is_zero(), "Small-order issuer key");
    let base8 = BabyJubJub::new(
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203,
    );
    let lhs = multiply_signature_scalar(base8, scalar);
    let rhs = r + multiply_challenge(a8, challenge);
    // The same two coordinate copy constraints as edwards' `assert_equal`.
    assert(lhs.x == rhs.x, "EdDSA signature mismatch");
    assert(lhs.y == rhs.y, "EdDSA signature mismatch");
}

/// Check a name/value pair in a POD's LeanIMT. Siblings start ABOVE the pair.
/// `depth` is the number of supplied upper siblings after LeanIMT compression.
///
/// Exact relation: `hash_2([name_hash, value_hash])` is a Poseidon2 node on a
/// path of `depth <= D` siblings to `content_id`. POD does not domain-separate
/// entry leaves from inner nodes, or entry leaves from eddsa_pubkey value hashes
/// (`hash_2([x, y])`). So the relation also holds for the two children of any
/// inner node (the root at depth 0) and for the coordinates of a public-key
/// value. It proves a typed POD entry only when the caller fixes `name_hash` to
/// `bytes_hash` of the expected name and computes `value_hash` in the circuit
/// from a typed value (see the helper functions and `assert_named_entry`).
pub fn assert_entry<let D: u32>(
    content_id: Field,
    name_hash: Field,
    value_hash: Field,
    depth: u32,
    indices: [bool; D],
    siblings: [Field; D],
) {
    assert(depth <= D, "POD proof exceeds capacity");
    let pair = hash_2([name_hash, value_hash]);
    let root = binary_merkle_root::binary_merkle_root(hash_2, pair, depth, indices, siblings);
    assert(root == content_id, "POD entry mismatch");
}

/// `assert_entry` with the name hash computed in the circuit from the entry name.
/// The caller must still compute `value_hash` in the circuit from a typed value.
pub fn assert_named_entry<let D: u32, let L: u32>(
    content_id: Field,
    name: [u8; L],
    value_hash: Field,
    depth: u32,
    indices: [bool; D],
    siblings: [Field; D],
) {
    assert_entry(
        content_id,
        bytes_hash(name),
        value_hash,
        depth,
        indices,
        siblings,
    );
}

pub fn numeric_value_hash(value: Field) -> Field {
    hash_1([value])
}
pub fn public_key_value_hash(key: PublicKey) -> Field {
    hash_2([key.x, key.y])
}

/// POD name and string/bytes hashing is SHA256 interpreted big-endian, shifted
/// right by eight bits. Types are intentionally not domain-separated by POD.
pub fn bytes_hash<let N: u32>(bytes: [u8; N]) -> Field {
    let digest = sha256::digest(bytes);
    let mut result: Field = 0;
    for i in 0..31 {
        result = result * 256 + digest[i] as Field;
    }
    result
}

/// Prove that a POD that `issuer` signed names `holder` in the entry
/// `holder_name_hash` (an eddsa_pubkey value). `holder_name_hash` is the
/// expected schema field, fixed by the caller.
pub fn assert_certified_holder<let D: u32>(
    content_id: Field,
    issuer: PublicKey,
    issuer_signature: Signature,
    holder: PublicKey,
    holder_name_hash: Field,
    depth: u32,
    indices: [bool; D],
    siblings: [Field; D],
) {
    assert_pod_signature(content_id, issuer, issuer_signature);
    assert_entry(
        content_id,
        holder_name_hash,
        public_key_value_hash(holder),
        depth,
        indices,
        siblings,
    );
}

/// Entry names of the holder approval POD. POD names allow only letters,
/// digits and underscores. In POD's sorted order: account, action, expires.
pub global APPROVAL_ACCOUNT_ENTRY: str<22> = "_aztec_auth_v1_account";
pub global APPROVAL_ACTION_ENTRY: str<21> = "_aztec_auth_v1_action";
pub global APPROVAL_EXPIRES_ENTRY: str<22> = "_aztec_auth_v1_expires";

/// The approval that a holder signs as a POD with exactly three entries:
/// `_aztec_auth_v1_account` (cryptographic), `_aztec_auth_v1_action`
/// (cryptographic) and `_aztec_auth_v1_expires` (int, Unix seconds). The
/// approval is valid strictly before `expires`.
pub struct HolderApproval {
    pub account: Field,
    pub action: Field,
    pub expires: u64,
}

/// The content ID of the holder approval POD. POD hashes `cryptographic` and
/// `int` values with Poseidon1 and builds a LeanIMT over the interleaved
/// leaves [name hash, value hash] of the sorted entries. For six leaves:
/// root = H(H(E_account, E_action), E_expires) with E = H(name hash, value hash).
/// A POD with any other entry set, name or value has another root. Value
/// types are not bound: `date` and `boolean` also hash with Poseidon1, so
/// holder software must sign `expires` as an `int` in seconds.
pub fn holder_approval_content_id(approval: HolderApproval) -> Field {
    let account_name = comptime { bytes_hash(APPROVAL_ACCOUNT_ENTRY.as_bytes()) };
    let action_name = comptime { bytes_hash(APPROVAL_ACTION_ENTRY.as_bytes()) };
    let expires_name = comptime { bytes_hash(APPROVAL_EXPIRES_ENTRY.as_bytes()) };
    let account = hash_2([account_name, numeric_value_hash(approval.account)]);
    let action = hash_2([action_name, numeric_value_hash(approval.action)]);
    let expires = hash_2(
        [expires_name, numeric_value_hash(approval.expires as Field)],
    );
    hash_2([hash_2([account, action]), expires])
}

/// Prove that a POD that `issuer` signed names `holder` in the entry
/// `holder_name_hash`, and that `holder` signed the holder approval POD of
/// `approval`. The circuit recomputes the approval POD's content ID, so honest
/// holder software signs a POD with this fixed schema, not the action field.
/// A raw signer over that root (`signPODRoot`) is still an approval oracle.
/// The caller must set `approval.account` to its own address, determine
/// `approval.action` (account, chain, call and replay nonce) and
/// bound inclusion strictly before `approval.expires`.
pub fn assert_holder_approval<let D: u32>(
    content_id: Field,
    issuer: PublicKey,
    issuer_signature: Signature,
    holder: PublicKey,
    holder_name_hash: Field,
    depth: u32,
    indices: [bool; D],
    siblings: [Field; D],
    approval: HolderApproval,
    holder_signature: Signature,
) {
    assert_certified_holder(
        content_id,
        issuer,
        issuer_signature,
        holder,
        holder_name_hash,
        depth,
        indices,
        siblings,
    );
    assert_pod_signature(
        holder_approval_content_id(approval),
        holder,
        holder_signature,
    );
}

/// Entry names of the holder login POD. In POD's sorted order: challenge,
/// issued_at.
pub global LOGIN_CHALLENGE_ENTRY: str<24> = "_aztec_link_v1_challenge";
pub global LOGIN_ISSUED_AT_ENTRY: str<24> = "_aztec_link_v1_issued_at";

/// The login that a holder signs as a POD with exactly two entries:
/// `_aztec_link_v1_challenge` (cryptographic) and `_aztec_link_v1_issued_at`
/// (int, Unix seconds, the login time that the holder states).
pub struct HolderLogin {
    pub challenge: Field,
    pub issued_at: u64,
}

/// The content ID of the holder login POD: for four leaves,
/// root = H(E_challenge, E_issued_at) with E = H(name hash, value hash), both
/// values hashed with Poseidon1. As for the approval POD, value types are not
/// bound, so holder software must sign `issued_at` as an `int` in seconds.
/// The entry names differ from the approval POD's, so a signature on one
/// schema does not verify as the other.
pub fn holder_login_content_id(login: HolderLogin) -> Field {
    let challenge_name = comptime { bytes_hash(LOGIN_CHALLENGE_ENTRY.as_bytes()) };
    let issued_at_name = comptime { bytes_hash(LOGIN_ISSUED_AT_ENTRY.as_bytes()) };
    let challenge = hash_2([challenge_name, numeric_value_hash(login.challenge)]);
    let issued_at = hash_2(
        [issued_at_name, numeric_value_hash(login.issued_at as Field)],
    );
    hash_2([challenge, issued_at])
}

/// Prove that a POD that `issuer` signed names `holder` in the entry
/// `holder_name_hash`, and that `holder` signed the holder login POD of
/// `login`. The circuit recomputes the login POD's content ID, so honest
/// holder software signs a POD with this fixed schema, not a raw field. A raw
/// signer over that root (`signPODRoot`) is still a login oracle. The caller
/// must determine `login.challenge` (chain, contract, caller and round) and
/// bound the age of `login.issued_at`; the holder can state any past time.
pub fn assert_holder_login<let D: u32>(
    content_id: Field,
    issuer: PublicKey,
    issuer_signature: Signature,
    holder: PublicKey,
    holder_name_hash: Field,
    depth: u32,
    indices: [bool; D],
    siblings: [Field; D],
    login: HolderLogin,
    holder_signature: Signature,
) {
    assert_certified_holder(
        content_id,
        issuer,
        issuer_signature,
        holder,
        holder_name_hash,
        depth,
        indices,
        siblings,
    );
    assert_pod_signature(holder_login_content_id(login), holder, holder_signature);
}

mod tests;
mod benchmarks;
mod known_answer_tests;
