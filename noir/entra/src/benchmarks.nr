// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.

use oidc::{JwtInput, TrustedRsaKey};

// Verify a Microsoft Entra ID token for the expected tenant, audience, subject and nonce.
#[export]
pub fn entra_verify(
    token: JwtInput<256, 2048, 344>,
    trusted_key: TrustedRsaKey,
    tenant: [u8; 36],
    audience: BoundedVec<u8, 128>,
    subject: BoundedVec<u8, 256>,
    nonce: BoundedVec<u8, 64>,
    now: u64,
) -> [u128; 18] {
    // The modulus limbs are the public output, which a verifier compares with its
    // trusted key. The redc limbs stay private: they are a range-checked Barrett
    // hint, several values verify one key, and a public redc would let one proof
    // match many public-input vectors.
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_canonical(audience);
    canonical_bytes::assert_canonical(subject);
    canonical_bytes::assert_canonical(nonce);
    let _expiry = crate::verify_entra(token, tenant, audience, subject, nonce, now, trusted_key);
    trusted_key.modulus_limbs
}
