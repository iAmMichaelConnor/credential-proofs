// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.

use crate::verify_linkedin_bearer;
use oidc::{JwtInput, TrustedRsa4096Key};

// Verify a LinkedIn bearer ID token against the expected audience, subject and time.
//
// The trusted key modulus (the public output), audience and subject are public:
// a verifier must compare them with its own policy. A proof checked against a prover-chosen key says
// nothing about LinkedIn. LinkedIn tokens carry no nonce (bearer token).
#[export]
pub(crate) fn linkedin_verify_bearer(
    token: JwtInput<256, 2048, 684>,
    trusted_key: TrustedRsa4096Key,
    audience: BoundedVec<u8, 256>,
    subject: BoundedVec<u8, 256>,
    now: u64,
) -> [u128; 35] {
    // The modulus limbs are the public output, which a verifier compares with its
    // trusted key. The redc limbs stay private: they are a range-checked Barrett
    // hint, several values verify one key, and a public redc would let one proof
    // match many public-input vectors.
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_canonical(audience);
    canonical_bytes::assert_canonical(subject);
    let _expiry = verify_linkedin_bearer(token, audience, subject, now, trusted_key);
    trusted_key.modulus_limbs
}
