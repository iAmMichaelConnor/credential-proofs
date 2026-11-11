// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.

use crate::webauthn::{assert_valid_webauthn, PasskeyPublicKey, WebAuthnAssertion, WebAuthnPolicy};

// Verify a WebAuthn assertion against the expected key and challenge.
#[export]
pub(crate) fn passkey_webauthn(
    public_key: PasskeyPublicKey,
    challenge: Field,
    policy: WebAuthnPolicy<64, 128>,
    assertion: WebAuthnAssertion<256>,
) {
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_zero_padded(policy.rp_id, policy.rp_id_len);
    canonical_bytes::assert_zero_padded(policy.origin, policy.origin_len);
    assert_valid_webauthn::<256, 64, 128>(public_key, challenge, policy, assertion);
}
