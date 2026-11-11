// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.

use crate::eip191::verify_personal_sign;
use crate::secret_key::assert_secret_key_for_address;
use crate::siwe::{SiweContext, verify_siwe_signature};

// Verify an Ethereum personal-sign message against the expected address.
#[export]
pub(crate) fn ethereum_personal_sign(
    message: [u8; 256],
    message_len: u32,
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; 64],
    expected_address: [u8; 20],
) {
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_zero_padded(message, message_len);
    assert(verify_personal_sign(
        message,
        message_len,
        public_key_x,
        public_key_y,
        signature,
        expected_address,
    ));
}

// Check that a secret key derives the expected Ethereum address.
#[export]
pub(crate) fn ethereum_secret_key(secret_key: [u8; 32], expected_address: [u8; 20]) {
    assert_secret_key_for_address(secret_key, expected_address);
}

// Verify a Sign-In with Ethereum signature and bind its request context.
#[export]
pub(crate) fn ethereum_siwe(
    address: [u8; 20],
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; 64],
    context: SiweContext<128, 128, 32>,
    submitted_message: [u8; 512],
    submitted_len: u32,
) {
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_zero_padded(context.domain, context.domain_len);
    canonical_bytes::assert_zero_padded(context.uri, context.uri_len);
    canonical_bytes::assert_zero_padded(context.nonce, context.nonce_len);
    verify_siwe_signature::<512, 128, 128, 32>(
        address,
        public_key_x,
        public_key_y,
        signature,
        context,
        submitted_message,
        submitted_len,
    );
}
