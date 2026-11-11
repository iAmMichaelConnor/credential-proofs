//! Verify a WebAuthn authentication assertion over a caller supplied challenge.
//!
//! Adapted from the public Oxide WebAuthn verifier at
//! https://github.com/aztec-labs-eng/zkmoney-public (MIT), snapshot
//! 00e54087526d6d89f1755958eb027e077184cd9a; see ../LICENSE.
//! This version also binds the
//! RP ID hash and exact origin, and accepts only the bounded clientDataJSON
//! forms that current browsers emit for a same-origin `get()` ceremony.

use sha256::sha256_var;

pub struct PasskeyPublicKey {
    /// P-256 x coordinate, 32-byte big-endian encoding.
    pub x: [u8; 32],
    /// P-256 y coordinate, 32-byte big-endian encoding.
    pub y: [u8; 32],
}

pub struct WebAuthnAssertion<let CLIENT_MAX: u32> {
    /// authenticatorData without extensions or attested credential data.
    pub authenticator_data: [u8; 37],
    /// Zero-padded clientDataJSON bytes.
    pub client_data_json: [u8; CLIENT_MAX],
    pub client_data_json_len: u32,
    /// P-256 signature in r || s order, each scalar 32-byte big-endian.
    pub signature: [u8; 64],
}

/// Relying-party policy that the application must derive from trusted state.
/// Never populate this structure directly from the untrusted assertion.
pub struct WebAuthnPolicy<let RP_MAX: u32, let ORIGIN_MAX: u32> {
    /// Expected RP ID bytes, without scheme or port, zero-padded.
    pub rp_id: [u8; RP_MAX],
    pub rp_id_len: u32,
    /// Expected origin, including scheme and optional port, zero-padded.
    pub origin: [u8; ORIGIN_MAX],
    pub origin_len: u32,
    /// Whether the application requires authenticator user verification.
    pub require_user_verification: bool,
}

global CLIENT_PREFIX: [u8; 36] = "{\"type\":\"webauthn.get\",\"challenge\":\"".as_bytes();
global ORIGIN_PREFIX: [u8; 12] = "\",\"origin\":\"".as_bytes();
global CROSS_ORIGIN_FALSE: [u8; 20] = ",\"crossOrigin\":false".as_bytes();
global BASE64_URL_ALPHABET: [u8; 64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".as_bytes();

// The member that Chromium appends to about one ceremony in five
// (components/webauthn/core/browser/client_data_json.cc). It is pinned byte
// for byte: an open-ended member list could carry keys such as "Challenge"
// that a case-insensitive JSON decoder (Go encoding/json) would read.
global CHROMIUM_EXTRA_MEMBER: [u8; 109] = ",\"other_keys_can_be_added_here\":\"do not compare clientDataJSON against a template. See https://goo.gl/yabPex\""
    .as_bytes();

fn encode_challenge(challenge: [u8; 32]) -> [u8; 43] {
    let mut encoded: [u8; 43] = [0; 43];
    for group in 0..10 {
        let offset = group * 3;
        let word = ((challenge[offset] as u32) << 16)
            | ((challenge[offset + 1] as u32) << 8)
            | (challenge[offset + 2] as u32);
        encoded[group * 4] = BASE64_URL_ALPHABET[((word >> 18) & 0x3f) as u32];
        encoded[group * 4 + 1] = BASE64_URL_ALPHABET[((word >> 12) & 0x3f) as u32];
        encoded[group * 4 + 2] = BASE64_URL_ALPHABET[((word >> 6) & 0x3f) as u32];
        encoded[group * 4 + 3] = BASE64_URL_ALPHABET[(word & 0x3f) as u32];
    }
    let word = ((challenge[30] as u32) << 16) | ((challenge[31] as u32) << 8);
    encoded[40] = BASE64_URL_ALPHABET[((word >> 18) & 0x3f) as u32];
    encoded[41] = BASE64_URL_ALPHABET[((word >> 12) & 0x3f) as u32];
    encoded[42] = BASE64_URL_ALPHABET[((word >> 6) & 0x3f) as u32];
    encoded
}

/// Constrain a WebAuthn assertion to the provided challenge, RP ID and origin.
///
/// The caller must supply the registered key and policy from trusted state.
/// Challenge, RP ID, origin, and user-verification policy are separate from
/// the untrusted assertion, but this circuit cannot enforce where public
/// inputs came from: the application must bind policy to its stored session or
/// account state. Use the UTF-8 bytes of the origin supplied by the relying
/// party. The authenticator data must be exactly 37 bytes, so extensions and
/// registration data are not accepted.
///
/// `clientDataJSON` must start with the fixed prefix
/// `{"type":"webauthn.get","challenge":"<B64URL>","origin":"<ORIGIN>"`, and
/// the rest must be exactly one of:
/// - `}` (Safari and iOS omit crossOrigin for a same-origin ceremony);
/// - `,"crossOrigin":false}` (Chrome, Edge, Android Chrome, Firefox);
/// - `,"crossOrigin":false` + `CHROMIUM_EXTRA_MEMBER` + `}` (Chromium adds
///   this member to about one in five ceremonies).
/// Every accepted byte is fixed except the challenge and origin values, so
/// `"crossOrigin":true`, `topOrigin` and any other member are rejected.
///
/// Precondition: `91 + origin_len + 22 <= CLIENT_MAX`. The Chromium form with
/// its extra member is `222 + origin_len` bytes, so it fits only when
/// `origin_len <= CLIENT_MAX - 222`; the other forms are still accepted for
/// longer origins.
pub fn assert_valid_webauthn<let CLIENT_MAX: u32, let RP_MAX: u32, let ORIGIN_MAX: u32>(
    public_key: PasskeyPublicKey,
    challenge: Field,
    policy: WebAuthnPolicy<RP_MAX, ORIGIN_MAX>,
    assertion: WebAuthnAssertion<CLIENT_MAX>,
) {
    assert(policy.rp_id_len > 0);
    assert(policy.rp_id_len <= RP_MAX);
    assert(policy.origin_len > 0);
    assert(policy.origin_len <= ORIGIN_MAX);

    let rp_id_hash = sha256_var(policy.rp_id, policy.rp_id_len);
    for i in 0..32 {
        assert_eq(assertion.authenticator_data[i], rp_id_hash[i], "RP ID hash mismatch");
    }

    let flags = assertion.authenticator_data[32];
    // UP is required. UV is application-selectable. Reject reserved bits,
    // attested-credential data and extensions because this API accepts a
    // strict 37-byte authentication authenticatorData form.
    assert((flags & 0x01) == 0x01, "authenticator did not assert user presence");
    if policy.require_user_verification {
        assert((flags & 0x04) == 0x04, "authenticator did not verify the user");
    }
    assert((flags & 0x22) == 0, "reserved authenticator flag set");
    assert((flags & 0xc0) == 0, "attested credential data or extensions are unsupported");
    assert(
        ((flags & 0x10) == 0) | ((flags & 0x08) != 0),
        "backup state without backup eligibility",
    );

    let client = assertion.client_data_json;
    let client_len = assertion.client_data_json_len;
    let challenge_bytes: [u8; 32] = challenge.to_be_bytes();
    let encoded_challenge = encode_challenge(challenge_bytes);
    // `origin_end` is the index of the quote that closes the origin value.
    let origin_end = 91 + policy.origin_len;
    assert(origin_end + 22 <= CLIENT_MAX, "clientDataJSON capacity too small for origin");

    for i in 0..36 {
        assert_eq(client[i], CLIENT_PREFIX[i], "clientDataJSON type prefix mismatch");
    }
    for i in 0..43 {
        assert_eq(client[36 + i], encoded_challenge[i], "clientDataJSON challenge mismatch");
    }
    for i in 0..12 {
        assert_eq(client[79 + i], ORIGIN_PREFIX[i], "clientDataJSON origin key mismatch");
    }
    for i in 0..ORIGIN_MAX {
        if i < policy.origin_len {
            let byte = policy.origin[i];
            // JSON quoting and backslashes must be represented literally by the
            // trusted caller's origin. Control bytes are not valid origin syntax.
            assert(byte >= 0x20);
            assert(byte != 0x22);
            assert(byte != 0x5c);
            assert_eq(client[91 + i], byte, "clientDataJSON origin mismatch");
        }
    }
    assert_eq(client[origin_end], 0x22, "clientDataJSON origin mismatch");

    // WebAuthn Level 3, section 5.8.1.1 (serialization of
    // CollectedClientData) writes type, challenge, origin, then crossOrigin
    // and topOrigin, and only then any other members, each key once. The
    // limited verification algorithm of section 5.8.1.2 therefore reads
    // type, challenge, origin and crossOrigin from this fixed prefix. A
    // signer outside the browser could still append members that a full
    // JSON parser would read instead (a later duplicate, or a key that a
    // case-insensitive decoder folds onto one of these). So every byte after
    // the prefix is fixed: no JSON parser can read a different type,
    // challenge, origin or crossOrigin from an accepted value.
    assert(client_len <= CLIENT_MAX, "clientDataJSON length exceeds capacity");
    let cross_origin_omitted = client_len == origin_end + 2;
    let chromium_extra = client_len == origin_end + 22 + 109;
    if !cross_origin_omitted {
        // In bounds by the capacity precondition above.
        for i in 0..20 {
            assert_eq(
                client[origin_end + 1 + i],
                CROSS_ORIGIN_FALSE[i],
                "clientDataJSON crossOrigin must be false or omitted",
            );
        }
    }
    assert(
        cross_origin_omitted | (client_len == origin_end + 22) | chromium_extra,
        "clientDataJSON has an unsupported length or extra member",
    );
    if chromium_extra {
        // In bounds because client_len <= CLIENT_MAX.
        for i in 0..109 {
            assert_eq(
                client[origin_end + 21 + i],
                CHROMIUM_EXTRA_MEMBER[i],
                "clientDataJSON has an unsupported length or extra member",
            );
        }
    }
    assert_eq(client[client_len - 1], 0x7d, "clientDataJSON must end with }");
    for i in 0..CLIENT_MAX {
        if i >= client_len {
            assert_eq(client[i], 0, "clientDataJSON padding must be zero");
        }
    }

    let client_data_hash = sha256_var(client, client_len);
    let mut signed_data: [u8; 69] = [0; 69];
    for i in 0..37 {
        signed_data[i] = assertion.authenticator_data[i];
    }
    for i in 0..32 {
        signed_data[37 + i] = client_data_hash[i];
    }
    let message_hash = sha256_var(signed_data, 69);

    assert(
        std::ecdsa_secp256r1::verify_signature(
            public_key.x,
            public_key.y,
            assertion.signature,
            message_hash,
        ),
        "passkey signature verification failed",
    );
}

#[test]
fn verifies_public_oxide_passkey_vector_with_origin_and_rp_binding() {
    let public_key = PasskeyPublicKey {
        x: [
            0xd8, 0xcd, 0x12, 0xea, 0x5c, 0x67, 0xf2, 0xf8, 0xa0, 0x0c, 0x11, 0x24, 0x89, 0x3e,
            0xdc, 0xfa, 0x67, 0x54, 0xc4, 0xd6, 0xce, 0xde, 0x6b, 0xe1, 0x3b, 0xdf, 0x22, 0x95,
            0xc8, 0x10, 0xa9, 0x7f,
        ],
        y: [
            0xa5, 0xa8, 0x9d, 0x2d, 0x2a, 0x36, 0x0c, 0x0c, 0xa9, 0xa4, 0xd6, 0xc7, 0xc9, 0xed,
            0x4b, 0x28, 0xd3, 0xe1, 0x99, 0xd6, 0x62, 0x7f, 0x2e, 0x69, 0x6d, 0x68, 0x9c, 0x31,
            0x0a, 0x5b, 0x0f, 0x48,
        ],
    };
    let challenge: Field = 0x18380a3a4dec4daa04fe30592fa1f43bce1fb7e07fbcf136954ce1d9ce76cf98;
    let client_json = "{\"type\":\"webauthn.get\",\"challenge\":\"GDgKOk3sTaoE_jBZL6H0O84ft-B_vPE2lUzh2c52z5g\",\"origin\":\"https://stub.passkey.test\",\"crossOrigin\":false}"
        .as_bytes();
    let policy = WebAuthnPolicy {
        rp_id: "stub.passkey.test".as_bytes(),
        rp_id_len: 17,
        origin: "https://stub.passkey.test".as_bytes(),
        origin_len: 25,
        require_user_verification: true,
    };
    let auth = WebAuthnAssertion {
        authenticator_data: [
            0x06, 0xcc, 0x72, 0xc2, 0xe6, 0x6c, 0xe5, 0x75, 0x4e, 0xa5, 0x79, 0x2b, 0xa3, 0x91,
            0x9b, 0x3e, 0x49, 0x35, 0xe7, 0x01, 0x9a, 0x17, 0x23, 0xe2, 0x5c, 0xab, 0xde, 0x11,
            0x34, 0xef, 0xc6, 0xf9, 0x05, 0x00, 0x00, 0x00, 0x07,
        ],
        client_data_json: client_json,
        client_data_json_len: 138,
        signature: [
            0xcc, 0x37, 0x3c, 0x50, 0x5a, 0x3e, 0x68, 0x9a, 0x64, 0xd0, 0x54, 0x8f, 0x07, 0x66,
            0xe6, 0xf5, 0xf3, 0x68, 0xd1, 0x57, 0x0f, 0xe0, 0x38, 0x19, 0xd8, 0x18, 0xb9, 0xee,
            0xb0, 0x77, 0x53, 0x1a, 0x61, 0xe5, 0x9a, 0x8c, 0x9c, 0x0c, 0x7e, 0x38, 0xcb, 0xee,
            0x29, 0x6f, 0x44, 0xdf, 0x3b, 0xe1, 0x8d, 0xec, 0x79, 0x6c, 0x3c, 0x01, 0x23, 0xed,
            0xc9, 0xd1, 0xee, 0x89, 0x92, 0xf0, 0x03, 0xd9,
        ],
    };
    assert_valid_webauthn(public_key, challenge, policy, auth);
}

#[test(should_fail_with = "clientDataJSON challenge mismatch")]
fn rejects_other_challenge() {
    let public_key = PasskeyPublicKey {
        x: [
            0xd8, 0xcd, 0x12, 0xea, 0x5c, 0x67, 0xf2, 0xf8, 0xa0, 0x0c, 0x11, 0x24, 0x89, 0x3e,
            0xdc, 0xfa, 0x67, 0x54, 0xc4, 0xd6, 0xce, 0xde, 0x6b, 0xe1, 0x3b, 0xdf, 0x22, 0x95,
            0xc8, 0x10, 0xa9, 0x7f,
        ],
        y: [
            0xa5, 0xa8, 0x9d, 0x2d, 0x2a, 0x36, 0x0c, 0x0c, 0xa9, 0xa4, 0xd6, 0xc7, 0xc9, 0xed,
            0x4b, 0x28, 0xd3, 0xe1, 0x99, 0xd6, 0x62, 0x7f, 0x2e, 0x69, 0x6d, 0x68, 0x9c, 0x31,
            0x0a, 0x5b, 0x0f, 0x48,
        ],
    };
    let challenge: Field = 0x18380a3a4dec4daa04fe30592fa1f43bce1fb7e07fbcf136954ce1d9ce76cf98;
    let client_json = "{\"type\":\"webauthn.get\",\"challenge\":\"GDgKOk3sTaoE_jBZL6H0O84ft-B_vPE2lUzh2c52z5g\",\"origin\":\"https://stub.passkey.test\",\"crossOrigin\":false}"
        .as_bytes();
    let policy = WebAuthnPolicy {
        rp_id: "stub.passkey.test".as_bytes(),
        rp_id_len: 17,
        origin: "https://stub.passkey.test".as_bytes(),
        origin_len: 25,
        require_user_verification: true,
    };
    let mut auth = WebAuthnAssertion {
        authenticator_data: [
            0x06, 0xcc, 0x72, 0xc2, 0xe6, 0x6c, 0xe5, 0x75, 0x4e, 0xa5, 0x79, 0x2b, 0xa3, 0x91,
            0x9b, 0x3e, 0x49, 0x35, 0xe7, 0x01, 0x9a, 0x17, 0x23, 0xe2, 0x5c, 0xab, 0xde, 0x11,
            0x34, 0xef, 0xc6, 0xf9, 0x05, 0x00, 0x00, 0x00, 0x07,
        ],
        client_data_json: client_json,
        client_data_json_len: 138,
        signature: [
            0xcc, 0x37, 0x3c, 0x50, 0x5a, 0x3e, 0x68, 0x9a, 0x64, 0xd0, 0x54, 0x8f, 0x07, 0x66,
            0xe6, 0xf5, 0xf3, 0x68, 0xd1, 0x57, 0x0f, 0xe0, 0x38, 0x19, 0xd8, 0x18, 0xb9, 0xee,
            0xb0, 0x77, 0x53, 0x1a, 0x61, 0xe5, 0x9a, 0x8c, 0x9c, 0x0c, 0x7e, 0x38, 0xcb, 0xee,
            0x29, 0x6f, 0x44, 0xdf, 0x3b, 0xe1, 0x8d, 0xec, 0x79, 0x6c, 0x3c, 0x01, 0x23, 0xed,
            0xc9, 0xd1, 0xee, 0x89, 0x92, 0xf0, 0x03, 0xd9,
        ],
    };
    auth.client_data_json[0] = 0x7b;
    assert_valid_webauthn(public_key, challenge + 1, policy, auth);
}
