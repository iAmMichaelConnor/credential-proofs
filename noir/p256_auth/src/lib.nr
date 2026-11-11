//! Reusable byte-bound P256 SHA256 digest verification, independent of JWT.
//!
//! Pinned-toolchain behaviour of the ECDSA black box (nargo 1.0.0-rc.3 5a7ee9bf
//! ACVM, bb 6.0.0). Both differences only reject more, so soundness holds, but
//! an honest signature can fail:
//! - ACVM rejects a valid signature whose R.x lies in [n, p) (it converts R.x to
//!   a scalar instead of reducing mod n, as SEC 1 does); probability about
//!   2^-129.9 per P-256 signature (secp256k1 about 2^-127.7). The signer must
//!   sign again (an RFC 6979 signer needs a changed message).
//! - bb rejects a valid P-256 signature with u2 = r/s mod n in {0, 1, n-1}
//!   (r = s or r = n - s), which ACVM accepts: it executes but cannot be proved.
//!   Normalising s does not help; probability about 2^-255, not attacker
//!   forceable without the private key. secp256k1 is unaffected.
//! Do not special-case these values. Recheck both after a nargo or bb pin
//! change; every direct caller of the black box (passkey, Ethereum EIP-191,
//! peer_v4) shares this behaviour.
/// An authenticated issuer P-256 key, with big-endian affine coordinates.
/// Consumers must bind both coordinates to their trusted issuer key registry.
/// The P-256 verification blackbox checks the curve point and signature ranges.
pub struct TrustedP256Key {
    pub public_key_x: [u8; 32],
    pub public_key_y: [u8; 32],
}

/// Raw P256 digest verification, used by the OIDC ES256 path.
/// Digest construction and authenticated key selection remain the caller's job.
/// Both valid S representatives are accepted; zero/out-of-order S is rejected.
/// So s and n-s are two valid signatures of one digest: never key a nullifier
/// on signature bytes. The caller computes the digest in circuit from the
/// signed message: ECDSA over a free digest is existentially forgeable from the
/// public key alone. Pinned-toolchain limits: see the module comment.
pub fn verify_p256_digest(key: TrustedP256Key, signature: [u8; 64], digest: [u8; 32]) {
    assert(
        std::ecdsa_secp256r1::verify_signature(
            key.public_key_x,
            key.public_key_y,
            normalize_s(signature),
            digest,
        ),
        "ES256 signature verification failed",
    );
}

// The backend accepts low-S signatures. JOSE also permits high-S signatures;
// constrain n-S byte by byte so both encodings retain their ECDSA meaning.
// This is a constrained 2-to-1 map from [1, n-1] onto [1, (n-1)/2].
fn normalize_s(mut signature: [u8; 64]) -> [u8; 64] {
    let order: [u8; 32] = [
        255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 188, 230, 250, 173,
        167, 23, 158, 132, 243, 185, 202, 194, 252, 99, 37, 81,
    ];
    let half: [u8; 32] = [
        127, 255, 255, 255, 128, 0, 0, 0, 127, 255, 255, 255, 255, 255, 255, 255, 222, 115, 125, 86,
        211, 139, 207, 66, 121, 220, 229, 97, 126, 49, 146, 168,
    ];
    let mut nonzero = false;
    let mut less = false;
    let mut greater_half = false;
    let mut equal_order = true;
    let mut equal_half = true;
    for i in 0..32 {
        let b = signature[32 + i];
        nonzero = nonzero | (b != 0);
        less = less | (equal_order & (b < order[i]));
        greater_half = greater_half | (equal_half & (b > half[i]));
        equal_order = equal_order & (b == order[i]);
        equal_half = equal_half & (b == half[i]);
    }
    assert(nonzero & less, "ES256 scalar outside curve order");
    let mut borrow: u16 = 0;
    for j in 0..32 {
        let i = 31 - j;
        let difference = 256 + order[i] as u16 - signature[32 + i] as u16 - borrow;
        borrow = if difference < 256 { 1 } else { 0 };
        if greater_half {
            signature[32 + i] = (difference % 256) as u8;
        }
    }
    signature
}
mod benchmarks;
mod known_answer_tests;
