//! Native Noir verification of a UIDAI Aadhaar Secure QR (V2 layout).
//!
//! The statement follows the pinned Anon Aadhaar v2 circuit
//! (anon-aadhaar@4dad918, `AadhaarQRVerifier(121, 17, 1536)`), without Circom
//! or Groth16:
//!
//! - RSA-2048 PKCS#1 v1.5 SHA-256 signature by the trusted issuer key over the
//!   exact signed bytes (the decompressed QR payload without its last 256
//!   signature bytes; the host decompresses);
//! - the issuer key hash is the upstream `pubkeyHash` (Poseidon over the
//!   modulus as 17 x 121-bit limbs), so upstream key hashes stay valid;
//! - fields are located by the first 18 delimiter bytes (255);
//! - the reference-id timestamp, date of birth, gender, PIN code and state are
//!   extracted from the signed bytes.
//!
//! Deliberate differences from upstream: exact Gregorian time to the second
//! (no 2032 error, no hour truncation), a demographic nullifier that survives
//! photo updates and QR re-issue, an inclusive `age_at_least(years)` predicate,
//! only V2 payloads (upstream does not check the version bytes), and no
//! separate signal input. `verify` runs inside the Aztec function that performs
//! the fixed effect, so the proof is bound to that call by construction; it
//! does not show that the QR holder approved the call.
//!
//! `verify` also checks the fixed V2 prefix (indicator digit, 21-digit
//! reference id), that the delimiter hints are the first 18 bytes equal to 255
//! (none skipped, none taken from the photo), a valid IST issuance time at or
//! after the Unix epoch, and a `DD-MM-YYYY` date of birth (a year-only birth
//! date is rejected for every consumer). Other fields are checked only by the
//! accessor that reads them, so an age, PIN or state check accepts a QR with a
//! name longer than `MAX_NAME_BYTES`.
//!
//! Caller obligations:
//! - A Secure QR is a static bearer document: anyone holding a fresh copy can
//!   prove. Use it only for a fixed effect (attribute gate, one action per
//!   person through the nullifier, identity-gated fixed payload), never as an
//!   account entrypoint. A copy holder can act first and use up the nullifier.
//! - Pin `expected_issuer_key_hash` (the modulus only: Barrett limbs steer only
//!   hints) from trusted state. `UPSTREAM_TEST_ISSUER_KEY_HASH` has a published
//!   private key. The UIDAI 2021 certificate hash
//!   `18063425702624337643644061197836918910810808173893535653269228433734128853484`
//!   expired on 2024-02-27; obtain and check UIDAI's current certificate. A
//!   short list of hashes from trusted state spans a key rotation (the
//!   nullifier does not depend on the key).
//! - Call `assert_fresh` with an anchor-block `now` (the example uses
//!   `max_age` 10800 s and `max_future` 900 s), bound the inclusion time from the
//!   anchor, and never publish `issued_at` or set the transaction expiry from
//!   it: UIDAI logs downloads, so the exact time can identify the holder.
//! - The nullifier is linkable to anyone who knows the holder's name and date of
//!   birth, and same-name, same-birth-date, same-last-four holders collide; see
//!   `docs/SECURITY.md`. Use one seed per app and action and never publish
//!   `identity_commitment()`.
//!
//! Host input preparation (`packages/credential-proofs-inputs/src/aadhaar-secure-qr.ts`):
//! read the QR as a decimal integer, decompress (gzip, or zlib for the upstream
//! test QR; the host caps output at 64 KiB), split off the last 256 bytes as the
//! signature, take the first 18 indices of byte 255 as hints and convert the
//! signature, modulus and Barrett parameter to 18 x 120-bit limbs.

mod layout;
mod date;

mod tests;
mod layout_tests;
mod vectors;

use poseidon::poseidon2::Poseidon2;
use rsa_signature::{hash::poseidon_large, RSAPubkey};

/// RSA-2048 modulus, Barrett parameter and signature limbs (18 x 120 bits,
/// little-endian), as in the shared rsa_signature component.
pub global KEY_LIMBS: u32 = 18;
/// Delimiters before the photo: 17 field separators plus the photo delimiter.
pub global DELIMITERS: u32 = 18;
/// Upstream accepts at most 1536 SHA-256-padded bytes, which is at most 1527
/// signed bytes. Callers may choose another capacity; cost grows with it.
pub global UPSTREAM_MAX_SIGNED_BYTES: u32 = 1527;
/// Longest name in bytes that `identity_commitment` and `nullifier` accept
/// (five 31-byte chunks). Longer names are rejected there, not truncated.
/// `verify` and the attribute checks accept any name length.
pub global MAX_NAME_BYTES: u32 = 155;
/// Longest supported state field in bytes. Upstream packs at most 31 bytes.
pub global MAX_STATE_BYTES: u32 = 64;
/// India Standard Time is UTC+05:30 with no daylight saving time.
pub global IST_OFFSET_SECONDS: u64 = 19800;
/// Upstream `testPublicKeyHash` (packages/core/src/constants.ts at 4dad918).
/// The matching private key is published upstream. Never trust it outside
/// tests.
pub global UPSTREAM_TEST_ISSUER_KEY_HASH: Field =
    15134874015316324267425466444584014077184337590635665158241104437045239495873;
/// ASCII "aadhaar_secure_qr.identity.v1" as a big-endian field element.
pub global IDENTITY_DOMAIN: Field = 0x616164686161725f7365637572655f71722e6964656e746974792e7631;
/// ASCII "aadhaar_secure_qr.nullifier.v1" as a big-endian field element.
pub global NULLIFIER_DOMAIN: Field = 0x616164686161725f7365637572655f71722e6e756c6c69666965722e7631;

pub(crate) global NAME_START: u32 = 27;
pub(crate) global NAME_CHUNKS: u32 = 5;

/// Prover-supplied Secure QR input. Every field is untrusted: `verify` checks
/// the signature, the key against the caller's expected hash, and the
/// delimiter hints against the signed bytes.
pub struct SecureQrInput<let N: u32> {
    /// Decompressed QR payload without the trailing 256-byte signature.
    pub signed_data: BoundedVec<u8, N>,
    /// RSA signature (the last 256 decompressed bytes) as 18 x 120-bit limbs.
    pub signature: [Field; KEY_LIMBS],
    /// Issuer modulus limbs; bound by `expected_issuer_key_hash`.
    pub modulus: [Field; KEY_LIMBS],
    /// Barrett parameter limbs. They steer only unconstrained hint code in
    /// noir-bignum, so they are not part of the key hash.
    pub redc: [Field; KEY_LIMBS],
    /// Hint: indices of the first 18 bytes equal to 255.
    pub delimiters: [u32; DELIMITERS],
}

pub struct Date {
    pub year: u32,
    pub month: u32,
    pub day: u32,
}

/// A verified Secure QR. Fields are crate-private, so a consumer can only get
/// a value through `verify` (or the crate's own tests).
pub struct SecureQr<let N: u32> {
    pub(crate) data: BoundedVec<u8, N>,
    pub(crate) delimiters: [u32; DELIMITERS],
    pub(crate) issuer_key_hash: Field,
    pub(crate) issued_at: u64,
    pub(crate) issued_ist: Date,
    pub(crate) birth: Date,
    pub(crate) aadhaar_last4: u32,
}

/// Upstream-compatible issuer key hash of an RSA-2048 modulus.
pub fn issuer_key_hash(modulus: [Field; KEY_LIMBS]) -> Field {
    poseidon_large(modulus)
}

/// Verify a Secure QR signed by the issuer whose key hash the caller trusts.
/// `expected_issuer_key_hash` must come from trusted application state.
pub fn verify<let N: u32>(input: SecureQrInput<N>, expected_issuer_key_hash: Field) -> SecureQr<N> {
    let key_hash = issuer_key_hash(input.modulus);
    assert(key_hash == expected_issuer_key_hash, "Wrong Aadhaar issuer key");
    let _digest = RSAPubkey::new(input.modulus, input.redc).verify_rsa_sha256_pkcs1v15(
        input.signed_data,
        input.signature,
    );
    layout::parse(input.signed_data, input.delimiters, key_hash)
}

/// The nullifier for one identity commitment and application seed.
pub fn nullifier_from_identity(identity_commitment: Field, app_seed: Field) -> Field {
    Poseidon2::hash([NULLIFIER_DOMAIN, app_seed, identity_commitment], 3)
}

impl<let N: u32> SecureQr<N> {
    pub fn issuer_key_hash(self) -> Field {
        self.issuer_key_hash
    }

    /// Issuance time in Unix seconds (UTC), exact to the second. The QR's
    /// milliseconds are dropped. Keep this value private: UIDAI logs QR
    /// downloads, so a published exact time can identify the holder.
    pub fn issued_at(self) -> u64 {
        self.issued_at
    }

    /// Require `now - max_age_seconds <= issued_at <= now + max_future_seconds`
    /// without u64 overflow. `now` must be a trusted time, such as the anchor
    /// block timestamp; the future allowance covers anchor lag.
    pub fn assert_fresh(self, now: u64, max_age_seconds: u64, max_future_seconds: u64) {
        let issued = self.issued_at;
        if issued <= now {
            assert(now - issued <= max_age_seconds, "Aadhaar QR is too old");
        } else {
            assert(issued - now <= max_future_seconds, "Aadhaar QR timestamp is in the future");
        }
    }

    /// True when the holder had reached `years` whole years on the QR issuance
    /// date in IST. The birthday counts (inclusive). A 29 February birthday is
    /// reached on 1 March in a non-leap year. Upstream `ageAbove18` instead
    /// means more than 18 whole years.
    pub fn age_at_least(self, years: u32) -> bool {
        date::age_at_least(self.birth, self.issued_ist, years)
    }

    /// The signed gender byte (UIDAI uses ASCII M, F or T). It is not checked
    /// against a list, as upstream does not.
    pub fn gender(self) -> u8 {
        let d = self.delimiters;
        assert(d[5] == d[4] + 2, "Gender must be one byte");
        self.data.storage()[d[4] + 1]
    }

    /// The six-digit PIN code as an integer.
    pub fn pincode(self) -> u32 {
        let d = self.delimiters;
        assert(d[11] == d[10] + 7, "PIN code must have six digits");
        let bytes = self.data.storage();
        let mut value = 0;
        for i in 0..6 {
            value = value * 10 + date::digit(bytes[d[10] + 1 + i]);
        }
        value
    }

    /// The exact signed state bytes, zero beyond their length.
    pub fn state(self) -> BoundedVec<u8, MAX_STATE_BYTES> {
        let d = self.delimiters;
        let start = d[12] + 1;
        let length = d[13] - start;
        assert(length <= MAX_STATE_BYTES, "State exceeds supported length");
        let bytes = self.data.storage();
        let mut out = [0; MAX_STATE_BYTES];
        for i in 0..MAX_STATE_BYTES {
            let inside = i < length;
            // Masked reads use index 0 so they stay inside the array.
            let index = if inside { start + i } else { 0 };
            out[i] = if inside { bytes[index] } else { 0 };
        }
        BoundedVec::from_parts(out, length)
    }

    /// Poseidon2 commitment to the stable demographic identity: the last four
    /// Aadhaar digits, the date of birth and the exact signed name bytes. It
    /// excludes the photo, the issuance time, the address, the mobile digits,
    /// gender and the issuer key, so photo updates, QR re-issue, moves and key
    /// rotation keep it. See `docs/SECURITY.md` for collision and linkability
    /// limits. The encoding is injective for names up to `MAX_NAME_BYTES`: the
    /// length is an input and name byte `i` is always byte `i mod 31` of chunk
    /// `i / 31`, each chunk below 2^248.
    /// Fails for a name longer than `MAX_NAME_BYTES`.
    pub fn identity_commitment(self) -> Field {
        assert(NAME_CHUNKS * 31 == MAX_NAME_BYTES, "Name chunks must cover the name capacity");
        let bytes = self.data.storage();
        // parse fixes delimiter 2 at NAME_START - 1 and delimiter 3 above it,
        // so this subtraction cannot underflow.
        let name_length = self.delimiters[3] - NAME_START;
        assert(name_length <= MAX_NAME_BYTES, "Name exceeds supported length");
        let mut input = [0; 6 + NAME_CHUNKS];
        input[0] = IDENTITY_DOMAIN;
        input[1] = self.aadhaar_last4 as Field;
        input[2] = self.birth.year as Field;
        input[3] = self.birth.month as Field;
        input[4] = self.birth.day as Field;
        input[5] = name_length as Field;
        for j in 0..NAME_CHUNKS {
            let mut chunk = 0;
            for i in 0..31 {
                let k = j * 31 + i;
                let byte = if k < name_length {
                    bytes[NAME_START + k] as Field
                } else {
                    0
                };
                chunk = chunk * 256 + byte;
            }
            input[6 + j] = chunk;
        }
        Poseidon2::hash(input, 6 + NAME_CHUNKS)
    }

    /// One value per person and application seed. Consume it in the app
    /// contract's nullifier set for one-use-per-person rules.
    pub fn nullifier(self, app_seed: Field) -> Field {
        nullifier_from_identity(self.identity_commitment(), app_seed)
    }
}
mod benchmarks;
mod known_answer_tests;
