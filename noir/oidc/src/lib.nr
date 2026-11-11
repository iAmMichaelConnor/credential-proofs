//! JWT verification, bounded JSON policy, and named Google and Apple profiles.
//!
//! The compact token is supplied as three bounded ASCII segments. The verifier
//! reconstructs `header.payload` itself, decodes the header and payload from
//! those exact segments, and binds the signature segment to the RSA limbs.
//! The payload must match the flat JSON claims profile of `json.nr`: the
//! selected claims are direct root members, and other members are checked as
//! bounded JSON and ignored (nested values and escapes included). The signature
//! covers the whole reconstructed message; no external partial hash state
//! authenticates an omitted prefix.
//!
//! Entry points:
//! - `verify_google`, `verify_apple` (and `*_with_iat`): RS256 under a 2048-bit
//!   `TrustedRsaKey`. Google accepts `https://accounts.google.com` and
//!   `accounts.google.com`; Apple requires `https://appleid.apple.com`. Every
//!   other verifier compares one exact expected issuer.
//! - `JwtInput::verify`, `verify_profile`, `verify_es256`, `verify_es256_profile`
//!   (and `*_with_iat`): generic RS256/ES256 with an exact issuer; `profile` is
//!   `PROFILE_FLAT`, `PROFILE_AMR` (`amr` string array) or
//!   `PROFILE_AMR_SCOPE_RELIABILITY` (also gov.br `reliability_info.level`).
//! - `verify_rs256_payload`, `verify_es256_payload` (and the typed, ID-token and
//!   RSA-4096 forms): authenticate the complete JWS and return the decoded
//!   payload; they authorize nothing until the caller binds the claims.
//! - `parse_document_claims(_for_audience)` with `assert_claims_policy`: claims
//!   of a structured document (strings up to 4096 bytes, depth 8, u64 integers;
//!   `iat` required). The consumer enforces its own `iat` rule and extra claims.
//!
//! Caller obligations (shared by every provider wrapper in this workspace):
//! - The key comes from enrolled state or an authenticated registry, never from
//!   the token: `kid`, `jku` and similar members select nothing. Key update and
//!   rotation policy is the caller's.
//! - RSA Barrett limbs are an unconstrained reduction hint: several values verify
//!   one key. Identify a key by its modulus alone in any denylist, registry or
//!   nullifier, and keep the Barrett limbs out of public inputs. An exact-match
//!   commitment to the (modulus, Barrett) pair the owner enrolled is a safe
//!   allowlist.
//! - Expected issuer, audience and subject come from enrolled policy. The nonce
//!   is derived from the action, fresh and single-use; the circuit only compares
//!   it with the signed claim. `now` is a trusted time. Replay protection is the
//!   caller's.
//! - ES256 accepts both `s` and `n - s`, so one token has two compact encodings:
//!   never key a nullifier or replay record on signature or token bytes.
//!
//! Accepted profile (anything else fails):
//! - RSA keys: canonical 120-bit limbs of an odd modulus of exactly 2048 bits
//!   (4096 for `TrustedRsa4096Key`), exponent 65537, Barrett limbs below 2^120.
//!   ES256 signatures are 64-byte JOSE `r || s`, not DER.
//! - Header: `alg` once (`RS256` or `ES256`), optional `typ` = `JWT`, optional
//!   `kid`; the ID-token payload forms also admit `cty` = `JWT`. Unknown or
//!   duplicate members fail; values are unescaped strings of at most 256 bytes.
//! - Claims: `iss`, `aud`, `sub`, `nonce`, `azp`, `exp`, `nbf` (and `iat` in the
//!   `*_with_iat` forms) at most once each as direct root members. `aud` is one
//!   string; a present `azp` equals it; `exp > now`; a present `nbf <= now`;
//!   `iat <= now` where read. Selected strings hold at most 256 decoded bytes
//!   with `\/` as the only escape; selected numbers are canonical unsigned
//!   decimals up to 2^64 - 1. Without `_with_iat`, `iat` is not read.
//! - Other members are validated JSON (any escape, nesting depth at most 8) and
//!   ignored; nested names cannot shadow a root claim. A DPoP `cnf` is not
//!   enforced, so sender-constrained tokens verify as bearer tokens.
//! - Keys are unescaped and at most 256 bytes at every level; strings are valid
//!   UTF-8 without raw control characters; segments are canonical unpadded
//!   base64url within the declared `BoundedVec` capacities. Audience arrays
//!   (outside `parse_document_claims_for_audience`), negative, fractional or
//!   exponent numbers are unsupported.

mod json;
mod json_profile;
mod jwt;
mod providers;

pub use jwt::{
    assert_claims_policy, assert_claims_policy_with_iat, JwtInput, TrustedRsa4096Key, TrustedRsaKey,
};
pub use providers::{verify_apple, verify_apple_with_iat, verify_google, verify_google_with_iat};

mod es256;
pub use es256::{TrustedP256Key, verify_p256_digest};
pub use json::{
    Claims, ClaimsWithIat, literal_vec, parse_claims_profile, parse_claims_profile_with_iat,
    PROFILE_AMR, PROFILE_AMR_SCOPE_RELIABILITY, PROFILE_FLAT, ProfileClaims, string_matches,
};
mod json_document;
pub use json_document::{
    assert_json_document, json_array_element, json_member, json_optional_member, json_string,
    json_u64, JsonSpan,
};

mod json_document_claims;
pub use json_document_claims::{
    DocumentClaims, parse_document_claims, parse_document_claims_for_audience,
};

mod policy;
pub use policy::{claims_with_iat_and_required_string, claims_with_required_string};
mod benchmarks;
mod known_answer_tests;
