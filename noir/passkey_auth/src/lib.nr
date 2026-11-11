//! Bounded WebAuthn assertion checks for P-256 passkeys.
//!
//! `webauthn::assert_valid_webauthn` verifies a `navigator.credentials.get()`
//! assertion: `webauthn.get` type, a 32-byte challenge as canonical unpadded
//! base64url, exact origin, RP ID hash, user presence, optional user
//! verification and the P-256 signature. Current Chrome, Edge, Safari, Firefox
//! and Android Chrome assertions are accepted; native Android app client data
//! (`androidPackageName`) is not. `authenticatorData` is exactly 37 bytes: the
//! signature counter is signed but not interpreted (no clone detection), and
//! this is authentication only, not registration. The pinned black box needs a
//! low-`s` signature; the host importer maps a high `s` to `n - s`.
//!
//! Caller obligations:
//! - Bind the registered key to the account and take `WebAuthnPolicy` from
//!   trusted state; consume each challenge once.
//! - Serve the ceremony page with `Content-Security-Policy: frame-ancestors
//!   'none'` or `X-Frame-Options: DENY` (a framed ceremony reports
//!   `"crossOrigin":true`, which is rejected).
//! - At enrolment, execute one test assertion from the new passkey with the
//!   account's policy, so an unsupported authenticator or browser is found
//!   while the user can still choose another passkey.
pub mod webauthn;
mod browser_vectors;
mod benchmarks;
mod known_answer_tests;
