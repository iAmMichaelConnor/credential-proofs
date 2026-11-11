//! Bounded DER and certificate primitives. Offsets are derived from constrained
//! parent/child TLV boundaries; no host-selected subject or key offset is trusted.
//!
//! Syntax, signature verification, certificate purpose and trust-anchor
//! selection are separate. Parsing a certificate or a good OCSP status does not
//! authenticate it, and a self-signed certificate is not an authority because
//! it verifies its own signature. The consumer authenticates the trust anchor,
//! constrains issuer Name/key relations and path purpose, and enforces current
//! validity and revocation.
//!
//! - `der`: low-tag-number DER with canonical lengths; indefinite or
//!   noncanonical lengths and trailing bytes fail.
//! - `rsa_certificate::parse_rsa_certificate`: X.509 v3 with positive canonical
//!   serials up to 20 bytes, exponent 65537, exact 2048/4096-bit odd moduli, DER
//!   NULL algorithm parameters, matching inner/outer signature algorithms
//!   (`SHA512` 0 = SHA256withRSA, 1 = SHA512withRSA), RFC 5280 Validity times
//!   (UTCTime through 2049, GeneralizedTime from 2050; before 1970 rejected) and
//!   an extensions field; unique identifiers are rejected. It does not verify the
//!   signature. Names stay exact DER TLVs: compare their constrained hashes.
//!   `certificate::parse` is the RSA-2048/SHA-256 profile.
//! - `extensions::purpose` / `ca_purpose` / `assert_purpose` / `check_purpose`:
//!   role 0 CA (basicConstraints CA:true, keyCertSign, minimal pathLen; with
//!   `ca_purpose` a present pathLen covers the following intermediates), role 1
//!   holder (digitalSignature, no CA usages, the selected policy OID, clientAuth
//!   if EKU present), role 2 delegated OCSP (digitalSignature, OCSPSigning,
//!   noCheck). Duplicate or unknown critical extensions fail; at most 16
//!   extensions, 8 policies and 8 EKUs. The policy configuration and encoded
//!   policy OIDs must be nonempty and the requested policy fits 32 bytes; this
//!   is not general OID validation. A delegated responder without noCheck needs
//!   independently authenticated fresh status.
//! - `ocsp::parse_unverified_good_response` returns digest, signature and
//!   exclusive expiry without verifying the signature: the caller must verify
//!   those bytes under the authenticated responder key. `ocsp::good` verifies
//!   RSA-2048/SHA-256 itself. Profile: one SingleResponse, SHA-1 CertID with
//!   exact issuer hashes and serial, `good`, mandatory thisUpdate/nextUpdate,
//!   producedAt ordering, maximum age, signer validity, at most one embedded
//!   certificate equal to the authenticated signer, at most 8 noncritical
//!   extensions. Consumers also clamp expiry to certificate and policy validity.
//!
//! SHA-1 is used only for RFC 6960 identifiers; the pinned SHA-1 dependency
//! emits manual-constraint-coverage diagnostics, which are not suppressed and
//! are not by themselves a confirmed unconstrained relation.
pub mod der;
pub mod crypto;
pub mod time;
pub mod certificate;
pub mod extensions;
pub mod ocsp;
mod hash_tests;

pub mod rsa_certificate;
mod purpose_tests;
mod path_len_vectors;

mod policy_vectors;
