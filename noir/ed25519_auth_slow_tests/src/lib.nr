//! The slower tests of ed25519_auth: every Ed25519 verification costs one to two
//! minutes of constrained execution, so the package keeps a representative
//! subset and these live apart.
mod tests;
mod edge_vectors;
mod rfc_tests;
mod known_answer_tests;
