//! A contract with no private or public function, deployed by the core TXE
//! tests with a chosen `immutables_hash`. The tests then run the cores' public
//! functions (`settle`, `gate`, `entrypoint`, ...) in a private context at its
//! address, so `bind_terms` and `bind_policy` read a real deployed instance.
//!
//! Its artifact has only the macro-generated utility functions. TXE therefore
//! deploys it without verification keys or transpilation: no key generation
//! and no SRS read: `bb aztec_process` writes no verification key for it.
use aztec::macros::aztec;

#[aztec]
pub contract TermsShell {}
