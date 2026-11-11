// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.
//
// Verify a PhilSys credential and enforce the supplied identity and freshness policy.
#[export]
pub fn philsys_verify(auth: crate::AuthInput, policy: crate::AuthPolicy) {
    auth.verify(policy);
}
