// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.

use crate::{AuthInput, authorise, AuthPolicy};

// Authorise a JPKI holder signature bound to the account, action and session.
#[export]
pub(crate) fn jpki_authorise(
    input: AuthInput,
    policy: AuthPolicy,
    account: [u8; 32],
    action: [u8; 32],
    session: [u8; 32],
    now: u64,
) -> u64 {
    authorise(input, policy, account, action, session, now)
}
