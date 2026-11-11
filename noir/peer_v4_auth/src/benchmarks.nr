// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.

use crate::{PeerV4Attestation, PeerV4Policy, verify_peer_v4};

// Verify a Peer V4 payment attestation against the expected attestor and payment policy.
// Runtime synthetic V4 payment envelope. No holder action authorization or
// production attestor authority is inferred from this standalone relation.
#[export]
pub(crate) fn peer_v4_verify(attestation: PeerV4Attestation<544>, policy: PeerV4Policy, now: u64) {
    let _ = verify_peer_v4(attestation, policy, now);
}
