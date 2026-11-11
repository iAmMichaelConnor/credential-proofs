//! TEST ONLY: the target of the account dispatch deploy test (src/test.nr).
//! `mark` records a marker nullifier when its caller is the expected sender,
//! so a dispatched call that ran, and who made it, are observable.
use aztec::{macros::{aztec, AztecConfig}, messages::discovery::do_sync_state_no_op};

mod test;

#[aztec(AztecConfig::new().custom_sync_state(do_sync_state_no_op))]
pub contract AuthDispatchTarget {
    use aztec::{
        hash::hash_args,
        macros::functions::external,
        oracle::execution_cache,
        protocol::{abis::function_selector::FunctionSelector, address::AztecAddress},
    };

    /// Calls `selector` (an account entrypoint) on `account` with `args`. A
    /// wallet supplies the preimages of the payload's argument hashes; TXE has
    /// no request builder for that, so this launcher stores `target_args`, the
    /// arguments of the payload's call, in the same private execution first.
    #[external("private")]
    fn execute_account(account: AztecAddress, selector: FunctionSelector, args: [Field; 83], target_args: [Field; 2]) {
        execution_cache::store(target_args, hash_args(target_args));
        let _ = self.context.call_private_function(account, selector, args);
    }

    #[external("private")]
    fn mark(expected_sender: AztecAddress, marker: Field) {
        assert_eq(self.msg_sender(), expected_sender, "Expected the account as caller");
        self.context.push_nullifier_unsafe(marker);
    }
}
