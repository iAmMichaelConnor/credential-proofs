// Checked against the fix in noir-lang/sha256 commit a82d3ea6 (partial_sha256_var_end
// constrained/unconstrained divergence on non-block-aligned messages): this copy is not
// affected, since both runtimes read the final chunk as the first `message_size` bytes of
// `msg`; partial_hash/tests.nr covers those cases in both runtimes.
use std::hash::sha256_compression;
use std::runtime::is_unconstrained;

mod tests;

// https://github.com/noir-lang/noir/blob/76eec710ff73e5e45fdddcd41ae2cd74e879cfa5/noir_stdlib/src/hash/sha256.nr#L23
// Convert 64-byte array to array of 16 u32s
pub fn msg_u8_to_u32(msg: [u8; BLOCK_SIZE]) -> [u32; 16] {
    let mut msg32: [u32; 16] = [0; 16];

    for i in 0..16 {
        let mut msg_field: Field = 0;
        for j in 0..4 {
            msg_field = msg_field * 256 + msg[64 - 4 * (i + 1) + j] as Field;
        }
        msg32[15 - i] = msg_field as u32;
    }

    msg32
}

// https://github.com/noir-lang/noir/blob/76eec710ff73e5e45fdddcd41ae2cd74e879cfa5/noir_stdlib/src/hash/sha256.nr#L38
unconstrained fn build_msg_block_iter<let N: u32>(
    msg: [u8; N],
    message_size: u32,
    msg_start: u32,
) -> ([u8; BLOCK_SIZE], u32) {
    let mut msg_block: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    // We insert `BLOCK_SIZE` bytes (or up to the end of the message)
    let block_input = if msg_start + BLOCK_SIZE > message_size {
        if message_size < msg_start {
            // This function is sometimes called with `msg_start` past the end of the message.
            // In this case we return an empty block and zero pointer to signal that the result should be ignored.
            0
        } else {
            message_size - msg_start
        }
    } else {
        BLOCK_SIZE
    };
    for k in 0..block_input {
        msg_block[k] = msg[msg_start + k];
    }
    (msg_block, block_input)
}

// https://github.com/noir-lang/noir/blob/76eec710ff73e5e45fdddcd41ae2cd74e879cfa5/noir_stdlib/src/hash/sha256.nr#L59
// Verify the block we are compressing was appropriately constructed
fn verify_msg_block<let N: u32>(
    msg: [u8; N],
    message_size: u32,
    msg_block: [u8; 64],
    msg_start: u32,
) -> u32 {
    let mut msg_byte_ptr: u32 = 0; // Message byte pointer
    let mut msg_end = msg_start + BLOCK_SIZE;
    if msg_end > N {
        msg_end = N;
    }

    for k in msg_start..msg_end {
        if k < message_size {
            assert_eq(msg_block[msg_byte_ptr], msg[k]);
            msg_byte_ptr = msg_byte_ptr + 1;
        }
    }

    msg_byte_ptr
}

global BLOCK_SIZE: u32 = 64;

// https://github.com/noir-lang/noir/blob/76eec710ff73e5e45fdddcd41ae2cd74e879cfa5/noir_stdlib/src/hash/sha256.nr#L86-L116
/**
 * Partially computes a SHA256 hash of a message but does not finalize
 * @notice can be used for post-partial hashing where client proves part of hash and relies on server to finish
 * 
 *
 * @param N: the fixed length of the message to hash. It must be divisible by
 *  BLOCK_SIZE; this is enforced at compile time.
 * @param msg: the preimage to begin hashing
 * @return the intermediate hash state
 */
pub fn partial_sha256_var_start<let N: u32>(msg: [u8; N]) -> [u32; 8] {
    std::static_assert(
        N % BLOCK_SIZE == 0,
        "Partial SHA start input must contain full blocks",
    );
    let num_blocks = N / BLOCK_SIZE;
    let mut msg_block: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    let mut h: [u32; 8] = [
        1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
        1541459225,
    ]; // Intermediate hash, starting with the canonical initial value
    let mut msg_byte_ptr = 0; // Pointer into msg_block
    for i in 0..num_blocks {
        let msg_start = BLOCK_SIZE * i;
        let (new_msg_block, new_msg_byte_ptr) = unsafe { build_msg_block_iter(msg, N, msg_start) };
        if msg_start < N {
            msg_block = new_msg_block;
        }

        if !is_unconstrained() {
            // Verify the block we are compressing was appropriately constructed
            let new_msg_byte_ptr = verify_msg_block(msg, N, msg_block, msg_start);
            if msg_start < N {
                msg_byte_ptr = new_msg_byte_ptr;
            }
        } else if msg_start < N {
            msg_byte_ptr = new_msg_byte_ptr;
        }

        // If the block is filled, compress it.
        // An un-filled block is handled after this loop.
        if (msg_start < N) & (msg_byte_ptr == BLOCK_SIZE) {
            h = sha256_compression(msg_u8_to_u32(msg_block), h);
        }
    }

    h
}

/**
 * Given some state of a partially computed sha256 hash and part of the preimage, continue hashing
 * @notice used for complex/ recursive offloading of post-partial hashing
 *
 * @param N - the maximum length of the message to hash
 * @param h - the intermediate hash state
 * @param msg - the preimage to hash
 * @param message_size - the actual length of the preimage to hash
 *   It must be a multiple of BLOCK_SIZE and no larger than N.
 * @return the intermediate hash state after compressing in msg to h
 */
pub fn partial_sha256_var_interstitial<let N: u32>(
    mut h: [u32; 8],
    msg: [u8; N],
    message_size: u32,
) -> [u32; 8] {
    assert(message_size % BLOCK_SIZE == 0, "Message size must be a multiple of the block size");
    assert(message_size <= N, "Message size exceeds interstitial input capacity");
    let num_blocks = N / BLOCK_SIZE;
    let mut msg_block: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    let mut msg_byte_ptr = 0; // Pointer into msg_block
    for i in 0..num_blocks {
        let msg_start = BLOCK_SIZE * i;
        let (new_msg_block, new_msg_byte_ptr) = unsafe { build_msg_block_iter(msg, N, msg_start) };
        if msg_start < N {
            msg_block = new_msg_block;
        }

        if !is_unconstrained() {
            // Verify the block we are compressing was appropriately constructed
            let new_msg_byte_ptr = verify_msg_block(msg, N, msg_block, msg_start);
            if msg_start < N {
                msg_byte_ptr = new_msg_byte_ptr;
            }
        } else if msg_start < N {
            msg_byte_ptr = new_msg_byte_ptr;
        }

        // If the block is filled, compress it.
        // An un-filled block is handled after this loop.
        if (msg_start < N) & (msg_byte_ptr == BLOCK_SIZE) & (msg_start < message_size) {
            h = sha256_compression(msg_u8_to_u32(msg_block), h);
        }
    }

    h
}

// https://github.com/noir-lang/noir/blob/76eec710ff73e5e45fdddcd41ae2cd74e879cfa5/noir_stdlib/src/hash/sha256.nr#L85
/**
 * Given some state of a partially computed sha256 hash and remaining preimage, complete the hash
 * @notice used for traditional partial hashing
 *
 * @param N - the maximum length of the message to hash
 * @param h - the intermediate hash state
 * @param msg - the remaining preimage to hash
 * @param message_size - the size of the remaining preimage
 * @param real_message_size -= the total size of the preimage
 *   The remaining length must be no larger than N and no larger than the total.
 *   Total bytes must be below 2^61 so its bit length fits the SHA-256 u64 field.
 * @return finalized sha256 hash
 */
pub fn partial_sha256_var_end<let N: u32>(
    mut h: [u32; 8],
    msg: [u8; N],
    message_size: u64,
    real_message_size: u64,
) -> [u8; 32] {
    // SHA-256 stores the message length in a 64-bit bit count, so the byte length
    // must be at most 2^61 - 1. Check before narrowing the bounded suffix length.
    assert(message_size <= N as u64, "Message size exceeds end input capacity");
    assert(message_size <= real_message_size, "Remaining length exceeds total message length");
    assert(real_message_size < (1u64 << 61), "SHA-256 message length exceeds 64-bit bit count");
    let message_size = message_size as u32;
    let num_blocks = N / BLOCK_SIZE;
    let mut msg_block: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    let mut msg_byte_ptr = 0; // Pointer into msg_block
    for i in 0..num_blocks {
        let msg_start = BLOCK_SIZE * i;
        let (new_msg_block, new_msg_byte_ptr) =
            unsafe { build_msg_block_iter(msg, message_size, msg_start) };
        if msg_start < message_size {
            msg_block = new_msg_block;
        }

        if !is_unconstrained() {
            // Verify the block we are compressing was appropriately constructed
            let new_msg_byte_ptr = verify_msg_block(msg, message_size, msg_block, msg_start);
            if msg_start < message_size {
                msg_byte_ptr = new_msg_byte_ptr;
            }
        } else if msg_start < message_size {
            msg_byte_ptr = new_msg_byte_ptr;
        }

        // If the block is filled, compress it.
        // An un-filled block is handled after this loop.
        if (msg_start < message_size) & (msg_byte_ptr == BLOCK_SIZE) {
            h = sha256_compression(msg_u8_to_u32(msg_block), h);
        }
    }

    let modulo = N % BLOCK_SIZE;
    // Handle setup of the final msg block.
    // This case is only hit if the msg is less than the block size,
    // or our message cannot be evenly split into blocks.
    if modulo != 0 {
        let msg_start = BLOCK_SIZE * num_blocks;
        let (new_msg_block, new_msg_byte_ptr) =
            unsafe { build_msg_block_iter(msg, message_size, msg_start) };

        if msg_start < message_size {
            msg_block = new_msg_block;
        }

        if !is_unconstrained() {
            let new_msg_byte_ptr = verify_msg_block(msg, message_size, msg_block, msg_start);
            if msg_start < message_size {
                msg_byte_ptr = new_msg_byte_ptr;
            }
        } else if msg_start < message_size {
            msg_byte_ptr = new_msg_byte_ptr;
        }
    }

    if msg_byte_ptr == BLOCK_SIZE {
        msg_byte_ptr = 0;
    }

    // This variable is used to get around the compiler under-constrained check giving a warning.
    // We want to check against a constant zero, but if it does not come from the circuit inputs
    // or return values the compiler check will issue a warning.
    let zero = msg_block[0] - msg_block[0];

    // Pad the rest such that we have a [u32; 2] block at the end representing the length
    // of the message, and a block of 1 0 ... 0 following the message (i.e. [1 << 7, 0, ..., 0]).
    msg_block[msg_byte_ptr] = 1 << 7;
    let last_block = msg_block;
    msg_byte_ptr = msg_byte_ptr + 1;

    unsafe {
        let (new_msg_block, new_msg_byte_ptr) = pad_msg_block(msg_block, msg_byte_ptr);
        msg_block = new_msg_block;
        if is_unconstrained() {
            msg_byte_ptr = new_msg_byte_ptr;
        }
    }

    if !is_unconstrained() {
        for i in 0..64 {
            assert_eq(msg_block[i], last_block[i]);
        }

        // If i >= 57, there aren't enough bits in the current message block to accomplish this, so
        // the 1 and 0s fill up the current block, which we then compress accordingly.
        // Not enough bits (64) to store length. Fill up with zeros.
        for _i in 57..64 {
            if msg_byte_ptr <= 63 & msg_byte_ptr >= 57 {
                assert_eq(msg_block[msg_byte_ptr], zero);
                msg_byte_ptr += 1;
            }
        }
    }

    if msg_byte_ptr >= 57 {
        h = sha256_compression(msg_u8_to_u32(msg_block), h);

        msg_byte_ptr = 0;
    }

    msg_block = unsafe { attach_len_to_msg_block(msg_block, msg_byte_ptr, real_message_size) };

    if !is_unconstrained() {
        for i in 0..56 {
            if i < msg_byte_ptr {
                assert_eq(msg_block[i], last_block[i]);
            } else {
                assert_eq(msg_block[i], zero);
            }
        }

        let len = 8u64 * real_message_size;
        let len_bytes: [u8; 8] = (len as Field).to_be_bytes();
        for i in 56..64 {
            assert_eq(msg_block[i], len_bytes[i - 56]);
        }
    }

    hash_final_block(msg_block, h)
}

unconstrained fn pad_msg_block(
    mut msg_block: [u8; BLOCK_SIZE],
    mut msg_byte_ptr: u32,
) -> ([u8; BLOCK_SIZE], u32) {
    // If i >= 57, there aren't enough bits in the current message block to accomplish this, so
    // the 1 and 0s fill up the current block, which we then compress accordingly.
    if msg_byte_ptr >= 57 {
        // Not enough bits (64) to store length. Fill up with zeros.
        for i in msg_byte_ptr..BLOCK_SIZE {
            msg_block[i] = 0;
        }
        (msg_block, BLOCK_SIZE)
    } else {
        (msg_block, msg_byte_ptr)
    }
}

unconstrained fn attach_len_to_msg_block(
    mut msg_block: [u8; BLOCK_SIZE],
    mut msg_byte_ptr: u32,
    message_size: u64,
) -> [u8; BLOCK_SIZE] {
    // We assume that `msg_byte_ptr` is less than 57 because if not then it is reset to zero before calling this function.
    // In any case, fill blocks up with zeros until the last 64 (i.e. until msg_byte_ptr = 56).
    for i in msg_byte_ptr..56 {
        msg_block[i] = 0;
    }

    let len = 8u64 * message_size;
    let len_bytes: [u8; 8] = (len as Field).to_be_bytes();
    for i in 0..8 {
        msg_block[56 + i] = len_bytes[i];
    }
    msg_block
}

fn hash_final_block(msg_block: [u8; BLOCK_SIZE], mut state: [u32; 8]) -> [u8; 32] {
    let mut out_h: [u8; 32] = [0; 32]; // Digest as sequence of bytes
    // Hash final padded block
    state = sha256_compression(msg_u8_to_u32(msg_block), state);

    // Return final hash as byte array
    for j in 0..8 {
        let h_bytes: [u8; 4] = (state[7 - j] as Field).to_le_bytes();
        for k in 0..4 {
            out_h[31 - 4 * j - k] = h_bytes[k];
        }
    }

    out_h
}

#[test]
fn test_partial_sha_start_and_interstitial_full_block() {
    let iv: [u32; 8] = [
        1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
        1541459225,
    ];
    let block: [u8; 64] = [0; 64];
    let started = partial_sha256_var_start(block);
    let continued = partial_sha256_var_interstitial(iv, block, 64);
    assert_eq(started, continued);
}

#[test]
fn test_partial_sha_empty_suffix_and_largest_valid_length() {
    let iv: [u32; 8] = [
        1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
        1541459225,
    ];
    let empty: [u8; 0] = [];
    let actual = partial_sha256_var_end(iv, empty, 0, 0);
    let expected: [u8; 32] = sha256::sha256_var(empty, 0);
    assert_eq(actual, expected);

    // The intermediate state remains the caller's responsibility; this checks
    // that the largest byte count whose bit length fits u64 is accepted.
    let _ = partial_sha256_var_end(iv, empty, 0, (1u64 << 61) - 1);
}

#[test(should_fail_with = "Message size exceeds end input capacity")]
fn test_partial_sha_end_rejects_length_before_u32_cast() {
    let iv: [u32; 8] = [0; 8];
    let empty: [u8; 0] = [];
    let _ = partial_sha256_var_end(iv, empty, 1u64 << 32, 1u64 << 32);
}

#[test(should_fail_with = "SHA-256 message length exceeds 64-bit bit count")]
fn test_partial_sha_end_rejects_bit_length_overflow() {
    let iv: [u32; 8] = [0; 8];
    let empty: [u8; 0] = [];
    let _ = partial_sha256_var_end(iv, empty, 0, 1u64 << 61);
}

#[test(should_fail_with = "Remaining length exceeds total message length")]
fn test_partial_sha_end_rejects_suffix_longer_than_total() {
    let iv: [u32; 8] = [0; 8];
    let one_byte: [u8; 1] = [0];
    let _ = partial_sha256_var_end(iv, one_byte, 1, 0);
}

#[test(should_fail_with = "Message size exceeds interstitial input capacity")]
fn test_partial_sha_interstitial_rejects_length_over_capacity() {
    let iv: [u32; 8] = [0; 8];
    let empty: [u8; 0] = [];
    let _ = partial_sha256_var_interstitial(iv, empty, 64);
}
