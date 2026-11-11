//! Canonical encoding of variable-length public byte strings.
//!
//! A circuit usually takes a variable-length byte string as a fixed-capacity
//! array and a length (a `BoundedVec`, or a `[u8; N]` and a separate length),
//! and reads only the bytes below the length. When the string is a public
//! input, the verifier receives the whole array, so the bytes from the length
//! up to the capacity would be free: one witness would satisfy many distinct
//! public-input vectors. A verifier that hashes, deduplicates or keys on the
//! raw public inputs could then accept one credential more than once.
//!
//! These checks accept only the zero-padded encoding. After them, the public
//! array and length are a function of the active bytes. Call them in a circuit
//! entry point on each public byte string whose tail the circuit does not
//! otherwise constrain. Public-input canonicality does not concern private
//! inputs, but a private tail can still matter to a function that reads the
//! whole storage (for example zkpassport sha512 v0.2.0 `sha512_var`).

/// Assert that `storage` is the zero-padded encoding of its first `len` bytes:
/// `len <= N`, and `storage[i] == 0` for every `i` with `len <= i < N`.
/// Bytes below `len` are not restricted; zero bytes there stay valid.
pub fn assert_zero_padded<let N: u32>(storage: [u8; N], len: u32) {
    assert(len <= N, "byte string length exceeds its capacity");
    // `tail` becomes true at index `len` and stays true. If `len == N`, it
    // never becomes true and every byte is active.
    let mut tail = false;
    for i in 0..N {
        tail = tail | (i == len);
        if tail {
            assert(storage[i] == 0, "byte string has a nonzero byte after its length");
        }
    }
}

/// Assert that `value` is the canonical (zero-padded) `BoundedVec` of its
/// active bytes. See `assert_zero_padded`.
pub fn assert_canonical<let N: u32>(value: BoundedVec<u8, N>) {
    assert_zero_padded(value.storage(), value.len());
}

#[test]
fn accepts_zero_padded_strings() {
    assert_zero_padded([1, 2, 0, 0], 2);
    assert_zero_padded([1, 2, 3, 4], 4);
    assert_zero_padded([0, 0, 0, 0], 0);
    // Zero bytes below the length are active bytes, not padding.
    assert_zero_padded([0, 0, 0, 0], 3);
    assert_canonical(BoundedVec::<u8, 8>::from_array([1, 2, 3]));
    assert_canonical(BoundedVec::<u8, 8>::new());
}

#[test(should_fail_with = "byte string has a nonzero byte after its length")]
fn rejects_nonzero_first_tail_byte() {
    assert_zero_padded([1, 2, 9, 0], 2);
}

#[test(should_fail_with = "byte string has a nonzero byte after its length")]
fn rejects_nonzero_last_tail_byte() {
    assert_zero_padded([1, 2, 0, 9], 2);
}

#[test(should_fail_with = "byte string has a nonzero byte after its length")]
fn rejects_nonzero_byte_of_empty_string() {
    assert_zero_padded([0, 0, 0, 1], 0);
}

#[test(should_fail_with = "byte string length exceeds its capacity")]
fn rejects_length_above_capacity() {
    assert_zero_padded([1, 2, 3, 4], 5);
}

#[test(should_fail_with = "byte string has a nonzero byte after its length")]
fn rejects_bounded_vec_with_nonzero_tail() {
    assert_canonical(BoundedVec::<u8, 4>::from_parts([1, 2, 3, 0], 2));
}
