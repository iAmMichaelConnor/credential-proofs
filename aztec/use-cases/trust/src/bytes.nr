//! Canonical byte encodings shared by the credential adapters.
//! Capacity remains part of the encoding: hash the zero-padded array at its
//! original capacity, then bind the logical length. Do not trim the array.
use aztec::protocol::hash::{poseidon2_hash, poseidon2_hash_bytes};

/// A big-endian 32-byte word as two 128-bit field elements.
pub fn halves(word: [u8; 32]) -> (Field, Field) {
    let mut high: Field = 0;
    let mut low: Field = 0;
    for i in 0..16 {
        high = high * 256 + word[i] as Field;
        low = low * 256 + word[16 + i] as Field;
    }
    (high, low)
}

/// Hash the zero-padded prefix, binding its length and rejecting overflow.
pub fn prefix_hash<let N: u32>(bytes: [u8; N], len: u32) -> Field {
    assert(len <= N, "Length exceeds capacity");
    let mut canonical = [0; N];
    for i in 0..N {
        if i < len {
            canonical[i] = bytes[i];
        }
    }
    poseidon2_hash([len as Field, poseidon2_hash_bytes(canonical)])
}

/// Hash the logical bytes, ignoring storage beyond the bounded length.
pub fn bytes_hash<let N: u32>(bytes: BoundedVec<u8, N>) -> Field {
    let mut canonical = [0; N];
    for i in 0..N {
        if i < bytes.len() {
            canonical[i] = bytes.get_unchecked(i);
        }
    }
    poseidon2_hash([bytes.len() as Field, poseidon2_hash_bytes(canonical)])
}

/// The value of at most 20 decimal digits, most significant first. The
/// caller has already checked that every byte within the length is an ASCII
/// digit and that the value fits a u64 (the platform response verifiers do);
/// a byte below `0` or a value past u64 fails here, any other byte is not
/// detected.
pub fn decimal_u64(digits: BoundedVec<u8, 20>) -> u64 {
    let mut value: u64 = 0;
    for i in 0..20 {
        if i < digits.len() {
            value = value * 10 + (digits.get_unchecked(i) - 48) as u64;
        }
    }
    value
}
