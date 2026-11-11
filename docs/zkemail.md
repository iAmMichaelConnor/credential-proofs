# zkEmail: DKIM verification arithmetic and limits

`noir/zkemail` adapts [zkemail/zkemail.nr](https://github.com/zkemail/zkemail.nr/tree/8264758c6dbd6d5e29a3d58b482c3eb014424efb)
`v2.0.0` to the Aztec v6 toolchain and uses `noir/rsa_signature` for RSA. The
API and the header and mailbox profile are documented in
[`noir/zkemail/src/lib.nr`](../noir/zkemail/src/lib.nr) and its `headers`
module; this page holds the arithmetic preconditions and the trust limits. The
fixture's modulus and signature are the public upstream email fixture; its
`redc` is recomputed for BigNum as `floor(2^(2*2048+6) / modulus)`, which
changes the fixture's key-hash output 1, not the key or the signed message.

## RSA limb domain

Each original `Field` limb is constrained before its `u128` cast, which makes
the cast exact. For a 2048-bit key there are eighteen limbs: the first seventeen
are `< 2^120` and the top modulus/signature limb is `< 2^8`. For 1024 bits the
first eight are `< 2^120` and the top limb `< 2^64`. The modulus and Barrett
`redc` limbs are each bounded to `< 2^120` before the cast. Without these
checks a Field above 128 bits would alias after truncation, and the verified
signature could differ from the Field-array signature used for the nullifier.

The runtime signature is checked with BigNum's `validate_in_field()`, which
enforces `signature <= modulus`. `signature = modulus` then fails the PKCS#1
v1.5 encoded-message equation, so accepted signatures lie in `[1, modulus - 1]`.
The circuit bounds the `redc` encoding but does not prove that `redc` equals
the Barrett reciprocal of the modulus.

The exported 18-limb converter constrains each input `< 2^120` before its
`u128` cast. `fold_limbs121` constrains every input `< 2^121`; each folded pair
`a + 2^121 * b` is below `2^242`, less than the BN254 scalar-field modulus, so
the arithmetic does not wrap. Direct-helper tests cover the largest accepted
limb and reject `2^120` and `2^121`.

## Partial SHA-256 helpers

The partial-SHA API is a low-level continuation primitive, separate from the
complete DKIM relation. `partial_sha256_var_start<N>` requires `N` to be
divisible by 64 at compile time. The interstitial and end helpers constrain the
runtime message length to the array capacity before iterating or indexing. The
end helper rejects a suffix longer than the claimed total and requires the
total byte length to be below `2^61`, the largest byte bound whose SHA-256 bit
length fits 64 bits; it encodes the length as `u64`. Callers must supply a
state derived from the claimed already-hashed prefix: the API cannot
authenticate an external SHA state. Boundary tests cover the `2^32` cast alias,
over-capacity lengths, suffix/total ordering, the maximum accepted length and
one-bit-length overflow.

## Trust and replay limits

A DKIM circuit returns the key's modulus commitment (output 0) and a hash of the
Barrett `redc` hint (output 1). Only output 0 is a key commitment: several
`redc` values verify the same key and signature. A consumer must compare
output 0 with a trusted DKIM modulus commitment or another explicit key-policy
proof, and must never use output 1 as a key identifier, registry or denylist
entry, or nullifier input. A self-chosen key with a matching signature does not
establish a trusted sender. The DKIM parser ignores the `c=`, `v=`, `l=`, `x=`
and `sdid=` tags and does not enforce domain alignment.

A signed `To` address shows that the signer named that address in the
authenticated header, not that the prover controls it: anyone can send a signed
message to another person's address. Account authorization needs a secret
challenge and an explicit sender/domain policy.

The signature hash is deterministic and can identify a message, but the
relation has no freshness, expiry or application nonce. A consumer that needs
replay prevention must track used identifiers or bind a fresh challenge in a
higher-level protocol.
