# Zupass POD verification

`noir/zupass` verifies the native EdDSA-Poseidon signature over a POD content ID
and a name/value entry in its LeanIMT. A private Aztec function can call these
relations with the POD as a private witness, without wrapping the POD in a
separate Groth16 proof. GPC proof objects and legacy PCD variants are different
formats and are not accepted. The protocol reference is
[Zupass POD](https://github.com/proofcarryingdata/zupass/tree/d553fd1dd9ec9c4a641fa01326a14ef90e4d20f1/packages/lib/pod);
the local code follows its hash layout and signature equation.

## Issuer signature

The caller must anchor the issuer key in trusted account state and constrain the
required claim names and values. An issuer supplied by the prover would let
anyone sign their own credential.

The signature relation constrains both points to BabyJubJub, requires
`0 <= S < l` with
`l = 2736030358979909402780800718157159386076813972158567259200215660948447373041`,
rejects issuer keys killed by cofactor eight, and checks
`[S]Base8 = R8 + [H(R8.x, R8.y, A.x, A.y, contentID)]([8]A)`. Poseidon uses the
BN254 scalar field
`p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`.
The verifier does not separately require `A` to be in the prime subgroup:
`8A` is, so the equation constrains `R8` to it.

BabyJubJub is the twisted Edwards curve `a = 168700`, `d = 168696` over that
field. Euler's criterion gives `a^((p-1)/2) = 1` and `d^((p-1)/2) = p-1`, so
`a` is a square and `d` a nonsquare, and the unified addition law is complete
for valid points. The noir-edwards `__add_unconstrained` routine only produces
`(x, y, lambda)` hints; the constrained addition and doubling relations bind
them to the inputs. The compiler emits manual-constraint coverage diagnostics
for those upstream calls; compiling and executing is not an audit of them.

`S` is multiplied with `ScalarField<63>`: since `l < 2^252`, the constrained
63-slice reconstruction equals `S` as an integer (see
[Backend and compiler premises](#backend-and-compiler-premises)). The Poseidon
challenge `h` is any element of `[0, p)` and uses canonical 254-bit
double-and-add. It does not use `ScalarField<64>`: the pinned noir-edwards
`main` binds that conversion to its input and rejects `x + p` aliases
(noir-edwards #55), but no tagged release contains the fix, and the bitwise
ladder needs no hint at all.
Tests compare challenges 0, 1, 15, 16, `2^252 + 123` and `p - 1` with the
bitwise reference, and cover `S = 0`, `S = l - 1`, `S = l` (rejected) and
identity/inverse points.

The lower-level `assert_pod_signature_equation` takes `h` directly and does not
bind it to the POD transcript; call `assert_pod_signature` unless the
application constrains that hash itself.

## Backend and compiler premises

`multiply_signature_scalar` relies on a bound that the compiled circuit gets
from the backend, not from a RANGE gate. `ScalarField::<63>::from` takes 63
`u8` slices and a skew bit from a Brillig hint, constrains
`sum_i (2*s_i - 15) * 16^(62-i) - skew == S` and asks for
`assert_max_bit_size::<4>()` on each slice
(noir-edwards `src/scalar_field.nr`). `mul` then reads `table_x[s_i]`
and `table_y[s_i]` from 16-entry tables (noir-edwards `src/lib.nr`).
The pinned compiler (Noir 1.0.0-rc.3, 5a7ee9bf) treats each slice as bounded
by the 4-bit memory index and removes both the 4-bit and the `u8` RANGE. In a
compiled `BabyJubJub::mul(ScalarField::<63>::from(s))` the only RANGE is the
1-bit skew, and 126 table reads use the slices as indices. The remaining bound,
`s_i < 16`, is the ACIR memory bound, which the backend enforces: bb turns a
read-only block into a ROM table with one row per index, checked by a lookup
argument, so an index outside the table has no row to match.

With `0 <= s_i < 16` every digit is odd and in `[-15, 15]`, so the
reconstruction is an integer in `[-2^252, 2^252 - 1]`. Since `S < l < 2^252`
and `p > 2^253`, the reconstruction equals `S` as an integer, and `mul`
computes `[S]Base8` from the table entries the slices select. A backend that
did not enforce the memory bound would let a slice index past the table and
read an arbitrary value, so the multiplier would not be `S`.

The premise holds at bb 6.0.0 (aztec-packages 0219f11d81) for the Ultra and
Mega arithmetisations used by the Zupass instances. Show it again before
proving these circuits with another backend, including co-Noir. The upstream
source range checks stay and are the bound wherever a slice is not also a
table index. `multiply_challenge` uses `to_le_bits` and does not depend on
this premise. The strict Ed25519 verifier's `ScalarField<63>` multiplications
(Git `edwards_bignum` alpha.4) use the same slice-indexed 16-entry tables; the
premise has not been re-shown for those compiled circuits.

## Entry membership

`bytes_hash` implements POD's SHA256 shifted right by eight bits for names and
strings/bytes. `numeric_value_hash` implements Poseidon1;
`public_key_value_hash` implements Poseidon2. POD does not cryptographically
distinguish every JSON value type; the application fixes its schema and checks
numeric/date bounds as required.

`assert_entry` proves exactly this: `hash_2([name_hash, value_hash])` is a
Poseidon2 node on a path of at most the capacity to the content ID. POD uses
Poseidon2 for tree nodes, entry leaves and eddsa_pubkey value hashes without
domain separation, so the relation also holds for the two children of any
inner node (the root at depth 0) and for the (x, y) coordinates of a
public-key value. It proves a typed POD entry only when the caller fixes the
name hash to `bytes_hash` of the expected name and computes the value hash in
the circuit from a typed value. `assert_named_entry` computes the name hash
from the name bytes. The standalone example exposes both hashes as public
inputs, so its verifier must check them against the expected name and typed
value.

`assert_entry` starts with the name/value pair and takes the compressed upper
siblings. Given `PODContent.generateEntryProof(name)`, the value hash is
`siblings[0]`; pass the remaining siblings and index bits starting at bit one.
Pad the arrays to the chosen capacity and set depth to the number of remaining
siblings; the function constrains depth to that capacity. It does not
reconstruct the entire object or enforce sorting of undisclosed names. The
Merkle root comes from
[zk-kit.noir `binary-merkle-root`](https://github.com/zk-kit/zk-kit.noir/tree/ff3070116b446ca02ad233b9ad466677d127e64e/packages/binary-merkle-root),
pinned in `noir/zupass/Nargo.toml`.

## Holder control

A valid issuer signature proves a credential was issued, not that the prover is
its intended owner. `assert_certified_holder` checks the issuer signature and
that an expected POD entry names an EdDSA holder key. `assert_holder_approval`
and `assert_holder_login` additionally require the holder's signature on a POD
with a fixed schema. Credentials using a Semaphore identity or another owner
schema need that schema's ownership relation instead.

### Holder approval POD

The holder approves an account action by signing, with the holder key, a POD
with exactly three entries:

| Entry | POD type | Value |
| --- | --- | --- |
| `_aztec_auth_v1_account` | `cryptographic` | the account address |
| `_aztec_auth_v1_action` | `cryptographic` | the account's action hash |
| `_aztec_auth_v1_expires` | `int` | Unix seconds; valid strictly before it |

POD names allow only letters, digits and underscores. `holder_approval_content_id`
recomputes the content ID in the circuit: each value hash is Poseidon1 of the
value (`int` and `cryptographic` hash the same way), each entry is
`E = H(bytes_hash(name), value_hash)`, and the LeanIMT over the six sorted
leaves gives `root = H(H(E_account, E_action), E_expires)`.
`assert_holder_approval` checks the holder signature on that root with
`assert_pod_signature`. A POD with another entry set, name or value has another
root. The circuit does not bind value types: `int`, `cryptographic`, `boolean`
and `date` all hash with Poseidon1. Holder software must sign `expires` as an
`int` in seconds; a `date` hashes milliseconds and would read as an expiry about
1000 times later. The account entry is `context.this_address()`; `expires` is a
`u64`, so a non-negative POD `int` below `2^64` (POD itself allows at most
`2^63 - 1`). The `zupass` account requires `anchor timestamp < expires` and sets
the transaction expiration to `expires - 1`.

### Holder login POD

For a login link the holder signs a POD with exactly two entries:

| Entry | POD type | Value |
| --- | --- | --- |
| `_aztec_link_v1_challenge` | `cryptographic` | the link challenge |
| `_aztec_link_v1_issued_at` | `int` | Unix seconds; the login time that the holder states |

The link challenge already commits to the chain ID, protocol version, linking
contract, caller and round, so the POD needs no account or action entry. The
relying party's `max_age` bounds the age of the signed issue time and sets the
transaction expiration to `issued_at + max_age`. The holder can state any past
time; `max_age` limits how long a signature stays usable after the holder made
it. `holder_login_content_id` computes `root = H(E_challenge, E_issued_at)`
over the four sorted leaves. The entry names differ from the approval POD's, so
an approval signature does not verify as a login, or the reverse. Holder
software must sign `issued_at` as an `int` in seconds.

### Holder key hazards

- The action entry is an opaque Poseidon2 hash: a wallet cannot show the calls
  behind it. Only the holder's own software should make an approval. It must
  compute `action` itself, from the entrypoint domain, scheme, account, chain
  ID, protocol version and payload (calls and `tx_nonce`) that it shows the
  holder, and choose a short expiry.
- Holder software must not sign, for any other party, a POD that has an entry
  named `_aztec_auth_v1_*` or `_aztec_link_v1_*`. An app API that signs POD
  entries chosen by the app is an approval or login oracle for these names.
  Holder software computes the link challenge itself from the chain, contract,
  caller and round that it shows the holder.
- A raw root signer (`signPODRoot`, `signMessage`, Semaphore
  `Identity.signMessage` on a caller field) is also an oracle: the caller can
  compute the approval or login root and ask for its signature. Never sign a
  field supplied by a dApp, a web page or any other party.
- The library has no relation in which the holder signs a raw action or
  challenge field.

## Fixtures

`fixtures/data/zupass/fixture.json` is a synthetic event/owner POD made by
`@pcd/pod@0.5.1`: SDK interoperability, not possession of a real ticket. The
approval and login vectors come from `scripts/fixtures/generate-zupass-holder-approval.mjs`.
`fixtures/data/zupass/holder-fixture.json` is a raw holder signature over the
synthetic field `123456789`, used only to test the certified-holder and EdDSA
components; real holder software must not sign fields this way. The holder-side
helpers in `packages/credential-proofs-inputs/src/zupass.ts` check schema, types,
bounds and signer before returning a Noir witness.
