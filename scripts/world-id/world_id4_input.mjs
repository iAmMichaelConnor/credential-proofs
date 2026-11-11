// Public synthetic test identities only. This does not attest to an Orb enrollment.
// Reference implementation of the World ID OPRFNullifierProof relations.
// world-id-protocol revision 46f6b43d231780e4fc0b5030bd71e846664532d1;
// see circom/client_side_proofs, poseidon2, encode_to_curve_babyjj and verify_dlog.
// No setup, witness calculation, proof generation, network or package installation.
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const L =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;
const G = [
  5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  16950150798460657717958625567821834550301663161624707787222815936182638968203n,
];
const mod = (x, p = P) => ((x % p) + p) % p;
function pow(x, n) {
  let y = 1n;
  for (x = mod(x); n; n >>= 1n, x = mod(x * x)) if (n & 1n) y = mod(y * x);
  return y;
}
const inv = (x) => pow(x, P - 2n); // inv(0)=0, as in InverseOrZero.
function add([x, y], [u, v]) {
  const d = mod(168696n * x * u * y * v);
  return [
    mod((x * v + y * u) * inv(1n + d)),
    mod((y * v - 168700n * x * u) * inv(1n - d)),
  ];
}
function mul(p, n) {
  let q = [0n, 1n];
  for (; n; n >>= 1n, p = add(p, p)) if (n & 1n) q = add(q, p);
  return q;
}
function sqrt(n) {
  n = mod(n);
  if (!n) return 0n;
  if (pow(n, (P - 1n) / 2n) !== 1n) throw Error("Not a quadratic residue");
  let q = P - 1n,
    s = 0;
  while (!(q & 1n)) {
    q >>= 1n;
    s++;
  }
  let z = 2n;
  while (pow(z, (P - 1n) / 2n) !== P - 1n) z++;
  let c = pow(z, q),
    r = pow(n, (q + 1n) / 2n),
    t = pow(n, q),
    m = s;
  while (t !== 1n) {
    let i = 1,
      u = mod(t * t);
    while (u !== 1n) {
      u = mod(u * u);
      i++;
    }
    const b = pow(c, 1n << BigInt(m - i - 1));
    r = mod(r * b);
    c = mod(b * b);
    t = mod(t * c);
    m = i;
  }
  return r;
}

// Read constants as data, never evaluate source. Reject upstream changes so a
// changed permutation cannot silently change the fixture identity.
let constantsPromise;
async function constants() {
  constantsPromise ??= (async () => {
    const bytes = await readFile(
      new URL(
        "../../fixtures/world-id/upstream/world-id-protocol/circom/poseidon2/poseidon2_constants.circom",
        import.meta.url,
      ),
    );
    if (
      createHash("sha256").update(bytes).digest("hex") !==
      "a969baddd669b513d72f5bf54aed1049ed312c806e23589823b17bb48cfb6559"
    )
      throw Error("Pinned World ID Poseidon2 constants differ");
    const source = bytes.toString(),
      result = {};
    for (const name of [
      "load_diag",
      "load_rc_full1",
      "load_rc_partial",
      "load_rc_full2",
    ]) {
      const body = source
        .split(`function ${name}(t) {`)[1]
        .split("\nfunction ")[0];
      for (const t of [2, 3, 4, 8, 16]) {
        if (name === "load_diag" && t < 4) continue;
        const marker = t === 16 ? "assert(t==16);" : `if (t == ${t})`;
        const tail = body
          .replaceAll(" ", "")
          .split(marker.replaceAll(" ", ""))[1];
        if (!tail) throw Error(`Missing ${name}(${t}) constants`);
        const data = tail.split("return")[1].split(";")[0];
        result[`${name}:${t}`] = [...data.matchAll(/0x[0-9a-f]+/g)].map(
          ([hex]) => BigInt(hex),
        );
      }
    }
    return result;
  })();
  return constantsPromise;
}
function external(a) {
  const t = a.length;
  if (t < 4) {
    const sum = a.reduce((x, y) => x + y);
    return a.map((x) => mod(x + sum));
  }
  const out = [];
  for (let i = 0; i < t; i += 4) {
    const [a0, a1, a2, a3] = a.slice(i, i + 4);
    const t0 = a0 + a1,
      t1 = a2 + a3,
      t2 = 2n * a1 + t1,
      t3 = 2n * a3 + t0;
    const t4 = 4n * t1 + t3,
      t5 = 4n * t0 + t2;
    out.push(t3 + t5, t5, t2 + t4, t4);
  }
  if (t === 4) return out.map((x) => mod(x));
  const sums = [0n, 0n, 0n, 0n];
  out.forEach((x, i) => {
    sums[i % 4] += x;
  });
  return out.map((x, i) => mod(x + sums[i % 4]));
}
function permutation(a, c) {
  const t = a.length,
    full = (state, rc, offset) =>
      external(state.map((x, i) => pow(x + rc[offset + i], 5n)));
  a = external(a);
  for (let i = 0; i < 4; i++) a = full(a, c[`load_rc_full1:${t}`], i * t);
  for (const rc of c[`load_rc_partial:${t}`]) {
    a[0] = pow(a[0] + rc, 5n);
    const sum = a.reduce((x, y) => x + y);
    const diag =
      t < 4
        ? Array.from({ length: t }, (_, i) => (i === t - 1 ? 2n : 1n))
        : c[`load_diag:${t}`];
    a = a.map((x, i) => mod(x * diag[i] + sum));
  }
  for (let i = 0; i < 4; i++) a = full(a, c[`load_rc_full2:${t}`], i * t);
  return a;
}
const domain = (s) => BigInt(`0x${Buffer.from(s).toString("hex")}`);
function encode(query, h) {
  const u = h([domain("OPRF_HashToField_BabyJubJub"), query, 0n])[1];
  let tv = mod(5n * u * u);
  if (tv === P - 1n) tv = 0n;
  const x1 = mod(-168698n * inv(tv + 1n));
  const gx1 = mod(((x1 + 168698n) * x1 + 1n) * x1);
  const square = gx1 === 0n || pow(gx1, (P - 1n) / 2n) === 1n;
  const x = square ? x1 : mod(-x1 - 168698n);
  let y = sqrt(square ? gx1 : mod(tv * gx1));
  if ((y & 1n) !== BigInt(square)) y = mod(-y);
  const denominator = inv((x + 1n) * y);
  return mul(
    [
      mod(x * (x + 1n) * denominator),
      denominator ? mod((x - 1n) * denominator * y) : 1n,
    ],
    8n,
  );
}
// Deterministic nonces below are public test material. This helper is unsuitable
// for production signing; never reuse this construction with a real secret key.
function sign(message, secret, nonce, h) {
  const pk = mul(G, secret),
    r = mul(G, nonce);
  const challenge = h([
    domain("EdDSA Signature"),
    ...r,
    ...pk,
    message,
    0n,
    0n,
  ])[1];
  return { pk, r, s: mod(nonce + challenge * secret, L) };
}
function range(name, x, limit) {
  if (typeof x !== "bigint" || x < 0n || x >= limit)
    throw Error(`${name} outside fixture policy domain`);
}

/** Generate complete private inputs; callers bind signal_hash to their actual Aztec context. */
export async function generateWorldId4Input({
  rpId = 6n,
  action = 7n,
  signalHash = 0n,
  nonce = 17n,
  expiry = 1800000000n,
  genesis = 9n,
} = {}) {
  range("rpId", rpId, 1n << 64n);
  range("action", action, 1n << 248n);
  range("signalHash", signalHash, 1n << 248n);
  range("nonce", nonce, P);
  range("expiry", expiry, (1n << 64n) - 60n);
  range("genesis", genesis, 1n << 64n);
  if (genesis > expiry) throw Error("Genesis must not exceed expiry");
  const c = await constants(),
    h = (a) => permutation(a, c);
  const mt_index = 1n,
    beta = 13n,
    oprfSecret = 19n,
    dleqNonce = 23n;
  const query = h([domain("World ID Query"), mt_index, rpId, action])[1];
  const user = sign(query, 29n, 31n, h);
  const pk = [user.pk, ...Array.from({ length: 6 }, () => [0n, 1n])];
  let root = h([domain("World ID PK"), ...pk.flat(), 0n])[1],
    zero = 0n;
  const siblings = [];
  for (let i = 0; i < 30; i++) {
    siblings.push(zero);
    const pair = (mt_index >> BigInt(i)) & 1n ? [zero, root] : [root, zero];
    root = mod(h(pair)[0] + pair[0]);
    zero = mod(h([zero, zero])[0] + zero);
  }
  const cred_user_id_r = 37n,
    cred_id = 41n,
    issuer_schema_id = 1n,
    cred_hashes = [43n, 0n];
  const blindedId = h([domain("H_CS(id, r)"), mt_index, cred_user_id_r])[1];
  const credential = sign(
    h([
      domain("POSEIDON2+EDDSA-BJJ"),
      issuer_schema_id,
      blindedId,
      genesis,
      expiry + 60n,
      ...cred_hashes,
      cred_id,
    ])[1],
    47n,
    53n,
    h,
  );
  const point = encode(query, h),
    blinded = mul(point, beta);
  const oprf_pk = mul(G, oprfSecret),
    oprf_response = mul(point, oprfSecret);
  const oprf_response_blinded = mul(blinded, oprfSecret);
  const dlog_e = h([
    domain("DLOG Equality Proof"),
    ...oprf_pk,
    ...blinded,
    ...oprf_response_blinded,
    ...G,
    ...mul(G, dleqNonce),
    ...mul(blinded, dleqNonce),
    0n,
    0n,
    0n,
  ])[1];
  const id_commitment_r = 59n;
  return {
    pk,
    pk_index: 0n,
    s: user.s,
    r: user.r,
    issuer_schema_id,
    cred_pk: credential.pk,
    cred_hashes,
    cred_genesis_issued_at: genesis,
    cred_genesis_issued_at_min: genesis,
    cred_expires_at: expiry + 60n,
    cred_s: credential.s,
    cred_r: credential.r,
    cred_user_id_r,
    cred_id,
    current_timestamp: expiry,
    merkle_root: root,
    depth: 30n,
    mt_index,
    siblings,
    beta,
    rp_id: rpId,
    action,
    nonce,
    dlog_e,
    dlog_s: mod(dleqNonce + dlog_e * oprfSecret, L),
    oprf_pk,
    oprf_response_blinded,
    oprf_response,
    signal_hash: signalHash,
    // Uniqueness mode explicitly disables the optional session ID commitment.
    id_commitment_r,
    id_commitment: 0n,
  };
}
