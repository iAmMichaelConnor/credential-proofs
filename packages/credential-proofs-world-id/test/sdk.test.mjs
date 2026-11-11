import test from "node:test";
import assert from "node:assert/strict";
import { FR, integer, hashToField, externalNullifier, contextSignalHash, signalBytes, checkClaim, nullifierFields, publicInputs } from "../dist/index.js";

const context = ["1", "1", "2", "3", "4", "5"];

test("strict encodings preserve zero and field boundaries", () => {
  for (const v of [0n, 1n, FR - 1n]) assert.equal(integer(v.toString()), v);
  for (const v of [0, 1, -1n, FR, "01", " 1", "1e2", "-1", "0x", ""])
    assert.throws(() => integer(v));
  assert.equal(
    hashToField(new Uint8Array()).toString(16),
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4",
  );
  assert.notEqual(
    externalNullifier("app_test", "a"),
    externalNullifier("app_test", "b"),
  );
});
test("signal binding hashes raw 224 bytes rather than UTF-8 hex text", () => {
  const context = ["1", "1", "2", "8", "4", "5"];
  const words = [0x574f524c445f49445f415a5445435f5631n, ...context.map(BigInt)];
  const encoded = words
    .map((word) => word.toString(16).padStart(64, "0"))
    .join("");
  const raw = Buffer.from(encoded, "hex");
  assert.equal(raw.length, 224);
  assert.deepEqual(Buffer.from(signalBytes(context)), raw);
  const rawHash = hashToField(raw);
  const textHash = hashToField(new TextEncoder().encode(`0x${encoded}`));
  assert.equal(contextSignalHash(context), rawHash);
  assert.notEqual(rawHash, textHash);
  const policy = {
    version: "world-id-3-semaphore",
    root: "7",
    validUntil: "100",
    externalNullifier: "8",
  };
  const inputs = ["7", "0", rawHash.toString(), "8"];
  assert.deepEqual(
    checkClaim(policy, inputs, context, "50"),
    inputs.map(BigInt),
  );
  assert.throws(
    () =>
      checkClaim(policy, ["7", "0", textHash.toString(), "8"], context, "50"),
    /Wrong signal binding/,
  );
});
test("semaphore policy binds all context fields and allows zero nullifier", () => {
  // The contract puts the external nullifier in context[3], so the
  // preflight now requires it there; the old context [.., 3, ..] would fail.
  const context = ["1", "1", "2", "8", "4", "5"];
  const policy = {
    version: "world-id-3-semaphore",
    root: "7",
    validUntil: "100",
    externalNullifier: "8",
  };
  const p = ["7", "0", contextSignalHash(context).toString(), "8"];
  assert.deepEqual(checkClaim(policy, p, context, "100"), p.map(BigInt));
  for (let i = 0; i < 6; i++) {
    const c = [...context];
    c[i] = String(BigInt(c[i]) + 1n);
    assert.throws(() => checkClaim(policy, p, c, "10"), /signal/);
  }
  assert.throws(() => checkClaim(policy, p, context, "101"), /expired/);
  assert.throws(
    () => checkClaim({ ...policy, root: "9" }, p, context, "10"),
    /root/,
  );
  assert.throws(
    () => checkClaim({ ...policy, externalNullifier: "9" }, p, context, "10"),
    /nullifier/,
  );
  const other = ["1", "1", "2", "9", "4", "5"];
  assert.throws(
    () =>
      checkClaim(
        policy,
        ["7", "0", contextSignalHash(other).toString(), "8"],
        other,
        "10",
      ),
    /Context action mismatch/,
  );
  assert.deepEqual(
    nullifierFields(policy, p),
    nullifierFields({ ...policy, root: "9" }, ["9", ...p.slice(1)]),
  );
});
test("World ID 4 checks credential, issuer, OPRF, RP, action, freshness and sessions", () => {
  // Context[3] is the policy action, as WorldId4Gate.claim builds it.
  const context = ["1", "1", "2", "7", "4", "5"];
  const policy = {
    version: "world-id-4-nullifier-v1",
    root: "7",
    validUntil: "100",
    issuerSchemaId: "1",
    issuerKey: ["2", "3"],
    oprfKey: ["4", "5"],
    rpId: "6",
    action: "7",
    treeDepth: "30",
    minExpiry: "50",
    minGenesis: "9",
  };
  const p = [
    "0",
    "1",
    "2",
    "3",
    "100",
    "9",
    "7",
    "30",
    "6",
    "7",
    "4",
    "5",
    contextSignalHash(context).toString(),
    "5",
    "0",
  ];
  const at = (i, v) => p.map((x, j) => (j === i ? v : x));
  assert.equal(checkClaim(policy, p, context, "50").length, 15);
  for (const i of [1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14]) {
    const changed = [...p];
    changed[i] = String(BigInt(p[i]) + 1n);
    assert.throws(() => checkClaim(policy, changed, context, "50"));
  }
  assert.throws(
    () => checkClaim(policy, at(4, "49"), context, "50"),
    /expiration/,
  );
  // Default upstream request flow, expires_at_min (100) is the request
  // time and the anchor time (101) is later. validUntil is raised so that the
  // root policy does not fail first.
  assert.throws(
    () => checkClaim({ ...policy, validUntil: "200" }, p, context, "101"),
    /Credential expiration bound too old/,
  );
  assert.throws(() => checkClaim(policy, at(5, "8"), context, "50"), /genesis/);
  // Genesis_issued_at_min = FR - 1 wraps upstream LessEqThan(64).
  for (const g of [FR - 1n, 1n << 64n, FR - (1n << 64n) + 10n])
    assert.throws(
      () => checkClaim(policy, at(5, g.toString()), context, "50"),
      /Genesis range/,
    );
  // Boundary values stay valid.
  const max = ((1n << 64n) - 1n).toString();
  assert.equal(
    checkClaim({ ...policy, minGenesis: max }, at(5, max), context, "50")
      .length,
    15,
  );
  assert.equal(
    checkClaim({ ...policy, minGenesis: "0" }, at(5, "0"), context, "50")
      .length,
    15,
  );
  // Policy integer domains.
  for (const minGenesis of [(FR - 1n).toString(), (1n << 64n).toString()])
    assert.throws(
      () => checkClaim({ ...policy, minGenesis }, p, context, "50"),
      /minGenesis: out of range/,
    );
  assert.throws(
    () =>
      checkClaim(
        { ...policy, minExpiry: (1n << 64n).toString() },
        p,
        context,
        "50",
      ),
    /minExpiry: out of range/,
  );
  // Zero root and tree depths outside [0, 30].
  assert.throws(
    () => checkClaim({ ...policy, root: "0" }, at(6, "0"), context, "50"),
    /Zero root/,
  );
  for (const d of ["31", (1n << 64n).toString(), (FR - 1n).toString()])
    assert.throws(() =>
      checkClaim({ ...policy, treeDepth: d }, at(7, d), context, "50"),
    );
  assert.throws(
    () =>
      checkClaim({ ...policy, treeDepth: "31" }, at(7, "31"), context, "50"),
    /Tree depth range/,
  );
  assert.equal(
    checkClaim({ ...policy, treeDepth: "0" }, at(7, "0"), context, "50").length,
    15,
  );
  assert.throws(
    () =>
      checkClaim(
        { ...policy, issuerKey: ["0", "3"] },
        at(2, "0"),
        context,
        "50",
      ),
    /Unregistered issuer/,
  );
  // The session prefix 0x02 (top byte) is not a uniqueness action.
  const session = ((2n << 248n) + 7n).toString();
  assert.throws(
    () =>
      checkClaim({ ...policy, action: session }, at(9, session), context, "50"),
    /Uniqueness action range/,
  );
  // A context whose action word differs from the policy is rejected.
  const other = ["1", "1", "2", "999", "4", "5"];
  assert.throws(
    () =>
      checkClaim(
        policy,
        at(12, contextSignalHash(other).toString()),
        other,
        "50",
      ),
    /Context action mismatch/,
  );
  // The upstream nullifier is issuer-independent, so the Aztec
  // nullifier preimage must not change with the accepted issuer.
  const issuer2 = { ...policy, issuerSchemaId: "2", issuerKey: ["12", "13"] };
  const p2 = at(1, "2").map((x, j) => (j === 2 ? "12" : j === 3 ? "13" : x));
  assert.equal(checkClaim(issuer2, p2, context, "50").length, 15);
  assert.deepEqual(nullifierFields(policy, p), nullifierFields(issuer2, p2));
  assert.notDeepEqual(
    nullifierFields(policy, p),
    nullifierFields(policy, at(0, "1")),
  );
});
test("the unsupported ownership claim version is rejected, not checked", () => {
  // Claim version 2 (ownership) is not supported and must fail closed.
  const context = ["1", "1", "2", "3", "4", "2"];
  const s = contextSignalHash(context).toString();
  const policy = {
    version: "world-id-4-ownership-wip103",
    root: "1",
    validUntil: "9",
    depth: "30",
    nonce: "2",
    commitment: "3",
    context: s,
  };
  const inputs = ["1", "30", "2", "3", s];
  assert.throws(
    () => checkClaim(policy, inputs, context, "5"),
    /Unsupported World ID claim version/,
  );
  assert.throws(
    () => publicInputs("world-id-4-ownership-wip103", inputs),
    /Unsupported World ID claim version/,
  );
  assert.throws(() => nullifierFields(policy, inputs), /no supported/);
});
test("over-long integer strings are rejected before BigInt conversion", () => {
  // A 12 MB decimal string must be rejected quickly, not parsed.
  const long = "1".repeat(12 * 1024 * 1024);
  for (const parse of [
    () => integer(long),
    () => integer("0x" + "f".repeat(12 * 1024 * 1024)),
  ]) {
    const started = performance.now();
    assert.throws(parse, /out of range|Invalid|Input/);
    assert.ok(performance.now() - started < 1000, "parse was not bounded");
  }
  // The accepted domain is unchanged, including zero-padded hex.
  const U64 = 1n << 64n;
  assert.equal(integer((FR - 1n).toString()), FR - 1n);
  assert.throws(() => integer(FR.toString()), /out of range/);
  assert.equal(
    integer("0x" + (FR - 1n).toString(16).padStart(64, "0")),
    FR - 1n,
  );
  assert.equal(integer("0x" + "0".repeat(100_000) + "1"), 1n);
  assert.equal(integer("0x" + "0".repeat(64)), 0n);
  assert.throws(() => integer("0x1" + "0".repeat(64)), /out of range/);
  assert.equal(integer((U64 - 1n).toString(), U64), U64 - 1n);
  assert.throws(() => integer(U64.toString(), U64), /out of range/);
  assert.equal(integer("0x" + "0".repeat(48) + "f".repeat(16), U64), U64 - 1n);
  assert.throws(() => integer("0x1" + "0".repeat(16), U64), /out of range/);
});
