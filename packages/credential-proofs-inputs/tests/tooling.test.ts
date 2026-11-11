import assert from "node:assert/strict";
import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createPersonalSign, createSecretKeyWitness, createSiwe, type SiweContext } from "credential-proofs-inputs/ethereum";

import { facebookAccountInput, importVerifiedOidc, rsaKeyToCircuit } from "credential-proofs-inputs/oidc";
import { createSyntheticOidc } from "credential-proofs-test-builders/oidc";

import { passkeyAssertionToCircuit } from "credential-proofs-inputs/passkey";

import { holderApprovalEntries, holderApprovalWitness, holderLoginEntries, holderLoginWitness, holderPublicKey, podToCircuitWitness, signHolderApproval, signHolderLogin } from "credential-proofs-inputs/zupass";
import { createSyntheticPod } from "credential-proofs-test-builders/zupass";

import { createRequire } from "node:module";
import { stringifyToml } from "credential-proofs-inputs/toml";

import { privateKeyToAccount } from "viem/accounts";

const now = 1_900_000_000;
const expected = {
  audience: "credential-test-client",
  subject: "synthetic-subject",
  nonce: "session-42",
  now,
};

test("Google, Apple and Facebook OIDC fixtures are locally signed, exact-claim checked and emit Noir arrays", async () => {
  for (const provider of ["google", "apple", "facebook"] as const) {
    const fixture = await createSyntheticOidc(provider, expected);
    const toml = stringifyToml(fixture.document);
    assert.match(toml, /\[trusted_key\]/);
    assert.match(toml, /modulus_limbs = \[/);
    assert.match(toml, /redc_params_limbs = \[/);
    assert.match(toml, /\[token\.header_b64\]/);
    assert.match(toml, /\[token\.payload_b64\]/);
    assert.match(toml, /\[token\.signature_b64\]/);
    assert.equal(fixture.document.now, now);
    await assert.rejects(
      importVerifiedOidc(
        provider,
        fixture.token,
        { ...expected, nonce: "wrong-session" },
        fixture.jwk,
      ),
      /nonce/,
    );
    await assert.rejects(
      importVerifiedOidc(
        provider,
        fixture.token,
        { ...expected, audience: "wrong-client" },
        fixture.jwk,
      ),
    );
  }
});

test("OIDC RSA conversion rejects non-2048-bit keys and computes exact redc limbs", async () => {
  const fixture = await createSyntheticOidc("google", expected);
  const key = rsaKeyToCircuit(fixture.jwk);
  assert.equal(key.modulus_limbs.length, 18);
  assert.equal(key.redc_params_limbs.length, 18);
  assert.throws(
    () =>
      rsaKeyToCircuit({
        ...fixture.jwk,
        n: Buffer.from([1, 2, 3]).toString("base64url"),
      }),
    /2048 bits/,
  );
  const even = Buffer.from(fixture.jwk.n!, "base64url");
  even[even.length - 1]! &= 0xfe;
  assert.throws(
    () => rsaKeyToCircuit({ ...fixture.jwk, n: even.toString("base64url") }),
    /must be odd/,
  );
});

test("OIDC conversion accepts a 72-byte client audience and retains the full 128-byte capacity", async () => {
  const audience = `client-${"x".repeat(65)}`;
  assert.equal(Buffer.byteLength(audience), 72);
  const fixture = await createSyntheticOidc("google", {
    ...expected,
    audience,
  });
  const boundedAudience = fixture.document.audience as {
    len: number;
    storage: number[];
  };
  assert.equal(boundedAudience.len, 72);
  assert.equal(boundedAudience.storage.length, 128);
  const token = fixture.document.token as Record<
    string,
    { len: number; storage: number[] }
  >;
  assert.equal(token.payload_b64!.storage.length, 1024);
});

test("Facebook account input maps signed Limited Login credentials into the deployed AuthInput layout", async () => {
  const fixture = await createSyntheticOidc("facebook", expected);
  const account = facebookAccountInput(fixture.document, expected);
  const policy = account.policy as Record<string, unknown>;
  assert.equal((policy.audience as { storage: number[] }).storage.length, 128);
  assert.equal((policy.subject as { storage: number[] }).storage.length, 256);
  assert.equal((account.header_b64 as number[]).length, 128);
  assert.equal(
    account.header_b64_len,
    (fixture.document.token as Record<string, { len: number }>).header_b64!.len,
  );
  assert.equal((account.payload_b64 as number[]).length, 1024);
  assert.equal((account.signature_b64 as number[]).length, 344);
});

test("Zupass synthetic POD is directly importable and invalid signatures are rejected", async () => {
  const directory = await mkdtemp(join(tmpdir(), "auth-credentials-pod-"));
  try {
    const output = join(directory, "pod.toml");
    await createSyntheticPod(output, "event");
    const pod = JSON.parse(
      await readFile(`${output}.pod.json`, "utf8"),
    ) as Record<string, unknown>;
    const witness = podToCircuitWitness(pod, "event");
    assert.equal(witness.depth, 1);
    assert.equal(witness.indices.length, 8);
    assert.equal(witness.siblings.length, 8);
    assert.match(stringifyToml(witness), /\[issuer\]/);
    const mutated = structuredClone(pod) as { signature: string };
    mutated.signature = `${mutated.signature.slice(0, -1)}${mutated.signature.endsWith("A") ? "B" : "A"}`;
    assert.throws(() => podToCircuitWitness(mutated, "event"), /signature/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("Zupass holder approval POD has the fixed schema and rejects other PODs", () => {
  const { POD } = createRequire(import.meta.url)(
    "@pcd/pod",
  ) as typeof import("@pcd/pod");
  const holderKey = "11".repeat(32);
  const approval = { account: 5n, action: 7n, expires: 4_102_444_800n };
  const pod = signHolderApproval(approval, holderKey);
  const witness = holderApprovalWitness(pod, holderPublicKey(holderKey));
  assert.deepEqual(
    [witness.account, witness.action, witness.expires],
    ["5", "7", "4102444800"],
  );
  assert.throws(
    () => holderApprovalWitness(pod, holderPublicKey("22".repeat(32))),
    /another key/,
  );
  const extra = POD.sign(
    { ...holderApprovalEntries(approval), note: { type: "int", value: 1n } },
    holderKey,
  ).toJSON();
  assert.throws(() => holderApprovalWitness(extra), /exactly/);
  const typed = holderApprovalEntries(approval) as Record<
    string,
    { type: string; value: bigint }
  >;
  typed._aztec_auth_v1_expires = {
    type: "cryptographic",
    value: approval.expires,
  };
  assert.throws(
    () => holderApprovalWitness(POD.sign(typed as never, holderKey).toJSON()),
    /types/,
  );
  assert.throws(
    () => holderApprovalEntries({ ...approval, expires: 0n }),
    /expires/,
  );
  assert.throws(
    () => holderApprovalEntries({ ...approval, action: -1n }),
    /field/,
  );
});

test("Zupass holder login POD has the fixed schema and rejects other PODs", () => {
  const { POD } = createRequire(import.meta.url)(
    "@pcd/pod",
  ) as typeof import("@pcd/pod");
  const holderKey = "11".repeat(32);
  const login = { challenge: 9n, issuedAt: 3_999_999_940n };
  const pod = signHolderLogin(login, holderKey);
  const witness = holderLoginWitness(pod, holderPublicKey(holderKey));
  assert.deepEqual([witness.challenge, witness.issued_at], ["9", "3999999940"]);
  assert.throws(
    () => holderLoginWitness(pod, holderPublicKey("22".repeat(32))),
    /another key/,
  );
  const extra = POD.sign(
    { ...holderLoginEntries(login), note: { type: "int", value: 1n } },
    holderKey,
  ).toJSON();
  assert.throws(() => holderLoginWitness(extra), /exactly/);
  const approval = signHolderApproval(
    { account: 5n, action: 9n, expires: 4_102_444_800n },
    holderKey,
  );
  assert.throws(() => holderLoginWitness(approval), /exactly/);
  const typed = holderLoginEntries(login) as Record<
    string,
    { type: string; value: bigint }
  >;
  typed._aztec_link_v1_issued_at = {
    type: "cryptographic",
    value: login.issuedAt,
  };
  assert.throws(
    () => holderLoginWitness(POD.sign(typed as never, holderKey).toJSON()),
    /types/,
  );
  assert.throws(
    () => holderLoginEntries({ ...login, issuedAt: 0n }),
    /issuedAt/,
  );
  assert.throws(
    () => holderLoginEntries({ ...login, challenge: -1n }),
    /field/,
  );
});

test("Ethereum EIP-191 and canonical SIWE fixtures keep consumer field shapes", async () => {
  const key = `0x${"0".repeat(63)}1`;
  const personal = await createPersonalSign("synthetic login", key);
  assert.equal((personal.message as number[]).length, 256);
  assert.equal(personal.message_len, 15);
  assert.equal((personal.signature as number[]).length, 64);
  assert.ok(Array.isArray(personal.public_key_x));
  assert.ok(Array.isArray(personal.public_key_y));
  assert.match(stringifyToml(personal), /expected_address = \[/);

  const context: SiweContext = {
    domain: "example.com",
    uri: "https://example.com/login",
    chainId: 1n,
    nonce: "32891756",
    issuedAt: "2026-10-21T12:00:00Z",
    expirationTime: "2026-10-21T12:05:00Z",
    currentTime: "2026-10-21T12:02:00Z",
  };
  const siwe = await createSiwe(key, context);
  assert.equal((siwe.submitted_message as number[]).length, 512);
  assert.ok((siwe.submitted_len as number) > 100);
  assert.equal((siwe.signature as number[]).length, 64);
  assert.ok(Array.isArray(siwe.public_key_x));
  assert.ok(Array.isArray(siwe.public_key_y));
  assert.match(stringifyToml(siwe), /\[context\]/);
  await assert.rejects(
    createSiwe(key, { ...context, currentTime: "2026-10-21T12:06:00Z" }),
    /window/,
  );
  // issuedAt may equal currentTime (the anchor time) but not exceed it.
  await createSiwe(key, { ...context, issuedAt: "2026-10-21T12:02:00Z" });
  await assert.rejects(
    createSiwe(key, { ...context, issuedAt: "2026-10-21T12:02:01Z" }),
    /window/,
  );
});

test("SIWE domain and URI accept only visible ASCII, matching the Noir builder", async () => {
  const key = `0x${"0".repeat(63)}1`;
  const context: SiweContext = {
    domain: "example.com",
    uri: "https://example.com/login",
    chainId: 1n,
    nonce: "32891756",
    issuedAt: "2026-10-21T12:00:00Z",
    expirationTime: "2026-10-21T12:05:00Z",
    currentTime: "2026-10-21T12:02:00Z",
  };
  // First and last accepted bytes, and the 128-byte limit.
  await createSiwe(key, {
    ...context,
    domain: "!example.com~",
    uri: "https://example.com/!~",
  });
  await createSiwe(key, {
    ...context,
    uri: `https://example.com/${"a".repeat(108)}`,
  });
  await assert.rejects(
    createSiwe(key, {
      ...context,
      uri: `https://example.com/${"a".repeat(109)}`,
    }),
    /SIWE URI/,
  );
  await assert.rejects(
    createSiwe(key, { ...context, domain: "" }),
    /SIWE domain/,
  );
  const rejected = [
    "\u0085",
    "\u00a0",
    "\u2028",
    "\u2029",
    "\u200b",
    "\u202e",
    "\ufeff",
    "\x00",
    "\x01",
    "\t",
    "\x1f",
    " ",
    "\x7f",
    "\x80",
    "\u00e9",
  ];
  for (const value of rejected) {
    await assert.rejects(
      createSiwe(key, { ...context, domain: `example.com${value}x` }),
      /SIWE domain/,
      JSON.stringify(value),
    );
    await assert.rejects(
      createSiwe(key, { ...context, uri: `https://example.com/${value}x` }),
      /SIWE URI/,
      JSON.stringify(value),
    );
  }
});

test("direct Ethereum secret-key input rejects noncanonical scalars and derives the n-1 public address", () => {
  const order =
    0xffff_ffff_ffff_ffff_ffff_ffff_ffff_fffe_baaedce6_af48a03b_bfd25e8c_d0364141n;
  const key = `0x${(order - 1n).toString(16).padStart(64, "0")}`;
  const witness = createSecretKeyWitness(key);
  const expectedAddress = Array.from(
    Buffer.from(
      privateKeyToAccount(key as `0x${string}`).address.slice(2),
      "hex",
    ),
  );
  assert.deepEqual(witness.expected_address, expectedAddress);
  assert.equal((witness.secret_key as number[]).length, 32);
  assert.match(stringifyToml(witness), /secret_key = \[/);
  assert.throws(
    () => createSecretKeyWitness(`0x${"0".repeat(64)}`),
    /canonical nonzero/,
  );
  assert.throws(
    () => createSecretKeyWitness(`0x${order.toString(16).padStart(64, "0")}`),
    /canonical nonzero/,
  );
});

test("passkey synthetic P-256 assertion converts and rejects changed challenge or origin", () => {
  const rpId = "example.test";
  const origin = "https://example.test";
  const challenge = "123456789";
  const challengeBytes = Buffer.from(
    BigInt(challenge).toString(16).padStart(64, "0"),
    "hex",
  );
  const clientData = Buffer.from(
    JSON.stringify({
      type: "webauthn.get",
      challenge: challengeBytes.toString("base64url"),
      origin,
      crossOrigin: false,
    }),
  );
  const authData = Buffer.concat([
    createHash("sha256").update(rpId).digest(),
    Buffer.from([5, 0, 0, 0, 1]),
  ]);
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const jwk = publicKey.export({ format: "jwk" });
  assert.ok(jwk.x && jwk.y);
  const sec1 = Buffer.concat([
    Buffer.from([4]),
    Buffer.from(jwk.x, "base64url"),
    Buffer.from(jwk.y, "base64url"),
  ]);
  const signed = Buffer.concat([
    authData,
    createHash("sha256").update(clientData).digest(),
  ]);
  const signer = createSign("SHA256");
  signer.update(signed);
  signer.end();
  const assertion = {
    response: {
      authenticatorData: authData.toString("base64url"),
      clientDataJSON: clientData.toString("base64url"),
      signature: signer.sign(privateKey).toString("base64url"),
    },
  };
  const policy = {
    challenge,
    rpId,
    origin,
    publicKeySec1: sec1.toString("hex"),
    requireUserVerification: true,
  };
  const witness = passkeyAssertionToCircuit(assertion, policy);
  assert.equal(witness.challenge, challenge);
  assert.equal(
    (witness.assertion as { signature: number[] }).signature.length,
    64,
  );
  assert.match(stringifyToml(witness), /\[public_key\]/);
  assert.throws(
    () =>
      passkeyAssertionToCircuit(assertion, {
        ...policy,
        origin: "https://attacker.test",
      }),
    /does not match the expected values/,
  );
  assert.throws(
    () =>
      passkeyAssertionToCircuit(assertion, {
        ...policy,
        challenge: "123456790",
      }),
    /does not match the expected values/,
  );
});
