import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { importPKCS8, SignJWT, CompactSign, type JWK } from "jose";
import { importVerifiedUniversity, assertAssertedUniversityAffiliation, type UniversityExpected } from "credential-proofs-inputs/university";

const material = new URL(
  "../../../../fixtures/material/university/local-test/",
  import.meta.url,
);
const expected = JSON.parse(
  await readFile(new URL("policy.json", material), "utf8"),
) as UniversityExpected;
const token = (
  await readFile(new URL("id-token.txt", material), "utf8")
).trim();
const jwk = JSON.parse(
  await readFile(new URL("issuer-key.json", material), "utf8"),
) as JWK;
const privateKey = await importPKCS8(
  await readFile(
    new URL("../../../../fixtures/data/synthetic-rs256-private.pem", import.meta.url),
    "utf8",
  ),
  "RS256",
);
const raw = JSON.parse(
  Buffer.from(token.split(".")[1]!, "base64url").toString(),
) as Record<string, unknown>;
const sign = async (claims: Record<string, unknown>) =>
  new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: jwk.kid })
    .sign(privateKey);
test("CILogon login binds broker and signed original institutional idp", async () => {
  const d = await importVerifiedUniversity(token, expected, jwk);
  assert.equal(d.brokered, true);
  for (const change of [
    { institutionalIdp: "http://github.com/login/oauth/authorize" },
    { nonce: "1".repeat(64) },
    { subject: "wrong" },
    { audience: "wrong" },
    { now: 1900003600 },
  ])
    await assert.rejects(
      importVerifiedUniversity(token, { ...expected, ...change }, jwk),
    );
});
test("signed missing, social and duplicate idp fail and direct cannot bypass broker policy", async () => {
  const absent = { ...raw };
  delete absent.idp;
  await assert.rejects(
    importVerifiedUniversity(await sign(absent), expected, jwk),
    /idp/,
  );
  await assert.rejects(
    importVerifiedUniversity(
      await sign({ ...raw, idp: "http://github.com/login/oauth/authorize" }),
      expected,
      jwk,
    ),
    /idp/,
  );
  const dup = JSON.stringify(raw).replace('"idp":', '"idp":null,"idp":');
  const duplicate = await new CompactSign(Buffer.from(dup))
    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: jwk.kid })
    .sign(privateKey);
  await assert.rejects(
    importVerifiedUniversity(duplicate, expected, jwk),
    /duplicate/,
  );
  await assert.rejects(
    importVerifiedUniversity(token, { ...expected, mode: "direct" }, jwk),
    /institutional idp mode/,
  );
});
test("direct campus issuer and optional nbf/iat/audience types", async () => {
  const issuer = "https://oidc.example.edu";
  const d = await importVerifiedUniversity(
    await sign({ ...raw, iss: issuer }),
    { ...expected, mode: "direct", issuer, institutionalIdp: "" },
    jwk,
  );
  assert.equal(d.brokered, false);
  await assert.rejects(
    importVerifiedUniversity(
      await sign({ ...raw, iss: issuer }),
      { ...expected, mode: "direct", issuer },
      jwk,
    ),
    /empty institutional idp/,
  );
  for (const patch of [
    { iat: 1900000001 },
    { nbf: 1900000001 },
    { aud: [expected.audience] },
  ])
    await assert.rejects(
      importVerifiedUniversity(await sign({ ...raw, ...patch }), expected, jwk),
    );
});
test("affiliation exact membership is explicitly as asserted, not fresh status", () => {
  assertAssertedUniversityAffiliation(
    raw,
    "student@example.edu",
    "cilogon-semicolon",
  );
  assert.throws(() =>
    assertAssertedUniversityAffiliation(
      raw,
      "student@example.ed",
      "cilogon-semicolon",
    ),
  );
  assertAssertedUniversityAffiliation(
    { eduPersonScopedAffiliation: ["staff@stanford.edu"] },
    "staff@stanford.edu",
    "camelcase-array",
  );
  assertAssertedUniversityAffiliation(
    { eduperson_scoped_affiliation: ["staff@example.edu"] },
    "staff@example.edu",
    "snakecase-array",
  );
  assert.throws(() =>
    assertAssertedUniversityAffiliation(
      {},
      "student@example.edu",
      "cilogon-semicolon",
    ),
  );
  assert.throws(() =>
    assertAssertedUniversityAffiliation(
      { eduPersonScopedAffiliation: ["staff@stanford.edu", 123] },
      "staff@stanford.edu",
      "camelcase-array",
    ),
  );
});
// A signed azp must equal the audience, as in the circuit; the payload is the structured document.
test("signed azp must equal aud and the payload is the structured document", async () => {
  assert.ok(
    (
      await importVerifiedUniversity(
        await sign({ ...raw, azp: expected.audience }),
        expected,
        jwk,
      )
    ).token,
  );
  await assert.rejects(
    importVerifiedUniversity(
      await sign({ ...raw, azp: "cilogon:/client_id/attacker" }),
      expected,
      jwk,
    ),
    /azp must match aud/,
  );
  assert.ok(
    (
      await importVerifiedUniversity(
        await sign({ ...raw, x: "y".repeat(300) }),
        expected,
        jwk,
      )
    ).token,
  );
  await assert.rejects(
    importVerifiedUniversity(
      await sign({ ...raw, x: [[[[[[[[1]]]]]]]] }),
      expected,
      jwk,
    ),
    /depth/,
  );
});
