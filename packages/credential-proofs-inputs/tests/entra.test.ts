import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { exportJWK, importPKCS8, importSPKI, SignJWT } from "jose";
import { entraIssuer, importVerifiedEntra, importEntraToken } from "credential-proofs-inputs/entra";

const expected = {
  tenant: "12345678-1234-1234-1234-123456789abc",
  audience: "12345678-abcd-abcd-abcd-123456789abc",
  subject: "tenant-pairwise-subject",
  nonce: "action-hash",
  now: 1900000000,
};
async function fixture(
  overrides: Record<string, unknown> = {},
  headerOverrides: Record<string, unknown> = {},
) {
  const priv = await importPKCS8(
    await readFile(
      new URL("../../../../fixtures/data/synthetic-rs256-private.pem", import.meta.url),
      "utf8",
    ),
    "RS256",
  );
  const pub = await importSPKI(
    await readFile(
      new URL("../../../../fixtures/data/synthetic-rs256-public.pem", import.meta.url),
      "utf8",
    ),
    "RS256",
  );
  const jwk = {
    ...(await exportJWK(pub)),
    kid: "local-synthetic-entra",
    alg: "RS256",
  };
  const token = await new SignJWT({
    iss: entraIssuer(expected.tenant),
    aud: expected.audience,
    sub: expected.subject,
    nonce: expected.nonce,
    tid: expected.tenant,
    ver: "2.0",
    iat: expected.now - 60,
    nbf: expected.now - 60,
    exp: expected.now + 3600,
    name: "Synthetic Test User",
    preferred_username: "synthetic@example.invalid",
    ...overrides,
  })
    .setProtectedHeader({
      alg: "RS256",
      typ: "JWT",
      kid: jwk.kid,
      ...headerOverrides,
    })
    .sign(priv);
  return { token, jwk };
}
test("imports representative synthetic tenant-bound v2 token", async () => {
  const { token, jwk } = await fixture();
  const doc = await importVerifiedEntra(token, expected, jwk);
  assert.deepEqual(doc.tenant, [...Buffer.from(expected.tenant)]);
});
for (const [name, override] of Object.entries({
  tenant: { tid: "00000000-0000-0000-0000-000000000000" },
  issuer: { iss: "https://login.microsoftonline.com/common/v2.0" },
  audience: { aud: "wrong-client" },
  subject: { sub: "wrong-user" },
  nonce: { nonce: "wrong-action" },
  expiry: { exp: expected.now },
  future: { nbf: expected.now + 1 },
  version: { ver: "1.0" },
})) {
  test(`rejects ${name}`, async () => {
    const { token, jwk } = await fixture(override);
    await assert.rejects(importVerifiedEntra(token, expected, jwk));
  });
}
// The circuit checks and ignores nested and escaped claims.
test("accepts app-role arrays, nested and escaped claims", async () => {
  const { token, jwk } = await fixture({
    roles: ["Admin", "User"],
    wids: ["b79fbf4d-3ef9-4689-8143-76b194e85509"],
    _claim_names: { groups: "src1" },
    name: 'Quoted "User" \\ \u00e9',
  });
  assert.ok((await importVerifiedEntra(token, expected, jwk)).token);
});
test("rejects signature mutation", async () => {
  const { token, jwk } = await fixture();
  const parts = token.split(".");
  parts[2] = (parts[2]![0] === "A" ? "B" : "A") + parts[2]!.slice(1);
  await assert.rejects(importVerifiedEntra(parts.join("."), expected, jwk));
});
test("rejects Entra azp outside the constrained audience profile", async () => {
  const { token, jwk } = await fixture({ azp: "other-client" });
  await assert.rejects(
    importVerifiedEntra(token, expected, jwk),
    /azp must equal aud/,
  );
});
for (const [name, header] of Object.entries({
  unknown: { extra: "x" },
  wrongType: { typ: "at+jwt" },
})) {
  test(`rejects Entra ${name} JOSE header`, async () => {
    const { token, jwk } = await fixture({}, header);
    await assert.rejects(importVerifiedEntra(token, expected, jwk));
  });
}
test("rejects noncanonical tenant authority", () => {
  assert.throws(() => entraIssuer("common"));
  assert.throws(() => entraIssuer(expected.tenant.toUpperCase()));
});

test("uses only configured tenant JWKS and checks issuer metadata", async (t) => {
  const { token, jwk } = await fixture();
  const calls: string[] = [];
  const mocked = t.mock.method(
    globalThis,
    "fetch",
    async (input: string | URL | Request) => {
      calls.push(String(input));
      return new Response(
        JSON.stringify({
          keys: [
            {
              ...jwk,
              issuer: "https://login.microsoftonline.com/{tenantid}/v2.0",
            },
          ],
        }),
        { status: 200 },
      );
    },
  );
  await importEntraToken(token, expected);
  assert.deepEqual(calls, [
    `https://login.microsoftonline.com/${expected.tenant}/discovery/v2.0/keys`,
  ]);
  mocked.mock.mockImplementation(
    async () =>
      new Response(
        JSON.stringify({
          keys: [
            { ...jwk, issuer: "https://login.microsoftonline.com/common/v2.0" },
          ],
        }),
        { status: 200 },
      ),
  );
  await assert.rejects(importEntraToken(token, expected), /JWKS key issuer/);
});
