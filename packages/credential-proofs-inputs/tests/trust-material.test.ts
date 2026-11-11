import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createPublicKey } from "node:crypto";
import { describePublicJwks, sha256 } from "credential-proofs-inputs/trust-material";

test("public trust manifest binds exact bytes and stable SPKI independently of JWK order", async () => {
  const pem = await readFile(
    new URL("../../../../fixtures/data/synthetic-rs256-public.pem", import.meta.url),
    "utf8",
  );
  const key = createPublicKey(pem);
  const jwk = key.export({ format: "jwk" });
  const raw = JSON.stringify({ keys: [{ ...jwk, kid: "synthetic" }] });
  const source = {
    provider: "test",
    url: "https://example.invalid/fixed",
    issuer: "https://example.invalid",
    purpose: "synthetic unit test",
    rotation: "review",
  };
  const out = describePublicJwks(raw, source, "2026-10-22T00:00:00Z");
  assert.equal(out.responseSha256, sha256(raw));
  assert.equal(
    out.keys[0]!.spkiSha256,
    sha256(key.export({ type: "spki", format: "der" })),
  );
  assert.throws(() =>
    describePublicJwks(
      JSON.stringify({ keys: [{ ...jwk, d: "secret" }] }),
      source,
      "now",
    ),
  );
  assert.throws(() => describePublicJwks('{"keys":[]}', source, "now"));
});
