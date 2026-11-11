import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { jpkiChallenge, jpkiCardDigestInfo, jpkiToml, type JpkiCapture } from "credential-proofs-inputs/jpki";

const dir = new URL("../../../../fixtures/material/jpki/local-test/", import.meta.url);
function input(): JpkiCapture {
  const m = JSON.parse(readFileSync(new URL("fixture.json", dir), "utf8"));
  return {
    root: readFileSync(new URL("root.der", dir)),
    certificate: readFileSync(new URL("holder.der", dir)),
    responder: readFileSync(new URL("responder.der", dir)),
    ocsp: readFileSync(new URL("good.ocsp.der", dir)),
    holderSignature: readFileSync(new URL("holder-signature.bin", dir)),
    account: m.account,
    action: m.action,
    session: "03".repeat(32),
    now: m.now,
    localTestRoot: true,
  };
}
test("fixed challenge and PKCS11 DigestInfo sizes", () => {
  const i = input();
  assert.equal(jpkiChallenge(i.account, i.action, i.session).length, 128);
  assert.equal(jpkiCardDigestInfo(i.account, i.action, i.session).length, 51);
});
test("explicit synthetic-root import", () =>
  assert.match(jpkiToml(input()), /anchor_class = 1/));
test("synthetic root fails production selector", () =>
  assert.throws(
    () => jpkiToml({ ...input(), localTestRoot: false }),
    /unapproved JPKI root/,
  ));
test("changed action rejects holder signature", () =>
  assert.throws(
    () => jpkiToml({ ...input(), action: "04".repeat(32) }),
    /holder challenge signature rejected/,
  ));
test("expired certificate rejected", () =>
  assert.throws(
    () => jpkiToml({ ...input(), now: 2_100_000_000 }),
    /outside validity/,
  ));
test("missing signed OCSP rejected", () =>
  assert.throws(
    () => jpkiToml({ ...input(), ocsp: new Uint8Array() }),
    /signed OCSP response required/,
  ));
test("invalid freshness rejected", () =>
  assert.throws(
    () => jpkiToml({ ...input(), maxOcspAge: 86401 }),
    /freshness/,
  ));
test("ambiguous challenge bytes rejected", () =>
  assert.throws(
    () => jpkiChallenge("AA".repeat(32), "02".repeat(32), "03".repeat(32)),
    /canonical lowercase/,
  ));
