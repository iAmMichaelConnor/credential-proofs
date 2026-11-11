import { test } from "node:test";
import assert from "node:assert/strict";
import { assertBoundedJsonObject, assertJoseHeaderObject, assertOidcJsonProfile, assertStructuredJsonDocument } from "credential-proofs-inputs/oidc-json";

const base = '"iss":"i","aud":"a","sub":"s","nonce":"n","exp":9';
test("profile1 reads AMR string arrays; profile0 ignores amr like any nested member", () => {
  assert.doesNotThrow(() =>
    assertOidcJsonProfile('{"amr":["future-method","mfa"]}', 1),
  );
  // Profile 0 accepts nested values.
  assert.doesNotThrow(() => assertOidcJsonProfile('{"amr":[{}]}', 0));
  for (const raw of ['{"amr":[{}]}', '{"amr":[1]}', '{"amr":"pwd"}'])
    assert.throws(
      () => assertOidcJsonProfile(raw, 1),
      /array must contain strings/,
    );
  assert.throws(
    () => assertOidcJsonProfile('{"scope":[1]}', 2),
    /array must contain strings/,
  );
});
test("profile2 validates nested assurance without confusing sibling keys or shadow levels", () => {
  const x = assertOidcJsonProfile(
    '{"reliability_info":{"level":"bronze","other":{"level":"gold"},"reliabilities":[{"id":"601"},{"id":"626"}]}}',
    2,
  );
  assert.equal((x.reliability_info as { level: string }).level, "bronze");
  for (const raw of [
    '{"reliability_info":{"level":"bronze","level":"gold"}}',
    '{"amr":[],"amr":[]}',
    '{"reliability_info":{"level":[]}}',
    '{"reliability_info":{"level":"go\\/ld"}}',
    '{"reliability_info":[]}',
  ])
    assert.throws(() => assertOidcJsonProfile(raw, 2));
  assert.doesNotThrow(() =>
    assertOidcJsonProfile('{"unknown":{"x":["\\u00e9"]},"amr":["p\\/w"]}', 2),
  );
});
test("flat profile: escapes, nested values, lengths and integers match the circuit", () => {
  // Selected claims: only the escaped solidus, at most 256 decoded bytes, no nesting.
  const decoded = assertOidcJsonProfile(
    '{"iss":"https:\\/\\/sso.acesso.gov.br\\/","aud":"a","sub":"s","nonce":"n","exp":9}',
  );
  assert.equal(decoded.iss, "https://sso.acesso.gov.br/");
  for (const claim of ["iss", "aud", "sub", "nonce", "azp"])
    for (const value of ['"a\\\\b"', '"a\\"b"', '"a\\u002fb"', '"\\n"'])
      assert.throws(
        () => assertOidcJsonProfile('{"' + claim + '":' + value + "}"),
        /escaped/,
      );
  assert.throws(() => assertOidcJsonProfile('{"aud":["a"]}'), /nested/);
  assert.throws(() => assertOidcJsonProfile('{"sub":1}'), /must be a string/);
  assert.doesNotThrow(() =>
    assertOidcJsonProfile('{"sub":"' + "x".repeat(255) + '\\/"}'),
  );
  assert.throws(
    () => assertOidcJsonProfile('{"sub":"' + "x".repeat(256) + '\\/"}'),
    /capacity/,
  );
  assert.throws(() => assertOidcJsonProfile('{"exp":"9"}'), /must be a number/);
  // Other members: any escape, any length, any canonical integer, nested to depth 9 with the root.
  assert.doesNotThrow(() =>
    assertOidcJsonProfile(
      "{" +
        base +
        ',"name":"Q \\"U\\" \\\\ \\/ \\b\\f\\n\\r\\t \\u00e9","long":"' +
        "y".repeat(5000) +
        '","big":123456789012345678901234567890,"cnf":{"jkt":"k"},"roles":["Admin","User"],"deep":' +
        "[".repeat(8) +
        "0" +
        "]".repeat(8) +
        "}",
    ),
  );
  assert.throws(
    () =>
      assertOidcJsonProfile(
        '{"deep":' + "[".repeat(9) + "0" + "]".repeat(9) + "}",
      ),
    /depth/,
  );
  for (const value of ["-1", "1.5", "1e3", "01"])
    assert.throws(() => assertOidcJsonProfile('{"x":{"y":[' + value + "]}}"));
  // Keys stay unescaped and at most 256 bytes, at every level.
  for (const raw of ['{"x\\/":1}', '{"x":{"k\\/":1}}'])
    assert.throws(() => assertOidcJsonProfile(raw), /escaped JSON keys/);
  assert.doesNotThrow(() =>
    assertOidcJsonProfile('{"' + "k".repeat(256) + '":1}'),
  );
  assert.throws(
    () => assertOidcJsonProfile('{"' + "k".repeat(257) + '":1}'),
    /key exceeds/,
  );
  assert.throws(
    () => assertOidcJsonProfile('{"x":{"' + "k".repeat(257) + '":1}}'),
    /key exceeds/,
  );
  // The host still rejects every duplicate key, at every level.
  assert.throws(
    () => assertOidcJsonProfile('{"x":{"a":1,"a":2}}'),
    /duplicate/,
  );
});
test("structured document and header envelopes keep their domains", () => {
  const nest = (d: number) => "[".repeat(d) + "1" + "]".repeat(d);
  // The document profile is depth 8 with the root and 4096-byte strings.
  assert.doesNotThrow(() =>
    assertStructuredJsonDocument(
      '{"a":' + nest(7) + ',"s":"' + "y".repeat(4096) + '"}',
    ),
  );
  assert.throws(
    () => assertStructuredJsonDocument('{"a":' + nest(8) + "}"),
    /depth/,
  );
  assert.throws(
    () => assertStructuredJsonDocument('{"s":"' + "y".repeat(4097) + '"}'),
    /capacity/,
  );
  for (const raw of ['{"s":"a\\/b"}', '{"x":18446744073709551616}', '{"x":-1}'])
    assert.throws(() => assertStructuredJsonDocument(raw));
  assert.doesNotThrow(() =>
    assertJoseHeaderObject('{"alg":"RS256","typ":"JWT","kid":"k"}'),
  );
  for (const raw of [
    '{"alg":"RS256","kid":"k\\/"}',
    '{"alg":"RS256","kid":1}',
    '{"alg":"RS256","x":{}}',
    '{"alg":"RS256","kid":"' + "k".repeat(257) + '"}',
  ])
    assert.throws(() => assertJoseHeaderObject(raw));
  // Legacy PhilSys envelope: unchanged.
  assert.throws(() => assertBoundedJsonObject('{"s":"a\\/b"}'));
  assert.throws(() =>
    assertBoundedJsonObject('{"s":"' + "y".repeat(257) + '"}'),
  );
});
test("oidc_policy required strings (FranceConnect acr) are unescaped root strings of at most 256 bytes", () => {
  assert.equal(
    assertOidcJsonProfile(
      '{"u1":"\\"}\\"","x":{"acr":"eidas3"},"acr":"eidas1"}',
      1,
      ["acr"],
    ).acr,
    "eidas1",
  );
  for (const raw of [
    '{"acr":"eidas\\u0032"}',
    '{"acr":["eidas2"]}',
    '{"acr":"' + "e".repeat(257) + '"}',
  ])
    assert.throws(() => assertOidcJsonProfile(raw, 1, ["acr"]));
});
