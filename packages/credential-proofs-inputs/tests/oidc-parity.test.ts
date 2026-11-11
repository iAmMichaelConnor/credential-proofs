import assert from "node:assert/strict";
import { createSign } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { importVerifiedOidc, type Provider } from "credential-proofs-inputs/oidc";
import { createSyntheticOidc } from "credential-proofs-test-builders/oidc";


const expected = {
  audience: "client",
  subject: "test-user",
  nonce: "action-nonce",
  now: 1_900_000_000,
};
const issuers: Record<Provider, string> = {
  google: "https://accounts.google.com",
  apple: "https://appleid.apple.com",
  telegram: "https://oauth.telegram.org",
  kakao: "https://kauth.kakao.com",
  miargentina: "https://id.argentina.gob.ar",
  facebook: "https://www.facebook.com",
};
const privatePem = await readFile(
  new URL("../../../../fixtures/data/synthetic-rs256-private.pem", import.meta.url),
  "utf8",
);

function b64url(bytes: Buffer): string {
  return bytes.toString("base64url");
}
function signRaw(header: Buffer, payload: Buffer): string {
  const signingInput = `${b64url(header)}.${b64url(payload)}`;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput, "ascii");
  signer.end();
  return `${signingInput}.${signer.sign(privatePem).toString("base64url")}`;
}
function claims(provider: Provider, extra = ""): string {
  return `{"iss":"${issuers[provider]}","aud":"client","sub":"test-user","nonce":"action-nonce","iat":1899999940,"exp":1900003600${extra}}`;
}
const header = (extra = ""): string =>
  `{"alg":"RS256","typ":"JWT","kid":"local-synthetic-rs256"${extra}}`;

test("shared RSA OIDC import accepts the existing flat profile, including optional matching azp", async () => {
  for (const provider of [
    "google",
    "apple",
    "telegram",
    "kakao",
    "miargentina",
    "facebook",
  ] as const) {
    const fixture = await createSyntheticOidc(provider, expected);
    assert.ok(fixture.document.token);
    const withAzp = signRaw(
      Buffer.from(header()),
      Buffer.from(claims(provider, ',"azp":"client"')),
    );
    assert.ok(
      (await importVerifiedOidc(provider, withAzp, expected, fixture.jwk))
        .token,
    );
    // The default Noir header permits typ to be absent; RS256 and kid remain required.
    const noTyp = signRaw(
      Buffer.from('{"alg":"RS256","kid":"local-synthetic-rs256"}'),
      Buffer.from(claims(provider)),
    );
    assert.ok(
      (await importVerifiedOidc(provider, noTyp, expected, fixture.jwk)).token,
    );
  }
});

test("shared RSA OIDC import rejects headers outside the Noir JOSE profile", async () => {
  for (const provider of [
    "google",
    "apple",
    "telegram",
    "kakao",
    "miargentina",
    "facebook",
  ] as const) {
    const { jwk } = await createSyntheticOidc(provider, expected);
    for (const rawHeader of [
      header(',"extra":"x"'),
      header().replace('"JWT"', '"at+jwt"'),
      '{"alg":"RS256","typ":"JWT","kid":"local-synthetic-rs256","kid":"local-synthetic-rs256"}',
      '{"alg":"RS256","typ":"JWT","kid":"local\\u002dsynthetic-rs256"}',
      '{"alg":"RS256","typ":1,"kid":"local-synthetic-rs256"}',
    ]) {
      await assert.rejects(
        importVerifiedOidc(
          provider,
          signRaw(Buffer.from(rawHeader), Buffer.from(claims(provider))),
          expected,
          jwk,
        ),
      );
    }
  }
});

test("shared RSA OIDC import rejects payloads outside the flat constrained profile", async () => {
  for (const provider of [
    "google",
    "apple",
    "telegram",
    "kakao",
    "miargentina",
    "facebook",
  ] as const) {
    const { jwk } = await createSyntheticOidc(provider, expected);
    const base = claims(provider);
    // The circuit checks and ignores an escaped unknown string, a nested
    // unknown value and a 257-byte unknown string, so they are accepted below;
    // the selected claims keep the
    // 256-byte cap, admit only the escaped solidus, and cannot be nested.
    const invalidPayloads: [string, RegExp][] = [
      [
        base.replace('"sub":"test-user"', '"sub":"test-\\"user"'),
        /escaped JSON strings/,
      ],
      [base.replace('"aud":"client"', '"aud":["client"]'), /nested JSON/],
      [
        base.replace(
          '"sub":"test-user"',
          '"sub":"test-user","sub":"test-user"',
        ),
        /duplicate JWT claims/,
      ],
      [
        base.replace('"exp":1900003600', '"exp":1900003600,"future":1.5'),
        /scalar/,
      ],
      [
        base.replace(
          '"nonce":"action-nonce"',
          `"nonce":"action-nonce","azp":"${"x".repeat(257)}"`,
        ),
        /capacity/,
      ],
      [
        base.replace(
          '"exp":1900003600',
          '"exp":1900003600,"azp":"other-client"',
        ),
        /azp must equal aud/,
      ],
    ];
    const validPayloads = [
      base.replace(
        '"exp":1900003600',
        '"exp":1900003600,"name":"Quoted \\"User\\""',
      ),
      base.replace('"exp":1900003600', '"exp":1900003600,"amr":["pwd","mfa"]'),
      base.replace(
        '"exp":1900003600',
        '"exp":1900003600,"future":{"nested":true,"iss":"https://attacker.example"}',
      ),
      base.replace(
        '"exp":1900003600',
        `"exp":1900003600,"future":"${"x".repeat(257)}"`,
      ),
      base.replace(
        '"exp":1900003600',
        '"exp":1900003600,"future":18446744073709551616',
      ),
    ];
    for (const payload of validPayloads) {
      assert.ok(
        (
          await importVerifiedOidc(
            provider,
            signRaw(Buffer.from(header()), Buffer.from(payload)),
            expected,
            jwk,
          )
        ).token,
      );
    }
    for (const [payload, reason] of invalidPayloads) {
      await assert.rejects(
        importVerifiedOidc(
          provider,
          signRaw(Buffer.from(header()), Buffer.from(payload)),
          expected,
          jwk,
        ),
        reason,
      );
    }
    const malformedUtf8 = Buffer.from(
      base.replace('"exp":1900003600', '"exp":1900003600,"future":"x"'),
    );
    malformedUtf8[malformedUtf8.indexOf(Buffer.from('"future":"x"')) + 10] =
      0xff;
    await assert.rejects(
      importVerifiedOidc(
        provider,
        signRaw(Buffer.from(header()), malformedUtf8),
        expected,
        jwk,
      ),
      /encoded data|UTF-8/i,
    );

    const largePayload = Buffer.from(
      `${base.slice(0, -1)},${Array.from({ length: 220 }, (_, i) => `"future${i}":0`).join(",")}}`,
    );
    await assert.rejects(
      importVerifiedOidc(
        provider,
        signRaw(Buffer.from(header()), largePayload),
        expected,
        jwk,
      ),
      /capacities/,
    );
  }
});
