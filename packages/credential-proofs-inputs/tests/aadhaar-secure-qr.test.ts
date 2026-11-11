import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { deflateSync, gzipSync } from "node:zlib";
import { AADHAAR_SECURE_QR_MAX_DECOMPRESSED_BYTES, AADHAAR_SECURE_QR_UPSTREAM_MAX_SIGNED_BYTES, decompressSecureQr, prepareSecureQrInput, rsaLimbs, secureQrDelimiterHints, secureQrNumberToBytes, splitSecureQr } from "credential-proofs-inputs/aadhaar-secure-qr";


// Hint generation is checked here, on the host. The circuit's checks of the
// same hints are separate Noir tests (layout_tests.nr) that feed it wrong hints.
const material = new URL(
  "../../../../fixtures/material/anon_aadhaar/provider-test/",
  import.meta.url,
);
const fixture = JSON.parse(
  readFileSync(new URL("test.json", material), "utf8"),
) as Record<string, string>;
const certificate = readFileSync(
  new URL("testCertificate.pem", material),
  "utf8",
);
const synthetic = createPrivateKey(
  readFileSync(
    new URL("../../../../fixtures/data/synthetic-rs256-private.pem", import.meta.url),
    "utf8",
  ),
);
const decompressed = decompressSecureQr(
  secureQrNumberToBytes(fixture.testQRData!),
);

test("upstream test QR decodes to the published field values", () => {
  assert.equal(
    secureQrNumberToBytes(fixture.testQRData!)[0],
    0x78,
    "upstream test QR is a zlib stream",
  );
  const { signed, signature } = splitSecureQr(decompressed);
  assert.equal(signed.length, 1137);
  assert.equal(signature.length, 256);
  const hints = secureQrDelimiterHints(signed);
  assert.deepEqual(
    hints,
    [
      2, 4, 26, 38, 49, 51, 68, 79, 80, 96, 97, 104, 118, 124, 152, 165, 179,
      184,
    ],
  );
  const field = (k: number) =>
    signed.subarray(hints[k - 1]! + 1, hints[k]!).toString("latin1");
  assert.equal(signed.subarray(0, 2).toString("latin1"), fixture["undefined"]);
  assert.equal(field(1), fixture.Email_mobile_present_bit_indicator_value);
  assert.equal(field(2), fixture.ReferenceId);
  assert.equal(field(3), fixture.Name);
  assert.equal(field(4), fixture.DOB);
  assert.equal(field(5), fixture.Gender);
  assert.equal(field(11), fixture.PinCode);
  assert.equal(field(13), fixture.State);
  assert.equal(field(17), fixture.PhoneNumberLast4);
  // The photo (JPEG 2000) starts with 0xff, so a naive scan finds more 255s.
  assert.equal(signed[hints[17]! + 1], 255);
});

test("prepared input matches the circuit layout and the host signature check", () => {
  const prepared = prepareSecureQrInput(
    { qrDecimal: fixture.testQRData! },
    certificate,
  );
  assert.equal(prepared.hostSignatureValid, true);
  assert.equal(prepared.input.signed_data.len, 1137);
  assert.equal(
    prepared.input.signed_data.storage.length,
    AADHAAR_SECURE_QR_UPSTREAM_MAX_SIGNED_BYTES,
  );
  assert.ok(
    prepared.input.signed_data.storage.slice(1137).every((b) => b === 0),
  );
  for (const limbs of [
    prepared.input.signature,
    prepared.input.modulus,
    prepared.input.redc,
  ]) {
    assert.equal(limbs.length, 18);
    assert.ok(limbs.every((v) => BigInt(v) < 1n << 120n));
  }
  const modulus = prepared.input.modulus.reduceRight(
    (acc, v) => (acc << 120n) + BigInt(v),
    0n,
  );
  const jwk = createPublicKey(certificate).export({ format: "jwk" });
  assert.equal(
    modulus,
    BigInt(`0x${Buffer.from(jwk.n!, "base64url").toString("hex")}`),
  );
  const signature = prepared.input.signature.reduceRight(
    (acc, v) => (acc << 120n) + BigInt(v),
    0n,
  );
  assert.equal(signature, BigInt(`0x${prepared.signature.toString("hex")}`));
});

test("the host reports a wrong key or a changed byte as an invalid signature", () => {
  assert.equal(
    prepareSecureQrInput({ decompressed }, createPublicKey(synthetic))
      .hostSignatureValid,
    false,
  );
  const changed = Buffer.from(decompressed);
  changed[48] = 0x33;
  assert.equal(
    prepareSecureQrInput({ decompressed: changed }, certificate)
      .hostSignatureValid,
    false,
  );
});

test("gzip and zlib streams decompress to the same bytes; other bytes are rejected", () => {
  assert.deepEqual(decompressSecureQr(gzipSync(decompressed)), decompressed);
  assert.throws(
    () => decompressSecureQr(Buffer.from("not compressed")),
    /neither a gzip nor a zlib/,
  );
  assert.throws(() => secureQrNumberToBytes("0123"), /decimal/);
  assert.throws(() => secureQrNumberToBytes("12a"), /decimal/);
});

test("decompression output is bounded well above real QR sizes", () => {
  // A real payload (1,393 bytes here) is far below the limit.
  assert.ok(
    decompressed.length * 40 < AADHAAR_SECURE_QR_MAX_DECOMPRESSED_BYTES,
  );
  const atLimit = Buffer.alloc(AADHAAR_SECURE_QR_MAX_DECOMPRESSED_BYTES, 7);
  assert.equal(decompressSecureQr(gzipSync(atLimit)).length, atLimit.length);
  assert.equal(decompressSecureQr(deflateSync(atLimit)).length, atLimit.length);
  // A 1 MiB bomb compresses to about 1 KiB, smaller than a real QR.
  const bomb = Buffer.alloc(1024 * 1024, 0);
  for (const stream of [gzipSync(bomb), deflateSync(bomb)]) {
    assert.ok(stream.length < 2953);
    assert.throws(
      () => decompressSecureQr(stream),
      /decompresses to more than 65536 bytes/,
    );
  }
  const oneOver = Buffer.alloc(AADHAAR_SECURE_QR_MAX_DECOMPRESSED_BYTES + 1, 7);
  assert.throws(
    () => decompressSecureQr(gzipSync(oneOver)),
    /decompresses to more than 65536 bytes/,
  );
});

test("hint generation needs 18 delimiters and fits the capacity", () => {
  assert.throws(
    () => secureQrDelimiterHints(Buffer.from([86, 50, 255, 51, 255])),
    /expected 18/,
  );
  const { signed } = splitSecureQr(decompressed);
  const long = Buffer.concat([
    signed,
    Buffer.alloc(
      AADHAAR_SECURE_QR_UPSTREAM_MAX_SIGNED_BYTES - signed.length + 1,
      7,
    ),
  ]);
  const resigned = Buffer.concat([long, sign("sha256", long, synthetic)]);
  assert.throws(
    () =>
      prepareSecureQrInput(
        { decompressed: resigned },
        createPublicKey(synthetic),
      ),
    /capacity is 1527/,
  );
  const fits = long.subarray(0, AADHAAR_SECURE_QR_UPSTREAM_MAX_SIGNED_BYTES);
  const prepared = prepareSecureQrInput(
    { decompressed: Buffer.concat([fits, sign("sha256", fits, synthetic)]) },
    createPublicKey(synthetic),
  );
  assert.equal(prepared.input.signed_data.len, 1527);
  assert.equal(prepared.hostSignatureValid, true);
});

test("RSA limbs reject integers above 2160 bits", () => {
  assert.deepEqual(rsaLimbs(Buffer.from([1])), ["1", ...Array(17).fill("0")]);
  assert.throws(() => rsaLimbs(Buffer.alloc(271, 255)), /envelope/);
});
