/** Public local-test scalar only; never use for production keys. */
import { createECDH, createPrivateKey, createHash } from "node:crypto";
import { p256 } from "@noble/curves/p256";
export function localP256Key(scalar) {
  if (!Number.isInteger(scalar) || scalar < 1 || scalar > 255)
    throw Error("local test scalar out of range");
  const d = Buffer.alloc(32);
  d[31] = scalar;
  const e = createECDH("prime256v1");
  e.setPrivateKey(d);
  const p = e.getPublicKey(undefined, "uncompressed");
  return {
    key: {
      public_key_x: [...p.subarray(1, 33)],
      public_key_y: [...p.subarray(33)],
    },
    privateKey: createPrivateKey({
      key: {
        kty: "EC",
        crv: "P-256",
        d: d.toString("base64url"),
        x: p.subarray(1, 33).toString("base64url"),
        y: p.subarray(33).toString("base64url"),
      },
      format: "jwk",
    }),
  };
}

/** RFC6979 signing with an explicitly public scalar; never a production signer. */
export function signLocalP256(scalar, message) {
  if (!Number.isInteger(scalar) || scalar < 1 || scalar > 255)
    throw Error("local test scalar out of range");
  const key = Buffer.alloc(32);
  key[31] = scalar;
  return p256
    .sign(createHash("sha256").update(message).digest(), key, { lowS: false })
    .toCompactRawBytes();
}
