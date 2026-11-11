import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createPrivateKey,
  createPublicKey,
  sign,
  createHash,
} from "node:crypto";
import { importVerifiedEd25519 } from "credential-proofs-inputs/ed25519";

const sk = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.alloc(32, 42),
    ]),
    format: "der",
    type: "pkcs8",
  }),
  pk = Buffer.from(
    createPublicKey(sk).export({ format: "jwk" }).x!,
    "base64url",
  ),
  message = Buffer.from("PhilSys local test"),
  signature = sign(null, message, sk);
const ell = (1n << 252n) + 27742317777372353535851937790883648493n;
const le = (b: Uint8Array) =>
  BigInt("0x" + Buffer.from(b).reverse().toString("hex"));
const enc = (n: bigint) =>
  Buffer.from(n.toString(16).padStart(64, "0"), "hex").reverse();
test("strict Ed25519 regular and exceptional identity R", () => {
  assert.equal(
    importVerifiedEd25519(message, signature, pk).signature.length,
    64,
  );
  const h = createHash("sha512").update(Buffer.alloc(32, 42)).digest();
  h[0]! &= 248;
  h[31]! &= 63;
  h[31]! |= 64;
  const r = Buffer.alloc(32);
  r[0] = 1;
  const k =
    le(
      createHash("sha512")
        .update(Buffer.concat([r, pk, message]))
        .digest(),
    ) % ell;
  const exceptional = Buffer.concat([
    r,
    enc((k * le(h.subarray(0, 32))) % ell),
  ]);
  assert.equal(
    importVerifiedEd25519(message, exceptional, pk).signature.length,
    64,
  );
});
test("Ed25519 rejects scalar alias, wrong message, identity issuer and malformed point", () => {
  const alias = Buffer.concat([
    signature.subarray(0, 32),
    enc(le(signature.subarray(32)) + ell),
  ]);
  assert.throws(() => importVerifiedEd25519(message, alias, pk), /canonical/);
  assert.throws(
    () => importVerifiedEd25519(Buffer.from("wrong"), signature, pk),
    /verification failed/,
  );
  const identity = Buffer.alloc(32);
  identity[0] = 1;
  assert.throws(
    () => importVerifiedEd25519(message, signature, identity),
    /identity/,
  );
  assert.throws(() =>
    importVerifiedEd25519(message, signature, Buffer.alloc(32, 255)),
  );
});
