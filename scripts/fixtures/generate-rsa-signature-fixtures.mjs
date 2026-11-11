// Explicit public local-test key material only; not issuer credentials.
import { readFile, writeFile, mkdir } from "node:fs/promises";
import {
  generateKeyPairSync,
  createPublicKey,
  sign,
  createHash,
} from "node:crypto";
import { rsaKeyToCircuit } from "credential-proofs-inputs/oidc";

const directory = new URL("../../fixtures/data/rsa-signature/", import.meta.url);
await mkdir(directory, { recursive: true });
const rows = [];
let code =
  "//! Generated synthetic RSA API regression vectors, not production keys.\nuse crate::RSAPubkey;\nuse bignum::{params::BigNumParams, RuntimeBigNum};\n";
let rsa2048;
for (const bits of [1024, 2048, 4096]) {
  let pem;
  if (bits === 2048)
    pem = await readFile(
      new URL("../../fixtures/data/synthetic-rs256-private.pem", import.meta.url),
      "utf8",
    );
  else {
    const file = new URL(`rsa${bits}-test-private.pem`, directory);
    try {
      pem = await readFile(file, "utf8");
    } catch (e) {
      if (e.code !== "ENOENT") throw e;
      pem = generateKeyPairSync("rsa", {
        modulusLength: bits,
        publicExponent: 65537,
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
      }).privateKey;
      await writeFile(file, pem, { mode: 0o600, flag: "wx" });
    }
  }
  const publicKey = createPublicKey(pem);
  const jwk = publicKey.export({ format: "jwk" });
  const key = rsaKeyToCircuit(jwk, bits);
  const message = Buffer.from("test");
  const digest = createHash("sha256").update(message).digest();
  const signature = sign("RSA-SHA256", message, pem);
  let integer = BigInt("0x" + signature.toString("hex"));
  const limbs = [];
  for (let j = 0; j < key.modulus_limbs.length; j++) {
    limbs.push((integer & ((1n << 120n) - 1n)).toString());
    integer >>= 120n;
  }
  if (bits === 2048) rsa2048 = { key, limbs, digest };
  const arr = (a) => "[" + a.join(", ") + "]";
  const setup = `let key: RSAPubkey<${key.modulus_limbs.length}> = RSAPubkey::new(${arr(key.modulus_limbs)},${arr(key.redc_params_limbs)}); let signature: [Field;${limbs.length}]=${arr(limbs)}; let message: BoundedVec<u8,4> = BoundedVec::from_array([116u8,101,115,116]);`;
  code += `\n#[test]\nfn rsa${bits}_generic_digest_and_legacy_agree() { ${setup} let digest: [u8;32]=${arr([...digest])}; assert_eq(key.verify_rsa_sha256_pkcs1v15(message,signature),digest); ${bits !== 4096 ? "assert_eq(key.verify_dkim_signature(message,signature),digest);" : ""} assert_eq(key.verify_digest_sha256_pkcs1v15(digest,signature),digest); }\n`;
  code += `\n#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]\nfn rsa${bits}_changed_message_rejects() { ${setup} let changed: BoundedVec<u8,4> = BoundedVec::from_array([116u8,101,115,117]); let _=key.verify_rsa_sha256_pkcs1v15(changed,signature); }\n`;
  rows.push({
    bits,
    message: "test",
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
    signatureBase64: signature.toString("base64"),
    keyRole: "Explicitly public synthetic local-test key only",
  });
}
// The regression assertions are maintained separately; their cryptographic
// arrays and digest are regenerated from the same public vector above.
const arr = (a) => "[" + a.join(", ") + "]";
code +=
  "\n// The RSA2048 vector of rsa2048_generic_digest_and_legacy_agree, as arrays.\n";
code += `fn rsa2048_fixture() -> ([Field;18],[Field;18],[Field;18]) {let modulus: [Field;18]=${arr(rsa2048.key.modulus_limbs)};let redc: [Field;18]=${arr(rsa2048.key.redc_params_limbs)};let signature: [Field;18]=${arr(rsa2048.limbs)};(modulus,redc,signature)}\n`;
code += `\nfn rsa2048_test_digest() -> [u8;32] {${arr([...rsa2048.digest])}}\n\n`;
code += await readFile(
  new URL("./templates/rsa-signature-regressions.nr.inc", import.meta.url),
  "utf8",
);
await writeFile(
  new URL("vectors.json", directory),
  JSON.stringify(rows, null, 2) + "\n",
);
await writeFile(
  new URL(
    "../../noir/rsa_signature/src/api_tests.nr",
    import.meta.url,
  ),
  code,
);
