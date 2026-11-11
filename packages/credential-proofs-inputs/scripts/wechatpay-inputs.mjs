import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
// Verify an exact WeChat Pay v3 fixture and serialize trusted RSA and response
// inputs through the shared credentials converter. Test fixtures are not live
// payments; never put platform private keys here.
import { readFile } from "node:fs/promises";
import { createHash, createPublicKey, verify } from "node:crypto";
import { rsaKeyToCircuit } from "credential-proofs-inputs/oidc";

import { boundedBytes, writeToml } from "credential-proofs-inputs/toml";


function rsaSignatureLimbs(signature) {
  if (signature.length !== 256)
    throw new Error("expected a 2048-bit RSA signature");
  let value = BigInt(`0x${signature.toString("hex")}`);
  const limbs = Array.from({ length: 18 }, () => {
    const limb = (value & ((1n << 120n) - 1n)).toString();
    value >>= 120n;
    return limb;
  });
  if (value !== 0n) throw new Error("RSA signature exceeds 18 limbs");
  return limbs;
}

export function responseToInput(response) {
  if (response.mode !== "v3") throw new Error("mode must be v3");
  if (typeof response.body !== "string")
    throw new Error("body must be the exact raw response string");
  if (!/^(0|[1-9][0-9]{0,19})$/.test(response.timestamp))
    throw new Error("invalid timestamp");
  if (!/^[!-~]{1,128}$/.test(response.nonce)) throw new Error("invalid nonce");
  const issued = BigInt(response.timestamp);
  const now = BigInt(response.nowSeconds);
  const age = BigInt(response.maxAgeSeconds);
  if ([issued, now, age].some((v) => v < 0n || v >= 1n << 64n))
    throw new Error("timestamp outside u64");
  if (issued > now || now - issued > age)
    throw new Error("future or stale response");

  const key = createPublicKey(response.publicKeyPem);
  const keyParams = rsaKeyToCircuit(key.export({ format: "jwk" }));
  const signatureBytes = Buffer.from(response.signature, "base64");
  if (
    signatureBytes.length !== 256 ||
    signatureBytes.toString("base64") !== response.signature
  ) {
    throw new Error("signature must be canonical base64 RSA-2048");
  }
  const preimage = Buffer.from(
    `${response.timestamp}\n${response.nonce}\n${response.body}\n`,
    "utf8",
  );
  if (!verify("RSA-SHA256", preimage, key, signatureBytes))
    throw new Error("invalid WeChat response signature");
  const body = Buffer.from(response.body, "utf8");
  return {
    timestamp: boundedBytes(Buffer.from(response.timestamp, "ascii"), 20),
    nonce: boundedBytes(Buffer.from(response.nonce, "ascii"), 128),
    body: boundedBytes(body, 1024),
    signature: rsaSignatureLimbs(signatureBytes),
    modulus: keyParams.modulus_limbs,
    redc: keyParams.redc_params_limbs,
    now_seconds: now,
    max_age_seconds: age,
    expected_digest: [...createHash("sha256").update(preimage).digest()],
    expected_appid: boundedBytes(
      Buffer.from(response.expectedAppid, "utf8"),
      128,
    ),
    expected_mchid: boundedBytes(
      Buffer.from(response.expectedMchid, "utf8"),
      128,
    ),
    expected_transaction_id: boundedBytes(
      Buffer.from(response.expectedTransactionId, "utf8"),
      128,
    ),
    expected_openid: boundedBytes(
      Buffer.from(response.expectedOpenid, "utf8"),
      128,
    ),
    expected_attach: boundedBytes(
      Buffer.from(response.expectedAttach, "utf8"),
      128,
    ),
    expected_total: BigInt(response.expectedTotal),
  };
}

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain && process.argv[2] === "import") {
  const response = JSON.parse(await readFile(process.argv[3], "utf8"));
  await writeToml(process.argv[4], responseToInput(response));
} else if (isMain) {
  throw Error("usage: wechatpay-inputs.mjs import response.json output.toml");
}
