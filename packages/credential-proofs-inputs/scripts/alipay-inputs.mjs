// Node input adapter for the exact raw response bytes. Build credentials first.
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { createPublicKey, createHash, verify } from "node:crypto";
import { rsaKeyToCircuit } from "credential-proofs-inputs/oidc";

import { boundedBytes, writeToml } from "credential-proofs-inputs/toml";


export function responseToInput(response) {
  if (!["v2", "v3"].includes(response.mode))
    throw new Error("mode must be v2 or v3");
  const key = createPublicKey(response.publicKeyPem);
  const params = rsaKeyToCircuit(key.export({ format: "jwk" }));
  if (typeof response.body !== "string")
    throw new Error("body must be the exact raw response string");
  let preimage = response.body;
  if (response.mode === "v3") {
    if (!/^(0|[1-9][0-9]{0,19})$/.test(response.timestamp))
      throw new Error("invalid timestamp");
    if (!/^[!-~]{1,128}$/.test(response.nonce))
      throw new Error("invalid nonce");
    const issued = BigInt(response.timestamp);
    const now = BigInt(response.nowMs),
      age = BigInt(response.maxAgeMs);
    if ([issued, now, age].some((v) => v < 0n || v >= 1n << 64n))
      throw new Error("timestamp/age outside u64");
    if (issued > now || now - issued > age)
      throw new Error("future or stale response");
    preimage = `${response.timestamp}\n${response.nonce}\n${response.body}\n`;
  }
  const signature = Buffer.from(response.signature, "base64");
  if (
    signature.length !== 256 ||
    signature.toString("base64") !== response.signature
  )
    throw new Error("signature must be canonical base64 RSA-2048");
  if (!verify("RSA-SHA256", Buffer.from(preimage), key, signature))
    throw new Error("invalid Alipay response signature");
  let value = BigInt(`0x${signature.toString("hex")}`);
  const limbs = Array.from({ length: 18 }, () => {
    const result = (value & ((1n << 120n) - 1n)).toString();
    value >>= 120n;
    return result;
  });
  const out = {
    signature: limbs,
    modulus: params.modulus_limbs,
    redc: params.redc_params_limbs,
    expected_digest: [...createHash("sha256").update(preimage).digest()],
    body: boundedBytes(Buffer.from(response.body), 512),
  };
  if (response.mode === "v3")
    Object.assign(out, {
      now_ms: BigInt(response.nowMs),
      max_age_ms: BigInt(response.maxAgeMs),
      timestamp: boundedBytes(Buffer.from(response.timestamp), 20),
      nonce: boundedBytes(Buffer.from(response.nonce), 128),
      expected_user_id: boundedBytes(Buffer.from(response.expectedUserId), 32),
    });
  return out;
}

const isMain =
  process.argv[1] &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain && process.argv[2] === "import") {
  const response = JSON.parse(await readFile(process.argv[3], "utf8"));
  await writeToml(process.argv[4], responseToInput(response));
}
