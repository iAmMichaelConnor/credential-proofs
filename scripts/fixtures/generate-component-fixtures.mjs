/** Public, deterministic component scenarios; no provider capture, keys or proofs. */
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { boundedBytes, stringifyToml } from "credential-proofs-inputs/toml";

import { localP256Key, signLocalP256 } from "./lib/local-p256-key.mjs";
import { responseToInput } from "../../packages/credential-proofs-inputs/scripts/alipay-inputs.mjs";

const auth = fileURLToPath(new URL("../../", import.meta.url));
// Preserve the decoder's existing opaque ASCII input, hence its exact public return.
export const encodedSample =
  "_J07rJjes6VWWY3Dtyk4XdDlSpJ5K93uIIZ7b2bFtk8E-b_Dg8-lhldvFgWEfEoVzcncfHBtb3GpA6_s7WIC0Q";
// Duplicate ignored idp values and wrong ignored azp are intentional in direct mode.
export const jsonSample =
  '{"iss":"issuer","aud":"client","sub":"subject","nonce":"nonce","exp":2000000000,"iat":1900000000,"idp":null,"idp":{},"azp":"wrong"}';
// The known-answer input directory of each scenario.
const KAT_NAMES = {
  auth_base64url: "base64url",
  auth_json_member_batch: "json_member_batch",
  auth_es256: "es256_jwt",
  auth_es256_component: "p256_black_box",
  rsa_signature_compat: "rsa_signature_compat",
};
const p256Order =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export async function componentFixtures() {
  const header = Buffer.from(
    JSON.stringify({ alg: "ES256", typ: "JWT" }),
  ).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      iss: "issuer",
      aud: "client",
      sub: "user",
      nonce: "nonce",
      exp: 2000000000,
      nbf: 1800000000,
    }),
  ).toString("base64url");
  const message = Buffer.from(header + "." + payload);
  const signature = Buffer.from(signLocalP256(42, message));
  const lowSignature = Buffer.from(signature);
  const s = BigInt("0x" + signature.subarray(32).toString("hex"));
  if (s > p256Order / 2n)
    Buffer.from((p256Order - s).toString(16).padStart(64, "0"), "hex").copy(
      lowSignature,
      32,
    );
  const key = localP256Key(42).key;
  const parsed = JSON.parse(jsonSample);
  const names = ["iss", "aud", "sub", "nonce", "exp", "iat", "nbf", "idp"];
  const present = names.map(
    (name) => name !== "idp" && Object.hasOwn(parsed, name),
  );
  const expected = names.map((name, i) => {
    if (!present[i]) return { start: 0, end: 0, kind: 0 };
    const start = jsonSample.indexOf('"' + name + '":') + name.length + 3;
    return {
      start,
      end: start + JSON.stringify(parsed[name]).length,
      kind: jsonSample.charCodeAt(start),
    };
  });
  const response = JSON.parse(
    await readFile(
      new URL(
        "../../fixtures/data/alipay/upstream-v2-file-upload.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  return {
    auth_base64url: { encoded: boundedBytes(Buffer.from(encodedSample), 344) },
    auth_json_member_batch: {
      brokered: false,
      present,
      document: boundedBytes(Buffer.from(jsonSample), 512),
      expected,
    },
    auth_es256: {
      now: "1900000000",
      key,
      token: {
        header_b64: boundedBytes(Buffer.from(header), 64),
        payload_b64: boundedBytes(Buffer.from(payload), 128),
        signature_b64: boundedBytes(
          Buffer.from(signature.toString("base64url")),
          86,
        ),
      },
    },
    auth_es256_component: {
      x: key.public_key_x,
      y: key.public_key_y,
      signature: [...lowSignature],
      digest: [...createHash("sha256").update(message).digest()],
    },
    rsa_signature_compat: responseToInput(response),
  };
}

if (
  process.argv[1] &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url
) {
  if (process.argv.length > 3)
    throw new Error(
      "usage: generate-component-fixtures.mjs [output-repository-directory]",
    );
  const destination = resolve(process.argv[2] ?? auth);
  for (const [name, document] of Object.entries(await componentFixtures())) {
    const folder = resolve(destination, "target/kat", KAT_NAMES[name]);
    await mkdir(folder, { recursive: true });
    const { expected, ...fields } = document;
    let text = stringifyToml(fields);
    if (expected)
      for (const span of expected)
        text += "\n[[expected]]\n" + stringifyToml(span);
    await writeFile(resolve(folder, "Prover.toml"), text);
  }
}
