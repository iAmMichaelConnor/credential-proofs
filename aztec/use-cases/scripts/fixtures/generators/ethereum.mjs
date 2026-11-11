// Writes src/fixture.nr and fixtures/manifest.json of the Ethereum accounts:
// account-authorisation/{ethereum_personal_sign,ethereum_siwe,ethereum_secret_key}.
//
// node scripts/fixtures/generators/ethereum.mjs --instance account-authorisation/<scheme> --action <field hex>
//
// personal_sign signs, with EIP-191, the 32 big-endian bytes of the approval
// digest Poseidon2([APPROVAL_DOMAIN, action, deadline]); SIWE signs an
// EIP-4361 message whose nonce is the action's lowercase hex; the secret-key
// account takes the key itself. The secp256k1 keys are derived from public
// seeds. Needs `npm ci` in aztec/use-cases (viem, @zkpassport/poseidon2).
import {
  array,
  credentials,
  options,
  padded,
  require,
  seed,
  write,
} from "./account.mjs";

const NOW = 4000000000;
const DOMAIN = "example.com";
const URI = "https://example.com/login";
const CHAIN_ID = 1n;
// The personal_sign approval deadline: the last second of inclusion.
const DEADLINE = NOW + 300;
const APPROVAL_TAG = "MIKE_AUTH_ETHEREUM_PERSONAL_SIGN_V1";

const values = options();
const scheme = values.instance.split("/")[1];
const contracts = {
  ethereum_personal_sign: "EthereumSignatureAccount",
  ethereum_siwe: "EthereumSiweAccount",
  ethereum_secret_key: "EthereumSecretKeyAccount",
};
const contract = contracts[scheme];
if (!contract) throw new Error(`${values.instance}: not an Ethereum account`);
const { privateKeyToAccount } = require("viem/accounts");
const key = `0x${seed("ethereum account key v1").toString("hex")}`;
const otherKey = `0x${seed("ethereum account other key v1").toString("hex")}`;
const account = privateKeyToAccount(key);
const other = privateKeyToAccount(otherKey);
const hex = (value, length) =>
  Buffer.from(value.replace(/^0x/, ""), "hex").subarray(0, length);
const bytes = (buffer, indent = "        ") => array([...buffer], indent);
const point = (a) => hex(a.publicKey, 65);
const utc = (seconds) =>
  new Date(seconds * 1000).toISOString().replace(".000Z", "Z");

let fields;
let claims;
let extra = "";
if (scheme === "ethereum_secret_key") {
  fields = `        secret_key: ${bytes(hex(key, 32))},`;
  extra = `/// Another secret key (from a public seed); its address is not the policy's.
pub global OTHER_SECRET_KEY: [u8; 32] = ${bytes(hex(otherKey, 32), "")};
`;
  claims = { address: account.address };
} else {
  let message;
  let times = "";
  if (scheme === "ethereum_personal_sign") {
    const { poseidon2Hash } = await import("@zkpassport/poseidon2");
    const poseidon = async (fields) => BigInt(poseidon2Hash(fields.map(BigInt)));
    // poseidon2_hash_bytes(tag): 31-byte little-endian chunks, as aztec-nr packs them.
    const tag = Buffer.from(APPROVAL_TAG);
    const chunks = [];
    for (let i = 0; i < tag.length; i += 31) {
      chunks.push(
        BigInt(
          `0x${Buffer.from(tag.subarray(i, i + 31))
            .reverse()
            .toString("hex")}`,
        ),
      );
    }
    const domain = await poseidon(chunks);
    const digest = (
      await poseidon([domain, BigInt(`0x${values.action}`), BigInt(DEADLINE)])
    )
      .toString(16)
      .padStart(64, "0");
    message = { raw: Buffer.from(digest, "hex") };
    claims = {
      address: account.address,
      action: `0x${values.action}`,
      deadline: DEADLINE,
      approval_domain: `poseidon2_hash_bytes("${APPROVAL_TAG}")`,
      message: `0x${digest}`,
    };
    times = `
        deadline: ${DEADLINE},`;
    extra = `/// A Unix time before the deadline, and the signed deadline (the last second of inclusion).
pub global NOW: u64 = ${NOW};
pub global DEADLINE: u64 = ${DEADLINE};
`;
  } else {
    const [issued, expires, current] = [
      utc(NOW - 60),
      utc(NOW + 300),
      utc(NOW),
    ];
    message = `${DOMAIN} wants you to sign in with your Ethereum account:\n${account.address}\n\n\nURI: ${URI}\nVersion: 1\nChain ID: ${CHAIN_ID}\nNonce: ${values.action}\nIssued At: ${issued}\nExpiration Time: ${expires}`;
    times = `
        issued_at: ${bytes(Buffer.from(issued))},
        expiration_time: ${bytes(Buffer.from(expires))},
        current_time: ${bytes(Buffer.from(current))},`;
    claims = { address: account.address, message };
    extra = `/// The anchor block time that \`current_time\` names, and the signed expiry.
pub global NOW: u64 = ${NOW};
pub global EXPIRY: u64 = ${NOW + 300};
`;
  }
  const signature = hex(await account.signMessage({ message }), 64);
  fields = `        public_key_x: ${bytes(point(account).subarray(1, 33))},
        public_key_y: ${bytes(point(account).subarray(33, 65))},
        signature: ${bytes(signature)},${times}`;
  extra += `/// Another secp256k1 public key (from a public seed). Nothing is signed under it.
pub global OTHER_KEY_X: [u8; 32] = ${bytes(point(other).subarray(1, 33), "")};
pub global OTHER_KEY_Y: [u8; 32] = ${bytes(point(other).subarray(33, 65), "")};
`;
}
const policy =
  scheme === "ethereum_siwe"
    ? `            address: ${bytes(hex(account.address, 20), "            ")},
            domain: ${padded(Buffer.from(DOMAIN), 128, "            ")},
            domain_len: ${DOMAIN.length},
            uri: ${padded(Buffer.from(URI), 128, "            ")},
            uri_len: ${URI.length},
            chain_id: ${CHAIN_ID},`
    : `            address: ${bytes(hex(account.address, 20), "            ")},`;

const fixture = `//! Generated by scripts/fixtures/generators/ethereum.mjs; see fixtures/manifest.json. Do not edit.
//! Synthetic secp256k1 keys derived from public seeds. They are not wallet
//! keys; anyone can sign with them.
use crate::${contract}::{AuthInput, AuthPolicy};

/// The action hash that the credential binds.
pub global ACTION: Field = 0x${values.action};
/// The address of the other key.
pub global OTHER_ADDRESS: [u8; 20] = ${bytes(hex(other.address, 20), "")};
${extra}
pub fn auth() -> AuthInput {
    AuthInput {
        policy: AuthPolicy {
${policy}
        },
${fields}
    }
}
`;

await write({
  instance: values.instance,
  generator: "ethereum.mjs",
  argv: ["--action", values.action],
  library:
    scheme === "ethereum_personal_sign"
      ? `aztec/use-cases dependencies viem privateKeyToAccount (EIP-191 signMessage, low s); @zkpassport/poseidon2 Poseidon2 (approval digest)`
      : `aztec/use-cases dependencies viem privateKeyToAccount (EIP-191 signMessage, low s)`,
  inputs: [],
  keyProvenance:
    "secp256k1 keys sha256('credential-proofs synthetic ethereum account key v1') and '... other key v1'; public seeds, not wallet keys. Anyone can sign with them.",
  claims,
  fixture,
});
