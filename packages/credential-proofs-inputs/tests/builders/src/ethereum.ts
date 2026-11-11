/** Public example private key; test fixtures only. */
import { createPersonalSign, createSiwe, createSecretKeyWitness, type SiweContext } from "credential-proofs-inputs/ethereum";
import { writeToml } from "credential-proofs-inputs/toml";
const SYNTHETIC_PRIVATE_KEY = `0x${"0".repeat(63)}1`;
const SECP256K1_ORDER = 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_fffe_baaedce6_af48a03b_bfd25e8c_d0364141n;
export async function generateSyntheticEthereumFixtures(
  directory: string,
): Promise<void> {
  const context: SiweContext = {
    domain: "example.com",
    uri: "https://example.com/login",
    chainId: 1n,
    nonce: "32891756",
    issuedAt: "2026-10-21T12:00:00Z",
    expirationTime: "2026-10-21T12:05:00Z",
    currentTime: "2026-10-21T12:02:00Z",
  };
  await writeToml(
    `${directory}/ethereum-personal-sign.synthetic.toml`,
    await createPersonalSign("hello", SYNTHETIC_PRIVATE_KEY),
  );
  await writeToml(
    `${directory}/ethereum-siwe.synthetic.toml`,
    await createSiwe(SYNTHETIC_PRIVATE_KEY, context),
  );
  await writeToml(
    `${directory}/ethereum-secret-key.synthetic.toml`,
    createSecretKeyWitness(SYNTHETIC_PRIVATE_KEY),
  );
  await writeToml(
    `${directory}/ethereum-secret-key-n-minus-one.synthetic.toml`,
    createSecretKeyWitness(
      `0x${(SECP256K1_ORDER - 1n).toString(16).padStart(64, "0")}`,
    ),
  );
}

