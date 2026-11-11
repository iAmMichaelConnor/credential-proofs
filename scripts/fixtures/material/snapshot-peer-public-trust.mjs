// Read-only chain provenance for published adjacent Peer deployments, NOT automatic V4 trust enrollment.
import { writeFile } from "node:fs/promises";
import {
  createPublicClient,
  http,
  toFunctionSelector,
  decodeAbiParameters,
  parseAbiParameters,
  keccak256,
} from "viem";
const rpc = "https://mainnet.base.org";
const client = createPublicClient({
  transport: http(rpc, { timeout: 10000, retryCount: 0 }),
});
const chainId = await client.getChainId();
if (chainId !== 8453) throw Error("Unexpected chain");
const block = await client.getBlock({ blockTag: "latest" });
const blockHex = "0x" + block.number.toString(16);
const results = [];
for (const [name, address, method, type] of [
  [
    "SimpleAttestationVerifier",
    "0xED6C0C34c3964D239e7a315C55E620fafE5Ae3AC",
    "witness()",
    "address",
  ],
  [
    "MultiAttestationVerifier",
    "0x9Fe920b24e50e6a6362BA71a1BeB502A99c402d5",
    "witnesses()",
    "address[]",
  ],
  [
    "MultiAttestationVerifier",
    "0x9Fe920b24e50e6a6362BA71a1BeB502A99c402d5",
    "requiredSignatures()",
    "uint256",
  ],
  [
    "UnifiedPaymentVerifierV3",
    "0xC6F4a193576C60892a47e111Bb5706c30162502B",
    "attestationVerifier()",
    "address",
  ],
]) {
  const data = toFunctionSelector(method);
  const raw = await client.request({
    method: "eth_call",
    params: [{ to: address, data }, blockHex],
  });
  const code = await client.getBytecode({ address, blockNumber: block.number });
  if (!code || code === "0x") throw Error("No contract code");
  results.push({
    name,
    address,
    method,
    callData: data,
    rawReturn: raw,
    decoded: decodeAbiParameters(parseAbiParameters(type), raw)[0],
    codeKeccak256: keccak256(code),
  });
}
await writeFile(
  new URL(
    "../../../fixtures/material/peer_v4/provider-public/chain-snapshot.json",
    import.meta.url,
  ),
  JSON.stringify(
    {
      retrievedAt: new Date().toISOString(),
      rpc,
      chainId,
      blockNumber: block.number,
      blockHash: block.hash,
      results,
      authentication:
        "HTTPS to official Base RPC; pinned block number/hash and exact eth_call bytes retained. Not an independently verified light-client/storage proof.",
      trustLimit:
        "These are published Simple/Multi attestor and V3 deployments adjacent to the implemented V4 source. No matching V4 deployment or signed V4 payment has been authenticated; do not use these addresses as V4 domain/policy automatically.",
    },
    (_, x) => (typeof x === "bigint" ? x.toString() : x),
    2,
  ) + "\n",
);
console.log(
  "Recorded read-only Base registry snapshot; V4 enrollment remains separate.",
);
