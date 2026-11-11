// Fixed official sources; no arbitrary URL supplied by tokens or callers.
// Refreshes the JWKS fixture; review kid/SPKI changes and update the material manifest hash and keys.
import { mkdir, writeFile } from "node:fs/promises";
import { describePublicJwks } from "credential-proofs-inputs/trust-material";

import { publicOidcSources } from "credential-proofs-inputs/provider-config";

const sources = publicOidcSources;
for (const provider of process.argv.slice(2)) {
  const source = sources[provider];
  if (!source)
    throw Error("Unknown configured public trust source " + provider);
  const { jwks: url, issuer } = source;
  const response = await fetch(url, {
    redirect: "error",
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw Error("HTTP " + response.status);
  const raw = await response.text();
  const fetchedAt = new Date().toISOString();
  const report = describePublicJwks(
    raw,
    {
      provider,
      url,
      issuer,
      purpose:
        "Public identity-provider ID-token signature verification key. Account policy must independently enroll the exact key and issuer/audience/subject.",
      rotation:
        "Refresh only this fixed official endpoint; review kid/SPKI changes and explicitly update enrolled account policy. Existing key snapshot is not a perpetual trust guarantee.",
    },
    fetchedAt,
  );
  const output = new URL(
    `../../../fixtures/data/public-trust/${provider}/`,
    import.meta.url,
  );
  await mkdir(output, { recursive: true });
  await writeFile(new URL("jwks.json", output), raw);
  console.log(JSON.stringify(report, null, 2));
}
