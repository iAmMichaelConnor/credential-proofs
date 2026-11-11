/** Public POD signing key; test fixtures only. */
import { createRequire } from "node:module";
import { writeFile } from "node:fs/promises";
import { podToCircuitWitness } from "credential-proofs-inputs/zupass";
import { writeToml } from "credential-proofs-inputs/toml";
const { POD } = createRequire(import.meta.url)("@pcd/pod") as typeof import("@pcd/pod");
const SYNTHETIC_KEY = "0001020304050607080900010203040506070809000102030405060708090001";
export async function createSyntheticPod(
  outputPath: string,
  entryName: string,
): Promise<void> {
  const pod = POD.sign(
    { event: { type: "int", value: 42n }, owner: { type: "int", value: 7n } },
    SYNTHETIC_KEY,
  );
  const json = pod.toJSON();
  const witness = podToCircuitWitness(json, entryName);
  // Keep this directly importable by `zupass import`; provenance is documented
  // in the package README rather than wrapping the POD in a non-standard shape.
  await writeFile(
    `${outputPath}.pod.json`,
    `${JSON.stringify(json, null, 2)}\n`,
    { mode: 0o600 },
  );
  await writeToml(outputPath, witness);
}

