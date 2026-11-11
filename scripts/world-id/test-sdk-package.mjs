// Packed-consumer check: packs credential-proofs-world-id and the installed groth16-verifier-hints
// peer (scripts/world-id/install-groth16-verifier-hints.sh), installs both tarballs in a scratch
// consumer, type-checks a TypeScript import of every public subpath and runs it.
// Run `npm run build -w credential-proofs-world-id` first.
import {
  mkdtemp,
  mkdir,
  readFile,
  writeFile,
  stat,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
const sdk = fileURLToPath(new URL("../../packages/credential-proofs-world-id/", import.meta.url));
// The installed package directory, found as Node resolves it from packages/credential-proofs-world-id.
async function installed(name) {
  for (let dir = sdk; ; dir = dirname(dir)) {
    const candidate = join(dir, "node_modules", name);
    if (await stat(join(candidate, "package.json")).catch(() => null)) return candidate;
    if (dirname(dir) === dir) return null;
  }
}
const hints = await installed("groth16-verifier-hints");
if (!hints)
  throw Error(
    "Install the groth16-verifier-hints peer first: scripts/world-id/install-groth16-verifier-hints.sh",
  );
const tsc = join(await installed("typescript"), "bin/tsc");
function run(cmd, args, cwd) {
  const r = spawnSync(cmd, args, {
    cwd,
    encoding: "utf8",
    timeout: 120000,
    maxBuffer: 8 * 1024 * 1024,
  });
  if (r.error) throw r.error;
  if (r.status !== 0)
    throw Error(`${cmd} ${args.join(" ")} failed: ${r.stderr}\n${r.stdout}`);
  return r.stdout;
}
const notices = new Map();
for (const name of ["LICENSE"])
  notices.set(name, await readFile(join(sdk, name)));
const temp = await mkdtemp(join(tmpdir(), "world-sdk-consumer-"));
try {
  const packs = [hints, sdk].map(
    (cwd) =>
      JSON.parse(
        run(
          "npm",
          ["pack", "--ignore-scripts", "--json", "--pack-destination", temp],
          cwd,
        ),
      )[0],
  );
  const consumer = join(temp, "consumer");
  await mkdir(consumer);
  await writeFile(
    join(consumer, "package.json"),
    JSON.stringify({ private: true, type: "module" }),
  );
  run(
    "npm",
    [
      "install",
      "--prefer-offline",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      ...packs.map((p) => join(temp, p.filename)),
    ],
    consumer,
  );
  run(
    "npm",
    [
      "install",
      "--prefer-offline",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--save-dev",
      "@types/node@24.0.0",
    ],
    consumer,
  );
  const source = `import {integer} from 'credential-proofs-world-id';\nimport {prepareWorldIdGroth16,prepareRuntimeKey} from 'credential-proofs-world-id/groth16';\nif(integer('0')!==0n)throw Error('Canonical zero changed');\nconst functions=[prepareWorldIdGroth16,prepareRuntimeKey];\nif(functions.some(value=>typeof value!=='function'))throw Error('Missing public export');\nconsole.log(JSON.stringify({exports: functions.length,zero: integer('0').toString()}));\n`;
  await writeFile(join(consumer, "consumer.ts"), source);
  run(
    process.execPath,
    [
      tsc,
      "consumer.ts",
      "--strict",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      "--target",
      "ES2022",
      "--lib",
      "ES2022",
      "--types",
      "node",
    ],
    consumer,
  );
  const imports = JSON.parse(run(process.execPath, ["consumer.js"], consumer));
  for (const name of ["credential-proofs-world-id", "groth16-verifier-hints"]) {
    const installed = join(consumer, "node_modules", name);
    const metadata = JSON.parse(
      await readFile(join(installed, "package.json"), "utf8"),
    );
    if (metadata.license !== "Apache-2.0")
      throw Error(`${name}: missing Apache-2.0 license metadata`);
    await stat(join(installed, "LICENSE"));
  }
  for (const [name, expected] of notices) {
    const distributed = await readFile(
      join(consumer, "node_modules/credential-proofs-world-id", name),
    );
    if (!expected.equals(distributed))
      throw Error(`Packed SDK ${name} differs from packages/credential-proofs-world-id/${name}`);
  }
  console.log(
    JSON.stringify({
      status: "PASS",
      scope:
        "Two local tarballs, every public subpath, the real Groth16 peer, TypeScript compile and Node import; no proof",
      packages: packs.map((p) => ({ name: p.name, files: p.files.length })),
      imports,
      published: false,
    }),
  );
} finally {
  await rm(temp, { recursive: true, force: true });
}
