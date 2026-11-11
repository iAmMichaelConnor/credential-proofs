// Shared steps of the World ID gate fixture generators (world_id_foundation.mjs for
// World ID 3, world_id4_foundation.mjs for World ID 4). Each saved proof's signal binds
// (chain id, version, gate address, action, beneficiary, nonce). The tests run the
// gate's claim in a TXE private context at the generator's fixed gate address, where
// the chain id and version are 1, so no compiled gate is involved.
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parseArgs } from "node:util";
import { spawnSync } from "node:child_process";

export const ROOT = path.resolve(import.meta.dirname, "../..");

export function options() {
  return parseArgs({
    options: {
      check: { type: "boolean" },
      "foundation-proof": { type: "boolean" },
      "work-dir": { type: "string" },
    },
  }).values;
}

// TXE's chain id and protocol version, and the beneficiary and nonce of the saved claims.
export const CHAIN_ID = 1n,
  VERSION = 1n,
  BENEFICIARY = 13n,
  NONCE = 17n;

// The signal context [chain id, version, gate address, action, beneficiary, nonce].
export const claimContext = (address, action) => [CHAIN_ID, VERSION, address, action, BENEFICIARY, NONCE];

export const stringify = (value) =>
  JSON.stringify(value, (_, v) => (typeof v === "bigint" ? String(v) : v), 2) + "\n";

const noir = (value) =>
  Array.isArray(value) ? "[" + value.map(noir).join(", ") + "]" : String(value);

// One `pub global` per entry: [name, Noir type, value], formatted by `nargo fmt`
// ($NARGO, else nargo on PATH; nargo 1.0.0-rc.3, the version Aztec 6.0.0 ships) with the
// Aztec workspace's settings.
export async function renderFixture(header, globals) {
  let source = header;
  for (const [name, type, value] of globals)
    source += `pub global ${name}: ${type} = ${noir(value)};\n`;
  const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "world-id-fmt-"));
  try {
    await fs.mkdir(path.join(scratch, "src"));
    await fs.writeFile(
      path.join(scratch, "Nargo.toml"),
      '[package]\nname = "fmt_scratch"\ntype = "lib"\nauthors = [""]\n',
    );
    await fs.copyFile(path.join(ROOT, "aztec/noirfmt.toml"), path.join(scratch, "noirfmt.toml"));
    await fs.writeFile(path.join(scratch, "src/lib.nr"), source);
    const run = spawnSync(process.env.NARGO ?? "nargo", ["fmt"], { cwd: scratch, encoding: "utf8" });
    if (run.error || run.status !== 0)
      throw Error(`nargo fmt failed: ${run.error ?? run.stderr}`);
    return await fs.readFile(path.join(scratch, "src/lib.nr"), "utf8");
  } finally {
    await fs.rm(scratch, { recursive: true, force: true });
  }
}

// Writes `content`, or with `check` fails if the file differs from it.
export async function writeOrCheck(file, content, check) {
  const current = await fs.readFile(file, "utf8").catch(() => null);
  const relative = path.relative(ROOT, file);
  if (current === content) return;
  if (check) throw Error(`${relative} is stale; rerun the generator without --check`);
  await fs.writeFile(file, content);
  console.error(`wrote ${relative}`);
}

export function assertBound(saved, context, script) {
  const want = saved.context.map(String),
    have = context.map(String);
  if (JSON.stringify(want) === JSON.stringify(have)) return;
  throw Error(
    `The saved proof is bound to context ${JSON.stringify(want)}, the generator expects ` +
      `${JSON.stringify(have)}: create a new proof with \`node ${script} --foundation-proof ` +
      `--work-dir <dir>\` (see CONTRIBUTING.md).`,
  );
}
