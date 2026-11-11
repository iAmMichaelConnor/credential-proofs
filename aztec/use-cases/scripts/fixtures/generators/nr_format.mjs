// Formats generated Noir source with the Aztec 6.0.0 `nargo fmt` and the Aztec
// workspace's aztec/noirfmt.toml, so a generated src/fixture.nr is already what
// `nargo fmt` writes. Running `nargo fmt` on the workspace then changes nothing,
// and the fixture manifest hash (taken over the formatted text) stays valid. The
// layout is the formatter's, not a copy of its rules. Mirrors nr_format.py.
import { execFileSync, spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";

// The nargo of Aztec 6.0.0.
export const NARGO_IDENTITY =
  "1.0.0-rc.3+5a7ee9bf5ed8973076df7bb0d2b723024db09ae7";

const config = fileURLToPath(
  new URL("../../../../noirfmt.toml", import.meta.url),
);
let checked = null;

function onPath(name) {
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    if (dir && existsSync(join(dir, name))) return join(dir, name);
  }
  return null;
}

/** The Aztec 6.0.0 nargo: $NARGO, else `aztec-nargo` or `nargo` on PATH. */
function nargo() {
  if (checked) return checked;
  const path = process.env.NARGO || onPath("aztec-nargo") || onPath("nargo");
  if (!path || !existsSync(path))
    throw new Error("nargo not found; set NARGO to the nargo of Aztec 6.0.0");
  const out = execFileSync(path, ["--version"], { encoding: "utf8" });
  if (!out.includes(`noirc version = ${NARGO_IDENTITY}`))
    throw new Error(`${path} is not nargo ${NARGO_IDENTITY}`);
  checked = path;
  return path;
}

/** `source` as `nargo fmt` lays it out. */
export function formatNoir(source) {
  const directory = mkdtempSync(join(tmpdir(), "uc-nr-format-"));
  try {
    mkdirSync(join(directory, "src"));
    writeFileSync(
      join(directory, "Nargo.toml"),
      '[package]\nname = "uc_nr_format"\ntype = "lib"\nauthors = [""]\n\n[dependencies]\n',
    );
    copyFileSync(config, join(directory, "noirfmt.toml"));
    writeFileSync(join(directory, "src/lib.nr"), source);
    const run = spawnSync(nargo(), ["fmt"], {
      cwd: directory,
      encoding: "utf8",
    });
    // This nargo exits 0 and leaves the file unchanged on a parse error, so
    // any output on stderr is a failure, except the notice that another nargo
    // holds the git dependency cache lock.
    const stderr = run.stderr
      .split("\n")
      .filter((line) => !line.startsWith("Waiting for lock on git dependencies cache"))
      .join("\n");
    if (run.error || run.status !== 0 || stderr.trim())
      throw new Error(
        `nargo fmt failed: ${(run.error?.message ?? (run.stderr || run.stdout)).slice(0, 500)}`,
      );
    return readFileSync(join(directory, "src/lib.nr"), "utf8");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}
