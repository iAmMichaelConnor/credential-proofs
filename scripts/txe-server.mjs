// Starts the TXE of the installed Aztec CLI, as `aztec start --txe --port <port>` does, but with an HTTP
// keep-alive timeout of one hour instead of Node's 5 s default.
//
// The TXE disposes a test's session when its socket closes. Some tests run unconstrained code for longer than
// 5 s between two oracle calls (heavy hashing or curve arithmetic in a private context), and with the default
// timeout the server closes the idle socket, so the next oracle call finds no session (errors such as "Expected
// to be in state other than TOP_LEVEL" or "Private oracles not available with the current handler").
//
// Usage: node scripts/txe-server.mjs <port>   (finds the Aztec CLI's packages from the `aztec` on PATH, or
// $AZTEC_HOME)
import { execFileSync } from "node:child_process";
import { readFileSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

const port = Number(process.argv[2]);
if (!Number.isInteger(port) || port <= 0) throw new Error("Usage: node scripts/txe-server.mjs <port>");
const home =
  process.env.AZTEC_HOME ??
  join(dirname(realpathSync(execFileSync("which", ["aztec"], { encoding: "utf8" }).trim())), "..");
// `<package>/<subpath>` through the package's ESM `exports`.
const load = (name) => {
  const [scope, base, ...rest] = name.split("/");
  const directory = join(home, "node_modules", scope, base);
  const entry = JSON.parse(readFileSync(join(directory, "package.json"), "utf8")).exports[`./${rest.join("/")}`];
  return import(pathToFileURL(join(directory, typeof entry === "string" ? entry : entry.import)).href);
};

const { createLogger } = await load("@aztec-labs/foundation/log");
const { startHttpRpcServer } = await load("@aztec-labs/foundation/json-rpc/server");
const { createTXERpcServer } = await load("@aztec-labs/txe/server");

const logger = createLogger("txe");
const server = await startHttpRpcServer(await createTXERpcServer(logger), {
  port,
  timeoutMs: 5 * 60 * 1000,
  keepAliveTimeoutMs: 60 * 60 * 1000,
  headersTimeoutMs: 60 * 60 * 1000 + 1000,
});
logger.info(`TXE listening on port ${server.port}`);
