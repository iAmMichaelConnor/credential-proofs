#!/usr/bin/env node
/** Fixture generation only: uses intentionally public signing keys. */
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { writeOidcFixture } from "./oidc.js";
import { createSyntheticPod } from "./zupass.js";
import { generateSyntheticEthereumFixtures } from "./ethereum.js";
import type { Provider, OidcExpected } from "credential-proofs-inputs/oidc";
type Options = Record<string, string>;

function parseArgs(args: string[]): {
  positionals: string[];
  options: Options;
} {
  const positionals: string[] = [];
  const options: Options = {};
  for (let i = 0; i < args.length; i++) {
    const item = args[i]!;
    if (!item.startsWith("--")) {
      positionals.push(item);
      continue;
    }
    const key = item.slice(2);
    if (!key) throw new Error("empty option name");
    const next = args[i + 1];
    if (next === undefined || next.startsWith("--")) options[key] = "true";
    else {
      options[key] = next;
      i++;
    }
  }
  return { positionals, options };
}

function required(options: Options, key: string): string {
  const value = options[key];
  if (value === undefined || value === "")
    throw new Error(`missing required --${key}`);
  return value;
}

function provider(value: string): Provider {
  if (
    value !== "google" &&
    value !== "apple" &&
    value !== "telegram" &&
    value !== "kakao" &&
    value !== "miargentina" &&
    value !== "facebook"
  )
    throw new Error(
      "provider must be google, apple, telegram, kakao, miargentina or facebook",
    );
  return value;
}

function expected(options: Options, defaults = false): OidcExpected {
  const number = defaults
    ? (options.now ?? "1900000000")
    : required(options, "now");
  const now = Number(number);
  if (!Number.isSafeInteger(now) || now < 0)
    throw new Error("--now must be a nonnegative Unix timestamp in seconds");
  return {
    audience: defaults
      ? (options.audience ??
        "synthetic-client-id-0123456789abcdefghijklmnopqrstuvwxyz-0123456789")
      : required(options, "audience"),
    subject: defaults
      ? (options.subject ?? "synthetic-user")
      : required(options, "subject"),
    nonce: defaults
      ? (options.nonce ?? "test-nonce")
      : required(options, "nonce"),
    now,
  };
}


async function main() {
 const { positionals, options } = parseArgs(process.argv.slice(2));
 const [command, action, arg] = positionals;
  if (command === "synthetic" && action === "oidc") {
    const p = provider(arg ?? "");
    const claims = expected(options, true);
    if (p === "telegram" && options.audience === undefined)
      claims.audience = "123456789";
    await writeOidcFixture(required(options, "out"), p, claims);
    console.log(`wrote synthetic ${p} OIDC Prover.toml: ${options.out}`);
    return;
  }
  if (command === "synthetic" && action === "pod") {
    const output = required(options, "out");
    await createSyntheticPod(output, options.entry ?? "event");
    console.log(`wrote synthetic Zupass POD fixture: ${output}`);
    return;
  }
  if (command === "synthetic" && action === "ethereum") {
    const outputDir = resolve(required(options, "out-dir"));
    await mkdir(outputDir, { recursive: true });
    await generateSyntheticEthereumFixtures(outputDir);
    console.log(
      `wrote public-key/test-message Ethereum fixtures to ${outputDir}`,
    );
    return;
  }
 throw Error("Usage: fixture-builder synthetic oidc PROVIDER | synthetic pod | synthetic ethereum, with explicit --out or --out-dir");
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
