#!/usr/bin/env node
import {
  decryptFranceConnectJwe,
  importFranceConnectToken,
  importFranceConnectV2Token,
  type FranceConnectExpected,
  type FranceConnectV2Expected,
} from "./franceconnect.js";
import {
  decryptSingpassJwe,
  importSingpassToken,
  importVerifiedSingpass,
  type SingpassExpected,
} from "./singpass.js";
import { selectVerificationJwk } from "./jws.js";
import { jpkiToml, jpkiCardDigestInfo } from "./jpki.js";
import { readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { importLineToken } from "./line.js";
import { importGovbrToken, type GovbrExpected } from "./govbr.js";
import { importEntraToken } from "./entra.js";
import { importLinkedInToken } from "./linkedin.js";
import { resolve } from "node:path";
import {
  createPersonalSignFromFile,
  createSecretKeyFromEnvironment,
  createSiweFromContextFile,
} from "./ethereum.js";
import {
  importFacebookAccountToken,
  importProviderToken,
  readTokenFile,
  type OidcExpected,
  type Provider,
} from "./oidc.js";
import { importPasskeyAssertion, writeChallenge } from "./passkey.js";
import { importPodFile } from "./zupass.js";
import { chmod, writeFile } from "node:fs/promises";
import { prepareSecureQrInput } from "./aadhaar-secure-qr.js";
import { stringifyToml } from "./toml.js";

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

function expected(options: Options): OidcExpected {
  const now = Number(required(options, "now"));
  if (!Number.isSafeInteger(now) || now < 0)
    throw new Error("--now must be a nonnegative Unix timestamp in seconds");
  return {
    audience: required(options, "audience"),
    subject: required(options, "subject"),
    nonce: required(options, "nonce"),
    now,
  };
}

function usage(): string {
  return `Usage:
  credential-proofs-inputs oidc import --provider <google|apple|telegram|kakao|miargentina|facebook> --token-file FILE --audience AUD --subject SUB --nonce NONCE --now UNIX --out FILE
  credential-proofs-inputs facebook import --token-file FILE --audience APP_ID --subject SUB --nonce ACTION_NONCE --now UNIX --out FILE
  credential-proofs-inputs franceconnect import --platform plus|standard --environment production|integration|sandbox --min-acr 1|2|3 --token-file FILE --audience AUD --subject SUB --nonce NONCE --now UNIX --out FILE.toml [--jwe-key PRIVATE_JWK.json]
  credential-proofs-inputs jpki import --capture-file FILE.json --out FILE.toml [--local-test-root true]
  credential-proofs-inputs jpki challenge --account HEX --action HEX --session HEX --out DIGEST_INFO.bin
  credential-proofs-inputs line import --channel-id CHANNEL --token-file FILE --subject SUB --nonce NONCE --now UNIX --out FILE
  credential-proofs-inputs govbr import --environment production|staging --min-level bronze|silver|gold --token-file FILE --audience AUD --subject SUB --nonce NONCE --now UNIX --out FILE
  credential-proofs-inputs singpass import --environment production|staging --min-assurance 1|2|3 --token-file FILE --audience AUD --subject SUB --nonce NONCE --now UNIX --out FILE [--jwe-key FILE] [--jwks-file TRUSTED_FILE]
  credential-proofs-inputs entra import --tenant GUID --token-file FILE --audience AUD --subject SUB --nonce NONCE --now UNIX --out FILE
  credential-proofs-inputs linkedin import --token-file FILE --audience AUD --subject SUB --now UNIX --out FILE
  credential-proofs-inputs zupass import --pod-file FILE.json --entry NAME --out FILE.toml
  credential-proofs-inputs ethereum personal-sign --message-file FILE --out FILE.toml
  credential-proofs-inputs ethereum siwe --context-file FILE.json --out FILE.toml
  credential-proofs-inputs ethereum secret-key --out FILE.toml
  credential-proofs-inputs passkey challenge --rp-id HOST --origin ORIGIN --out FILE.json
  credential-proofs-inputs aadhaar-secure-qr import --qr-file DECIMAL.txt --certificate ISSUER.pem --out FILE.toml
  credential-proofs-inputs passkey import --assertion-file FILE.json --challenge FIELD --rp-id HOST --origin ORIGIN --public-key 04... --out FILE.toml [--require-uv true|false]

Real OIDC imports fetch JWKS only from the fixed configured provider issuer endpoint.
Ethereum signing reads AUTH_ETHEREUM_PRIVATE_KEY from the process environment.`;
}

async function main(): Promise<void> {
  const { positionals, options } = parseArgs(process.argv.slice(2));
  const [command, action, arg] = positionals;
  if (command === "help" || command === undefined || command === "--help") {
    console.log(usage());
    return;
  }

  if (command === "oidc" && action === "import") {
    const p = provider(required(options, "provider"));
    const token = await readTokenFile(required(options, "token-file"));
    const document = await importProviderToken(p, token, expected(options));
    await writeFile(
      required(options, "out"),
      `${(await import("./toml.js")).stringifyToml(document)}`,
      { mode: 0o600 },
    );
    await chmod(required(options, "out"), 0o600);
    console.log(
      `verified ${p} ID token; wrote bounded Noir input to ${options.out}`,
    );
    return;
  }
  if (command === "facebook" && action === "import") {
    const document = await importFacebookAccountToken(
      await readTokenFile(required(options, "token-file")),
      expected(options),
    );
    const output = required(options, "out");
    await writeFile(
      output,
      (await import("./toml.js")).stringifyToml(document),
      { mode: 0o600, flag: "wx" },
    );
    console.log(
      `verified Facebook Limited Login token; wrote private account input to ${output}`,
    );
    return;
  }
  if (command === "singpass" && action === "import") {
    const environment = required(options, "environment"),
      minimum = Number(required(options, "min-assurance"));
    if (
      (environment !== "production" && environment !== "staging") ||
      ![1, 2, 3].includes(minimum)
    )
      throw new Error("invalid Singpass environment/assurance policy");
    const policy: SingpassExpected = {
      ...expected(options),
      environment,
      minimumAssurance: minimum as 1 | 2 | 3,
    };
    let token = await readTokenFile(required(options, "token-file"));
    if (token.split(".").length === 5)
      token = await decryptSingpassJwe(
        token,
        JSON.parse(await readFile(required(options, "jwe-key"), "utf8")),
      );
    let document;
    if (options["jwks-file"]) {
      const trusted = JSON.parse(await readFile(options["jwks-file"], "utf8")),
        header = JSON.parse(
          Buffer.from(token.split(".")[0]!, "base64url").toString("utf8"),
        );
      document = await importVerifiedSingpass(
        token,
        policy,
        selectVerificationJwk(trusted.keys, {
          kid: header.kid,
          kty: "EC",
          crv: "P-256",
          alg: "ES256",
        }),
      );
    } else document = await importSingpassToken(token, policy);
    await writeFile(
      required(options, "out"),
      (await import("./toml.js")).stringifyToml(document),
      { mode: 0o600, flag: "wx" },
    );
    console.log(
      "verified Singpass inner signature, identity and assurance; wrote private Noir input",
    );
    return;
  }
  if (command === "franceconnect" && action === "import") {
    const environment = required(options, "environment"),
      minimumAcr = Number(required(options, "min-acr"));
    const platform = options.platform ?? "plus";
    if (
      !["plus", "standard"].includes(platform) ||
      ![1, 2, 3].includes(minimumAcr) ||
      (platform === "plus" &&
        (minimumAcr < 2 ||
          !["production", "integration"].includes(environment))) ||
      (platform === "standard" &&
        !["production", "sandbox"].includes(environment))
    )
      throw new Error("invalid FranceConnect platform policy");
    let token = await readTokenFile(required(options, "token-file"));
    if (token.split(".").length === 5)
      token = await decryptFranceConnectJwe(
        token,
        JSON.parse(await readFile(required(options, "jwe-key"), "utf8")),
      );
    const policy = { ...expected(options), environment, minimumAcr };
    const document =
      platform === "plus"
        ? await importFranceConnectToken(token, policy as FranceConnectExpected)
        : await importFranceConnectV2Token(
            token,
            policy as FranceConnectV2Expected,
          );
    await writeFile(
      required(options, "out"),
      (await import("./toml.js")).stringifyToml(document),
      { mode: 0o600, flag: "wx" },
    );
    console.log(
      "verified selected FranceConnect inner signature, identity and assurance; wrote private Noir input",
    );
    return;
  }
  if (command === "jpki" && action === "challenge") {
    await writeFile(
      required(options, "out"),
      jpkiCardDigestInfo(
        required(options, "account"),
        required(options, "action"),
        required(options, "session"),
      ),
      { mode: 0o600, flag: "wx" },
    );
    console.log("wrote action-bound JPKI DigestInfo for on-card signing");
    return;
  }
  if (command === "jpki" && action === "import") {
    const file = resolve(required(options, "capture-file"));
    const value = JSON.parse(await readFile(file, "utf8")) as Record<
      string,
      unknown
    >;
    const bytes = async (name: string, optional = false): Promise<Buffer> => {
      const path = value[name];
      if (optional && path === undefined) return Buffer.alloc(0);
      if (typeof path !== "string" || !path)
        throw new Error(`missing capture path ${name}`);
      return readFile(resolve(dirname(file), path));
    };
    for (const name of ["account", "action", "session"])
      if (typeof value[name] !== "string") throw new Error(`missing ${name}`);
    if (typeof value.now !== "number")
      throw new Error("capture now must be an explicit Unix timestamp");
    const document = jpkiToml({
      root: await bytes("rootFile"),
      certificate: await bytes("certificateFile"),
      responder: await bytes("responderFile", true),
      ocsp: await bytes("ocspFile"),
      holderSignature: await bytes("holderSignatureFile"),
      account: value.account as string,
      action: value.action as string,
      session: value.session as string,
      now: value.now,
      maxOcspAge:
        typeof value.maxOcspAge === "number" ? value.maxOcspAge : undefined,
      localTestRoot: options["local-test-root"] === "true",
    });
    await writeFile(required(options, "out"), document, {
      mode: 0o600,
      flag: "wx",
    });
    console.log(
      "imported JPKI certificate and holder signature; complete purpose and OCSP checks remain in Noir",
    );
    return;
  }
  if (command === "line" && action === "import") {
    const policy = expected({
      ...options,
      audience: required(options, "channel-id"),
    });
    const document = await importLineToken(
      await readTokenFile(required(options, "token-file")),
      policy,
    );
    const output = required(options, "out");
    await writeFile(
      output,
      (await import("./toml.js")).stringifyToml(document),
      { mode: 0o600 },
    );
    await chmod(output, 0o600);
    console.log(
      `verified LINE native ES256 token; wrote Noir input to ${output}`,
    );
    return;
  }
  if (command === "govbr" && action === "import") {
    const environment = required(options, "environment");
    const minimumLevel = required(options, "min-level");
    if (
      (environment !== "production" && environment !== "staging") ||
      !["bronze", "silver", "gold"].includes(minimumLevel)
    )
      throw new Error("invalid gov.br environment or minimum assurance");
    const policy = {
      ...expected(options),
      environment,
      minimumLevel,
    } as GovbrExpected;
    const document = await importGovbrToken(
      await readTokenFile(required(options, "token-file")),
      policy,
    );
    const output = required(options, "out");
    await writeFile(
      output,
      (await import("./toml.js")).stringifyToml(document),
      { mode: 0o600 },
    );
    await chmod(output, 0o600);
    console.log(
      `verified gov.br signed identity and assurance; wrote Noir input to ${output}`,
    );
    return;
  }
  if (command === "entra" && action === "import") {
    const document = await importEntraToken(
      await readTokenFile(required(options, "token-file")),
      { ...expected(options), tenant: required(options, "tenant") },
    );
    const output = required(options, "out");
    await writeFile(
      output,
      (await import("./toml.js")).stringifyToml(document),
      { mode: 0o600 },
    );
    await chmod(output, 0o600);
    console.log(
      `verified tenant-bound Entra token; wrote Noir input to ${output}`,
    );
    return;
  }
  if (command === "aadhaar-secure-qr" && action === "import") {
    // The QR holds personal data: the output is private and never overwritten.
    const prepared = prepareSecureQrInput(
      { qrDecimal: await readFile(required(options, "qr-file"), "utf8") },
      await readFile(required(options, "certificate")),
    );
    if (!prepared.hostSignatureValid)
      throw new Error(
        "Secure QR signature does not verify with the given issuer certificate",
      );
    const output = required(options, "out");
    await writeFile(output, stringifyToml({ input: prepared.input }), {
      mode: 0o600,
      flag: "wx",
    });
    console.log(
      `verified Secure QR signature on the host; wrote private Noir input to ${output}`,
    );
    return;
  }
  if (command === "linkedin" && action === "import") {
    const now = Number(required(options, "now"));
    const document = await importLinkedInToken(
      await readTokenFile(required(options, "token-file")),
      {
        audience: required(options, "audience"),
        subject: required(options, "subject"),
        now,
      },
    );
    const output = required(options, "out");
    await writeFile(
      output,
      (await import("./toml.js")).stringifyToml(document),
      { mode: 0o600, flag: "wx" },
    );
    console.log(
      `verified LinkedIn bearer ID token; wrote private Noir input to ${output}`,
    );
    return;
  }

  if (command === "zupass" && action === "import") {
    await importPodFile(
      required(options, "pod-file"),
      required(options, "entry"),
      required(options, "out"),
    );
    console.log(
      `verified POD signature and entry; wrote bounded Noir input to ${options.out}`,
    );
    return;
  }

  if (command === "ethereum" && action === "personal-sign") {
    await createPersonalSignFromFile(
      required(options, "message-file"),
      required(options, "out"),
    );
    console.log(`wrote EIP-191 Noir input to ${options.out}`);
    return;
  }
  if (command === "ethereum" && action === "siwe") {
    await createSiweFromContextFile(
      required(options, "context-file"),
      required(options, "out"),
    );
    console.log(`wrote canonical SIWE Noir input to ${options.out}`);
    return;
  }
  if (command === "ethereum" && action === "secret-key") {
    await createSecretKeyFromEnvironment(required(options, "out"));
    console.log(`wrote direct secret-key Noir input to ${options.out}`);
    return;
  }
  if (command === "passkey" && action === "challenge") {
    const output = required(options, "out");
    await writeChallenge(
      output,
      required(options, "rp-id"),
      required(options, "origin"),
    );
    console.log(`wrote one-use passkey challenge request to ${output}`);
    return;
  }
  if (command === "passkey" && action === "import") {
    const requireUv = options["require-uv"] ?? "true";
    if (requireUv !== "true" && requireUv !== "false")
      throw new Error("--require-uv must be true or false");
    await importPasskeyAssertion(
      required(options, "assertion-file"),
      required(options, "out"),
      {
        challenge: required(options, "challenge"),
        rpId: required(options, "rp-id"),
        origin: required(options, "origin"),
        publicKeySec1: required(options, "public-key"),
        requireUserVerification: requireUv === "true",
      },
    );
    console.log(
      `checked the passkey assertion as the circuit does (client data, RP ID hash, flags, key, signature) and wrote bounded Noir input to ${options.out}`,
    );
    return;
  }
  throw new Error(usage());
}

main().catch((error) => {
  const message =
    error instanceof Error ? error.message : "unexpected credential tool error";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
