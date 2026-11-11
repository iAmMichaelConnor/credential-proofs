// Public selector provenance only. Does not collect or authenticate private email.
import { writeFile, mkdir } from "node:fs/promises";
import { createPublicKey, createHash } from "node:crypto";
import { Resolver } from "node:dns/promises";
const name = "s2048._domainkey.yahoo.com";
const output = new URL("../../../fixtures/material/zkemail/provider-public/", import.meta.url);
await mkdir(output, { recursive: true });
const sha = (b) => createHash("sha256").update(b).digest("hex");
const sources = [];
let joined;
for (const [label, url, headers] of [
  ["google", `https://dns.google/resolve?name=${name}&type=TXT&do=true`, {}],
  [
    "cloudflare",
    `https://cloudflare-dns.com/dns-query?name=${name}&type=TXT&do=true`,
    { accept: "application/dns-json" },
  ],
]) {
  const response = await fetch(url, {
    headers,
    redirect: "error",
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw Error(label + " DoH HTTP " + response.status);
  const raw = await response.text();
  await writeFile(new URL(`dns-${label}.json`, output), raw);
  const data = JSON.parse(raw);
  if (data.Status !== 0) throw Error("DNS status " + data.Status);
  const records = data.Answer?.filter((x) => x.type === 16);
  if (records?.length !== 1) throw Error("ambiguous selector TXT");
  const txt = records[0].data.replace(/"\s*"/g, "").replace(/^"|"$/g, "");
  if (joined !== undefined && joined !== txt)
    throw Error("Independent resolver TXT mismatch");
  joined = txt;
  sources.push({
    url,
    sha256: sha(raw),
    authenticatedData: !!data.AD,
    ttl: records[0].TTL,
    transport:
      "HTTPS to trusted recursive resolver; this alone is not DNSSEC validation",
  });
}
const fields = Object.fromEntries(
  joined
    .split(";")
    .map((x) => x.trim())
    .filter(Boolean)
    .map((x) => {
      const i = x.indexOf("=");
      return [x.slice(0, i), x.slice(i + 1)];
    }),
);
if (fields.k !== "rsa" || !fields.p)
  throw Error("unsupported/revoked DKIM selector");
const der = Buffer.from(fields.p, "base64");
const key = createPublicKey({ key: der, format: "der", type: "spki" });
await writeFile(new URL("selector-spki.der", output), der);
const authoritative = {};
try {
  const dns = new Resolver({ timeout: 3000, tries: 1 });
  const nsResponse = await fetch(
    "https://dns.google/resolve?name=yahoo.com&type=NS",
    { redirect: "error", signal: AbortSignal.timeout(10000) },
  );
  const nsRaw = await nsResponse.text();
  await writeFile(new URL("dns-authority-ns.json", output), nsRaw);
  const ns = JSON.parse(nsRaw).Answer.find((x) => x.type === 2).data;
  const ipResponse = await fetch(
    "https://dns.google/resolve?name=" + encodeURIComponent(ns) + "&type=A",
    { redirect: "error", signal: AbortSignal.timeout(10000) },
  );
  const ipRaw = await ipResponse.text();
  await writeFile(new URL("dns-authority-a.json", output), ipRaw);
  const address = JSON.parse(ipRaw).Answer.find((x) => x.type === 1).data;
  dns.setServers([address]);
  authoritative.nameserver = ns;
  authoritative.address = address;
  authoritative.records = await dns.resolveTxt(name);
} catch (e) {
  authoritative.error = e.code ?? String(e);
}
await writeFile(
  new URL("dns-provenance.json", output),
  JSON.stringify(
    {
      schemaVersion: 1,
      name,
      fetchedAt: new Date().toISOString(),
      sources,
      spkiSha256: sha(der),
      algorithm: "RSA/SHA256 DKIM",
      modulusLength: key.asymmetricKeyDetails.modulusLength,
      authoritativeAttempt: authoritative,
      trustRole:
        "Domain/selector public signature key; not an assertion of private email ownership. No email captured.",
      rotationRevocation:
        "Honor selector DNS TTL and p= revocation; account trust enrollment must authenticate domain+selector and refresh policy.",
      verification:
        "Public key parsed and independent HTTPS resolver answers compared. No DNSSEC guarantee unless explicitly evidenced by authenticatedData; no message-signature vector implied.",
    },
    null,
    2,
  ) + "\n",
);
console.log(name, key.asymmetricKeyDetails.modulusLength, sha(der));
