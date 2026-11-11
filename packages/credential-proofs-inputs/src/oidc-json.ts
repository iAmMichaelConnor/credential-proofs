/** Shared bounded JSON envelopes matching the Noir OIDC JSON scanners. */
export type OidcJsonProfile = 0 | 1 | 2;

const U64_MAX = (1n << 64n) - 1n;
/** Root claims that the flat Noir scanner copies (at most 256 decoded bytes). */
const SELECTED_STRINGS = new Set(["iss", "aud", "sub", "nonce", "azp"]);
/** Root claims that the flat Noir scanner reads as u64 (`iat` where read; the host checks it always). */
const SELECTED_NUMBERS = new Set(["exp", "nbf", "iat"]);

interface RawString {
  raw: string;
  value: string;
  escaped: boolean;
  bytes: number;
}
type JsonNode =
  | { type: "object"; members: [RawString, JsonNode][] }
  | { type: "array"; items: JsonNode[] }
  | { type: "string"; text: RawString }
  | { type: "number"; text: string }
  | { type: "literal"; text: string };

/**
 * Parse JSON that `JSON.parse` has accepted into a tree that keeps the raw
 * spelling of every string and number, and every duplicate key. Containers
 * deeper than `maxDepth` (the root counts as 1) fail before recursion.
 */
function parseRaw(text: string, maxDepth: number): JsonNode {
  let pos = 0;
  const ws = () => {
    while (pos < text.length && " \t\n\r".includes(text[pos]!)) pos++;
  };
  const string = (): RawString => {
    const start = ++pos;
    let escaped = false;
    while (text[pos] !== '"') {
      if (pos >= text.length) throw new Error("invalid JSON");
      if (text[pos] === "\\") {
        escaped = true;
        pos += 2;
      } else pos++;
    }
    const raw = text.slice(start, pos++);
    const value = JSON.parse(`"${raw}"`) as string;
    return { raw, value, escaped, bytes: Buffer.byteLength(value) };
  };
  const value = (depth: number): JsonNode => {
    ws();
    const c = text[pos];
    if (c === "{" || c === "[") {
      if (depth + 1 > maxDepth)
        throw new Error("nested JSON depth exceeds profile");
      pos++;
      const members: [RawString, JsonNode][] = [],
        items: JsonNode[] = [];
      ws();
      if (text[pos] !== (c === "{" ? "}" : "]")) {
        for (;;) {
          if (c === "{") {
            ws();
            const key = string();
            ws();
            pos++; // ':'
            members.push([key, value(depth + 1)]);
          } else items.push(value(depth + 1));
          ws();
          if (text[pos] === ",") pos++;
          else break;
        }
      }
      pos++;
      return c === "{" ? { type: "object", members } : { type: "array", items };
    }
    if (c === '"') return { type: "string", text: string() };
    const scalar =
      /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null/y;
    scalar.lastIndex = pos;
    const match = scalar.exec(text);
    if (match === null) throw new Error("invalid JSON");
    pos += match[0].length;
    return /^[-0-9]/.test(match[0])
      ? { type: "number", text: match[0] }
      : { type: "literal", text: match[0] };
  };
  return value(0);
}

function parseObject(
  raw: string,
  maxDepth: number,
): {
  object: Record<string, unknown>;
  root: Extract<JsonNode, { type: "object" }>;
} {
  const object: unknown = JSON.parse(raw);
  if (object === null || Array.isArray(object) || typeof object !== "object")
    throw new Error("JWT JSON must be an object");
  const root = parseRaw(raw, maxDepth);
  if (root.type !== "object") throw new Error("JWT JSON must be an object");
  rejectDuplicateKeys(root);
  return { object: object as Record<string, unknown>, root };
}

/** The host conservatively rejects every duplicate key, at every level. */
function rejectDuplicateKeys(node: JsonNode): void {
  if (node.type === "object") {
    const keys = new Set<string>();
    for (const [key, value] of node.members) {
      if (keys.has(key.value)) throw new Error("duplicate JWT claims");
      keys.add(key.value);
      rejectDuplicateKeys(value);
    }
  } else if (node.type === "array") node.items.forEach(rejectDuplicateKeys);
}

/** A canonical unsigned decimal integer; with `u64`, at most 2^64 - 1. */
function checkInteger(text: string, u64: boolean): void {
  if (!/^(?:0|[1-9][0-9]*)$/.test(text) || (u64 && BigInt(text) > U64_MAX))
    throw new Error("scalar exceeds the Noir JSON profile");
}

interface Envelope {
  escapes: boolean;
  maxKeyBytes: number;
  maxStringBytes: number;
  u64: boolean;
}

/** Check every key and value below a node against one envelope. */
function checkTree(node: JsonNode, rule: Envelope): void {
  if (node.type === "object") {
    for (const [key, value] of node.members) {
      if (key.escaped)
        throw new Error("escaped JSON keys exceed the Noir profile");
      if (key.bytes > rule.maxKeyBytes)
        throw new Error("OIDC JSON key exceeds capacity");
      checkTree(value, rule);
    }
  } else if (node.type === "array")
    node.items.forEach((item) => checkTree(item, rule));
  else if (node.type === "string") {
    if (node.text.escaped && !rule.escapes)
      throw new Error("escaped JSON strings exceed the Noir profile");
    if (node.text.bytes > rule.maxStringBytes)
      throw new Error("OIDC JSON string exceeds capacity");
  } else if (node.type === "number") checkInteger(node.text, rule.u64);
}

/** Legacy flat envelope (PhilSys): unescaped strings of at most 256 bytes, depth 9, u64 integers. */
export function assertBoundedJsonObject(raw: string): Record<string, unknown> {
  const { object, root } = parseObject(raw, 9);
  checkTree(root, {
    escapes: false,
    maxKeyBytes: 256,
    maxStringBytes: 256,
    u64: true,
  });
  return object;
}

/**
 * The structured-document domain of `oidc::assert_json_document` (University,
 * Singpass, LinkedIn and the ES256 document profile): unescaped keys and
 * strings of at most 4096 bytes, depth 8
 * including the root, u64 integers.
 */
export function assertStructuredJsonDocument(
  raw: string,
): Record<string, unknown> {
  const { object, root } = parseObject(raw, 8);
  checkTree(root, {
    escapes: false,
    maxKeyBytes: 4096,
    maxStringBytes: 4096,
    u64: true,
  });
  return object;
}

/**
 * The JOSE header domain of the `oidc` header scanner: a flat object of
 * unescaped string values, keys and values of at most 256 bytes. Callers
 * check the members.
 */
export function assertJoseHeaderObject(raw: string): Record<string, unknown> {
  const { object, root } = parseObject(raw, 1);
  for (const [key, value] of root.members) {
    if (key.escaped || (value.type === "string" && value.text.escaped))
      throw new Error("escaped JWS header strings exceed the Noir profile");
    if (value.type !== "string")
      throw new Error("JWS header values must be strings");
    if (key.bytes > 256 || value.text.bytes > 256)
      throw new Error("JWS header string exceeds capacity");
  }
  return object;
}

/** Ignored flat-profile values: any escape, any string length, integers of any length; keys unescaped, at most 256 bytes. */
const FLAT_VALUE: Envelope = {
  escapes: true,
  maxKeyBytes: 256,
  maxStringBytes: Infinity,
  u64: false,
};

/**
 * The flat claims domain of `oidc::parse_claims_profile`. Selected
 * string claims are root strings of at most 256 decoded bytes whose only
 * escape is the escaped solidus; selected numeric claims are root u64
 * integers. Profile 1 reads amr, and profile 2 also scope and
 * reliability_info.level. Every other member may hold any JSON value to
 * depth 9 including the root, checked and ignored. `requiredStrings` are
 * the extra root strings of `oidc_policy` (FranceConnect `acr`): unescaped,
 * at most 256 bytes.
 */
export function assertOidcJsonProfile(
  raw: string,
  profile: OidcJsonProfile = 0,
  requiredStrings: readonly string[] = [],
): Record<string, unknown> {
  if (profile !== 0 && profile !== 1 && profile !== 2)
    throw new Error("unknown OIDC JSON profile");
  const { object, root } = parseObject(raw, 9);
  for (const [key, value] of root.members) {
    if (key.escaped)
      throw new Error("escaped JSON keys exceed the Noir profile");
    if (key.bytes > 256) throw new Error("OIDC JSON key exceeds capacity");
    const name = key.value;
    if (requiredStrings.includes(name)) {
      if (value.type !== "string")
        throw new Error(`required OIDC claim ${name} must be a string`);
      if (value.text.escaped)
        throw new Error("escaped JSON strings exceed the Noir profile");
      if (value.text.bytes > 256)
        throw new Error("OIDC JSON string exceeds capacity");
    } else if (SELECTED_STRINGS.has(name)) {
      if (value.type === "object" || value.type === "array")
        throw new Error("nested JSON exceeds the Noir profile");
      if (value.type !== "string")
        throw new Error(`OIDC claim ${name} must be a string`);
      if (/\\[^/]/.test(value.text.raw))
        throw new Error(
          "escaped JSON strings exceed the Noir profile: OIDC claims admit only \\/",
        );
      if (value.text.bytes > 256)
        throw new Error("OIDC JSON string exceeds capacity");
    } else if (SELECTED_NUMBERS.has(name)) {
      if (value.type !== "number")
        throw new Error(`OIDC claim ${name} must be a number`);
      checkInteger(value.text, true);
    } else if (
      (profile > 0 && name === "amr") ||
      (profile === 2 && name === "scope")
    ) {
      if (
        value.type !== "array" ||
        value.items.some((item) => item.type !== "string")
      )
        throw new Error("OIDC profile array must contain strings");
      checkTree(value, FLAT_VALUE);
    } else if (profile === 2 && name === "reliability_info") {
      if (value.type !== "object")
        throw new Error("reliability_info must be object");
      for (const [member, level] of value.members) {
        if (member.value !== "level") continue;
        if (level.type !== "string")
          throw new Error("assurance level must be string");
        if (level.text.escaped)
          throw new Error("escaped JSON strings exceed the Noir profile");
        if (level.text.bytes > 256)
          throw new Error("OIDC JSON string exceeds capacity");
      }
      checkTree(value, FLAT_VALUE);
    } else checkTree(value, FLAT_VALUE);
  }
  return object;
}
