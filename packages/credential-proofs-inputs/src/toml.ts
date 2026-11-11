import { chmod, writeFile } from "node:fs/promises";

export type TomlPrimitive = string | number | bigint | boolean;
export type TomlValue = TomlPrimitive | readonly TomlPrimitive[];
export interface TomlTable {
  readonly [key: string]: TomlValue | TomlTable;
}
export type TomlDocument = TomlTable;

function valueToToml(value: TomlValue): string {
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return `[${value.map(valueToToml).join(", ")}]`;
  return String(value);
}

export function stringifyToml(document: TomlDocument): string {
  const lines: string[] = [];
  const table = (path: string[], entries: TomlTable): void => {
    if (path.length > 0) lines.push(`[${path.join(".")}]`);
    const children: [string, TomlTable][] = [];
    for (const [key, value] of Object.entries(entries)) {
      if (typeof value === "object" && !Array.isArray(value))
        children.push([key, value as TomlTable]);
      else lines.push(`${key} = ${valueToToml(value as TomlValue)}`);
    }
    if (path.length > 0 || children.length > 0) lines.push("");
    for (const [key, child] of children) table([...path, key], child);
  };
  // TOML has no syntax to return to the root table: emit ALL root values
  // before opening nested tables, irrespective of object insertion order.
  table([], document);
  return `${lines.join("\n").trimEnd()}\n`;
}

export async function writeToml(
  path: string,
  document: TomlDocument,
): Promise<void> {
  await writeFile(path, stringifyToml(document), { mode: 0o600 });
  await chmod(path, 0o600);
}

export function paddedBytes(bytes: Uint8Array, capacity: number): number[] {
  if (bytes.length > capacity)
    throw new Error(
      `input length ${bytes.length} exceeds circuit capacity ${capacity}`,
    );
  const result = new Array<number>(capacity).fill(0);
  for (let i = 0; i < bytes.length; i++) result[i] = bytes[i]!;
  return result;
}

export function boundedBytes(
  bytes: Uint8Array,
  capacity: number,
): { len: number; storage: number[] } {
  if (bytes.length > capacity)
    throw new Error(
      `input length ${bytes.length} exceeds circuit capacity ${capacity}`,
    );
  return { len: bytes.length, storage: paddedBytes(bytes, capacity) };
}

export function bytesFromHex(hex: string, expectedBytes?: number): Uint8Array {
  const normalized = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(normalized))
    throw new Error("expected an even-length hexadecimal byte string");
  const bytes = Uint8Array.from(Buffer.from(normalized, "hex"));
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) {
    throw new Error(
      `expected ${expectedBytes} bytes, received ${bytes.length}`,
    );
  }
  return bytes;
}

export function utf8(value: string, capacity: number): number[] {
  return paddedBytes(Buffer.from(value, "utf8"), capacity);
}
