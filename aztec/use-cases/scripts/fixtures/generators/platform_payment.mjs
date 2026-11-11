// Writes src/fixture.nr and fixtures/manifest.json for a payment-settlement
// instance whose evidence is an RSA-2048 platform-signed API response
// (WeChat Pay APIv3, Alipay v3). The responses are synthetic: they are
// signed with the public synthetic RS256 test key in
// fixtures/data, not by a payment platform.
//
// node scripts/fixtures/generators/platform_payment.mjs \
//   --instance payment-settlement/wechatpay --reference <field hex> [--now <unix s>]
//
// The reference is the order reference that the instance test prints
// (`fixture_reference_is_the_order_reference`). Uses node:crypto only. No
// network access, no proving.
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { formatNoir } from "./nr_format.mjs";

const project = fileURLToPath(new URL("../../../", import.meta.url));
const repository = fileURLToPath(new URL("../../../../../", import.meta.url));
const keyPath =
  "fixtures/data/synthetic-rs256-private.pem";
const generator =
  "aztec/use-cases/scripts/fixtures/generators/platform_payment.mjs";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function array(values, indent = "            ") {
  const lines = [];
  for (let i = 0; i < values.length; i += 16)
    lines.push(values.slice(i, i + 16).join(", "));
  return `[\n${indent}${lines.join(`,\n${indent}`)},\n${indent.slice(4)}]`;
}

function bounded(text, capacity) {
  const bytes = [...Buffer.from(text, "utf8")];
  if (bytes.length > capacity)
    throw new Error(`value of ${bytes.length} bytes exceeds ${capacity}`);
  const storage = [...bytes, ...new Array(capacity - bytes.length).fill(0)];
  return `BoundedVec::from_parts(${array(storage)}, ${bytes.length})`;
}

const limbs = (value) =>
  Array.from({ length: 18 }, (_, i) =>
    ((value >> (120n * BigInt(i))) & ((1n << 120n) - 1n)).toString(),
  );
const fromBytes = (bytes) => BigInt(`0x${Buffer.from(bytes).toString("hex")}`);

// One response profile per scheme: the signed body for a claim set, the
// envelope timestamp for `now`, and the Noir struct literal.
const profiles = {
  wechatpay: {
    input: "WechatpayPayment",
    crate: "uc_adapter_wechatpay",
    protocol: "WeChat Pay APIv3 transaction-query response",
    base: {
      appid: "wx1234567890abcdef",
      mchid: "1900000001",
      transaction_id: "4200000000202610250000000001",
      openid: "synthetic-openid-001",
      total: 2500,
    },
    variants: {
      other_transaction: { transaction_id: "4200000000202610250000000002" },
      other_amount: {
        transaction_id: "4200000000202610250000000003",
        total: 2499,
      },
      other_merchant: {
        transaction_id: "4200000000202610250000000004",
        mchid: "1900000002",
      },
      // Every member of the documented JSAPI query response, with
      // scene_info and a coupon (promotion_detail with goods_detail): over
      // 512 bytes, with objects and arrays that the parser skips.
      with_coupon: {
        transaction_id: "4200000000202610250000000005",
        coupon: 100,
      },
    },
    nonce: "synthetic-wechatpay-query-nonce",
    timestamp: (now) => String(now),
    body: (c, attach) =>
      c.coupon === undefined
        ? JSON.stringify({
            appid: c.appid,
            mchid: c.mchid,
            trade_state: "SUCCESS",
            transaction_id: c.transaction_id,
            attach,
            payer: { openid: c.openid },
            amount: { total: c.total, payer_total: c.total, currency: "CNY" },
          })
        : JSON.stringify({
            appid: c.appid,
            mchid: c.mchid,
            out_trade_no: "1217752501201407033233368018",
            transaction_id: c.transaction_id,
            trade_type: "JSAPI",
            trade_state: "SUCCESS",
            trade_state_desc: "支付成功",
            bank_type: "CMC",
            attach,
            success_time: "2026-10-25T10:34:56+08:00",
            payer: { openid: c.openid },
            amount: {
              total: c.total,
              payer_total: c.total - c.coupon,
              currency: "CNY",
              payer_currency: "CNY",
            },
            scene_info: { device_id: "013467007045764" },
            promotion_detail: [
              {
                coupon_id: "109519",
                name: "单品惠-6",
                scope: "SINGLE",
                type: "CASH",
                amount: c.coupon,
                stock_id: "931386",
                wechatpay_contribute: 0,
                merchant_contribute: c.coupon,
                other_contribute: 0,
                currency: "CNY",
                goods_detail: [
                  {
                    goods_id: "M1006",
                    quantity: 1,
                    unit_price: c.total,
                    discount_amount: c.coupon,
                    goods_remark: "商品备注信息",
                  },
                ],
              },
            ],
          }),
    literal: (c, attach, env) => `WechatpayPayment {
        modulus: ${array(env.modulus)},
        redc: ${array(env.redc)},
        max_age: MAX_AGE,
        timestamp: ${bounded(env.timestamp, 20)},
        nonce: ${bounded(env.nonce, 128)},
        body: ${bounded(env.body, 1024)},
        signature: ${array(env.signature)},
        appid: ${bounded(c.appid, 128)},
        mchid: ${bounded(c.mchid, 128)},
        transaction_id: ${bounded(c.transaction_id, 128)},
        openid: ${bounded(c.openid, 128)},
        attach: ${array([...Buffer.from(attach, "ascii")])},
        total_fen: ${c.total},
    }`,
    globals: (
      c,
    ) => `/// The payee claims of the base response and of \`other_merchant\`.
pub global APPID: str<${c.appid.length}> = "${c.appid}";
pub global MCHID: str<${c.mchid.length}> = "${c.mchid}";
/// The amount in fen of every response except \`other_amount\`.
pub global TOTAL_FEN: u64 = ${c.total};`,
  },
  alipay: {
    input: "AlipayTradeQuery",
    crate: "uc_adapter_alipay",
    protocol: "Alipay v3 trade-query response (alipay.trade.query)",
    base: {
      trade_no: "2026102522001400000000000001",
      total: 2500,
    },
    variants: {
      other_transaction: { trade_no: "2026102522001400000000000002" },
      other_amount: { trade_no: "2026102522001400000000000003", total: 2499 },
      other_status: {
        trade_no: "2026102522001400000000000004",
        status: "WAIT_BUYER_PAY",
      },
      // Signed 999 ms after NOW: tests the millisecond flooring of paid_at.
      late_millisecond: {
        trade_no: "2026102522001400000000000005",
        timestamp: (now) => `${now}999`,
      },
    },
    nonce: "synthetic-alipay-trade-query-nonce",
    // The v3 envelope timestamp is in milliseconds.
    timestamp: (now) => `${now}000`,
    body: (c, attach) =>
      JSON.stringify({
        trade_no: c.trade_no,
        out_trade_no: attach,
        buyer_logon_id: "159****0000",
        trade_status: c.status ?? "TRADE_SUCCESS",
        total_amount: `${Math.floor(c.total / 100)}.${String(c.total % 100).padStart(2, "0")}`,
        buyer_pay_amount: `${Math.floor(c.total / 100)}.${String(c.total % 100).padStart(2, "0")}`,
        send_pay_date: "2026-10-25 12:00:00",
      }),
    literal: (c, attach, env) => `AlipayTradeQuery {
        modulus: ${array(env.modulus)},
        redc: ${array(env.redc)},
        max_age: MAX_AGE,
        timestamp: ${bounded(env.timestamp, 20)},
        nonce: ${bounded(env.nonce, 128)},
        body: ${bounded(env.body, 512)},
        signature: ${array(env.signature)},
        trade_no: ${bounded(c.trade_no, 64)},
        out_trade_no: ${array([...Buffer.from(attach, "ascii")])},
        total_fen: ${c.total},
    }`,
    globals: (
      c,
    ) => `/// The amount in fen of every response except \`other_amount\`.
pub global TOTAL_FEN: u64 = ${c.total};`,
  },
};

async function main() {
  const { values } = parseArgs({
    options: {
      instance: { type: "string" },
      reference: { type: "string" },
      now: { type: "string", default: "4000000000" },
      "max-age": { type: "string", default: "300" },
    },
  });
  // Accept a Field as the instance test prints it (0x..., not zero-padded).
  const reference = (values.reference ?? "")
    .replace(/^0x/, "")
    .toLowerCase()
    .padStart(64, "0");
  if (!values.instance || !/^[0-9a-f]{64}$/.test(reference))
    throw new Error(
      "Pass --instance <use-case>/<scheme> and --reference <field as hex>",
    );
  const now = Number(values.now);
  const maxAge = Number(values["max-age"]);
  if (!Number.isSafeInteger(now) || now < 86400)
    throw new Error("--now must be Unix seconds");
  const [useCase, scheme] = values.instance.split("/");
  const profile = profiles[scheme];
  if (useCase !== "payment-settlement" || !profile)
    throw new Error(`${values.instance}: no platform response profile`);

  const key = createPrivateKey(await readFile(repository + keyPath));
  const jwk = createPublicKey(key).export({ format: "jwk" });
  const modulus = fromBytes(Buffer.from(jwk.n, "base64url"));
  const redc = (1n << 4102n) / modulus;
  // Another well-formed 2048-bit modulus (n + 2) with its own Barrett
  // parameters, for a wrong-key test that reaches the signature check.
  const otherModulus = modulus + 2n;
  const otherRedc = (1n << 4102n) / otherModulus;

  const timestamp = profile.timestamp(now);
  const claims = {};
  const functions = [];
  const signed = (name, overrides) => {
    const { timestamp: at, ...rest } = overrides;
    const c = { ...profile.base, ...rest };
    const stamp = at ? at(now) : timestamp;
    const body = profile.body(c, reference);
    const preimage = `${stamp}\n${profile.nonce}\n${body}\n`;
    const signature = fromBytes(
      sign("RSA-SHA256", Buffer.from(preimage, "utf8"), key),
    );
    claims[name] = { ...c, timestamp: stamp, body };
    const env = {
      modulus: limbs(modulus),
      redc: limbs(redc),
      timestamp: stamp,
      nonce: profile.nonce,
      body,
      signature: limbs(signature),
    };
    functions.push(`pub fn ${name}() -> ${profile.input} {
    ${profile.literal(c, reference, env)}
}`);
  };
  signed("payment", {});
  for (const [name, overrides] of Object.entries(profile.variants))
    signed(name, overrides);

  const unformatted = `//! Generated by scripts/fixtures/generators/platform_payment.mjs; see fixtures/manifest.json. Do not edit.
//! Synthetic ${profile.protocol}s signed with the public synthetic RS256 test
//! key in fixtures/data. They are not platform responses
//! and record no payment.
use ${profile.crate}::${profile.input};

/// The envelope time of every response, in Unix seconds.
pub global NOW: u64 = ${now};
/// The response age that the fixtures accept.
pub global MAX_AGE: u64 = ${maxAge};
/// The order reference that every response carries, in text form.
pub global REFERENCE: Field = 0x${reference};
${profile.globals(profile.base)}

/// Another well-formed 2048-bit RSA modulus and its Barrett parameters
/// (the fixture key's modulus + 2). No response is signed under it.
pub global OTHER_MODULUS: [Field; 18] = ${array(limbs(otherModulus), "    ")};
pub global OTHER_REDC: [Field; 18] = ${array(limbs(otherRedc), "    ")};

${functions.join("\n\n")}
`;
  const fixture = formatNoir(unformatted);
  const directory = `${project}${values.instance}/`;
  await mkdir(directory + "fixtures", { recursive: true });
  await writeFile(directory + "src/fixture.nr", fixture);
  const manifestPath = directory + "fixtures/manifest.json";
  const inputs = {};
  for (const path of [
    keyPath,
    "fixtures/data/synthetic-rs256-public.pem",
    generator,
  ])
    inputs[path] = sha256(await readFile(repository + path));
  const record = {
    schema: "uc-fixture-v1",
    scheme,
    use_case: useCase,
    kind: "synthetic",
    generator: {
      argv: [
        "node",
        "scripts/fixtures/generators/platform_payment.mjs",
        "--instance",
        values.instance,
        "--reference",
        reference,
        "--now",
        String(now),
        "--max-age",
        String(maxAge),
      ],
      cwd: "aztec/use-cases",
      library: "node:crypto RSA-SHA256 (PKCS#1 v1.5)",
    },
    inputs,
    key_provenance: `Public synthetic RS256 test key committed in fixtures/data; not a ${scheme} platform key. Anyone can sign with it.`,
    claims: { timestamp, nonce: profile.nonce, responses: claims },
    notes: [
      "The reference is the instance's order reference observed in TXE; the instance test fails with the value to use when it changes.",
      "Variants are separately signed responses for the wrong-term tests; other negative cases mutate a valid response in src/test.nr.",
    ],
    outputs: { "src/fixture.nr": sha256(fixture) },
  };
  await writeFile(manifestPath, JSON.stringify(record, null, 2) + "\n");
  console.log(
    `Wrote ${values.instance}/src/fixture.nr for reference ${reference}`,
  );
}

await main();
