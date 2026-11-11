from pathlib import Path
import base64, json, sys, subprocess

root = Path(__file__).resolve().parents[2]
nonce = sys.argv[1] if len(sys.argv) > 1 else "0" * 64
assert len(nonce) == 64 and all(c in "0123456789abcdef" for c in nonce), (
    "nonce must be 64 lowercase hex digits"
)
b = lambda v: base64.urlsafe_b64encode(v).rstrip(b"=").decode()
h = b(b'{"alg":"ES256","typ":"JWT","kid":"synthetic-line-key"}')
payload = {
    "iss": "https://access.line.me",
    "aud": "1234567890",
    "sub": "U0123456789abcdef0123456789abcdef",
    "nonce": nonce,
    "iat": 1899999940,
    "exp": 1900003600,
    "amr": ["lineautologin"],
}
p = b(json.dumps(payload, separators=(",", ":")).encode())
# Use the installed noble RFC6979 implementation, not randomized OpenSSL signing.
node = """import{localP256Key,signLocalP256}from'./scripts/fixtures/lib/local-p256-key.mjs';
import{readFileSync}from'node:fs';const message=readFileSync(0);
console.log(JSON.stringify({key:localP256Key(42).key,signature:[...signLocalP256(42,message)]}));"""
value = json.loads(
    subprocess.run(
        ["node", "--input-type=module", "-e", node],
        input=h + "." + p,
        text=True,
        cwd=root,
        capture_output=True,
        check=True,
    ).stdout
)
sig = b(bytes(value["signature"]))
d = {
    "header": h,
    "payload": p,
    "signature": sig,
    **value["key"],
    "nonce": nonce,
    "claims": payload,
}
(root / "fixtures/data/line.synthetic.json").write_text(
    json.dumps(d, indent=2) + "\n"
)
arr = lambda a: "[" + ", ".join(map(str, a)) + "]"
bv = lambda v, n: 'BoundedVec::from_array("' + v + '".as_bytes())'
# Standalone input, always same policy as library tests.
toml = (
    "now = 1900000000\n[key]\npublic_key_x = "
    + arr(d["public_key_x"])
    + "\npublic_key_y = "
    + arr(d["public_key_y"])
    + "\n"
)
for name, v, n in [
    ("channel_id", payload["aud"], 32),
    ("subject", payload["sub"], 256),
    ("nonce", nonce, 64),
    ("token.header_b64", h, 192),
    ("token.payload_b64", p, 1024),
    ("token.signature_b64", sig, 86),
]:
    toml += (
        "["
        + name
        + "]\nstorage = "
        + arr(list(v.encode()) + [0] * (n - len(v.encode())))
        + "\nlen = "
        + str(len(v.encode()))
        + "\n"
    )
(root / "target/kat/line/Prover.toml").write_text(toml)
# Test fixtures and assertions live after implementation.
f = root / "noir/line/src/lib.nr"
source = f.read_text()
source = source.split("// Synthetic")[0]
source += (
    "// Synthetic scalar 42; not issued by LINE.\nfn fixture() -> (JwtInput<192,1024,86>,TrustedP256Key) { (JwtInput {header_b64:"
    + bv(h, 192)
    + ",payload_b64:"
    + bv(p, 1024)
    + ",signature_b64:"
    + bv(sig, 86)
    + "},TrustedP256Key{public_key_x:"
    + arr(d["public_key_x"])
    + ",public_key_y:"
    + arr(d["public_key_y"])
    + "}) }\n"
)
source += "fn check(token:JwtInput<192,1024,86>, key:TrustedP256Key, audience:BoundedVec<u8,32>, subject:BoundedVec<u8,256>, nonce:BoundedVec<u8,64>, now:u64) { let _claims = verify_line(token,audience,subject,nonce,now,key); }\n"
for name, reason, mutation in [
    ("valid", "", ""),
    (
        "wrong_audience",
        "wrong OIDC audience",
        'a=BoundedVec::from_array("999".as_bytes());',
    ),
    (
        "wrong_subject",
        "wrong OIDC subject",
        'u=BoundedVec::from_array("wrong".as_bytes());',
    ),
    ("wrong_nonce", "wrong OIDC nonce", "n=BoundedVec::from_array([49;64]);"),
    ("expired", "OIDC token expired", "now=1900003600;"),
    (
        "invalid_key",
        "ES256 signature verification failed",
        "k.public_key_x=[0;32];k.public_key_y=[0;32];",
    ),
    (
        "hs256",
        "unexpected JWS algorithm",
        "t.header_b64=" + bv(b(b'{"alg":"HS256","typ":"JWT"}'), 192) + ";",
    ),
]:
    source += (
        ("#[test]" if not reason else '#[test(should_fail_with = "' + reason + '")]')
        + "\nfn line_"
        + name
        + "() { let (mut t,mut k)=fixture();let mut a="
        + bv(payload["aud"], 32)
        + ";let mut u="
        + bv(payload["sub"], 256)
        + ";let mut n="
        + bv(nonce, 64)
        + ";let mut now=1900000000;"
        + mutation
        + "check(t,k,a,u,n,now); }\n"
    )
source += (
    (root / "scripts/fixtures/templates/line-iat-regressions.nr.inc")
    .read_text()
    .replace("{{NONCE}}", nonce)
)
f.write_text(source)
