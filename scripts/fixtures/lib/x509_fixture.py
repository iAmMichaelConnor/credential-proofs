"""Explicit synthetic test certificate/status helpers; no provider authority."""

import datetime, hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def test_key(directory, name, bits=2048):
    p = directory / (name + "-test-only.key.pem")
    if not p.is_file():
        raise FileNotFoundError(f"Missing public synthetic test key: {p}")
    k = serialization.load_pem_private_key(p.read_bytes(), None)
    assert k.key_size == bits
    return k


def tlv(tag, data):
    n = len(data)
    size = (
        bytes([n])
        if n < 128
        else bytes([128 + (n.bit_length() + 7) // 8])
        + n.to_bytes((n.bit_length() + 7) // 8, "big")
    )
    return bytes([tag]) + size + data


def seq(*parts):
    return tlv(48, b"".join(parts))


def integer(n):
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return tlv(2, (b"\0" if b[0] >= 128 else b"") + b)


def gt(t):
    return tlv(24, t.strftime("%Y%m%d%H%M%SZ").encode())


def signed_ocsp(
    issuer_cert,
    subject_cert,
    signer_cert,
    signer_key,
    now,
    good=True,
    next_delta=600,
    this_delta=-60,
    embedded=True,
):
    issuer_name = issuer_cert.subject.public_bytes()
    issuer_key = issuer_cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.PKCS1
    )
    cid = seq(
        bytes.fromhex("300906052b0e03021a0500"),
        tlv(4, hashlib.sha1(issuer_name).digest()),
        tlv(4, hashlib.sha1(issuer_key).digest()),
        integer(subject_cert.serial_number),
    )
    state = tlv(128, b"") if good else tlv(161, gt(now - datetime.timedelta(days=1)))
    single = seq(
        cid,
        state,
        gt(now + datetime.timedelta(seconds=this_delta)),
        tlv(160, gt(now + datetime.timedelta(seconds=next_delta))),
    )
    signer_bits = signer_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.PKCS1
    )
    tbs = seq(
        tlv(162, tlv(4, hashlib.sha1(signer_bits).digest())), gt(now), seq(single)
    )
    signature = signer_key.sign(tbs, padding.PKCS1v15(), hashes.SHA256())
    parts = [
        tbs,
        bytes.fromhex("300d06092a864886f70d01010b0500"),
        tlv(3, b"\0" + signature),
    ]
    if embedded:
        parts.append(
            tlv(160, seq(signer_cert.public_bytes(serialization.Encoding.DER)))
        )
    return seq(
        tlv(10, b"\0"),
        tlv(160, seq(bytes.fromhex("06092b0601050507300101"), tlv(4, seq(*parts)))),
    )
