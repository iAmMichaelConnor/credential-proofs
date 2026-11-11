//! Bounded RSA X.509 syntax for explicit key/signature size and hash profiles.
//! Parsing does not select a trust anchor, verify a signature, or grant purpose.
use crate::der::{expect, literal, read, Tlv};
pub struct RsaCertificate<let KEY_BYTES: u32, let SIGNATURE_BYTES: u32> {
    pub tbs: Tlv,
    pub serial: Tlv,
    pub issuer: Tlv,
    pub subject: Tlv,
    pub spki: Tlv,
    pub key_bits: Tlv,
    pub modulus: [u8; KEY_BYTES],
    pub signature: [u8; SIGNATURE_BYTES],
    pub not_before: u64,
    pub not_after: u64,
    pub extensions: Tlv,
}
fn signature_algorithm<let N: u32, let SHA512: u8>(data: BoundedVec<u8, N>, node: Tlv) {
    assert(node.tag == 48);
    if SHA512 == 1 {
        literal(
            data,
            node,
            [6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 13, 5, 0],
        );
    } else {
        literal(
            data,
            node,
            [6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0],
        );
    }
}
pub fn parse_rsa_certificate<let N: u32, let KEY_BYTES: u32, let SIGNATURE_BYTES: u32, let SHA512: u8>(
    data: BoundedVec<u8, N>,
) -> RsaCertificate<KEY_BYTES, SIGNATURE_BYTES> {
    assert(SHA512 <= 1, "unsupported certificate signature hash profile");
    assert((KEY_BYTES == 256) | (KEY_BYTES == 512), "unsupported certificate RSA key size");
    assert(
        (SIGNATURE_BYTES == 256) | (SIGNATURE_BYTES == 512),
        "unsupported certificate RSA signature size",
    );
    let outer = expect(data, 0, data.len(), 48);
    assert(outer.end == data.len(), "trailing certificate data");
    let tbs = expect(data, outer.content, outer.end, 48);
    let alg = expect(data, tbs.end, outer.end, 48);
    signature_algorithm::<N, SHA512>(data, alg);
    let sig = expect(data, alg.end, outer.end, 3);
    assert(sig.end == outer.end);
    assert(sig.len == SIGNATURE_BYTES + 1);
    assert(data.storage()[sig.content] == 0);
    let mut signature = [0; SIGNATURE_BYTES];
    for i in 0..SIGNATURE_BYTES {
        signature[i] = data.storage()[sig.content + 1 + i];
    }
    let version = expect(data, tbs.content, tbs.end, 160);
    literal(data, version, [2, 1, 2]);
    let serial = expect(data, version.end, tbs.end, 2);
    crate::certificate::positive_integer(data, serial, 20);
    let inneralg = expect(data, serial.end, tbs.end, 48);
    signature_algorithm::<N, SHA512>(data, inneralg);
    let issuer = expect(data, inneralg.end, tbs.end, 48);
    let validity = expect(data, issuer.end, tbs.end, 48);
    let before = read(data, validity.content, validity.end);
    let after = read(data, before.end, validity.end);
    assert(after.end == validity.end);
    let not_before = crate::time::validity_unix(data, before);
    let not_after = crate::time::validity_unix(data, after);
    assert(not_before < not_after);
    let subject = expect(data, validity.end, tbs.end, 48);
    let spki = expect(data, subject.end, tbs.end, 48);
    let keyalg = expect(data, spki.content, spki.end, 48);
    literal(
        data,
        keyalg,
        [6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0],
    );
    let key_bits = expect(data, keyalg.end, spki.end, 3);
    assert(key_bits.end == spki.end);
    assert(data.storage()[key_bits.content] == 0);
    let key = expect(data, key_bits.content + 1, key_bits.end, 48);
    assert(key.end == key_bits.end);
    let n = expect(data, key.content, key.end, 2);
    assert(n.len == KEY_BYTES + 1);
    assert(data.storage()[n.content] == 0);
    assert(data.storage()[n.content + 1] >= 128);
    let exponent = expect(data, n.end, key.end, 2);
    literal(data, exponent, [1, 0, 1]);
    assert(exponent.end == key.end);
    let mut modulus = [0; KEY_BYTES];
    for i in 0..KEY_BYTES {
        modulus[i] = data.storage()[n.content + 1 + i];
    }
    assert((modulus[KEY_BYTES - 1] & 1) == 1, "RSA modulus must be odd");
    let extensions = expect(data, spki.end, tbs.end, 163);
    assert(extensions.end == tbs.end, "unsupported certificate unique identifiers");
    RsaCertificate {
        tbs,
        serial,
        issuer,
        subject,
        spki,
        key_bits,
        modulus,
        signature,
        not_before,
        not_after,
        extensions,
    }
}
