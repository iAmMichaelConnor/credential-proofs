use crate::der::{literal, slice, Tlv};
use sha256::sha256_var;
/// Compatibility profile: RSA2048 subject and RSA2048/SHA256 issuer.
pub type Certificate = crate::rsa_certificate::RsaCertificate<256, 256>;
pub fn rsa_sha256_algorithm<let N: u32>(data: BoundedVec<u8, N>, node: Tlv) {
    assert(node.tag == 48);
    literal(
        data,
        node,
        [6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0],
    );
}
pub fn parse<let N: u32>(data: BoundedVec<u8, N>) -> Certificate {
    crate::rsa_certificate::parse_rsa_certificate::<N, 256, 256, 0_u8>(data)
}
pub fn positive_integer<let N: u32>(data: BoundedVec<u8, N>, node: Tlv, max: u32) {
    assert((node.len > 0) & (node.len <= max), "unsupported serial length");
    assert(data.storage()[node.content] < 128, "negative serial");
    if node.len > 1 {
        assert(
            (data.storage()[node.content] != 0) | (data.storage()[node.content + 1] >= 128),
            "noncanonical serial",
        );
    }
    let mut nonzero = false;
    for i in 0..20 {
        if i < node.len {
            nonzero = nonzero | (data.storage()[node.content + i] != 0);
        }
    }
    assert(nonzero, "zero serial");
}
pub fn hash_tlv<let N: u32>(data: BoundedVec<u8, N>, node: Tlv) -> [u8; 32] {
    let bytes = slice::<N, N>(data, node.start, node.end - node.start);
    sha256_var(bytes.storage(), bytes.len())
}
/// RSA2048 exponent65537 SPKI has exact DER length294: algorithm15 +
/// BIT STRING275 + SEQUENCE header4. parse() constrains every constituent.
pub fn hash_spki<let N: u32>(data: BoundedVec<u8, N>, cert: Certificate) -> [u8; 32] {
    let bytes = slice::<N, 294>(data, cert.spki.start, cert.spki.end - cert.spki.start);
    sha256_var(bytes.storage(), bytes.len())
}
/// Parsed certificate/BasicOCSP signature wrappers contain at least278 bytes
/// outside the signed TLV: signature BIT STRING261 + algorithm15 + outer2.
/// Tightening hash capacity removes unreachable padding blocks, not inputs.
pub fn hash_signed_tlv<let N: u32>(data: BoundedVec<u8, N>, node: Tlv) -> [u8; 32] {
    let bytes = slice::<N, N - 278>(data, node.start, node.end - node.start);
    sha256_var(bytes.storage(), bytes.len())
}
pub fn verify_signature<let N: u32>(
    data: BoundedVec<u8, N>,
    cert: Certificate,
    key: crate::crypto::Rsa2048Key,
    now: u64,
) {
    assert((now >= cert.not_before) & (now < cert.not_after), "certificate outside validity");
    crate::crypto::verify_digest(key, hash_signed_tlv(data, cert.tbs), cert.signature);
}
