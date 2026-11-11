use crate::certificate::{Certificate, hash_tlv};
use crate::der::{expect, literal, read, slice, Tlv};
use sha1::sha1::sha1_var;
/// RFC6960 single-certificate BasicOCSPResponse. SHA1 CertID is an identifier,
/// not a signature; response signatures must be RSA2048/SHA256.
/// Caller independently authenticates responder certificate/key and purpose.
pub fn good<let N: u32, let C: u32, let I: u32, let R: u32>(
    data: BoundedVec<u8, N>,
    leaf_data: BoundedVec<u8, C>,
    leaf: Certificate,
    issuer_data: BoundedVec<u8, I>,
    issuer: Certificate,
    responder_data: BoundedVec<u8, R>,
    responder: Certificate,
    signer: crate::crypto::Rsa2048Key,
    now: u64,
    max_age: u64,
) -> u64 {
    let binding = OcspBinding {
        issuer_name_sha1: sha1_var(slice::<I, 512>(
            issuer_data,
            issuer.subject.start,
            issuer.subject.end - issuer.subject.start,
        )),
        issuer_key_sha1: sha1_var(slice::<I, 270>(
            issuer_data,
            issuer.key_bits.content + 1,
            issuer.key_bits.len - 1,
        )),
        responder_name_sha256: hash_tlv(responder_data, responder.subject),
        responder_key_sha1: sha1_var(slice::<R, 270>(
            responder_data,
            responder.key_bits.content + 1,
            responder.key_bits.len - 1,
        )),
        responder_certificate_sha256: sha256::sha256_var(
            responder_data.storage(),
            responder_data.len(),
        ),
        responder_not_before: responder.not_before,
        responder_not_after: responder.not_after,
        serial: slice::<C, 20>(leaf_data, leaf.serial.content, leaf.serial.len),
    };
    let parsed = parse_unverified_good_response::<N, 256>(data, binding, now, max_age);
    crate::crypto::verify_digest(signer, parsed.digest, parsed.signature);
    parsed.expires_at
}
/// Security bindings must be derived from independently authenticated issuer,
/// holder and responder certificates; these are not free witness hints.
pub struct OcspBinding {
    pub issuer_name_sha1: [u8; 20],
    pub issuer_key_sha1: [u8; 20],
    pub responder_name_sha256: [u8; 32],
    pub responder_key_sha1: [u8; 20],
    pub responder_certificate_sha256: [u8; 32],
    pub serial: BoundedVec<u8, 20>,
    pub responder_not_before: u64,
    pub responder_not_after: u64,
}
pub struct UnverifiedGoodResponse<let SIGNATURE_BYTES: u32> {
    pub digest: [u8; 32],
    pub signature: [u8; SIGNATURE_BYTES],
    pub expires_at: u64,
}
/// Parse and bind one good SHA1-CertID status with RSA/SHA256 signed bytes.
/// This function DOES NOT verify the returned signature. The caller MUST verify
/// digest/signature against the independently authenticated responder key before
/// accepting expires_at. Supports RSA2048/4096 response signatures explicitly.
pub fn parse_unverified_good_response<let N: u32, let SIGNATURE_BYTES: u32>(
    data: BoundedVec<u8, N>,
    binding: OcspBinding,
    now: u64,
    max_age: u64,
) -> UnverifiedGoodResponse<SIGNATURE_BYTES> {
    assert(
        (SIGNATURE_BYTES == 256) | (SIGNATURE_BYTES == 512),
        "unsupported OCSP RSA signature size",
    );
    assert(
        (binding.serial.len() > 0) & (binding.serial.len() <= 20),
        "invalid OCSP serial binding",
    );
    let outer = expect(data, 0, data.len(), 48);
    assert(outer.end == data.len(), "trailing OCSP bytes");
    let status = expect(data, outer.content, outer.end, 10);
    literal(data, status, [0]);
    let explicit = expect(data, status.end, outer.end, 160);
    assert(explicit.end == outer.end);
    let rb = expect(data, explicit.content, explicit.end, 48);
    assert(rb.end == explicit.end);
    let kind = expect(data, rb.content, rb.end, 6);
    literal(data, kind, [43, 6, 1, 5, 5, 7, 48, 1, 1]);
    let octets = expect(data, kind.end, rb.end, 4);
    assert(octets.end == rb.end);
    let basic = expect(data, octets.content, octets.end, 48);
    assert(basic.end == octets.end);
    let tbs = expect(data, basic.content, basic.end, 48);
    let algorithm = expect(data, tbs.end, basic.end, 48);
    crate::certificate::rsa_sha256_algorithm(data, algorithm);
    let sig = expect(data, algorithm.end, basic.end, 3);
    assert(sig.len == SIGNATURE_BYTES + 1);
    assert(data.storage()[sig.content] == 0);
    let mut signature = [0; SIGNATURE_BYTES];
    for i in 0..SIGNATURE_BYTES {
        signature[i] = data.storage()[sig.content + 1 + i];
    }
    if sig.end < basic.end {
        let certs = expect(data, sig.end, basic.end, 160);
        assert(certs.end == basic.end);
        let seq = expect(data, certs.content, certs.end, 48);
        assert(seq.end == certs.end);
        let cert = expect(data, seq.content, seq.end, 48);
        assert(cert.end == seq.end, "only one OCSP signer certificate supported");
        assert(
            hash_tlv(data, cert) == binding.responder_certificate_sha256,
            "embedded OCSP signer mismatch",
        );
    }
    let signed_bytes = slice::<N, N - SIGNATURE_BYTES - 22>(data, tbs.start, tbs.end - tbs.start);
    let digest = sha256::sha256_var(signed_bytes.storage(), signed_bytes.len());
    let mut rid = read(data, tbs.content, tbs.end);
    if rid.tag == 160 {
        literal(data, rid, [2, 1, 0]);
        rid = read(data, rid.end, tbs.end);
    }
    if rid.tag == 161 {
        let name = expect(data, rid.content, rid.end, 48);
        assert(name.end == rid.end);
        assert(
            hash_tlv(data, name) == binding.responder_name_sha256,
            "OCSP responder name mismatch",
        );
    } else {
        assert(rid.tag == 162, "unsupported OCSP responder ID");
        let hash = expect(data, rid.content, rid.end, 4);
        assert(hash.end == rid.end);
        assert(hash.len == 20);
        literal(data, hash, binding.responder_key_sha1);
    }
    let produced = expect(data, rid.end, tbs.end, 24);
    let produced_at = crate::time::unix(data, produced);
    let responses = expect(data, produced.end, tbs.end, 48);
    let single = expect(data, responses.content, responses.end, 48);
    assert(single.end == responses.end, "only one OCSP status supported");
    let id = expect(data, single.content, single.end, 48);
    let hash_alg = expect(data, id.content, id.end, 48);
    // Both RFC3279 absent parameters and explicit NULL SHA1 identifiers.
    let oid = expect(data, hash_alg.content, hash_alg.end, 6);
    literal(data, oid, [43, 14, 3, 2, 26]);
    if oid.end < hash_alg.end {
        let null = expect(data, oid.end, hash_alg.end, 5);
        assert(null.len == 0);
        assert(null.end == hash_alg.end);
    }
    let name_hash = expect(data, hash_alg.end, id.end, 4);
    literal(data, name_hash, binding.issuer_name_sha1);
    let key_hash = expect(data, name_hash.end, id.end, 4);
    literal(data, key_hash, binding.issuer_key_sha1);
    let serial = expect(data, key_hash.end, id.end, 2);
    assert(serial.end == id.end);
    assert(serial.len == binding.serial.len(), "OCSP serial mismatch");
    for i in 0..20 {
        if i < serial.len {
            assert(
                data.storage()[serial.content + i] == binding.serial.storage()[i],
                "OCSP serial mismatch",
            );
        }
    }
    let state = read(data, id.end, single.end);
    assert((state.tag == 128) & (state.len == 0), "OCSP certificate is not good");
    let this = expect(data, state.end, single.end, 24);
    let this_update = crate::time::unix(data, this);
    let next = expect(data, this.end, single.end, 160);
    let next_date = expect(data, next.content, next.end, 24);
    assert(next_date.end == next.end);
    let next_update = crate::time::unix(data, next_date);
    // Extensions (e.g. nonce) cannot override status; accept only noncritical.
    if next.end < single.end {
        let ext = expect(data, next.end, single.end, 161);
        assert(ext.end == single.end);
        noncritical_extensions(data, ext);
    }
    if responses.end < tbs.end {
        let ext = expect(data, responses.end, tbs.end, 161);
        assert(ext.end == tbs.end);
        noncritical_extensions(data, ext);
    }
    assert((this_update <= produced_at) & (produced_at <= now), "future OCSP response");
    assert((this_update < next_update) & (now < next_update), "expired OCSP response");
    assert(now - this_update <= max_age, "stale OCSP response");
    assert(
        (produced_at >= binding.responder_not_before) & (produced_at < binding.responder_not_after),
        "OCSP signed outside signer validity",
    );
    let freshness_expiry = if max_age >= 18446744073709551615 - this_update {
        18446744073709551615
    } else {
        this_update + max_age + 1
    };
    let expires_at = if freshness_expiry < next_update {
        freshness_expiry
    } else {
        next_update
    };
    UnverifiedGoodResponse { digest, signature, expires_at }
}
fn noncritical_extensions<let N: u32>(data: BoundedVec<u8, N>, outer: Tlv) {
    let seq = expect(data, outer.content, outer.end, 48);
    assert(seq.end == outer.end);
    let mut p = seq.content;
    let mut hashes = [[0; 32]; 8];
    let mut count = 0;
    for i in 0..8 {
        if p < seq.end {
            let ext = expect(data, p, seq.end, 48);
            let oid = expect(data, ext.content, ext.end, 6);
            let oid_bytes = slice::<N, 32>(data, oid.content, oid.len);
            let hash = sha256::sha256_var(oid_bytes.storage(), oid_bytes.len());
            for j in 0..8 {
                if j < count {
                    assert(hash != hashes[j], "duplicate OCSP extension");
                }
            }
            hashes[i] = hash;
            count += 1;
            // DER default FALSE is omitted. Any BOOLEAN therefore means critical.
            let value = expect(data, oid.end, ext.end, 4);
            assert(value.end == ext.end);
            p = ext.end;
        }
    }
    assert(p == seq.end, "too many OCSP extensions");
}
