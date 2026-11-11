pub struct Rsa2048Key {
    pub modulus: [u8; 256],
    pub redc: [u128; 18],
}
pub fn limbs(bytes: [u8; 256]) -> [u128; 18] {
    rsa_signature::rsa_bytes_to_limbs::<256, 256, 18>(BoundedVec::from_array(bytes))
}

pub fn verify_digest(key: Rsa2048Key, digest: [u8; 32], signature: [u8; 256]) {
    assert(key.modulus[0] >= 128, "RSA modulus must be 2048 bits");
    assert((key.modulus[255] & 1) == 1, "RSA modulus must be odd");
    let n = limbs(key.modulus);
    let sig = limbs(signature);
    let mut modulus = [0 as Field; 18];
    let mut redc = [0 as Field; 18];
    let mut signature_limbs = [0 as Field; 18];
    for i in 0..18 {
        modulus[i] = n[i] as Field;
        redc[i] = key.redc[i] as Field;
        signature_limbs[i] = sig[i] as Field;
    }
    let public_key = rsa_signature::RSAPubkey::<18>::new(modulus, redc);
    let _verified = public_key.verify_digest_sha256_pkcs1v15(digest, signature_limbs);
}

/// RSA4096 issuer key, using the same canonical 120-bit limb representation.
pub struct Rsa4096Key {
    pub modulus: [u8; 512],
    pub redc: [u128; 35],
}
fn key4096(key: Rsa4096Key) -> rsa_signature::RSAPubkey<35> {
    assert(key.modulus[0] >= 128, "RSA modulus must be4096 bits");
    assert((key.modulus[511] & 1) == 1, "RSA modulus must be odd");
    let n = rsa_signature::rsa_bytes_to_limbs::<512, 512, 35>(BoundedVec::from_array(key.modulus));
    let mut modulus = [0 as Field; 35];
    let mut redc = [0 as Field; 35];
    for i in 0..35 {
        modulus[i] = n[i] as Field;
        redc[i] = key.redc[i] as Field;
    }
    rsa_signature::RSAPubkey::<35>::new(modulus, redc)
}
fn signature4096(signature: [u8; 512]) -> [Field; 35] {
    let values =
        rsa_signature::rsa_bytes_to_limbs::<512, 512, 35>(BoundedVec::from_array(signature));
    let mut out = [0 as Field; 35];
    for i in 0..35 {
        out[i] = values[i] as Field;
    }
    out
}
pub fn verify_digest_4096_sha256(key: Rsa4096Key, digest: [u8; 32], signature: [u8; 512]) {
    key4096(key).assert_valid_sha256_digest(digest, signature4096(signature));
}
pub fn verify_digest_4096_sha512(key: Rsa4096Key, digest: [u8; 64], signature: [u8; 512]) {
    key4096(key).assert_valid_sha512_digest(digest, signature4096(signature));
}
