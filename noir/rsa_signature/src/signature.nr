use crate::{
    hash::{poseidon_large, poseidon_large_padded_1024},
    KEY_LIMBS_1024,
    KEY_LIMBS_2048,
    RSA_EXPONENT,
};
use bignum::{params::BigNumParams, RuntimeBigNum};
use rsa::rsa::verify_sha256_pkcs1v15;
use sha256::sha256_var;

pub struct RSAPubkey<let KEY_LIMBS: u32> {
    modulus: [Field; KEY_LIMBS],
    redc: [Field; KEY_LIMBS],
}

impl<let KEY_LIMBS: u32> RSAPubkey<KEY_LIMBS> {

    pub fn new(modulus: [Field; KEY_LIMBS], redc: [Field; KEY_LIMBS]) -> Self {
        let pubkey = Self { modulus, redc };
        pubkey
    }
}

impl RSAPubkey<KEY_LIMBS_1024> {
    /// Assert RSA PKCS1v1.5 SHA256 signature validity over an already-bound digest.
    /// Returns unit; verification constraints execute inside the shared verifier.
    pub fn assert_valid_sha256_digest(self, digest: [u8; 32], signature: [Field; KEY_LIMBS_1024]) {
        let _verified_digest = self.verify_digest_sha256_pkcs1v15(digest, signature);
    }

    /// Compatibility alias. Generic message callers use verify_rsa_sha256_pkcs1v15.
    pub fn verify_dkim_signature<let MAX_HEADER_LENGTH: u32>(
        self,
        header: BoundedVec<u8, MAX_HEADER_LENGTH>,
        signature: [Field; KEY_LIMBS_1024],
    ) -> [u8; 32] {
        self.verify_rsa_sha256_pkcs1v15(header, signature)
    }

    /// Hash and verify the exact supplied message bytes.
    pub fn verify_rsa_sha256_pkcs1v15<let MAX_MESSAGE_LENGTH: u32>(
        self,
        message: BoundedVec<u8, MAX_MESSAGE_LENGTH>,
        signature: [Field; KEY_LIMBS_1024],
    ) -> [u8; 32] {
        let digest = sha256_var(message.storage(), message.len() as u32);
        self.verify_digest_sha256_pkcs1v15(digest, signature)
    }

    /// Verify an already-computed SHA256 digest. The caller must constrain
    /// digest to its authenticated message; this method does not hash again.
    pub fn verify_digest_sha256_pkcs1v15(
        self,
        digest: [u8; 32],
        signature: [Field; KEY_LIMBS_1024],
    ) -> [u8; 32] {
        self.validate_in_range();
        verify_digest::<9, 1024>(self.modulus, self.redc, digest, signature)
    }

    /// [modulus commitment, redc hint hash]. Only element 0 identifies the
    /// key. The circuit never constrains redc to the Barrett reciprocal of the
    /// modulus: several redc values verify the same key and signature, so
    /// element 1 must never serve as a key identifier, registry or denylist
    /// entry, or nullifier input. Prefer modulus_commitment().
    pub fn hash(self) -> [Field; 2] {
        // validate
        self.validate_in_range();
        [poseidon_large_padded_1024(self.modulus), poseidon_large_padded_1024(self.redc)]
    }

    /// The key commitment: a Poseidon hash of the range-checked modulus limbs.
    /// Equal to hash()[0].
    pub fn modulus_commitment(self) -> Field {
        self.validate_in_range();
        poseidon_large_padded_1024(self.modulus)
    }

    pub fn validate_in_range(self) {
        for i in 0..(KEY_LIMBS_1024 - 1) {
            self.modulus[i].assert_max_bit_size::<120>();
            self.redc[i].assert_max_bit_size::<120>();
        }
        self.modulus[KEY_LIMBS_1024 - 1].assert_max_bit_size::<1024 - ((KEY_LIMBS_1024 - 1) * 120)>();
        self.redc[KEY_LIMBS_1024 - 1].assert_max_bit_size::<120>();
    }
}

impl RSAPubkey<KEY_LIMBS_2048> {
    /// Assert RSA PKCS1v1.5 SHA256 signature validity over an already-bound digest.
    /// Returns unit; verification constraints execute inside the shared verifier.
    pub fn assert_valid_sha256_digest(self, digest: [u8; 32], signature: [Field; KEY_LIMBS_2048]) {
        let _verified_digest = self.verify_digest_sha256_pkcs1v15(digest, signature);
    }

    /// Compatibility alias. Generic message callers use verify_rsa_sha256_pkcs1v15.
    pub fn verify_dkim_signature<let MAX_HEADER_LENGTH: u32>(
        self,
        header: BoundedVec<u8, MAX_HEADER_LENGTH>,
        signature: [Field; KEY_LIMBS_2048],
    ) -> [u8; 32] {
        self.verify_rsa_sha256_pkcs1v15(header, signature)
    }

    /// Hash and verify the exact supplied message bytes.
    pub fn verify_rsa_sha256_pkcs1v15<let MAX_MESSAGE_LENGTH: u32>(
        self,
        message: BoundedVec<u8, MAX_MESSAGE_LENGTH>,
        signature: [Field; KEY_LIMBS_2048],
    ) -> [u8; 32] {
        let digest = sha256_var(message.storage(), message.len() as u32);
        self.verify_digest_sha256_pkcs1v15(digest, signature)
    }

    /// Verify an already-computed SHA256 digest. The caller must constrain
    /// digest to its authenticated message; this method does not hash again.
    pub fn verify_digest_sha256_pkcs1v15(
        self,
        digest: [u8; 32],
        signature: [Field; KEY_LIMBS_2048],
    ) -> [u8; 32] {
        self.validate_in_range();
        verify_digest::<18, 2048>(self.modulus, self.redc, digest, signature)
    }

    /// [modulus commitment, redc hint hash]. Only element 0 identifies the
    /// key; element 1 is not a key commitment (see the RSA1024 hash).
    pub fn hash(self) -> [Field; 2] {
        // validate range
        self.validate_in_range();
        [poseidon_large(self.modulus), poseidon_large(self.redc)]
    }

    /// The key commitment: a Poseidon hash of the range-checked modulus limbs.
    /// Equal to hash()[0].
    pub fn modulus_commitment(self) -> Field {
        self.validate_in_range();
        poseidon_large(self.modulus)
    }

    pub fn validate_in_range(self) {
        for i in 0..(KEY_LIMBS_2048 - 1) {
            self.modulus[i].assert_max_bit_size::<120>();
            self.redc[i].assert_max_bit_size::<120>();
        }
        self.modulus[KEY_LIMBS_2048 - 1].assert_max_bit_size::<2048 - ((KEY_LIMBS_2048 - 1) * 120)>();
        self.redc[KEY_LIMBS_2048 - 1].assert_max_bit_size::<120>();
    }
}

// convert a Field array to a u128 array with generic number of limbs
fn convert_field_to_u128<let KEY_LIMBS: u32>(signature: [Field; KEY_LIMBS]) -> [u128; KEY_LIMBS] {
    let mut u128_signature: [u128; KEY_LIMBS] = [0; KEY_LIMBS];
    for i in 0..KEY_LIMBS {
        // Every caller first constrains these fields to less than 2^120, so
        // this narrowing cast is exact and needs no duplicate equality check.
        u128_signature[i] = signature[i] as u128;
    }
    u128_signature
}

fn validate_field_limbs_in_range<let KEY_LIMBS: u32, let MOD_BITS: u32>(limbs: [Field; KEY_LIMBS]) {
    for i in 0..(KEY_LIMBS - 1) {
        limbs[i].assert_max_bit_size::<120>();
    }
    limbs[KEY_LIMBS - 1].assert_max_bit_size::<MOD_BITS - ((KEY_LIMBS - 1) * 120)>();
}

// One generic cryptographic relation, shared by all supported modulus sizes.
fn verify_digest<let K: u32, let B: u32>(
    modulus: [Field; K],
    redc: [Field; K],
    digest: [u8; 32],
    signature: [Field; K],
) -> [u8; 32] {
    validate_field_limbs_in_range::<K, B>(signature);
    let params: BigNumParams<K, B> = BigNumParams::new(
        false,
        convert_field_to_u128(modulus),
        convert_field_to_u128(redc),
    );
    let value = RuntimeBigNum::from_array(params, convert_field_to_u128(signature));
    value.validate_in_field();
    assert(
        verify_sha256_pkcs1v15::<K, B>(digest, value, RSA_EXPONENT),
        "RSA signature verification failed",
    );
    digest
}

impl RSAPubkey<35> {
    /// Assert RSA PKCS1v1.5 SHA256 signature validity over an already-bound digest.
    /// Returns unit; verification constraints execute inside the shared verifier.
    pub fn assert_valid_sha256_digest(self, digest: [u8; 32], signature: [Field; 35]) {
        let _verified_digest = self.verify_digest_sha256_pkcs1v15(digest, signature);
    }

    pub fn verify_rsa_sha256_pkcs1v15<let N: u32>(
        self,
        message: BoundedVec<u8, N>,
        signature: [Field; 35],
    ) -> [u8; 32] {
        self.verify_digest_sha256_pkcs1v15(sha256_var(message.storage(), message.len()), signature)
    }
    pub fn verify_digest_sha256_pkcs1v15(
        self,
        digest: [u8; 32],
        signature: [Field; 35],
    ) -> [u8; 32] {
        self.validate_in_range();
        verify_digest::<35, 4096>(self.modulus, self.redc, digest, signature)
    }
    pub fn validate_in_range(self) {
        validate_field_limbs_in_range::<35, 4096>(self.modulus);
        for i in 0..35 {
            self.redc[i].assert_max_bit_size::<120>();
        }
    }
}

// SHA512 digests, for PKIX issuers.
fn assert_digest_sha512<let K: u32, let B: u32>(
    modulus: [Field; K],
    redc: [Field; K],
    digest: [u8; 64],
    signature: [Field; K],
) {
    validate_field_limbs_in_range::<K, B>(signature);
    let params: BigNumParams<K, B> = BigNumParams::new(
        false,
        convert_field_to_u128(modulus),
        convert_field_to_u128(redc),
    );
    let value = RuntimeBigNum::from_array(params, convert_field_to_u128(signature));
    value.validate_in_field();
    assert(
        rsa::rsa::verify_sha512_pkcs1v15::<K, B>(digest, value, RSA_EXPONENT),
        "RSA SHA512 signature verification failed",
    );
}
impl RSAPubkey<9> {
    pub fn assert_valid_sha512_digest(self, digest: [u8; 64], signature: [Field; 9]) {
        self.validate_in_range();
        assert_digest_sha512::<9, 1024>(self.modulus, self.redc, digest, signature);
    }
}
impl RSAPubkey<18> {
    pub fn assert_valid_sha512_digest(self, digest: [u8; 64], signature: [Field; 18]) {
        self.validate_in_range();
        assert_digest_sha512::<18, 2048>(self.modulus, self.redc, digest, signature);
    }
}
impl RSAPubkey<35> {
    pub fn assert_valid_sha512_digest(self, digest: [u8; 64], signature: [Field; 35]) {
        self.validate_in_range();
        assert_digest_sha512::<35, 4096>(self.modulus, self.redc, digest, signature);
    }
}
