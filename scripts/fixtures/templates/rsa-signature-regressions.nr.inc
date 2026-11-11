// Validate_in_field checks signature < n, so it rejects signature == modulus,
// and the PKCS1v1.5 equation rejects 0 (0^e = 0 is not an encoded message).
// So every accepted signature lies in [1, n - 1].
// The bound alone: validate_in_field rejects a value equal to the modulus.
#[test(should_fail_with = "assert_is_not_zero_integer fail")]
fn rsa2048_validate_in_field_rejects_modulus() {
    let (modulus, redc, _signature) = rsa2048_fixture();
    let mut n = [0 as u128; 18];
    let mut r = [0 as u128; 18];
    for i in 0..18 {
        n[i] = modulus[i] as u128;
        r[i] = redc[i] as u128;
    }
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, n, r);
    RuntimeBigNum::from_array(params, n).validate_in_field();
}

// The full relation: signature == modulus fails the same bound.
#[test(should_fail_with = "assert_is_not_zero_integer fail")]
fn rsa2048_signature_equal_to_modulus_rejected() {
    let (modulus, redc, _signature) = rsa2048_fixture();
    let key: RSAPubkey<18> = RSAPubkey::new(modulus, redc);
    let _ = key.verify_digest_sha256_pkcs1v15(rsa2048_test_digest(), modulus);
}

// The bound alone rejects modulus + 1 (limb 0 is below 2^120 - 1 here).
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rsa2048_validate_in_field_rejects_above_modulus() {
    let (modulus, redc, _signature) = rsa2048_fixture();
    let mut n = [0 as u128; 18];
    let mut r = [0 as u128; 18];
    for i in 0..18 {
        n[i] = modulus[i] as u128;
        r[i] = redc[i] as u128;
    }
    let mut above = n;
    above[0] += 1;
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, n, r);
    RuntimeBigNum::from_array(params, above).validate_in_field();
}

// Redc is a free Barrett hint. redc and redc - 1 both verify the same
// key and signature; only modulus_commitment() (= hash()[0]) is a key
// commitment, and hash()[1] changes with the hint.
#[test]
fn rsa2048_redc_hash_is_not_a_key_commitment() {
    let (modulus, redc, signature) = rsa2048_fixture();
    let mut other_redc = redc;
    other_redc[0] -= 1;
    let key: RSAPubkey<18> = RSAPubkey::new(modulus, redc);
    let other: RSAPubkey<18> = RSAPubkey::new(modulus, other_redc);
    let digest = rsa2048_test_digest();
    assert_eq(key.verify_digest_sha256_pkcs1v15(digest, signature), digest);
    assert_eq(other.verify_digest_sha256_pkcs1v15(digest, signature), digest);
    assert_eq(key.modulus_commitment(), other.modulus_commitment());
    assert_eq(key.modulus_commitment(), key.hash()[0]);
    assert(key.hash()[1] != other.hash()[1]);
}
