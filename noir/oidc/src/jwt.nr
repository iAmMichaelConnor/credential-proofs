use base64url::decode_canonical;
use sha256::sha256_var;

use crate::json::{assert_jose_header_rules, Claims, ClaimsWithIat, PROFILE_FLAT, string_matches};

pub struct JwtInput<let MAX_HEADER_B64: u32, let MAX_PAYLOAD_B64: u32, let MAX_SIG_B64: u32> {
    pub header_b64: BoundedVec<u8, MAX_HEADER_B64>,
    pub payload_b64: BoundedVec<u8, MAX_PAYLOAD_B64>,
    pub signature_b64: BoundedVec<u8, MAX_SIG_B64>,
}

/// RSA key material supplied by the consumer's trust anchor. Callers must
/// constrain these limbs to an issuer key or authenticated key registry.
pub struct TrustedRsaKey {
    pub modulus_limbs: [u128; 18],
    pub redc_params_limbs: [u128; 18],
}

/// RSA4096 trust key for the `verify_rs256_4096_*` entry points.
pub struct TrustedRsa4096Key {
    pub modulus_limbs: [u128; 35],
    pub redc_params_limbs: [u128; 35],
}

impl<let MAX_HEADER_B64: u32, let MAX_PAYLOAD_B64: u32, let MAX_SIG_B64: u32> JwtInput<MAX_HEADER_B64, MAX_PAYLOAD_B64, MAX_SIG_B64> {
    pub fn verify<let MAX_ISS: u32, let MAX_AUD: u32, let MAX_SUB: u32, let MAX_NONCE: u32>(
        self,
        expected_issuer: BoundedVec<u8, MAX_ISS>,
        expected_audience: BoundedVec<u8, MAX_AUD>,
        expected_subject: BoundedVec<u8, MAX_SUB>,
        expected_nonce: BoundedVec<u8, MAX_NONCE>,
        now: u64,
        trusted_key: TrustedRsaKey,
    ) -> Claims {
        self
            .verify_profile(
                expected_issuer,
                expected_audience,
                expected_subject,
                expected_nonce,
                now,
                trusted_key,
                PROFILE_FLAT,
            )
            .claims
    }
    pub fn verify_profile<let MAX_ISS: u32, let MAX_AUD: u32, let MAX_SUB: u32, let MAX_NONCE: u32>(
        self,
        expected_issuer: BoundedVec<u8, MAX_ISS>,
        expected_audience: BoundedVec<u8, MAX_AUD>,
        expected_subject: BoundedVec<u8, MAX_SUB>,
        expected_nonce: BoundedVec<u8, MAX_NONCE>,
        now: u64,
        trusted_key: TrustedRsaKey,
        profile: u8,
    ) -> crate::json::ProfileClaims {
        let payload = self.verify_rs256_payload(trusted_key);
        let result = crate::json::parse_claims_profile(payload, profile);
        assert_claims_policy(
            result.claims,
            expected_issuer,
            expected_audience,
            expected_subject,
            expected_nonce,
            now,
        );
        result
    }
    /// As `verify_profile`, and also returns the signed `iat`. The
    /// payload must have exactly one top-level unsigned-integer `iat`, and
    /// `iat <= now`. `verify` and `verify_profile` keep their domain.
    pub fn verify_profile_with_iat<let MAX_ISS: u32, let MAX_AUD: u32, let MAX_SUB: u32, let MAX_NONCE: u32>(
        self,
        expected_issuer: BoundedVec<u8, MAX_ISS>,
        expected_audience: BoundedVec<u8, MAX_AUD>,
        expected_subject: BoundedVec<u8, MAX_SUB>,
        expected_nonce: BoundedVec<u8, MAX_NONCE>,
        now: u64,
        trusted_key: TrustedRsaKey,
        profile: u8,
    ) -> ClaimsWithIat {
        let payload = self.verify_rs256_payload(trusted_key);
        let result = crate::json::parse_claims_profile_with_iat(payload, profile);
        assert_claims_policy_with_iat(
            result,
            expected_issuer,
            expected_audience,
            expected_subject,
            expected_nonce,
            now,
        );
        result
    }
    /// Verify the original full JWS. Consumers of this low-level API must also
    /// bind parsed identity, nonce, time and assurance to their expected policy.
    pub fn verify_rs256_payload(
        self,
        trusted_key: TrustedRsaKey,
    ) -> BoundedVec<u8, ((MAX_PAYLOAD_B64 + 3) / 4) * 3> {
        self.verify_rs256_payload_with_type(
            trusted_key,
            BoundedVec::<u8, 32>::from_array("JWT".as_bytes()),
            false,
            false,
            false,
        )
    }
    /// Opt-in typed JWS payload. The enrolled caller selects type/content policy;
    /// signed metadata consumers must validate structure, issuer, subject and time.
    pub fn verify_rs256_typed_payload(
        self,
        trusted_key: TrustedRsaKey,
        expected_typ: BoundedVec<u8, 32>,
        require_cty_jwt: bool,
    ) -> BoundedVec<u8, ((MAX_PAYLOAD_B64 + 3) / 4) * 3> {
        self.verify_rs256_payload_with_type(
            trusted_key,
            expected_typ,
            true,
            require_cty_jwt,
            require_cty_jwt,
        )
    }
    /// An ID token whose provider may omit both `typ` and `cty`: each header
    /// member is optional and, when present, must be `JWT`. The caller binds
    /// the claims that make it an ID token (nonce, audience, issuer, time)
    /// and requires a JSON object payload.
    pub fn verify_rs256_id_token_payload(
        self,
        trusted_key: TrustedRsaKey,
    ) -> BoundedVec<u8, ((MAX_PAYLOAD_B64 + 3) / 4) * 3> {
        self.verify_rs256_payload_with_type(
            trusted_key,
            BoundedVec::<u8, 32>::from_array("JWT".as_bytes()),
            false,
            true,
            false,
        )
    }
    fn verify_rs256_payload_with_type(
        self,
        trusted_key: TrustedRsaKey,
        expected_typ: BoundedVec<u8, 32>,
        require_typ: bool,
        allow_cty: bool,
        require_cty_jwt: bool,
    ) -> BoundedVec<u8, ((MAX_PAYLOAD_B64 + 3) / 4) * 3> {
        let (header, payload, signature) = self.decode_canonical_segments();
        assert(signature.len() == 256, "RS256 signature must be 2048 bits");
        assert_jose_header_rules(
            header,
            false,
            expected_typ,
            require_typ,
            allow_cty,
            require_cty_jwt,
        );

        // Decode the exact compact signature to the 18 120-bit limbs used by
        // noir_rsa. This prevents a caller from proving with detached RSA limbs.
        let signature_limbs = rsa_signature::rsa_bytes_to_limbs::<_, 256, 18>(signature);

        // Construct the original signed bytes, including the literal dot.
        let signed_data: BoundedVec<u8, MAX_HEADER_B64 + MAX_PAYLOAD_B64 + 1> =
            join_signed_data(self.header_b64, self.payload_b64);
        let digest = sha256_var(signed_data.storage(), signed_data.len());
        // The trusted modulus must be an odd, exactly 2048-bit integer in
        // canonical limbs, as the host key converter emits.
        rsa_signature::assert_rsa_modulus_shape::<18, 2048>(trusted_key.modulus_limbs);
        let mut modulus = [0 as Field; 18];
        let mut redc = [0 as Field; 18];
        let mut sig = [0 as Field; 18];
        for i in 0..18 {
            modulus[i] = trusted_key.modulus_limbs[i] as Field;
            redc[i] = trusted_key.redc_params_limbs[i] as Field;
            sig[i] = signature_limbs[i] as Field;
        }
        // The same shared relation as the RSA4096 path: key limb ranges
        // (modulus and redc below 2^120 per limb), signature limb ranges,
        // signature <= modulus and the PKCS1v1.5 SHA256 equation.
        let key = rsa_signature::RSAPubkey::<18>::new(modulus, redc);
        key.assert_valid_sha256_digest(digest, sig);

        payload
    }
    pub fn verify_rs256_4096_typed_payload(
        self,
        trusted_key: TrustedRsa4096Key,
        expected_typ: BoundedVec<u8, 32>,
        require_cty_jwt: bool,
    ) -> BoundedVec<u8, ((MAX_PAYLOAD_B64 + 3) / 4) * 3> {
        self.verify_rs256_4096_payload_with_type(
            trusted_key,
            expected_typ,
            true,
            require_cty_jwt,
            require_cty_jwt,
        )
    }
    /// The RSA4096 form of `verify_rs256_id_token_payload`.
    pub fn verify_rs256_4096_id_token_payload(
        self,
        trusted_key: TrustedRsa4096Key,
    ) -> BoundedVec<u8, ((MAX_PAYLOAD_B64 + 3) / 4) * 3> {
        self.verify_rs256_4096_payload_with_type(
            trusted_key,
            BoundedVec::<u8, 32>::from_array("JWT".as_bytes()),
            false,
            true,
            false,
        )
    }
    fn verify_rs256_4096_payload_with_type(
        self,
        trusted_key: TrustedRsa4096Key,
        expected_typ: BoundedVec<u8, 32>,
        require_typ: bool,
        allow_cty: bool,
        require_cty_jwt: bool,
    ) -> BoundedVec<u8, ((MAX_PAYLOAD_B64 + 3) / 4) * 3> {
        let (header, payload, signature) = self.decode_canonical_segments();
        assert(signature.len() == 512, "RS256 signature must be 4096 bits");
        assert_jose_header_rules(
            header,
            false,
            expected_typ,
            require_typ,
            allow_cty,
            require_cty_jwt,
        );
        let limbs = rsa_signature::rsa_bytes_to_limbs::<_, 512, 35>(signature);
        rsa_signature::assert_rsa_modulus_shape::<35, 4096>(trusted_key.modulus_limbs);
        let mut modulus = [0 as Field; 35];
        let mut redc = [0 as Field; 35];
        let mut sig = [0 as Field; 35];
        for i in 0..35 {
            modulus[i] = trusted_key.modulus_limbs[i] as Field;
            redc[i] = trusted_key.redc_params_limbs[i] as Field;
            sig[i] = limbs[i] as Field;
        }
        let signed_data = join_signed_data(self.header_b64, self.payload_b64);
        let digest = sha256_var(signed_data.storage(), signed_data.len());
        let key = rsa_signature::RSAPubkey::<35>::new(modulus, redc);
        // This unit API ASSERTS signature validity. signature.nr's
        // generic verify_digest<35,4096> internally asserts PKCS1v1.5 validity,
        // after signature/key range and signature <= modulus constraints
        // (signature = modulus then fails the PKCS1v1.5 equation). An
        // invalid signature fails that relation before this call can return.
        key.assert_valid_sha256_digest(digest, sig);
        payload
    }
    /// Canonical protected header bytes. This is decoding only: consumers must
    /// separately call a signature verifier before trusting header claims.
    pub fn header_json(self) -> BoundedVec<u8, ((MAX_HEADER_B64 + 3) / 4) * 3> {
        assert(self.header_b64.len() <= MAX_HEADER_B64, "header segment exceeds capacity");
        decode_canonical(self.header_b64, "non-canonical JOSE header encoding")
    }

    fn decode_canonical_segments(
        self,
    ) -> (BoundedVec<u8, ((MAX_HEADER_B64 + 3) / 4) * 3>, BoundedVec<u8, ((MAX_PAYLOAD_B64 + 3) / 4) * 3>, BoundedVec<u8, ((MAX_SIG_B64 + 3) / 4) * 3>) {
        assert(self.header_b64.len() <= MAX_HEADER_B64, "header segment exceeds capacity");
        assert(self.payload_b64.len() <= MAX_PAYLOAD_B64, "payload segment exceeds capacity");
        assert(self.signature_b64.len() <= MAX_SIG_B64, "signature segment exceeds capacity");
        let header = self.header_json();
        let payload = decode_canonical(self.payload_b64, "non-canonical JOSE payload encoding");
        let signature =
            decode_canonical(self.signature_b64, "non-canonical JOSE signature encoding");
        (header, payload, signature)
    }
}

pub(crate) fn join_signed_data<let H: u32, let P: u32>(
    header: BoundedVec<u8, H>,
    payload: BoundedVec<u8, P>,
) -> BoundedVec<u8, H + P + 1> {
    let mut result = BoundedVec::<u8, H + P + 1>::new();
    for i in 0..H {
        if i < header.len() {
            result.push(header.storage()[i]);
        }
    }
    result.push(46);
    for i in 0..P {
        if i < payload.len() {
            result.push(payload.storage()[i]);
        }
    }
    result
}

#[test]
fn test_google_synthetic_rs256_token() {
    let token = google_synthetic_token();
    let claims = token.verify(
        crate::json::literal_vec("https://accounts.google.com"),
        crate::json::literal_vec("test-client"),
        crate::json::literal_vec("synthetic-user"),
        crate::json::literal_vec("test-nonce"),
        1900000000,
        synthetic_trusted_key(),
    );
    assert(claims.expiry == 2000000000);
}

#[test]
fn test_apple_synthetic_rs256_token() {
    let token = apple_synthetic_token();
    let claims = token.verify(
        crate::json::literal_vec("https://appleid.apple.com"),
        crate::json::literal_vec("test-client"),
        crate::json::literal_vec("synthetic-user"),
        crate::json::literal_vec("test-nonce"),
        1900000000,
        synthetic_trusted_key(),
    );
    assert(claims.expiry == 2000000000);
}

#[test(should_fail_with = "wrong OIDC nonce")]
fn test_reject_google_token_with_wrong_nonce() {
    let _claims = google_synthetic_token().verify(
        crate::json::literal_vec("https://accounts.google.com"),
        crate::json::literal_vec("test-client"),
        crate::json::literal_vec("synthetic-user"),
        crate::json::literal_vec("different-nonce"),
        1900000000,
        synthetic_trusted_key(),
    );
}

#[test(should_fail_with = "OIDC token expired")]
fn test_reject_expired_apple_token() {
    let _claims = apple_synthetic_token().verify(
        crate::json::literal_vec("https://appleid.apple.com"),
        crate::json::literal_vec("test-client"),
        crate::json::literal_vec("synthetic-user"),
        crate::json::literal_vec("test-nonce"),
        2000000000,
        synthetic_trusted_key(),
    );
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
fn test_reject_google_token_with_wrong_trusted_key() {
    let _claims = google_synthetic_token().verify(
        crate::json::literal_vec("https://accounts.google.com"),
        crate::json::literal_vec("test-client"),
        crate::json::literal_vec("synthetic-user"),
        crate::json::literal_vec("test-nonce"),
        1900000000,
        wrong_trusted_key(),
    );
}

fn verify_google_with_key(key: TrustedRsaKey) {
    let _claims = google_synthetic_token().verify(
        crate::json::literal_vec("https://accounts.google.com"),
        crate::json::literal_vec("test-client"),
        crate::json::literal_vec("synthetic-user"),
        crate::json::literal_vec("test-nonce"),
        1900000000,
        key,
    );
}

// The same modulus integer in non-canonical limbs. The shape check rejects
// every such alias; without it the rejection would be data dependent.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_reject_trusted_modulus_limb_alias() {
    let mut key = synthetic_trusted_key();
    key.modulus_limbs[15] += 1 << 120;
    key.modulus_limbs[16] -= 1;
    verify_google_with_key(key);
}

// The same Barrett parameter in non-canonical limbs: redc limbs are range
// checked, not only passed to the unconstrained Barrett hint.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_reject_trusted_redc_limb_alias() {
    let mut key = synthetic_trusted_key();
    key.redc_params_limbs[0] += 1 << 120;
    key.redc_params_limbs[1] -= 1;
    verify_google_with_key(key);
}

// End-to-end rejections only: a changed modulus also breaks the PKCS1v1.5
// equation, so these do not isolate the shape check. The encoding.nr
// modulus_shape_* tests pin the shape constraint itself.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_reject_even_trusted_modulus() {
    let mut key = synthetic_trusted_key();
    key.modulus_limbs[0] -= 1;
    verify_google_with_key(key);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_reject_short_trusted_modulus() {
    let mut key = synthetic_trusted_key();
    key.modulus_limbs[17] -= 128;
    verify_google_with_key(key);
}

fn google_synthetic_token() -> JwtInput<128, 256, 342> {
    let token: JwtInput<128, 256, 342> = JwtInput {
        header_b64: BoundedVec::from_array(
            "eyJhbGciOiJSUzI1NiIsImtpZCI6InN5bnRoZXRpYy10ZXN0LWtleSIsInR5cCI6IkpXVCJ9".as_bytes(),
        ),
        payload_b64: BoundedVec::from_array(
            "eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiJ0ZXN0LWNsaWVudCIsInN1YiI6InN5bnRoZXRpYy11c2VyIiwibm9uY2UiOiJ0ZXN0LW5vbmNlIiwiZXhwIjoyMDAwMDAwMDAwfQ"
                .as_bytes(),
        ),
        signature_b64: BoundedVec::from_array(
            "OwmKhA-CneZU-vULn5ePdLqoj-L_XSCJrb3qo5jhZ_Fi6Dx4g8iHii2a6ue2Ptyi82L1Q-jfVkah8z7HszQuStQXTcgNn6cw9NeTXfargDsxsuZ-IgZIxTEcj1bHj9QT9Ku7mJfvCfUXlX8Gv2RvL4LDA_5gHu7v07IncZgjGKQUPWepxSplnG_c8WX_qi9D__4T2uuTuKn9FjBH_dAu0n_ybY2VAEAf7ZBeA6NBaT3xDY--nqFjrJ-15drXBcSxePtoFy7NIie_g1BiuGa0ZpGQ0IWrMriPX0EOrqrNPLwONyVQTQJj7egO_iTdWDq-N0a7k8igMPB1NkvnrXXYcg"
                .as_bytes(),
        ),
    };
    token
}

fn apple_synthetic_token() -> JwtInput<128, 256, 342> {
    let token: JwtInput<128, 256, 342> = JwtInput {
        header_b64: BoundedVec::from_array(
            "eyJhbGciOiJSUzI1NiIsImtpZCI6InN5bnRoZXRpYy10ZXN0LWtleSIsInR5cCI6IkpXVCJ9".as_bytes(),
        ),
        payload_b64: BoundedVec::from_array(
            "eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoidGVzdC1jbGllbnQiLCJzdWIiOiJzeW50aGV0aWMtdXNlciIsIm5vbmNlIjoidGVzdC1ub25jZSIsImV4cCI6MjAwMDAwMDAwMH0"
                .as_bytes(),
        ),
        signature_b64: BoundedVec::from_array(
            "H9bLZK5FDsfVrMuQ6P71FtKPfEpx9NRaZcF-YhQePurTQG_66_GOfeRYbKbZ5iraG3SK02O0O5V7JIc7OpqOVJs7B4qacWd6L88urEYqe8PdKGg1_9Gwba4WUa--Oi6Q5ehIZpYK3gm5adf_i5dmGnBJWnFSj3VsKsvcnuV0rDQu9OVjPdNLvTH975Cea6z8vV7R8_T08mL4Y0q5IxSrSohhV_5XuYDhdqEKuE4ngEOBTeIb7B0KB6E1JczZxeKnGo_q9P3EZs2TRYZnXDbMEPha7bI1LKi1CaPmfFGEX5VDbcj9KR9KQXLx7GrNAwElqlbvf0X1vHzyO3jhUHQlkA"
                .as_bytes(),
        ),
    };
    token
}

fn synthetic_trusted_key() -> TrustedRsaKey {
    TrustedRsaKey {
        modulus_limbs: [
            0xda6cfc5f870c05b6f75e3e9aa19bb3,
            0x2f5675116c5f590e0ab2159b84db94,
            0x97805070b9e03bf83d5ecb85bce968,
            0x192617078a60d89d3577553d1fafb3,
            0x506ceb2f2ada149a375be70c826de0,
            0xcd2672df84d96ea3e3204f8035d4d3,
            0x26236c3dee9191b4fabe1323960236,
            0x63baa74665af7c907e7525e6bd55f7,
            0xb025db6c92cefd4a1fc9bf0342f858,
            0x29adcbd0a22aef7afe47924f03c840,
            0x7dbb16685cec6a16c7c1ffd183d7a0,
            0x20d7921a432f12de27529ec873142e,
            0xb6304c10144f79eff82838fa981642,
            0x01f3a7d4371751307d534a2ec7316e,
            0xd3f3ce398ebc09396990ed26533907,
            0xafbada4807e5b71923aa419d6debe0,
            0xbffde4b1de62eeafeabbfceacb1b70,
            0xaa,
        ],
        redc_params_limbs: [
            0x7ed7897777daa1dc3698c18d3d8912,
            0x99ded586deace09c498243106a9406,
            0xe9da55952cf7945eea93c942284234,
            0xb2fc5df7e4eace614254c97f995720,
            0xc42fbf8ee51af34fc9722d80f895ac,
            0x7175101078dfed8b0f7807c18cbd75,
            0x0d9669f67808f303c37441a3ca7470,
            0xb6fde8fc7c901124dbdb8c908111f8,
            0xca33ad384d637829b7ff0fe7383687,
            0xa3f8bab5cb9e4afe27fea57b72318d,
            0x5fbc0b0f652617de021b2ee16a2417,
            0x566ed6402c79aa768f0214dcbb8ca2,
            0x9129ef2d1610323f43c21f4a07ed44,
            0x0cea57c3d520cd3bd10b9339806537,
            0xb5af2e6cfb2d2a784d2b29dfae4beb,
            0xe0080c7d76560c9429abeacdbeae15,
            0x02aee033de067894291b5e2a89a8cd,
            0x5ff4,
        ],
    }
}

fn wrong_trusted_key() -> TrustedRsaKey {
    TrustedRsaKey {
        modulus_limbs: [
            0x8dd1c83fc27a4dd4032aed4609f041,
            0x78ef5e369c4d848386668ae3029687,
            0xc1547dde48a4ec60cb2d10488fa3b0,
            0x941f35fedc3bfa1c1ae2adb4fde932,
            0x45a86b99bd5323965dfed891d728f8,
            0x365a258b1507ff1da265efcec3a6ac,
            0xbe4a450c53376fab9b14389e5f3f96,
            0x4046a7d3fef501b3f22f15edc2723e,
            0xfbacfaa9083ae60b8754fccb89eef5,
            0xeefcd571ed04a35463f6a17aeafd8a,
            0x50f8b31e3e2adbc7afcbb1658b8788,
            0x6e1a0e6e98177d9fd645374d80a95c,
            0xef7d746f0e54944b41c18969e0c45c,
            0x2615f59cc0a5c396864ceccd86c3af,
            0x111898d09befaf7df6712cd41ffd01,
            0x2390035cb2e0e48c7cca5c0990d823,
            0x153b7e3646b8c5ab5590bd8753e5e8,
            0xbe,
        ],
        redc_params_limbs: [
            0xaadb25a42774dada382dd6310e2f68,
            0xf330192a7f74f969c78d2c1b6e0d78,
            0x73d87706c7944bf0913eded5be1697,
            0xc79e6c597730e4fba1433037f9250b,
            0x250cf957a25fb7bc4eb690ede04fa5,
            0xea49b182d620a8f37a2d94860f9f0f,
            0x4969e5998f56931375ae929bea0cee,
            0xe6d6d414464c7bfbcca4501f2283b9,
            0x51b4224413b1be9d9c54369738eb84,
            0x361177fed6dc26c9da597a6b3a8518,
            0x8d7a9fc1a96de3a4d1906d1af314c7,
            0x9503ffb9533f4ade500c42f93139f5,
            0x55ec1d07c413cfd952c5174163246a,
            0x5da69be8900dc72593a084507c7429,
            0x5f161afadea390f4272816c004a252,
            0x1ffc6cf95093a8d1d38d11a86d1c03,
            0xa6eefae4e8ca98233ee3c553e4c065,
            0x5631,
        ],
    }
}

pub fn assert_claims_policy<let I: u32, let A: u32, let U: u32, let N: u32>(
    claims: Claims,
    expected_issuer: BoundedVec<u8, I>,
    expected_audience: BoundedVec<u8, A>,
    expected_subject: BoundedVec<u8, U>,
    expected_nonce: BoundedVec<u8, N>,
    now: u64,
) {
    assert(string_matches(claims.issuer, expected_issuer), "wrong OIDC issuer");
    assert_claims_binding(
        claims,
        expected_audience,
        expected_subject,
        expected_nonce,
        now,
    );
}
/// The audience, subject, nonce and time rules of `assert_claims_policy`. The
/// caller checks the issuer first.
pub(crate) fn assert_claims_binding<let A: u32, let U: u32, let N: u32>(
    claims: Claims,
    expected_audience: BoundedVec<u8, A>,
    expected_subject: BoundedVec<u8, U>,
    expected_nonce: BoundedVec<u8, N>,
    now: u64,
) {
    assert(string_matches(claims.audience, expected_audience), "wrong OIDC audience");
    assert(string_matches(claims.subject, expected_subject), "wrong OIDC subject");
    assert(string_matches(claims.nonce, expected_nonce), "wrong OIDC nonce");
    assert(claims.expiry > now, "OIDC token expired");
    assert(!claims.has_not_before | (claims.not_before <= now), "OIDC token not active yet");
}

/// `assert_claims_policy`, and the signed issue time is not after `now`.
pub fn assert_claims_policy_with_iat<let I: u32, let A: u32, let U: u32, let N: u32>(
    result: ClaimsWithIat,
    expected_issuer: BoundedVec<u8, I>,
    expected_audience: BoundedVec<u8, A>,
    expected_subject: BoundedVec<u8, U>,
    expected_nonce: BoundedVec<u8, N>,
    now: u64,
) {
    assert_claims_policy(
        result.claims,
        expected_issuer,
        expected_audience,
        expected_subject,
        expected_nonce,
        now,
    );
    assert(result.issued_at <= now, "OIDC token issued in the future");
}

#[test(should_fail_with = "missing OIDC iat claim")]
fn signed_token_without_iat_rejected() {
    // The synthetic Google token has no iat: verify accepts it (above), the
    // iat-reading verifier does not.
    let _ = google_synthetic_token().verify_profile_with_iat(
        crate::json::literal_vec("https://accounts.google.com"),
        crate::json::literal_vec("test-client"),
        crate::json::literal_vec("synthetic-user"),
        crate::json::literal_vec("test-nonce"),
        1900000000,
        synthetic_trusted_key(),
        PROFILE_FLAT,
    );
}
