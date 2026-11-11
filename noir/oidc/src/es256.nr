use crate::{json::{assert_jose_header_algorithm, Claims}, jwt::join_signed_data, JwtInput};
use base64url::decode_canonical;
use sha256::sha256_var;

pub use p256::{TrustedP256Key, verify_p256_digest};

impl<let H: u32, let P: u32, let S: u32> JwtInput<H, P, S> {
    pub fn verify_es256<let I: u32, let A: u32, let U: u32, let N: u32>(
        self,
        expected_issuer: BoundedVec<u8, I>,
        expected_audience: BoundedVec<u8, A>,
        expected_subject: BoundedVec<u8, U>,
        expected_nonce: BoundedVec<u8, N>,
        now: u64,
        trusted_key: TrustedP256Key,
    ) -> Claims {
        self
            .verify_es256_profile(
                expected_issuer,
                expected_audience,
                expected_subject,
                expected_nonce,
                now,
                trusted_key,
                crate::json::PROFILE_FLAT,
            )
            .claims
    }
    pub fn verify_es256_profile<let I: u32, let A: u32, let U: u32, let N: u32>(
        self,
        expected_issuer: BoundedVec<u8, I>,
        expected_audience: BoundedVec<u8, A>,
        expected_subject: BoundedVec<u8, U>,
        expected_nonce: BoundedVec<u8, N>,
        now: u64,
        trusted_key: TrustedP256Key,
        profile: u8,
    ) -> crate::json::ProfileClaims {
        let payload = self.verify_es256_payload(trusted_key);
        let result = crate::json::parse_claims_profile(payload, profile);
        crate::jwt::assert_claims_policy(
            result.claims,
            expected_issuer,
            expected_audience,
            expected_subject,
            expected_nonce,
            now,
        );
        result
    }
    /// As `verify_es256_profile`, and also returns the signed `iat`.
    /// The payload must have exactly one top-level unsigned-integer `iat`,
    /// and `iat <= now`. `verify_es256_profile` keeps its domain.
    pub fn verify_es256_profile_with_iat<let I: u32, let A: u32, let U: u32, let N: u32>(
        self,
        expected_issuer: BoundedVec<u8, I>,
        expected_audience: BoundedVec<u8, A>,
        expected_subject: BoundedVec<u8, U>,
        expected_nonce: BoundedVec<u8, N>,
        now: u64,
        trusted_key: TrustedP256Key,
        profile: u8,
    ) -> crate::json::ClaimsWithIat {
        let payload = self.verify_es256_payload(trusted_key);
        let result = crate::json::parse_claims_profile_with_iat(payload, profile);
        crate::jwt::assert_claims_policy_with_iat(
            result,
            expected_issuer,
            expected_audience,
            expected_subject,
            expected_nonce,
            now,
        );
        result
    }
    /// Verified full JWS payload; the consumer must bind its claims to policy.
    pub fn verify_es256_payload(
        self,
        trusted_key: TrustedP256Key,
    ) -> BoundedVec<u8, ((P + 3) / 4) * 3> {
        assert(
            (self.header_b64.len() <= H)
                & (self.payload_b64.len() <= P)
                & (self.signature_b64.len() <= S),
        );
        let header = decode_canonical(self.header_b64, "non-canonical JOSE header encoding");
        let payload = decode_canonical(self.payload_b64, "non-canonical JOSE payload encoding");
        let signature =
            decode_canonical(self.signature_b64, "non-canonical JOSE signature encoding");
        assert_jose_header_algorithm(header, true);
        assert(signature.len() == 64, "ES256 signature must be raw r||s");
        let mut raw_signature = [0; 64];
        for i in 0..64 {
            raw_signature[i] = signature.storage()[i];
        }
        let signed_data = join_signed_data(self.header_b64, self.payload_b64);
        let digest = sha256_var(signed_data.storage(), signed_data.len());
        verify_p256_digest(trusted_key, raw_signature, digest);
        payload
    }
}

fn fixture() -> JwtInput<64, 128, 86> {
    JwtInput {
        header_b64: BoundedVec::from_array("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9".as_bytes()),
        payload_b64: BoundedVec::from_array(
            "eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJjbGllbnQiLCJzdWIiOiJ1c2VyIiwibm9uY2UiOiJub25jZSIsImV4cCI6MjAwMDAwMDAwMCwibmJmIjoxODAwMDAwMDAwfQ"
                .as_bytes(),
        ),
        signature_b64: BoundedVec::from_array(
            "Jtl3en1iljigiT_951-EuZcZzhJSlS33dnZAMQzCovjDHLl07WSLVFXr-iUKaXaw1VbUUohbw7qkAluwnjvv7g"
                .as_bytes(),
        ),
    }
}
fn key() -> TrustedP256Key {
    TrustedP256Key {
        public_key_x: [
            103, 128, 197, 252, 112, 39, 94, 44, 112, 97, 160, 231, 135, 123, 177, 116, 222, 173,
            235, 152, 135, 2, 127, 63, 168, 54, 84, 21, 139, 167, 245, 12,
        ],
        public_key_y: [
            60, 186, 140, 52, 188, 53, 210, 14, 129, 247, 48, 172, 28, 123, 214, 214, 97, 169, 66,
            249, 12, 106, 156, 165, 92, 81, 47, 158, 74, 0, 18, 102,
        ],
    }
}
fn verify_fixture(token: JwtInput<64, 128, 86>, key: TrustedP256Key, nonce: str<5>, now: u64) {
    let claims = token.verify_es256(
        crate::literal_vec("issuer"),
        crate::literal_vec("client"),
        crate::literal_vec("user"),
        crate::literal_vec(nonce),
        now,
        key,
    );
    assert(claims.expiry == 2000000000);
}
#[test]
fn es256_valid() {
    verify_fixture(fixture(), key(), "nonce", 1900000000);
}
#[test(should_fail_with = "wrong OIDC nonce")]
fn es256_wrong_nonce() {
    verify_fixture(fixture(), key(), "wrong", 1900000000);
}
#[test(should_fail_with = "OIDC token expired")]
fn es256_expired() {
    verify_fixture(fixture(), key(), "nonce", 2000000000);
}
#[test(should_fail_with = "OIDC token not active yet")]
fn es256_not_active() {
    verify_fixture(fixture(), key(), "nonce", 1700000000);
}
#[test(should_fail_with = "ES256 signature verification failed")]
fn es256_invalid_key() {
    let mut k = key();
    k.public_key_x = [0; 32];
    k.public_key_y = [0; 32];
    verify_fixture(fixture(), k, "nonce", 1900000000);
}
#[test(should_fail_with = "ES256 scalar outside curve order")]
fn es256_tampered_signature() {
    let mut t = fixture();
    t.signature_b64 = BoundedVec::from_array(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            .as_bytes(),
    );
    verify_fixture(t, key(), "nonce", 1900000000);
}
#[test(should_fail_with = "unexpected JWS algorithm")]
fn es256_wrong_alg() {
    let mut t = fixture();
    t.header_b64 = BoundedVec::from_array("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9".as_bytes());
    verify_fixture(t, key(), "nonce", 1900000000);
}

#[test]
fn es256_low_s() {
    let mut t = fixture();
    t.signature_b64 = BoundedVec::from_array(
        "Jtl3en1iljigiT_951-EuZcZzhJSlS33dnZAMQzCovg840aKEpt0rKoUBdr1lolO55AmWx672spPt28SXic1Yw"
            .as_bytes(),
    );
    verify_fixture(t, key(), "nonce", 1900000000);
}

#[test(should_fail_with = "ES256 signature must be raw r||s")]
fn es256_short_signature() {
    let mut t = fixture();
    t.signature_b64 = BoundedVec::from_array("AA".as_bytes());
    verify_fixture(t, key(), "nonce", 1900000000);
}

#[test(should_fail_with = "ES256 scalar outside curve order")]
fn es256_reject_zero_s() {
    verify_p256_digest(key(), [0; 64], [0; 32]);
}

#[test(should_fail_with = "ES256 scalar outside curve order")]
fn es256_reject_out_of_range_s() {
    verify_p256_digest(key(), [255; 64], [0; 32]);
}

#[test(should_fail_with = "missing OIDC iat claim")]
fn es256_token_without_iat_rejected() {
    let _ = fixture().verify_es256_profile_with_iat(
        crate::literal_vec("issuer"),
        crate::literal_vec("client"),
        crate::literal_vec("user"),
        crate::literal_vec("nonce"),
        1900000000,
        key(),
        0,
    );
}
