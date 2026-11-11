// Official published staging vector and separate public local synthetic issuer.
use crate::{AuthInput, AuthPolicy};
pub fn official_fixture() -> (AuthInput, oidc::TrustedP256Key, AuthPolicy, BoundedVec<u8, 64>, u64) {
    (
        AuthInput {
            header_b64: BoundedVec::from_array(
                "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFsaWFzL3N0Zy1zcC1hdXRoLWFwaS1pZC10b2tlbi1zaWduaW5nLWtleS1rbXMtYXN5bW1ldHJpYy1rZXktYWxpYXMifQ"
                    .as_bytes(),
            ),
            payload_b64: BoundedVec::from_array(
                "eyJpYXQiOjE3Njk3Mzk4MjMsImV4cCI6MTc2OTc0MDQyMywiaXNzIjoiaHR0cHM6Ly9zdGctaWQuc2luZ3Bhc3MuZ292LnNnL2ZhcGkiLCJzdWIiOiI3YzljNzJlYy01YmUyLTQ5NWEtYTc4ZS02MWU4MDlhMmEyMzYiLCJhdWQiOiJSc3JPeTJpQjBlZFI1M1RKU3VENVVMYWQxcEdtclZaTCIsImFtciI6WyJwd2QiXSwic3ViX2F0dHJpYnV0ZXMiOnsibmFtZSI6Ik5BTUUgT0YgUzU0MTA4MjhBIn0sInN1Yl90eXBlIjoidXNlciIsIm5vbmNlIjoiV2pxVU1NbU9ldllPWG13QzI3bWNBUVdzRkJuM083d3doYlJJdGwyRkprOCIsImFjciI6InVybjpzaW5ncGFzczphdXRoZW50aWNhdGlvbjpsb2E6MSJ9"
                    .as_bytes(),
            ),
            signature_b64: BoundedVec::from_array(
                "pI0nhe0BLToMbuZ-9lpQiBNj2sj_ZWJwYFMT83u4yewZupTClPLUeYp08RR_sV2I70H6qpVmydRmoH8R9SipHQ"
                    .as_bytes(),
            ),
        },
        oidc::TrustedP256Key {
            public_key_x: [
                37, 108, 69, 78, 217, 222, 82, 51, 50, 104, 215, 250, 109, 178, 220, 183, 127, 199,
                3, 14, 45, 118, 246, 161, 81, 159, 11, 209, 39, 154, 145, 107,
            ],
            public_key_y: [
                131, 234, 87, 191, 226, 102, 244, 214, 244, 71, 238, 239, 229, 238, 80, 113, 62,
                199, 188, 220, 193, 201, 122, 116, 117, 224, 40, 198, 233, 95, 87, 217,
            ],
        },
        AuthPolicy {
            audience: BoundedVec::from_array([
                82, 115, 114, 79, 121, 50, 105, 66, 48, 101, 100, 82, 53, 51, 84, 74, 83, 117, 68,
                53, 85, 76, 97, 100, 49, 112, 71, 109, 114, 86, 90, 76,
            ]),
            subject: BoundedVec::from_array([
                55, 99, 57, 99, 55, 50, 101, 99, 45, 53, 98, 101, 50, 45, 52, 57, 53, 97, 45, 97,
                55, 56, 101, 45, 54, 49, 101, 56, 48, 57, 97, 50, 97, 50, 51, 54,
            ]),
            environment: 1,
            minimum_assurance: 1,
        },
        BoundedVec::from_array([
            87, 106, 113, 85, 77, 77, 109, 79, 101, 118, 89, 79, 88, 109, 119, 67, 50, 55, 109, 99,
            65, 81, 87, 115, 70, 66, 110, 51, 79, 55, 119, 119, 104, 98, 82, 73, 116, 108, 50, 70,
            74, 107, 56,
        ]), 1769739823,
    )
}
pub fn local_fixture() -> (AuthInput, oidc::TrustedP256Key, AuthPolicy, BoundedVec<u8, 64>, u64) {
    (
        AuthInput {
            header_b64: BoundedVec::from_array(
                "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImxvY2FsLXN5bnRoZXRpYy1zaW5ncGFzcyJ9"
                    .as_bytes(),
            ),
            payload_b64: BoundedVec::from_array(
                "eyJpc3MiOiJodHRwczovL2lkLnNpbmdwYXNzLmdvdi5zZy9mYXBpIiwiYXVkIjoibG9jYWwtc3ludGhldGljLXNpbmdwYXNzLWNsaWVudCIsInN1YiI6ImxvY2FsLXN5bnRoZXRpYy1zaW5ncGFzcy11c2VyIiwibm9uY2UiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwiaWF0IjoxODk5OTk5OTQwLCJleHAiOjE5MDAwMDM2MDAsInN1Yl90eXBlIjoidXNlciIsImFjciI6InVybjpzaW5ncGFzczphdXRoZW50aWNhdGlvbjpsb2E6MiIsImFtciI6WyJwd2QiLCJmdXR1cmUtcHJvdmlkZXItbWV0aG9kIl0sInN1Yl9hdHRyaWJ1dGVzIjp7Im5hbWUiOiJTWU5USEVUSUMgTE9DQUwgVEVTVCJ9fQ"
                    .as_bytes(),
            ),
            signature_b64: BoundedVec::from_array(
                "dlTe3aG6Pq4kg9DQ2jLY3FbbX0zCgSjV_7w33d19HgbNAuCF357oDkN91sSwufAPiaD0USsJgoCL00L1xU5tzg"
                    .as_bytes(),
            ),
        },
        oidc::TrustedP256Key {
            public_key_x: [
                103, 128, 197, 252, 112, 39, 94, 44, 112, 97, 160, 231, 135, 123, 177, 116, 222,
                173, 235, 152, 135, 2, 127, 63, 168, 54, 84, 21, 139, 167, 245, 12,
            ],
            public_key_y: [
                60, 186, 140, 52, 188, 53, 210, 14, 129, 247, 48, 172, 28, 123, 214, 214, 97, 169,
                66, 249, 12, 106, 156, 165, 92, 81, 47, 158, 74, 0, 18, 102,
            ],
        },
        AuthPolicy {
            audience: BoundedVec::from_array([
                108, 111, 99, 97, 108, 45, 115, 121, 110, 116, 104, 101, 116, 105, 99, 45, 115, 105,
                110, 103, 112, 97, 115, 115, 45, 99, 108, 105, 101, 110, 116,
            ]),
            subject: BoundedVec::from_array([
                108, 111, 99, 97, 108, 45, 115, 121, 110, 116, 104, 101, 116, 105, 99, 45, 115, 105,
                110, 103, 112, 97, 115, 115, 45, 117, 115, 101, 114,
            ]),
            environment: 0,
            minimum_assurance: 2,
        },
        BoundedVec::from_array([
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        ]), 1900000000,
    )
}
pub fn official_payload() -> BoundedVec<u8, 768> {
    BoundedVec::from_array(
        "{\"iat\":1769739823,\"exp\":1769740423,\"iss\":\"https://stg-id.singpass.gov.sg/fapi\",\"sub\":\"7c9c72ec-5be2-495a-a78e-61e809a2a236\",\"aud\":\"RsrOy2iB0edR53TJSuD5ULad1pGmrVZL\",\"amr\":[\"pwd\"],\"sub_attributes\":{\"name\":\"NAME OF S5410828A\"},\"sub_type\":\"user\",\"nonce\":\"WjqUMMmOevYOXmwC27mcAQWsFBn3O7wwhbRItl2FJk8\",\"acr\":\"urn:singpass:authentication:loa:1\"}"
            .as_bytes(),
    )
}
pub fn local_payload() -> BoundedVec<u8, 768> {
    BoundedVec::from_array(
        "{\"iss\":\"https://id.singpass.gov.sg/fapi\",\"aud\":\"local-synthetic-singpass-client\",\"sub\":\"local-synthetic-singpass-user\",\"nonce\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"iat\":1899999940,\"exp\":1900003600,\"sub_type\":\"user\",\"acr\":\"urn:singpass:authentication:loa:2\",\"amr\":[\"pwd\",\"future-provider-method\"],\"sub_attributes\":{\"name\":\"SYNTHETIC LOCAL TEST\"}}"
            .as_bytes(),
    )
}
pub fn delegated_payload() -> BoundedVec<u8, 768> {
    BoundedVec::from_array(
        "{\"iss\":\"https://id.singpass.gov.sg/fapi\",\"aud\":\"local-synthetic-singpass-client\",\"sub\":\"local-synthetic-singpass-user\",\"nonce\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"iat\":1899999940,\"exp\":1900003600,\"sub_type\":\"user\",\"acr\":\"urn:singpass:authentication:loa:2\",\"amr\":[\"pwd\",\"future-provider-method\"],\"sub_attributes\":{\"name\":\"SYNTHETIC LOCAL TEST\"},\"act\":{\"sub\":\"another-user\"}}"
            .as_bytes(),
    )
}
pub fn future_iat_payload() -> BoundedVec<u8, 768> {
    BoundedVec::from_array(
        "{\"iss\":\"https://id.singpass.gov.sg/fapi\",\"aud\":\"local-synthetic-singpass-client\",\"sub\":\"local-synthetic-singpass-user\",\"nonce\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"iat\":1900000001,\"exp\":1900003600,\"sub_type\":\"user\",\"acr\":\"urn:singpass:authentication:loa:2\",\"amr\":[\"pwd\",\"future-provider-method\"],\"sub_attributes\":{\"name\":\"SYNTHETIC LOCAL TEST\"}}"
            .as_bytes(),
    )
}
pub fn duplicate_acr_payload() -> BoundedVec<u8, 768> {
    BoundedVec::from_array(
        "{\"iss\":\"https://id.singpass.gov.sg/fapi\",\"aud\":\"local-synthetic-singpass-client\",\"sub\":\"local-synthetic-singpass-user\",\"nonce\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"iat\":1899999940,\"exp\":1900003600,\"sub_type\":\"user\",\"acr\":null,\"acr\":\"urn:singpass:authentication:loa:2\",\"amr\":[\"pwd\",\"future-provider-method\"],\"sub_attributes\":{\"name\":\"SYNTHETIC LOCAL TEST\"}}"
            .as_bytes(),
    )
}
