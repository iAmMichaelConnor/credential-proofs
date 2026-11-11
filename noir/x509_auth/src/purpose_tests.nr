use crate::{der::expect, extensions::{assert_purpose, purpose}};
#[test]
fn legacy_policy_without_eku() {
    let data = BoundedVec::<u8, 60>::from_array([
        163, 58, 48, 56, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 7, 128, 48, 12, 6, 3, 85,
        29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 24, 6, 3, 85, 29, 32, 4, 17, 48, 15, 48, 13, 6, 11, 42,
        131, 8, 140, 155, 85, 8, 5, 1, 3, 30,
    ]);
    let node = expect(data, 0, 60, 163);
    let policy = BoundedVec::<u8, 32>::from_array([42, 131, 8, 140, 155, 85, 8, 5, 1, 3, 30]);
    purpose(data, node, 1, policy);
}
#[test(should_fail_with = "missing authentication policy")]
fn legacy_missing_policy() {
    let data = BoundedVec::<u8, 34>::from_array([
        163, 32, 48, 30, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 7, 128, 48, 12, 6, 3, 85,
        29, 19, 1, 1, 255, 4, 2, 48, 0,
    ]);
    let node = expect(data, 0, 34, 163);
    let policy = BoundedVec::<u8, 32>::from_array([42, 131, 8, 140, 155, 85, 8, 5, 1, 3, 30]);
    purpose(data, node, 1, policy);
}
#[test]
fn client_auth_without_certificate_policy() {
    let data = BoundedVec::<u8, 55>::from_array([
        163, 53, 48, 51, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 7, 128, 48, 12, 6, 3, 85,
        29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 19, 6, 3, 85, 29, 37, 4, 12, 48, 10, 6, 8, 43, 6, 1, 5,
        5, 7, 3, 2,
    ]);
    let node = expect(data, 0, 55, 163);
    let policy = BoundedVec::<u8, 32>::from_array([42, 131, 8, 140, 155, 85, 8, 5, 1, 3, 30]);
    assert_purpose(data, node, 1, policy, false, true);
}
#[test(should_fail_with = "missing authentication EKU")]
fn reject_csd_without_client_auth() {
    let data = BoundedVec::<u8, 34>::from_array([
        163, 32, 48, 30, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 7, 128, 48, 12, 6, 3, 85,
        29, 19, 1, 1, 255, 4, 2, 48, 0,
    ]);
    let node = expect(data, 0, 34, 163);
    let policy = BoundedVec::<u8, 32>::from_array([42, 131, 8, 140, 155, 85, 8, 5, 1, 3, 30]);
    assert_purpose(data, node, 1, policy, false, true);
}
#[test(should_fail_with = "unsupported critical certificate extension")]
fn reject_unknown_critical() {
    let data = BoundedVec::<u8, 69>::from_array([
        163, 67, 48, 65, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 7, 128, 48, 12, 6, 3, 85,
        29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 19, 6, 3, 85, 29, 37, 4, 12, 48, 10, 6, 8, 43, 6, 1, 5,
        5, 7, 3, 2, 48, 12, 6, 3, 42, 3, 4, 1, 1, 255, 4, 2, 5, 0,
    ]);
    let node = expect(data, 0, 69, 163);
    let policy = BoundedVec::<u8, 32>::from_array([42, 131, 8, 140, 155, 85, 8, 5, 1, 3, 30]);
    assert_purpose(data, node, 1, policy, false, true);
}

#[test]
fn optional_ocsp_ku_and_no_check_remain_explicit() {
    let data = BoundedVec::<u8, 39>::from_array([
        163, 37, 48, 35, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 19, 6, 3, 85, 29, 37,
        4, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 9,
    ]);
    let node = expect(data, 0, 39, 163);
    let no_check = crate::extensions::check_purpose(
        data,
        node,
        crate::extensions::ExtensionPurposePolicy {
            role: 2,
            policy_oid: BoundedVec::<u8, 32>::new(),
            require_policy: false,
            require_authentication_eku: false,
            require_key_usage: false,
            require_ocsp_nocheck: false,
            following_intermediates: 0,
        },
    );
    assert(!no_check);
}

fn ca<let N: u32>(data: BoundedVec<u8, N>, following_intermediates: u8) {
    let node = expect(data, 0, data.len(), 163);
    crate::extensions::ca_purpose(data, node, BoundedVec::new(), following_intermediates);
}
#[test]
fn ca_path_len_absent_allows_intermediates() {
    ca(crate::path_len_vectors::ca_path_len_absent(), 255);
}
#[test]
fn ca_path_len_zero_allows_end_entity_only() {
    ca(crate::path_len_vectors::ca_path_len_0(), 0);
    // `purpose` with role 0 allows zero following intermediates.
    let data = crate::path_len_vectors::ca_path_len_0();
    purpose(data, expect(data, 0, data.len(), 163), 0, BoundedVec::new());
}
#[test(should_fail_with = "CA pathLenConstraint exceeded")]
fn ca_path_len_zero_rejects_intermediate() {
    ca(crate::path_len_vectors::ca_path_len_0(), 1);
}
#[test]
fn ca_path_len_one_allows_one_intermediate() {
    ca(crate::path_len_vectors::ca_path_len_1(), 1);
}
#[test(should_fail_with = "CA pathLenConstraint exceeded")]
fn ca_path_len_one_rejects_two_intermediates() {
    ca(crate::path_len_vectors::ca_path_len_1(), 2);
}
#[test]
fn ca_path_len_two_byte_value() {
    ca(crate::path_len_vectors::ca_path_len_128(), 128);
}
#[test(should_fail_with = "nonminimal pathLenConstraint")]
fn ca_path_len_rejects_nonminimal_integer() {
    ca(crate::path_len_vectors::ca_path_len_nonminimal_5(), 0);
}
#[test(should_fail_with = "unsupported pathLenConstraint width")]
fn ca_path_len_rejects_empty_integer() {
    ca(crate::path_len_vectors::ca_path_len_empty(), 0);
}
#[test(should_fail_with = "negative pathLenConstraint")]
fn ca_path_len_rejects_negative_integer() {
    ca(crate::path_len_vectors::ca_path_len_negative(), 0);
}
#[test(should_fail_with = "intermediate count requires CA role")]
fn intermediate_count_requires_ca_role() {
    let data = crate::path_len_vectors::ca_path_len_absent();
    let node = expect(data, 0, data.len(), 163);
    let _ = crate::extensions::check_purpose(
        data,
        node,
        crate::extensions::ExtensionPurposePolicy {
            role: 1,
            policy_oid: BoundedVec::new(),
            require_policy: false,
            require_authentication_eku: false,
            require_key_usage: true,
            require_ocsp_nocheck: false,
            following_intermediates: 1,
        },
    );
}

fn required_policy() -> BoundedVec<u8, 32> {
    BoundedVec::from_array([42, 131, 8, 140, 155, 85, 8, 5, 1, 3, 30])
}
fn holder_policy<let N: u32>(data: BoundedVec<u8, N>) {
    purpose(data, expect(data, 0, data.len(), 163), 1, required_policy());
}
#[test]
fn matching_policy_then_short_oid_at_exact_capacity() {
    holder_policy(crate::policy_vectors::matching_then_short());
}
#[test]
fn short_policy_before_matching_policy() {
    holder_policy(crate::policy_vectors::short_then_matching());
}
#[test]
fn matching_policy_then_short_oid_with_padding() {
    let exact = crate::policy_vectors::matching_then_short();
    let mut padded = BoundedVec::<u8, 128>::new();
    for i in 0..exact.len() {
        padded.push(exact.storage()[i]);
    }
    holder_policy(padded);
}
#[test(should_fail_with = "wrong authentication certificate policy")]
fn short_policy_does_not_match_requested_prefix() {
    holder_policy(crate::policy_vectors::short_only());
}
#[test(should_fail_with = "required certificate policy OID is empty")]
fn required_policy_cannot_be_empty() {
    let data = crate::policy_vectors::matching_only();
    purpose(data, expect(data, 0, data.len(), 163), 1, BoundedVec::new());
}
#[test(should_fail_with = "required certificate policy OID is empty")]
fn empty_encoded_oid_cannot_satisfy_empty_required_policy() {
    let data = crate::policy_vectors::empty_only();
    purpose(data, expect(data, 0, data.len(), 163), 1, BoundedVec::new());
}
#[test(should_fail_with = "certificate policy OID is empty")]
fn empty_encoded_oid_rejects_when_policy_is_optional() {
    let data = crate::policy_vectors::empty_only();
    assert_purpose(
        data,
        expect(data, 0, data.len(), 163),
        1,
        BoundedVec::new(),
        false,
        false,
    );
}
#[test(should_fail_with = "certificate policy OID is empty")]
fn matching_policy_does_not_hide_empty_encoded_oid() {
    holder_policy(crate::policy_vectors::matching_then_empty());
}
#[test]
fn optional_policy_allows_empty_requirement() {
    let data = crate::policy_vectors::matching_only();
    assert_purpose(
        data,
        expect(data, 0, data.len(), 163),
        1,
        BoundedVec::new(),
        false,
        false,
    );
}

#[test]
fn ca_optional_policy_allows_empty_requirement() {
    let data = crate::policy_vectors::ca_matching_only();
    purpose(data, expect(data, 0, data.len(), 163), 0, BoundedVec::new());
}
#[test(should_fail_with = "certificate policy OID is empty")]
fn ca_optional_policy_rejects_empty_encoded_oid() {
    let data = crate::policy_vectors::ca_empty_only();
    purpose(data, expect(data, 0, data.len(), 163), 0, BoundedVec::new());
}
