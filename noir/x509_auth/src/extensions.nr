use crate::der::{expect, literal, read, Tlv};
/// Purpose profile: 0 root CA; 1 holder authentication; 2 delegated OCSP.
/// Unknown noncritical extensions remain opaque. Unknown critical extensions fail.
/// A CA checked here may only sign end-entity certificates directly: its
/// pathLenConstraint, if present, must allow zero following intermediates.
/// Use `ca_purpose` for a CA that signs a further CA in the checked path.
pub fn purpose<let N: u32>(
    data: BoundedVec<u8, N>,
    container: Tlv,
    role: u8,
    policy_oid: BoundedVec<u8, 32>,
) {
    assert_purpose(data, container, role, policy_oid, role == 1, false);
}
/// CA purpose (role 0) for a CA that is followed in the checked path by
/// `following_intermediates` non-self-issued intermediate CA certificates
/// (RFC 5280 4.2.1.9). A present pathLenConstraint must be at least that count;
/// an absent one imposes no limit.
pub fn ca_purpose<let N: u32>(
    data: BoundedVec<u8, N>,
    container: Tlv,
    policy_oid: BoundedVec<u8, 32>,
    following_intermediates: u8,
) {
    let _no_check = check_purpose(
        data,
        container,
        ExtensionPurposePolicy {
            role: 0,
            policy_oid,
            require_policy: false,
            require_authentication_eku: false,
            require_key_usage: true,
            require_ocsp_nocheck: false,
            following_intermediates,
        },
    );
}
/// Explicit bounded purpose profile. Roles remain CA0/authentication1/OCSP2.
/// A required policy OID must be supplied when require_policy is true.
/// Authentication callers can require clientAuth EKU independently of policies.
/// Unknown critical and duplicate extensions always fail in every profile.
pub fn assert_purpose<let N: u32>(
    data: BoundedVec<u8, N>,
    container: Tlv,
    role: u8,
    policy_oid: BoundedVec<u8, 32>,
    require_policy: bool,
    require_authentication_eku: bool,
) {
    let _no_check = check_purpose(
        data,
        container,
        ExtensionPurposePolicy {
            role,
            policy_oid,
            require_policy,
            require_authentication_eku,
            require_key_usage: true,
            require_ocsp_nocheck: role == 2,
            following_intermediates: 0,
        },
    );
}
pub struct ExtensionPurposePolicy {
    pub role: u8,
    pub policy_oid: BoundedVec<u8, 32>,
    pub require_policy: bool,
    pub require_authentication_eku: bool,
    pub require_key_usage: bool,
    pub require_ocsp_nocheck: bool,
    /// Role 0 only: the number of intermediate CA certificates that follow this
    /// CA in the checked path. Must be 0 for other roles.
    pub following_intermediates: u8,
}
/// Returns only the syntactic presence of authenticated OCSP noCheck extension.
/// When noCheck is absent, callers must independently establish responder status.
/// KU absence may be allowed explicitly; a present KU always constrains usage.
pub fn check_purpose<let N: u32>(
    data: BoundedVec<u8, N>,
    container: Tlv,
    profile: ExtensionPurposePolicy,
) -> bool {
    let role = profile.role;
    let policy_oid = profile.policy_oid;
    let require_policy = profile.require_policy;
    assert(policy_oid.len() <= 32, "certificate policy OID exceeds capacity");
    let require_authentication_eku = profile.require_authentication_eku;
    assert(!require_policy | (policy_oid.len() > 0), "required certificate policy OID is empty");
    assert(role <= 2, "unsupported certificate purpose role");
    assert(
        !require_authentication_eku | (role == 1),
        "authentication EKU requires authentication role",
    );
    assert(
        (profile.following_intermediates == 0) | (role == 0),
        "intermediate count requires CA role",
    );
    let seq = expect(data, container.content, container.end, 48);
    assert(seq.end == container.end);
    let mut pos = seq.content;
    let mut seen_ku = false;
    let mut seen_bc = false;
    let mut seen_policy = false;
    let mut seen_eku = false;
    let mut seen_nocheck = false;
    let mut oid_hashes = [[0; 32]; 16];
    let mut count = 0;
    for index in 0..16 {
        if pos < seq.end {
            let ext = expect(data, pos, seq.end, 48);
            let oid = expect(data, ext.content, ext.end, 6);
            let oid_bytes = crate::der::slice::<N, 32>(data, oid.content, oid.len);
            let hash = sha256::sha256_var(oid_bytes.storage(), oid_bytes.len());
            for prior in 0..16 {
                if prior < count {
                    assert(hash != oid_hashes[prior], "duplicate X509 extension");
                }
            }
            oid_hashes[index] = hash;
            count += 1;
            let next = read(data, oid.end, ext.end);
            let mut critical = false;
            let mut value = next;
            if next.tag == 1 {
                literal(data, next, [255]);
                critical = true;
                value = expect(data, next.end, ext.end, 4);
            }
            assert(value.tag == 4);
            assert(value.end == ext.end);
            let mut known = false;
            // OIDs 2.5.29.{15,19,32,37}
            if oid.len == 3 {
                if (data.storage()[oid.content] == 85) & (data.storage()[oid.content + 1] == 29) {
                    let last = data.storage()[oid.content + 2];
                    if last == 15 {
                        known = true;
                        seen_ku = true;
                        let bits = expect(data, value.content, value.end, 3);
                        assert(bits.end == value.end);
                        assert(bits.len == 2, "unsupported key usage width");
                        let unused = data.storage()[bits.content];
                        let usage = data.storage()[bits.content + 1];
                        assert(unused <= 7);
                        assert((usage & (((1 as u16) << unused as u16) - 1) as u8) == 0);
                        if role == 0 {
                            assert((usage & 4) != 0, "CA lacks keyCertSign");
                        } else {
                            assert((usage & 128) != 0, "certificate lacks digitalSignature");
                            assert((usage & 6) == 0, "leaf has CA usage");
                        }
                    }
                    if last == 19 {
                        known = true;
                        seen_bc = true;
                        let bc = expect(data, value.content, value.end, 48);
                        assert(bc.end == value.end);
                        if role == 0 {
                            let ca = expect(data, bc.content, bc.end, 1);
                            literal(data, ca, [255]);
                            // pathLenConstraint: a minimal nonnegative DER INTEGER of
                            // one or two bytes. Absent means no limit.
                            if ca.end < bc.end {
                                let path = expect(data, ca.end, bc.end, 2);
                                assert(path.end == bc.end);
                                assert(
                                    (path.len >= 1) & (path.len <= 2),
                                    "unsupported pathLenConstraint width",
                                );
                                let high = data.storage()[path.content];
                                assert(high < 128, "negative pathLenConstraint");
                                let mut path_len = high as u32;
                                if path.len == 2 {
                                    let low = data.storage()[path.content + 1];
                                    assert(
                                        (high != 0) | (low >= 128),
                                        "nonminimal pathLenConstraint",
                                    );
                                    path_len = path_len * 256 + low as u32;
                                }
                                assert(
                                    path_len >= profile.following_intermediates as u32,
                                    "CA pathLenConstraint exceeded",
                                );
                            }
                        } else {
                            assert(bc.len == 0, "holder or OCSP certificate is CA");
                        }
                    }
                    if last == 32 {
                        known = true;
                        seen_policy = true;
                        let policies = expect(data, value.content, value.end, 48);
                        assert(policies.end == value.end);
                        let mut p = policies.content;
                        let mut found = false;
                        for _i in 0..8 {
                            if p < policies.end {
                                let info = expect(data, p, policies.end, 48);
                                let id = expect(data, info.content, info.end, 6);
                                assert(id.len > 0, "certificate policy OID is empty");
                                let mut matches = id.len == policy_oid.len();
                                for j in 0..32 {
                                    if (j < policy_oid.len()) & (j < id.len) {
                                        matches = matches
                                            & (
                                                data.storage()[id.content + j]
                                                    == policy_oid.storage()[j]
                                            );
                                    }
                                }
                                found = found | matches;
                                // Qualifiers remain opaque non-security metadata in this profile.
                                if id.end < info.end {
                                    let qualifiers = expect(data, id.end, info.end, 48);
                                    assert(qualifiers.end == info.end);
                                }
                                p = info.end;
                            }
                        }
                        assert(p == policies.end, "too many certificate policies");
                        if require_policy {
                            assert(found, "wrong authentication certificate policy");
                        }
                    }
                    if last == 37 {
                        known = true;
                        seen_eku = true;
                        let eku = expect(data, value.content, value.end, 48);
                        assert(eku.end == value.end);
                        let mut p = eku.content;
                        let mut ocsp = false;
                        let mut client = false;
                        for _i in 0..8 {
                            if p < eku.end {
                                let id = expect(data, p, eku.end, 6);
                                if id.len == 8 {
                                    let bytes =
                                        crate::der::slice::<N, 8>(data, id.content, 8).storage();
                                    ocsp = ocsp | (bytes == [43, 6, 1, 5, 5, 7, 3, 9]);
                                    client = client | (bytes == [43, 6, 1, 5, 5, 7, 3, 2]);
                                }
                                p = id.end;
                            }
                        }
                        assert(p == eku.end);
                        if role == 2 {
                            assert(ocsp, "OCSP signer lacks purpose");
                        }
                        if role == 1 {
                            assert(client, "holder EKU excludes authentication");
                        }
                    }
                }
            }
            if oid.len == 9 {
                let bytes = crate::der::slice::<N, 9>(data, oid.content, 9).storage();
                if bytes == [43, 6, 1, 5, 5, 7, 48, 1, 5] {
                    known = true;
                    seen_nocheck = true;
                    let null = expect(data, value.content, value.end, 5);
                    assert(null.len == 0);
                    assert(null.end == value.end);
                }
            }
            assert(!critical | known, "unsupported critical certificate extension");
            pos = ext.end;
        }
    }
    assert(pos == seq.end, "too many X509 extensions");
    if profile.require_key_usage {
        assert(seen_ku, "missing certificate key usage");
    }
    if role == 0 {
        assert(seen_bc, "missing CA basic constraints");
    }
    if require_policy {
        assert(seen_policy, "missing authentication policy");
    }
    if require_authentication_eku {
        assert(seen_eku, "missing authentication EKU");
    }
    if role == 2 {
        assert(
            seen_eku & (!profile.require_ocsp_nocheck | seen_nocheck),
            "OCSP certificate requires EKU and no-check",
        );
    }
    seen_nocheck
}

#[test(should_fail_with = "unsupported certificate purpose role")]
fn reject_undefined_certificate_role() {
    purpose(
        BoundedVec::<u8, 1>::new(),
        Tlv { tag: 163, start: 0, content: 0, len: 0, end: 0 },
        3,
        BoundedVec::<u8, 32>::new(),
    );
}
