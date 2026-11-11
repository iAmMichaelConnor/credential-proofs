//! Context-free tests of the zkEmail adapter: the rebuilt signing input and
//! the field checks. The signature verification runs in TXE in the
//! event-proof zkemail instance (`event-proof/zkemail/src/test.nr`).
use crate::{
    base64_digest, bytes_hash, decimal, dkim_issuer, link_body, SCHEME_ZKEMAIL, ZkemailLoginEmail, ZkemailReceivedEmail,
};
use uc_event_proof::EventEvidence;
use uc_login_link::LoginLink;

fn bounded<let N: u32, let M: u32>(text: str<M>) -> BoundedVec<u8, N> {
    BoundedVec::from_array(text.as_bytes())
}

fn email() -> ZkemailReceivedEmail {
    ZkemailReceivedEmail {
        modulus: [0; 18],
        redc: [0; 18],
        domain: bounded("mail.example"),
        selector: bounded("s1"),
        sender: bounded("alerts@mail.example"),
        recipient: bounded("bob@inbox.example"),
        subject: bounded("Order 42 shipped"),
        signed_at: 4000000000,
        body_hash: [0; 32],
        signature: [0; 18],
    }
}

#[test]
fn scheme_id_is_the_zkemail_account_id() {
    assert_eq(<ZkemailReceivedEmail as EventEvidence>::SCHEME, SCHEME_ZKEMAIL);
}

#[test]
fn signing_input_has_the_profile_bytes() {
    // bh of 32 zero bytes is AAAA...A= (43 letters A and one pad).
    let expected: BoundedVec<u8, 768> = BoundedVec::from_array(
        "from:alerts@mail.example\r\nto:bob@inbox.example\r\nsubject:Order 42 shipped\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=mail.example; s=s1; t=4000000000; h=from:to:subject; bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b="
            .as_bytes(),
    );
    assert_eq(email().signed_header(), expected);
}

#[test]
fn decimal_is_canonical() {
    assert_eq(decimal(0), bounded("0"));
    assert_eq(decimal(7), bounded("7"));
    assert_eq(decimal(1700000000), bounded("1700000000"));
    assert_eq(decimal(0xffffffffffffffff), bounded("18446744073709551615"));
}

#[test]
fn base64_digest_matches_a_known_vector() {
    // SHA-256 of the empty string, base64: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
    let digest = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae,
        0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    ];
    assert_eq(base64_digest(digest), "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".as_bytes());
}

#[test]
fn bytes_hash_ignores_bytes_past_the_length() {
    let a: BoundedVec<u8, 8> = BoundedVec::from_parts([1, 2, 3, 0, 0, 0, 0, 0], 3);
    let b: BoundedVec<u8, 8> = BoundedVec::from_parts([1, 2, 3, 9, 9, 9, 9, 9], 3);
    let c: BoundedVec<u8, 8> = BoundedVec::from_parts([1, 2, 3, 0, 0, 0, 0, 0], 4);
    assert_eq(bytes_hash(a), bytes_hash(b));
    assert(bytes_hash(a) != bytes_hash(c));
}

#[test]
fn issuer_pins_key_domain_and_selector() {
    let base = email();
    let mut key = email();
    key.modulus[0] = 1;
    let mut redc = email();
    redc.redc[0] = 1;
    let mut domain = email();
    domain.domain = bounded("mail.examplf");
    let mut selector = email();
    selector.selector = bounded("s2");
    assert(base.issuer() != key.issuer());
    assert(base.issuer() != redc.issuer());
    assert(base.issuer() != domain.issuer());
    assert(base.issuer() != selector.issuer());
    assert_eq(base.issuer(), dkim_issuer(base.modulus, base.redc, base.domain, base.selector));
}

#[test(should_fail_with = "Sender domain differs from the DKIM domain")]
fn sender_outside_the_dkim_domain_rejected() {
    let mut input = email();
    input.sender = bounded("alerts@other.example");
    let _ = input.signed_header();
}

#[test(should_fail_with = "Sender domain differs from the DKIM domain")]
fn sender_in_a_subdomain_rejected() {
    let mut input = email();
    input.sender = bounded("alerts@x.mail.example");
    let _ = input.signed_header();
}

#[test(should_fail_with = "Unsupported subject byte")]
fn header_injection_in_subject_rejected() {
    let mut input = email();
    input.subject = bounded("hi\r\nfrom:ceo@mail.example");
    let _ = input.signed_header();
}

#[test(should_fail_with = "Subject is not in relaxed form")]
fn double_space_in_subject_rejected() {
    let mut input = email();
    input.subject = bounded("Order  42");
    let _ = input.signed_header();
}

#[test(should_fail_with = "Subject is not in relaxed form")]
fn trailing_space_in_subject_rejected() {
    let mut input = email();
    input.subject = bounded("Order 42 ");
    let _ = input.signed_header();
}

#[test(should_fail_with = "Unsupported mailbox byte")]
fn display_name_recipient_rejected() {
    let mut input = email();
    input.recipient = bounded("Bob <bob@inbox.example>");
    let _ = input.signed_header();
}

#[test(should_fail_with = "A mailbox needs one at-sign")]
fn recipient_with_two_at_signs_rejected() {
    let mut input = email();
    input.recipient = bounded("bob@x@inbox.example");
    let _ = input.signed_header();
}

#[test(should_fail_with = "Unsupported DKIM selector byte")]
fn tag_separator_in_selector_rejected() {
    let mut input = email();
    input.selector = bounded("s1; h=from");
    let _ = input.signed_header();
}

#[test(should_fail_with = "Unsupported DKIM domain byte")]
fn uppercase_domain_rejected() {
    let mut input = email();
    input.domain = bounded("Mail.example");
    input.sender = bounded("alerts@Mail.example");
    let _ = input.signed_header();
}

fn login() -> ZkemailLoginEmail {
    ZkemailLoginEmail {
        modulus: [0; 18],
        redc: [0; 18],
        domain: bounded("mail.example"),
        selector: bounded("s1"),
        sender: bounded("alice@mail.example"),
        recipient: bounded("link@app.example"),
        subject: bounded("Link my mailbox"),
        signed_at: 4000000000,
        signature: [0; 18],
    }
}

#[test]
fn login_scheme_id_is_the_zkemail_account_id() {
    assert_eq(<ZkemailLoginEmail as LoginLink>::SCHEME, SCHEME_ZKEMAIL);
}

#[test]
fn login_body_carries_the_challenge_hex() {
    let expected = "CRED-PROOF-LINK:000000000000000000000000000000000000000000000000000000000000002a\r\n".as_bytes();
    assert_eq(link_body(42), expected);
}

#[test]
fn login_signing_input_has_the_body_hash_of_the_challenge() {
    // base64(sha256("CRED-PROOF-LINK:" + hex(42) + CRLF)), computed with Python hashlib.
    let expected: BoundedVec<u8, 768> = BoundedVec::from_array(
        "from:alice@mail.example\r\nto:link@app.example\r\nsubject:Link my mailbox\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=mail.example; s=s1; t=4000000000; h=from:to:subject; bh=qKlKKOK/n4QowkK0nqnOUiRhBcHGBxgul2atUo4lsjg=; b="
            .as_bytes(),
    );
    assert_eq(login().email(42).signed_header(), expected);
    assert(login().email(43).body_hash != login().email(42).body_hash);
}

#[test]
fn login_issuer_is_the_dkim_issuer() {
    let input = login();
    assert_eq(input.issuer(), dkim_issuer(input.modulus, input.redc, input.domain, input.selector));
}

#[test]
fn gate_and_link_purpose_have_exact_distinct_bytes() {
    let expected = "CRED-PROOF-GATE:0000000000000000000000000000000000000000000000000000000000000001\r\n".as_bytes();
    assert_eq(crate::gate_body(1), expected);
    assert(crate::gate_body(1) != link_body(1));
    assert_eq(<crate::ZkemailDomainEmail as uc_attribute_gate::AttributeEvidence>::SCHEME, SCHEME_ZKEMAIL);
}
