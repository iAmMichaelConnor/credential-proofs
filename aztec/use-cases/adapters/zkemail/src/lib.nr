//! zkEmail adapter: a received email, signed by its sender domain with DKIM,
//! as event evidence (`uc_event_proof::EventEvidence`). The event is "the
//! domain of mailbox S signed an email from S with subject T addressed to
//! mailbox R". DKIM does not show delivery, the envelope recipient or the
//! other recipients.
//!
//! Profile. The adapter rebuilds the exact DKIM signing input from the
//! supplied fields and verifies the RSA-SHA256 signature over it with
//! `zkemail::dkim::RSAPubkey` (2048-bit key). The signed headers are
//! `from`, `to` and `subject`, in this order, with relaxed header
//! canonicalisation (RFC 6376 section 3.4.2), followed by the
//! DKIM-Signature field without its `b=` value:
//!
//! ```text
//! from:<sender>\r\n
//! to:<recipient>\r\n
//! subject:<subject>\r\n
//! dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=<domain>; s=<selector>; t=<signed_at>; h=from:to:subject;
//! bh=<body hash>; b=
//! ```
//!
//! A mail system that signs another header list or tag order does not
//! verify under this profile. Each field must already be in relaxed form,
//! and the adapter refuses bytes that would make the rebuilt input
//! ambiguous (CR, LF, control bytes, `;` in a tag value). The sender and
//! recipient are bare lowercase mailboxes, and the sender's domain must equal
//! the DKIM `d=` domain (strict alignment). The body is not read: the body
//! hash `bh=` (SHA-256 of the canonical body, as the signer computed it) is
//! an input, and the event data commits to it.
//!
//! Event:
//! - trust: source `SOURCE_IDENTITY_PROVIDER` (the mail domain), issuer
//!   `dkim_issuer(key, domain, selector)`, no anchor, and
//!   `ALSO_MAIL_OPERATOR`: whoever runs the domain's signing key can sign
//!   any email.
//! - event id: the domain and the SHA-256 of the signed header bytes, which
//!   cover the body hash and `t=`.
//! - kind: (sender mailbox, subject); subject: the recipient mailbox; data:
//!   the body hash; occurred at: the DKIM `t=` time.
//!
//! Login link (`ZkemailLoginEmail`, `uc_login_link::LoginLink`): an email
//! in the same profile whose body is exactly `CRED-PROOF-LINK:<challenge
//! hex>\r\n`. The adapter computes the body hash from the link challenge,
//! so only an email that carries this caller's challenge verifies. The
//! claim:
//! - trust: source `SOURCE_IDENTITY_PROVIDER` (the mail domain), issuer
//!   `dkim_issuer(key, domain, selector)`, and `ALSO_IDP |
//!   ALSO_MAIL_OPERATOR`: the domain and whoever runs its signing key or the
//!   sender's mailbox can send such an email from any of its mailboxes.
//! - identity: the sender mailbox (`mailbox`), which strict alignment ties
//!   to the DKIM domain. It is the same in every app; the mail domain can
//!   reassign it.
//! - binding: the link challenge, written by the sender (`SET_BY_SENDER`).
//! - issued at: the DKIM `t=` time (the domain signs it); expires at: none.
//! Attribute gate (`ZkemailDomainEmail`): the same strict DKIM profile with
//! a GATE-purpose body bound to the core's caller/choice value. It reports the
//! aligned sender domain hash, the mailbox subject and signed DKIM time. The
//! sender and domain/mail operator can authorize it; this proves neither
//! employment nor independent holder-key control. LINK messages do not qualify.
use aztec::{
    context::PrivateContext,
    protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}},
};
use std::meta::derive;
use uc_attribute_gate::{AttributeClaim, AttributeEvidence, KIND_EMAIL_DOMAIN};
use uc_event_proof::{Event, EventEvidence};
use uc_login_link::{LinkClaim, LoginLink};
use uc_trust::{
    ALSO_IDP, ALSO_MAIL_OPERATOR, ANCHOR_NONE, Binding, field_hex, SET_BY_SENDER, SOURCE_IDENTITY_PROVIDER, Trust,
};
use zkemail::{dkim::RSAPubkey, KEY_LIMBS_2048};

mod tests;

/// The zkEmail scheme id.
pub global SCHEME_ZKEMAIL: u32 = 8;

pub global DOMAIN_DKIM_ISSUER: Field = comptime { poseidon2_hash_bytes("MIKE_UC_DKIM_ISSUER_V1".as_bytes()) };
pub global DOMAIN_EMAIL_EVENT: Field = comptime { poseidon2_hash_bytes("MIKE_UC_EMAIL_EVENT_V1".as_bytes()) };
pub global DOMAIN_EMAIL_KIND: Field = comptime { poseidon2_hash_bytes("MIKE_UC_EMAIL_KIND_V1".as_bytes()) };
pub global DOMAIN_EMAIL_MAILBOX: Field = comptime { poseidon2_hash_bytes("MIKE_UC_EMAIL_MAILBOX_V1".as_bytes()) };
pub global DOMAIN_EMAIL_BODY: Field = comptime { poseidon2_hash_bytes("MIKE_UC_EMAIL_BODY_V1".as_bytes()) };

/// Capacities of the profile fields and of the rebuilt signing input.
pub global MAX_MAILBOX: u32 = 96;
pub global MAX_DOMAIN: u32 = 64;
pub global MAX_SELECTOR: u32 = 64;
pub global MAX_SUBJECT: u32 = 128;
pub global MAX_SIGNED_HEADER: u32 = 768;

/// A received email under the profile above, with the DKIM key it must
/// verify under. The key is not trusted by itself: it enters the trust
/// issuer, which the event terms pin.
#[derive(Serialize, Deserialize)]
pub struct ZkemailReceivedEmail {
    /// The sender domain's 2048-bit RSA key and its Barrett parameters, as
    /// 18 little-endian 120-bit limbs.
    pub modulus: [Field; 18],
    pub redc: [Field; 18],
    /// DKIM `d=` and `s=`.
    pub domain: BoundedVec<u8, MAX_DOMAIN>,
    pub selector: BoundedVec<u8, MAX_SELECTOR>,
    /// The `From` and `To` mailboxes and the `Subject` value.
    pub sender: BoundedVec<u8, MAX_MAILBOX>,
    pub recipient: BoundedVec<u8, MAX_MAILBOX>,
    pub subject: BoundedVec<u8, MAX_SUBJECT>,
    /// DKIM `t=`, Unix seconds.
    pub signed_at: u64,
    /// DKIM `bh=`: the SHA-256 of the canonical body.
    pub body_hash: [u8; 32],
    /// DKIM `b=` as 18 little-endian 120-bit limbs.
    pub signature: [Field; 18],
}

/// Poseidon2 of a bounded byte string; bytes past its length do not count.
pub fn bytes_hash<let N: u32>(bytes: BoundedVec<u8, N>) -> Field {
    uc_trust::bytes::bytes_hash(bytes)
}

/// A 32-byte word as two 128-bit halves.
pub fn halves(word: [u8; 32]) -> (Field, Field) {
    uc_trust::bytes::halves(word)
}

/// The trust issuer of a DKIM key: the key material (both limb arrays; the
/// verifier uses the supplied Barrett parameters), the domain and the
/// selector.
pub fn dkim_issuer(
    modulus: [Field; 18],
    redc: [Field; 18],
    domain: BoundedVec<u8, MAX_DOMAIN>,
    selector: BoundedVec<u8, MAX_SELECTOR>,
) -> Field {
    let mut limbs = [0; 36];
    for i in 0..18 {
        limbs[i] = modulus[i];
        limbs[18 + i] = redc[i];
    }
    poseidon2_hash(
        [DOMAIN_DKIM_ISSUER, poseidon2_hash(limbs), bytes_hash(domain), bytes_hash(selector)],
    )
}

/// The event kind of an email: its sender mailbox and subject.
pub fn email_kind(sender: BoundedVec<u8, MAX_MAILBOX>, subject: BoundedVec<u8, MAX_SUBJECT>) -> Field {
    poseidon2_hash([DOMAIN_EMAIL_KIND, bytes_hash(sender), bytes_hash(subject)])
}

/// The event subject of an email: its recipient mailbox.
pub fn mailbox(recipient: BoundedVec<u8, MAX_MAILBOX>) -> Field {
    poseidon2_hash([DOMAIN_EMAIL_MAILBOX, bytes_hash(recipient)])
}

/// The event data of an email: its body hash.
pub fn body(body_hash: [u8; 32]) -> Field {
    let (high, low) = halves(body_hash);
    poseidon2_hash([DOMAIN_EMAIL_BODY, high, low])
}

fn is_lower_alphanumeric(c: u8) -> bool {
    ((c >= 97) & (c <= 122)) | ((c >= 48) & (c <= 57))
}

fn assert_domain(domain: BoundedVec<u8, MAX_DOMAIN>) {
    assert((domain.len() > 0), "Empty DKIM domain");
    for i in 0..MAX_DOMAIN {
        if i < domain.len() {
            let c = domain.get_unchecked(i);
            assert(is_lower_alphanumeric(c) | (c == 46) | (c == 45), "Unsupported DKIM domain byte");
        }
    }
}

fn assert_selector(selector: BoundedVec<u8, MAX_SELECTOR>) {
    assert((selector.len() > 0), "Empty DKIM selector");
    for i in 0..MAX_SELECTOR {
        if i < selector.len() {
            let c = selector.get_unchecked(i);
            assert(is_lower_alphanumeric(c) | (c == 45), "Unsupported DKIM selector byte");
        }
    }
}

/// A bare lowercase mailbox with one `@` and nonempty local and domain
/// parts. Returns the index of the `@`.
fn assert_mailbox(mailbox: BoundedVec<u8, MAX_MAILBOX>) -> u32 {
    let mut at_count = 0;
    let mut at_index = 0;
    for i in 0..MAX_MAILBOX {
        if i < mailbox.len() {
            let c = mailbox.get_unchecked(i);
            assert(
                is_lower_alphanumeric(c) | (c == 46) | (c == 95) | (c == 45) | (c == 43) | (c == 64),
                "Unsupported mailbox byte",
            );
            if c == 64 {
                at_count += 1;
                at_index = i;
            }
        }
    }
    assert(at_count == 1, "A mailbox needs one at-sign");
    assert(at_index > 0, "Empty mailbox local part");
    assert(at_index + 1 < mailbox.len(), "Empty mailbox domain");
    at_index
}

/// A relaxed-canonical unstructured value: printable ASCII and single
/// spaces, no leading or trailing space.
fn assert_subject(subject: BoundedVec<u8, MAX_SUBJECT>) {
    let len = subject.len();
    assert(len > 0, "Empty subject");
    let mut previous_space = true;
    for i in 0..MAX_SUBJECT {
        if i < len {
            let c = subject.get_unchecked(i);
            assert((c >= 32) & (c <= 126), "Unsupported subject byte");
            let space = c == 32;
            assert(!(space & previous_space), "Subject is not in relaxed form");
            previous_space = space;
        }
    }
    assert(!previous_space, "Subject is not in relaxed form");
}

fn push_literal<let N: u32, let M: u32>(out: &mut BoundedVec<u8, N>, value: str<M>) {
    let bytes = value.as_bytes();
    for i in 0..M {
        out.push(bytes[i]);
    }
}

fn push_bytes<let N: u32, let M: u32>(out: &mut BoundedVec<u8, N>, value: BoundedVec<u8, M>) {
    for i in 0..M {
        if i < value.len() {
            out.push(value.get_unchecked(i));
        }
    }
}

/// Canonical decimal digits of a u64, most significant first.
pub fn decimal(value: u64) -> BoundedVec<u8, 20> {
    let mut reversed = [0; 20];
    let mut remaining = value;
    let mut len = 0;
    for i in 0..20 {
        if (remaining != 0) | (i == 0) {
            reversed[i] = 48 + (remaining % 10) as u8;
            remaining = remaining / 10;
            len += 1;
        }
    }
    let mut digits = BoundedVec::new();
    for i in 0..20 {
        if i < len {
            digits.push(reversed[len - 1 - i]);
        }
    }
    digits
}

/// Standard base64 (with padding) of a SHA-256 digest, as DKIM `bh=` has it.
pub fn base64_digest(hash: [u8; 32]) -> [u8; 44] {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".as_bytes();
    let mut encoded = [0; 44];
    for group in 0..11 {
        let i = group * 3;
        let b0 = hash[i];
        let b1 = if i + 1 < 32 { hash[i + 1] } else { 0 };
        let b2 = if i + 2 < 32 { hash[i + 2] } else { 0 };
        encoded[group * 4] = alphabet[(b0 >> 2) as u32];
        encoded[group * 4 + 1] = alphabet[(((b0 & 3) << 4) | (b1 >> 4)) as u32];
        encoded[group * 4 + 2] = if i + 1 < 32 {
            alphabet[(((b1 & 15) << 2) | (b2 >> 6)) as u32]
        } else {
            61
        };
        encoded[group * 4 + 3] = if i + 2 < 32 {
            alphabet[(b2 & 63) as u32]
        } else {
            61
        };
    }
    encoded
}

impl ZkemailReceivedEmail {
    /// The trust issuer that this input pins.
    pub fn issuer(self) -> Field {
        dkim_issuer(self.modulus, self.redc, self.domain, self.selector)
    }

    /// Checks the profile fields and returns the exact DKIM signing input.
    pub fn signed_header(self) -> BoundedVec<u8, MAX_SIGNED_HEADER> {
        assert_domain(self.domain);
        assert_selector(self.selector);
        let at = assert_mailbox(self.sender);
        let _ = assert_mailbox(self.recipient);
        assert_subject(self.subject);
        // Strict alignment: the From domain is the signing domain.
        assert(at + 1 + self.domain.len() == self.sender.len(), "Sender domain differs from the DKIM domain");
        for i in 0..MAX_DOMAIN {
            if i < self.domain.len() {
                assert(
                    self.sender.get_unchecked(at + 1 + i) == self.domain.get_unchecked(i),
                    "Sender domain differs from the DKIM domain",
                );
            }
        }

        let mut header = BoundedVec::new();
        push_literal(&mut header, "from:");
        push_bytes(&mut header, self.sender);
        push_literal(&mut header, "\r\nto:");
        push_bytes(&mut header, self.recipient);
        push_literal(&mut header, "\r\nsubject:");
        push_bytes(&mut header, self.subject);
        push_literal(
            &mut header,
            "\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=",
        );
        push_bytes(&mut header, self.domain);
        push_literal(&mut header, "; s=");
        push_bytes(&mut header, self.selector);
        push_literal(&mut header, "; t=");
        push_bytes(&mut header, decimal(self.signed_at));
        push_literal(&mut header, "; h=from:to:subject; bh=");
        let bh = base64_digest(self.body_hash);
        for i in 0..44 {
            header.push(bh[i]);
        }
        // RFC 6376 section 3.7: the DKIM-Signature field is hashed with an
        // empty b= value and without its final CRLF.
        push_literal(&mut header, "; b=");
        header
    }

    /// Verifies the signature and returns the event. Needs no context.
    pub fn verify_email(self) -> Event {
        let header = self.signed_header();
        let key = RSAPubkey::<KEY_LIMBS_2048>::new(self.modulus, self.redc);
        let header_hash = key.verify_dkim_signature(header, self.signature);
        let (hash_high, hash_low) = halves(header_hash);
        Event {
            trust: Trust {
                source: SOURCE_IDENTITY_PROVIDER,
                issuer: self.issuer(),
                anchor_kind: ANCHOR_NONE,
                anchor: 0,
                finality: 0,
                also_authorised: ALSO_MAIL_OPERATOR,
            },
            event_id: poseidon2_hash(
                [DOMAIN_EMAIL_EVENT, bytes_hash(self.domain), hash_high, hash_low],
            ),
            kind: email_kind(self.sender, self.subject),
            subject: mailbox(self.recipient),
            data: body(self.body_hash),
            occurred_at: self.signed_at,
        }
    }
}

impl EventEvidence for ZkemailReceivedEmail {
    let SCHEME: u32 = 8;

    fn verify(self, _context: &mut PrivateContext) -> Event {
        self.verify_email()
    }
}

/// The body prefix of a login email; the challenge hex and CRLF follow.
pub global LINK_BODY_PREFIX: str<16> = "CRED-PROOF-LINK:";

/// A login email: a message in the profile above, from the mailbox that
/// links, whose body carries the link challenge. The body is not an input:
/// the adapter rebuilds it from the challenge.
#[derive(Serialize, Deserialize)]
pub struct ZkemailLoginEmail {
    pub modulus: [Field; 18],
    pub redc: [Field; 18],
    pub domain: BoundedVec<u8, MAX_DOMAIN>,
    pub selector: BoundedVec<u8, MAX_SELECTOR>,
    /// The mailbox that links (`From`).
    pub sender: BoundedVec<u8, MAX_MAILBOX>,
    /// Any recipient (`To`); the link does not read it.
    pub recipient: BoundedVec<u8, MAX_MAILBOX>,
    pub subject: BoundedVec<u8, MAX_SUBJECT>,
    /// DKIM `t=`, Unix seconds.
    pub signed_at: u64,
    pub signature: [Field; 18],
}

/// The exact login body for a challenge: `CRED-PROOF-LINK:<64 hex>\r\n`.
pub fn link_body(challenge: Field) -> [u8; 82] {
    let prefix = LINK_BODY_PREFIX.as_bytes();
    let hex = field_hex(challenge);
    let mut body = [0; 82];
    for i in 0..16 {
        body[i] = prefix[i];
    }
    for i in 0..64 {
        body[16 + i] = hex[i];
    }
    body[80] = 13;
    body[81] = 10;
    body
}

impl ZkemailLoginEmail {
    /// The trust issuer that this input pins.
    pub fn issuer(self) -> Field {
        dkim_issuer(self.modulus, self.redc, self.domain, self.selector)
    }

    /// The same message as a received email whose body is the login body
    /// for `challenge`.
    pub fn email(self, challenge: Field) -> ZkemailReceivedEmail {
        ZkemailReceivedEmail {
            modulus: self.modulus,
            redc: self.redc,
            domain: self.domain,
            selector: self.selector,
            sender: self.sender,
            recipient: self.recipient,
            subject: self.subject,
            signed_at: self.signed_at,
            body_hash: sha256::digest(link_body(challenge)),
            signature: self.signature,
        }
    }
}

impl LoginLink for ZkemailLoginEmail {
    let SCHEME: u32 = 8;

    fn verify(self, _context: &mut PrivateContext, challenge: Field) -> LinkClaim {
        let _ = self.email(challenge).verify_email();
        LinkClaim {
            trust: Trust {
                source: SOURCE_IDENTITY_PROVIDER,
                issuer: self.issuer(),
                anchor_kind: ANCHOR_NONE,
                anchor: 0,
                finality: 0,
                also_authorised: ALSO_IDP | ALSO_MAIL_OPERATOR,
            },
            identity: mailbox(self.sender),
            binding: Binding { value: challenge, set_by: SET_BY_SENDER },
            issued_at: self.signed_at,
            expires_at: 0,
            bearer: false,
        }
    }
}

/// A sender-domain gate request. The embedded fields share the login email's
/// canonical DKIM profile, but its signature must cover the GATE body below.
/// This attests domain-authorized mailbox access, not employment or personhood.
#[derive(Serialize, Deserialize)]
pub struct ZkemailDomainEmail {
    pub email: ZkemailLoginEmail,
}

/// The gate-specific body binds the chain, version, contract, caller and any
/// choice through the core's binding. A LINK-purpose email cannot authorize it.
pub fn gate_body(binding: Field) -> [u8; 82] {
    let mut body = link_body(binding);
    let purpose = "GATE".as_bytes();
    for i in 0..4 {
        body[11 + i] = purpose[i];
    }
    body
}

impl ZkemailDomainEmail {
    pub fn issuer(self) -> Field {
        self.email.issuer()
    }
}

impl AttributeEvidence for ZkemailDomainEmail {
    let SCHEME: u32 = 8;

    fn verify(self, _context: &mut PrivateContext, binding: Field) -> AttributeClaim {
        // Reuse the same strict mailbox alignment, canonical header and RSA
        // verifier as received/login emails. Only the signed body purpose differs.
        let mut email = self.email.email(binding);
        email.body_hash = sha256::digest(gate_body(binding));
        let verified = email.verify_email();
        let mut trust = verified.trust;
        trust.also_authorised = ALSO_IDP | ALSO_MAIL_OPERATOR;
        AttributeClaim {
            trust,
            kind: KIND_EMAIL_DOMAIN,
            value: bytes_hash(self.email.domain),
            subject: mailbox(self.email.sender),
            binding: Binding { value: binding, set_by: SET_BY_SENDER },
            issued_at: verified.occurred_at,
        }
    }
}
