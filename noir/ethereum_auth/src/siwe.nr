//! Canonical bounded EIP-4361 (Sign-In with Ethereum) message binding.
use crate::eip191::verify_personal_sign;

pub struct SiweContext<let DOMAIN_MAX: u32, let URI_MAX: u32, let NONCE_MAX: u32> {
    pub domain: [u8; DOMAIN_MAX],
    pub domain_len: u32,
    pub uri: [u8; URI_MAX],
    pub uri_len: u32,
    pub chain_id: u64,
    pub nonce: [u8; NONCE_MAX],
    pub nonce_len: u32,
    /// Canonical UTC timestamp `YYYY-MM-DDTHH:MM:SSZ`.
    pub issued_at: [u8; 20],
    /// Canonical UTC timestamp `YYYY-MM-DDTHH:MM:SSZ`.
    pub expiration_time: [u8; 20],
    /// Trusted current UTC timestamp `YYYY-MM-DDTHH:MM:SSZ`.
    pub current_time: [u8; 20],
}

pub struct BoundedSiweMessage<let MAX: u32> {
    pub bytes: [u8; MAX],
    pub len: u32,
}

/// EIP-4361 takes the domain (an RFC 3986 authority) and the URI (an RFC 3986
/// URI) as ASCII text. Accept only visible ASCII, 0x21..=0x7e. This rejects
/// space, every control byte, DEL and every non-ASCII byte, so UTF-8 encoded
/// Unicode spaces and line separators (U+0085, U+00A0, U+2028, U+2029) cannot
/// appear. Internationalised domain names must use their punycode form.
fn is_visible_ascii(byte: u8) -> bool {
    (byte >= 0x21) & (byte <= 0x7e)
}

fn is_digit(byte: u8) -> bool {
    byte >= 0x30 & byte <= 0x39
}

fn validate_utc_timestamp(timestamp: [u8; 20]) {
    for i in 0..20 {
        if (i == 4) | (i == 7) {
            assert_eq(timestamp[i], 0x2d); // -
        } else if i == 10 {
            assert_eq(timestamp[i], 0x54); // T
        } else if (i == 13) | (i == 16) {
            assert_eq(timestamp[i], 0x3a); // :
        } else if i == 19 {
            assert_eq(timestamp[i], 0x5a); // Z
        } else {
            assert(is_digit(timestamp[i]));
        }
    }
    let year = pair(timestamp[0], timestamp[1]) * 100 + pair(timestamp[2], timestamp[3]);
    let month = pair(timestamp[5], timestamp[6]);
    let day = pair(timestamp[8], timestamp[9]);
    let hour = pair(timestamp[11], timestamp[12]);
    let minute = pair(timestamp[14], timestamp[15]);
    let second = pair(timestamp[17], timestamp[18]);
    assert(month >= 1 & month <= 12);
    assert(day >= 1);
    assert(hour <= 23);
    assert(minute <= 59);
    assert(second <= 59);
    let leap = (year % 4 == 0) & ((year % 100 != 0) | (year % 400 == 0));
    if month == 2 {
        assert(day <= if leap { 29 } else { 28 });
    } else if (month == 4) | (month == 6) | (month == 9) | (month == 11) {
        assert(day <= 30);
    } else {
        assert(day <= 31);
    }
}

fn pair(first: u8, second: u8) -> u32 {
    ((first - 0x30) as u32) * 10 + (second - 0x30) as u32
}

fn timestamp_le(left: [u8; 20], right: [u8; 20]) -> bool {
    let mut equal = true;
    let mut less = false;
    for i in 0..20 {
        if equal {
            if left[i] < right[i] {
                less = true;
                equal = false;
            } else if left[i] > right[i] {
                equal = false;
            }
        }
    }
    less | equal
}

fn append<let MAX: u32, let N: u32>(
    out: &mut [u8; MAX],
    cursor: &mut u32,
    bytes: [u8; N],
    len: u32,
) {
    assert(len <= N);
    assert(*cursor + len <= MAX);
    for i in 0..N {
        if i < len {
            out[*cursor + i] = bytes[i];
        }
    }
    *cursor = *cursor + len;
}

fn lowercase_hex_digit(value: u8) -> u8 {
    if value < 10 {
        0x30 + value
    } else {
        0x61 + value - 10
    }
}

fn checksum_address(address: [u8; 20]) -> [u8; 42] {
    let mut lowercase: [u8; 40] = [0; 40];
    for i in 0..20 {
        lowercase[i * 2] = lowercase_hex_digit(address[i] >> 4);
        lowercase[i * 2 + 1] = lowercase_hex_digit(address[i] & 0x0f);
    }
    let address_hash = keccak256::keccak256(lowercase, 40);
    let mut checksummed: [u8; 42] = [0; 42];
    checksummed[0] = 0x30;
    checksummed[1] = 0x78;
    for i in 0..40 {
        let nibble = if i % 2 == 0 {
            address_hash[i / 2] >> 4
        } else {
            address_hash[i / 2] & 0x0f
        };
        let lower = lowercase[i];
        checksummed[2 + i] = if (lower >= 0x61) & (nibble >= 8) {
            lower - 0x20
        } else {
            lower
        };
    }
    checksummed
}

fn decimal_chain_id(value: u64) -> ([u8; 20], u32) {
    let mut reversed: [u8; 20] = [0; 20];
    let mut remaining = value as u128;
    for i in 0..20 {
        reversed[i] = 0x30 + (remaining % 10) as u8;
        remaining = remaining / 10;
    }
    let mut digit_len = 1;
    for i in 0..20 {
        if reversed[i] != 0x30 {
            digit_len = i + 1;
        }
    }
    let mut result: [u8; 20] = [0; 20];
    for i in 0..20 {
        if i < digit_len {
            result[i] = reversed[digit_len - 1 - i];
        }
    }
    (result, digit_len)
}

/// Construct the exact canonical SIWE profile accepted by this package.
///
/// This profile has no statement, request ID, not-before, or resources fields.
/// It requires a checksummed EIP-55 address, decimal chain ID, nonce, issued-at,
/// and expiration-time. Domain, URI, nonce, address, and dates are context
/// values supplied by the caller and must be bound to trusted application
/// state. Dates are validated as real UTC calendar timestamps; the caller must
/// bind `current_time` to a trusted clock or protocol timestamp. The accepted
/// window is `issued_at <= current_time < expiration_time`. When
/// `current_time` is an anchor block time, it lags wall-clock time: a message
/// whose `issued_at` is later than the anchor block is rejected until a newer
/// block is anchored. Signers should set `issued_at` to the anchor block time
/// or earlier. Domain and URI must be 1 or more bytes of visible ASCII
/// (0x21..=0x7e); their RFC 3986 syntax is not parsed further.
pub fn build_siwe_message<let MAX: u32, let DOMAIN_MAX: u32, let URI_MAX: u32, let NONCE_MAX: u32>(
    address: [u8; 20],
    context: SiweContext<DOMAIN_MAX, URI_MAX, NONCE_MAX>,
) -> BoundedSiweMessage<MAX> {
    assert(context.domain_len > 0);
    assert(context.domain_len <= DOMAIN_MAX);
    assert(context.uri_len > 0);
    assert(context.uri_len <= URI_MAX);
    assert(context.nonce_len >= 8);
    assert(context.nonce_len <= NONCE_MAX);
    for i in 0..DOMAIN_MAX {
        if i < context.domain_len {
            assert(is_visible_ascii(context.domain[i]), "SIWE domain byte is not visible ASCII");
        }
    }
    for i in 0..URI_MAX {
        if i < context.uri_len {
            assert(is_visible_ascii(context.uri[i]), "SIWE URI byte is not visible ASCII");
        }
    }
    for i in 0..NONCE_MAX {
        if i < context.nonce_len {
            let c = context.nonce[i];
            assert((c >= 0x30 & c <= 0x39) | (c >= 0x41 & c <= 0x5a) | (c >= 0x61 & c <= 0x7a));
        }
    }
    validate_utc_timestamp(context.issued_at);
    validate_utc_timestamp(context.expiration_time);
    validate_utc_timestamp(context.current_time);
    assert(
        timestamp_le(context.issued_at, context.current_time),
        "SIWE message issued after the current time",
    );
    assert(!timestamp_le(context.expiration_time, context.current_time), "SIWE message expired");

    let address_text = checksum_address(address);
    let (chain_text, chain_len) = decimal_chain_id(context.chain_id);
    let mut out: [u8; MAX] = [0; MAX];
    let mut cursor: u32 = 0;
    append(&mut out, &mut cursor, context.domain, context.domain_len);
    append(
        &mut out,
        &mut cursor,
        " wants you to sign in with your Ethereum account:\n".as_bytes(),
        50,
    );
    append(&mut out, &mut cursor, address_text, 42);
    append(&mut out, &mut cursor, "\n\n\nURI: ".as_bytes(), 8);
    append(&mut out, &mut cursor, context.uri, context.uri_len);
    append(
        &mut out,
        &mut cursor,
        "\nVersion: 1\nChain ID: ".as_bytes(),
        22,
    );
    append(&mut out, &mut cursor, chain_text, chain_len);
    append(&mut out, &mut cursor, "\nNonce: ".as_bytes(), 8);
    append(&mut out, &mut cursor, context.nonce, context.nonce_len);
    append(&mut out, &mut cursor, "\nIssued At: ".as_bytes(), 12);
    append(&mut out, &mut cursor, context.issued_at, 20);
    append(&mut out, &mut cursor, "\nExpiration Time: ".as_bytes(), 18);
    append(&mut out, &mut cursor, context.expiration_time, 20);
    BoundedSiweMessage { bytes: out, len: cursor }
}

/// Verify a signature over exactly the canonical profile produced above.
/// The expected address is derived from the supplied key and compared to the
/// context address by the caller (or through `verify_personal_sign`).
pub fn verify_siwe_signature<let MAX: u32, let DOMAIN_MAX: u32, let URI_MAX: u32, let NONCE_MAX: u32>(
    address: [u8; 20],
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; 64],
    context: SiweContext<DOMAIN_MAX, URI_MAX, NONCE_MAX>,
    submitted_message: [u8; MAX],
    submitted_len: u32,
) {
    let expected = build_siwe_message::<MAX, DOMAIN_MAX, URI_MAX, NONCE_MAX>(address, context);
    assert_eq(submitted_len, expected.len);
    // `expected.bytes` is zero-initialized by the builder, so full-array
    // equality enforces both the active message and canonical zero padding.
    assert_eq(submitted_message, expected.bytes);
    assert(verify_personal_sign(
        submitted_message,
        submitted_len,
        public_key_x,
        public_key_y,
        signature,
        address,
    ));
}

#[test]
fn builds_and_verifies_canonical_siwe_fixture() {
    let context = SiweContext {
        domain: "example.com".as_bytes(),
        domain_len: 11,
        uri: "https://example.com/login".as_bytes(),
        uri_len: 25,
        chain_id: 1,
        nonce: "32891756".as_bytes(),
        nonce_len: 8,
        issued_at: "2026-10-21T12:00:00Z".as_bytes(),
        expiration_time: "2026-10-21T12:05:00Z".as_bytes(),
        current_time: "2026-10-21T12:02:00Z".as_bytes(),
    };
    let address = [
        0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65,
        0x90, 0x29, 0x39, 0x5b, 0xdf,
    ];
    let public_key_x = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];
    let public_key_y = [
        0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08,
        0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10,
        0xd4, 0xb8,
    ];
    let signature = [
        0xf0, 0x16, 0xc5, 0x41, 0x26, 0xd3, 0xdb, 0x65, 0x04, 0x0e, 0xc6, 0x0f, 0xc5, 0x15, 0x12,
        0x2b, 0x42, 0x0d, 0x66, 0xaf, 0xf3, 0x1e, 0x45, 0x00, 0xcc, 0x92, 0x62, 0x3d, 0xcf, 0x57,
        0x2a, 0x0c, 0x4d, 0x80, 0xc2, 0xbd, 0x73, 0xf7, 0x55, 0xd5, 0x1f, 0x31, 0xd0, 0xab, 0x14,
        0xbd, 0x27, 0x46, 0xd4, 0x8f, 0x54, 0x5e, 0x6e, 0x84, 0x20, 0xd1, 0x38, 0x7c, 0x5f, 0xc7,
        0xb2, 0x82, 0x5d, 0x9c,
    ];
    let canonical = "example.com wants you to sign in with your Ethereum account:\n0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf\n\n\nURI: https://example.com/login\nVersion: 1\nChain ID: 1\nNonce: 32891756\nIssued At: 2026-10-21T12:00:00Z\nExpiration Time: 2026-10-21T12:05:00Z"
        .as_bytes();
    let built = build_siwe_message::<245, 11, 25, 8>(address, context);
    assert_eq(built.len, 245);
    for i in 0..245 {
        assert_eq(built.bytes[i], canonical[i]);
    }
    verify_siwe_signature::<245, 11, 25, 8>(
        address,
        public_key_x,
        public_key_y,
        signature,
        context,
        canonical,
        245,
    );
}

#[test(should_fail_with = "SIWE message expired")]
fn rejects_an_expired_siwe_context() {
    let context = SiweContext {
        domain: "example.com".as_bytes(),
        domain_len: 11,
        uri: "https://example.com/login".as_bytes(),
        uri_len: 25,
        chain_id: 1,
        nonce: "32891756".as_bytes(),
        nonce_len: 8,
        issued_at: "2026-10-21T12:00:00Z".as_bytes(),
        expiration_time: "2026-10-21T12:05:00Z".as_bytes(),
        current_time: "2026-10-21T12:06:00Z".as_bytes(),
    };
    let message = build_siwe_message::<245, 11, 25, 8>([0; 20], context);
    assert(message.len > 0);
}

// Domain and URI byte filter. EIP-4361 domain and URI are ASCII text.
// The byte vectors below come from the UTF-8 encodings of the named code
// points: U+0085 = c2 85, U+00A0 = c2 a0, U+2028 = e2 80 a8,
// U+2029 = e2 80 a9, U+202E = e2 80 ae.
fn context_with<let D: u32, let U: u32>(
    domain: [u8; D],
    uri: [u8; U],
    issued_at: str<20>,
    current_time: str<20>,
) -> SiweContext<D, U, 8> {
    SiweContext {
        domain,
        domain_len: D,
        uri,
        uri_len: U,
        chain_id: 1,
        nonce: "32891756".as_bytes(),
        nonce_len: 8,
        issued_at: issued_at.as_bytes(),
        expiration_time: "2026-10-21T12:05:00Z".as_bytes(),
        current_time: current_time.as_bytes(),
    }
}

fn build_with<let D: u32, let U: u32>(domain: [u8; D], uri: [u8; U]) -> u32 {
    let context = context_with(domain, uri, "2026-10-21T12:00:00Z", "2026-10-21T12:02:00Z");
    build_siwe_message::<400, D, U, 8>([0; 20], context).len
}

#[test]
fn accepts_visible_ascii_boundary_bytes_in_domain_and_uri() {
    // 0x21 ('!') and 0x7e ('~') are the first and last accepted bytes.
    let len = build_with(
        "!example.com~".as_bytes(),
        "https://example.com/!~".as_bytes(),
    );
    assert_eq(len, 13 + 50 + 42 + 8 + 22 + 22 + 1 + 8 + 8 + 12 + 20 + 18 + 20);
}

#[test(should_fail_with = "SIWE domain byte is not visible ASCII")]
fn rejects_utf8_no_break_space_in_domain() {
    let mut domain = "example.comXXwants".as_bytes();
    domain[11] = 0xc2;
    domain[12] = 0xa0;
    let _ = build_with(domain, "https://example.com/".as_bytes());
}

#[test(should_fail_with = "SIWE domain byte is not visible ASCII")]
fn rejects_utf8_paragraph_separator_in_domain() {
    let mut domain = "example.comXXX".as_bytes();
    domain[11] = 0xe2;
    domain[12] = 0x80;
    domain[13] = 0xa9;
    let _ = build_with(domain, "https://example.com/".as_bytes());
}

#[test(should_fail_with = "SIWE domain byte is not visible ASCII")]
fn rejects_ascii_control_byte_in_domain() {
    let mut domain = "example.comX".as_bytes();
    domain[11] = 0x01;
    let _ = build_with(domain, "https://example.com/".as_bytes());
}

#[test(should_fail_with = "SIWE URI byte is not visible ASCII")]
fn rejects_utf8_line_separator_in_uri() {
    // A wallet would render this as a new line "Chain ID:" with no-break
    // spaces in place of ASCII spaces.
    let mut uri = "https://example.com/XXXChainXXID:".as_bytes();
    uri[20] = 0xe2;
    uri[21] = 0x80;
    uri[22] = 0xa8;
    uri[28] = 0xc2;
    uri[29] = 0xa0;
    let _ = build_with("example.com".as_bytes(), uri);
}

#[test(should_fail_with = "SIWE URI byte is not visible ASCII")]
fn rejects_utf8_next_line_in_uri() {
    let mut uri = "https://example.com/XXx".as_bytes();
    uri[20] = 0xc2;
    uri[21] = 0x85;
    let _ = build_with("example.com".as_bytes(), uri);
}

#[test(should_fail_with = "SIWE URI byte is not visible ASCII")]
fn rejects_utf8_right_to_left_override_in_uri() {
    let mut uri = "https://example.com/XXX".as_bytes();
    uri[20] = 0xe2;
    uri[21] = 0x80;
    uri[22] = 0xae;
    let _ = build_with("example.com".as_bytes(), uri);
}

#[test(should_fail_with = "SIWE URI byte is not visible ASCII")]
fn rejects_first_non_ascii_byte_in_uri() {
    let mut uri = "https://example.com/X".as_bytes();
    uri[20] = 0x80;
    let _ = build_with("example.com".as_bytes(), uri);
}

#[test(should_fail_with = "SIWE URI byte is not visible ASCII")]
fn rejects_delete_byte_in_uri() {
    let mut uri = "https://example.com/X".as_bytes();
    uri[20] = 0x7f;
    let _ = build_with("example.com".as_bytes(), uri);
}

#[test(should_fail_with = "SIWE URI byte is not visible ASCII")]
fn rejects_space_in_uri() {
    let _ = build_with(
        "example.com".as_bytes(),
        "https://example.com/ x".as_bytes(),
    );
}

// Anchor-time window: `issued_at <= current_time` is inclusive, so a
// message issued at the anchor block time is accepted, and one issued one
// second after it is rejected until a newer block is anchored.
#[test]
fn accepts_issued_at_equal_to_current_time() {
    let context = context_with(
        "example.com".as_bytes(),
        "https://example.com/".as_bytes(),
        "2026-10-21T12:02:00Z",
        "2026-10-21T12:02:00Z",
    );
    let _ = build_siwe_message::<400, 11, 20, 8>([0; 20], context);
}

#[test(should_fail_with = "SIWE message issued after the current time")]
fn rejects_issued_at_after_current_time() {
    let context = context_with(
        "example.com".as_bytes(),
        "https://example.com/".as_bytes(),
        "2026-10-21T12:02:01Z",
        "2026-10-21T12:02:00Z",
    );
    let _ = build_siwe_message::<400, 11, 20, 8>([0; 20], context);
}
