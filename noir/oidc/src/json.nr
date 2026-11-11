//! Low-copy, bounded scanner for the flat OIDC ID-token JSON profile.
//! It stores offsets while scanning and copies only the five returned string claims.
//!
//! Domain. The root is an object. The selected claims (`iss`, `aud`,
//! `sub`, `nonce`, `azp`, `exp`, `nbf`, and `iat` where read) are direct root
//! members, at most once each. A selected string claim holds at most 256
//! decoded bytes and admits one escape, the escaped solidus, which the copy
//! decodes. A selected numeric claim is a canonical unsigned decimal integer
//! of at most 2^64 - 1. Any other member may hold any JSON string (any length,
//! any JSON escape), a canonical unsigned decimal integer of any length,
//! `true`, `false`, `null`, or a nested object or array of depth at most 8.
//! The scanner checks those values as JSON and ignores them, so their names
//! cannot shadow a root claim. Keys are unescaped and at most 256 bytes.

pub struct Claims {
    pub issuer: BoundedVec<u8, 256>,
    pub audience: BoundedVec<u8, 256>,
    pub subject: BoundedVec<u8, 256>,
    pub nonce: BoundedVec<u8, 256>,
    pub expiry: u64,
    pub authorized_party: BoundedVec<u8, 256>,
    pub not_before: u64,
    pub has_not_before: bool,
}

pub(crate) struct ScalarState {
    len: u32,
    /// The first five bytes, big-endian (enough for true, false and null).
    packed: Field,
    /// The first byte is '0'.
    leading_zero: bool,
    /// The value of the first 20 digits; below 10^20, so it cannot wrap.
    number: Field,
    digits_only: bool,
}

struct ClaimState {
    starts: [u32; 7],
    lengths: [u32; 7],
    seen: [u32; 7],
    /// The digits of `exp` and `nbf` (at most 20); the scanner checks that
    /// they fit in a u64 once, after the scan.
    expiry: Field,
    not_before: Field,
}

pub fn literal_vec<let N: u32>(value: str<N>) -> BoundedVec<u8, 256> {
    let mut out = BoundedVec::<u8, 256>::new();
    for j in 0..N {
        out.push(value.as_bytes()[j]);
    }
    out
}

pub fn string_matches<let A: u32, let B: u32>(a: BoundedVec<u8, A>, b: BoundedVec<u8, B>) -> bool {
    let mut ok = a.len() == b.len();
    for j in 0..A {
        if (j < a.len()) & (j < b.len()) {
            ok = ok & (a.storage()[j] == b.storage()[j]);
        }
    }
    ok
}

fn ws(b: u8) -> bool {
    (b == 32) | (b == 9) | (b == 10) | (b == 13)
}

fn claim_key_id(key_prefix: Field, len: u32) -> u32 {
    if len == 3 {
        if key_prefix == 6910835 {
            0
        } else if key_prefix == 6387044 {
            1
        } else if key_prefix == 7566690 {
            2
        } else if key_prefix == 6649968 {
            4
        } else if key_prefix == 6388336 {
            5
        } else if key_prefix == 7234150 {
            6
        } else {
            7
        }
    } else if (len == 5) & (key_prefix == 474315907941) {
        3
    } else {
        7
    }
}

pub(crate) fn start_scalar(b: u8) -> ScalarState {
    let s = ScalarState { len: 0, packed: 0, leading_zero: b == 48, number: 0, digits_only: true };
    advance_scalar(s, b)
}

pub(crate) fn advance_scalar(mut s: ScalarState, b: u8) -> ScalarState {
    if s.len < 5 {
        s.packed = s.packed * 256 + b as Field;
    }
    if (b < 48) | (b > 57) {
        s.digits_only = false;
    }
    if (s.len < 20) & (b >= 48) & (b <= 57) {
        s.number = s.number * 10 + (b - 48) as Field;
    }
    s.len += 1;
    s
}

/// A canonical unsigned decimal integer of any length: digits only, and no
/// leading zero unless the value is 0.
fn scalar_is_digits(s: ScalarState) -> bool {
    s.digits_only & (s.len > 0) & ((s.len == 1) | !s.leading_zero)
}

/// A canonical unsigned decimal integer that fits in a u64. With at most 20
/// digits `number` is the exact value (below 10^20 < 2^67).
fn scalar_is_uint(s: ScalarState) -> bool {
    scalar_is_digits(s) & (s.len <= 20) & (((s.number as u64) as Field) == s.number)
}

/// A canonical unsigned decimal integer of at most 20 digits. `number` is
/// then its exact value (below 10^20 < 2^67); `as_u64` checks that it fits.
fn scalar_is_short_uint(s: ScalarState) -> bool {
    scalar_is_digits(s) & (s.len <= 20)
}

/// The u64 value of a number below 2^67, which must fit in a u64.
fn as_u64(number: Field) -> u64 {
    let value = number as u64;
    assert((value as Field) == number, "OIDC numeric claim must be an unsigned integer");
    value
}

fn scalar_is_literal(s: ScalarState) -> bool {
    // "true", "false" and "null" as big-endian packed bytes.
    let is_true = (s.len == 4) & (s.packed == 0x74727565);
    let is_false = (s.len == 5) & (s.packed == 0x66616c7365);
    let is_null = (s.len == 4) & (s.packed == 0x6e756c6c);
    is_true | is_false | is_null
}

/// The structured-document scalar domain: u64 integers, true, false, null.
pub(crate) fn scalar_is_valid(s: ScalarState) -> bool {
    scalar_is_uint(s) | scalar_is_literal(s)
}

/// The scalar domain of an ignored flat-profile value: an
/// unsigned integer of any length, true, false, null.
pub(crate) fn scalar_is_valid_any(s: ScalarState) -> bool {
    scalar_is_digits(s) | scalar_is_literal(s)
}

/// The byte after a backslash in a JSON string (RFC 8259 section 7).
pub(crate) fn json_escape_byte(b: u8) -> bool {
    (b == 34)
        | (b == 92)
        | (b == 47)
        | (b == 98)
        | (b == 102)
        | (b == 110)
        | (b == 114)
        | (b == 116)
        | (b == 117)
}

pub(crate) fn hex_digit(b: u8) -> bool {
    ((b >= 48) & (b <= 57)) | ((b >= 65) & (b <= 70)) | ((b >= 97) & (b <= 102))
}

fn record_claim(
    mut state: ClaimState,
    id: u32,
    quoted: bool,
    value_start: u32,
    value_len: u32,
    scalar: ScalarState,
) -> ClaimState {
    if id < 7 {
        assert(state.seen[id] == 0, "duplicate OIDC claim");
        state.seen[id] = 1;
        if (id == 0) | (id == 1) | (id == 2) | (id == 3) | (id == 5) {
            assert(quoted, "OIDC string claim must be a string");
            state.starts[id] = value_start;
            state.lengths[id] = value_len;
        } else {
            assert(!quoted, "OIDC numeric claim must be a number");
            assert(scalar_is_short_uint(scalar), "OIDC numeric claim must be an unsigned integer");
            if id == 4 {
                state.expiry = scalar.number;
            } else {
                state.not_before = scalar.number;
            }
        }
    }
    // Another key needs no check here: the scanner checks every scalar when
    // it ends, and a string or nested value has no scalar of its own.
    state
}

fn copy_claim<let N: u32>(input: BoundedVec<u8, N>, start: u32, len: u32) -> BoundedVec<u8, 256> {
    // Parser-derived offsets: the raw value starts at `start` and holds `len`
    // <= 256 decoded bytes. Its only escape is the two-byte escaped solidus
    //, decoded here to one '/'. Every read stays inside the raw value,
    // so before input.len() <= N. An assurance level has no escape.
    let mut storage = [0; 256];
    let mut source = start;
    for j in 0..256 {
        if j < len {
            let b = input.storage()[source];
            if b == 92 {
                storage[j] = 47;
                source += 2;
            } else {
                storage[j] = b;
                source += 1;
            }
        }
    }
    BoundedVec::from_parts(storage, len)
}

pub struct ProfileClaims {
    pub claims: Claims,
    pub assurance_level: BoundedVec<u8, 256>,
}

/// The claims of `parse_claims_profile_with_iat`: the flat-profile claims,
/// the profile's assurance level and the signed issue time.
pub struct ClaimsWithIat {
    pub claims: Claims,
    /// Empty unless the profile reads one, as in `ProfileClaims`.
    pub assurance_level: BoundedVec<u8, 256>,
    /// The signed `iat`: the one top-level `iat` member, an unsigned
    /// decimal integer that fits in a u64.
    pub issued_at: u64,
}

/// "iat" as the big-endian key prefix that the scanner accumulates.
global IAT_KEY_PREFIX: Field = 6906228;
/// The scanner's id for `iat` when the caller reads it (ids 0 to 6 are the
/// claims of `ClaimState`, 7 is any other key).
global IAT_ID: u32 = 8;
/// "level" as the big-endian key prefix that the scanner accumulates.
global LEVEL_KEY_PREFIX: Field = 465558725996;

/// Claims profiles of `parse_claims_profile`. Every profile ignores other
/// root members after checking them as bounded JSON.
/// The flat domain: no profile-specific member.
pub global PROFILE_FLAT: u8 = 0;
/// `amr`, when present, is an array of strings.
pub global PROFILE_AMR: u8 = 1;
/// `amr` and `scope`, when present, are arrays of strings, and
/// `reliability_info` is an object whose direct string `level` is returned
/// as the assurance level.
pub global PROFILE_AMR_SCOPE_RELIABILITY: u8 = 2;

pub fn parse_claims<let N: u32>(input: BoundedVec<u8, N>) -> Claims {
    parse_claims_profile(input, PROFILE_FLAT).claims
}

/// `profile` is one of the `PROFILE_*` constants.
pub fn parse_claims_profile<let N: u32>(input: BoundedVec<u8, N>, profile: u8) -> ProfileClaims {
    let result = scan_claims(input, profile, false);
    ProfileClaims { claims: result.claims, assurance_level: result.assurance_level }
}

/// As `parse_claims_profile`, and also returns the signed `iat`.
/// The accepted domain is the profile's domain with one more rule: the
/// payload has exactly one top-level `iat` member, and its value is an
/// unsigned decimal integer (as for `exp` and `nbf`). A missing, repeated,
/// quoted, boolean, null, signed, fractional or leading-zero `iat` is
/// rejected, and so is a value above the u64 range.
pub fn parse_claims_profile_with_iat<let N: u32>(
    input: BoundedVec<u8, N>,
    profile: u8,
) -> ClaimsWithIat {
    scan_claims(input, profile, true)
}

/// The one claims scanner. `read_iat` is a constant at every call site; with
/// `false` the `iat` rules fold away and `iat` is another key.
///
/// Nested values. A root member value that is an object or an array is
/// scanned by the same byte machine as the root, with a counter of the open
/// nested containers (`depth`, at most 8) and a bit stack of their kinds. A
/// nested key never selects a claim, and a nested string follows the rules of
/// an ignored root string, so names inside a nested value cannot shadow a
/// root claim. The amr/scope arrays and reliability_info of profiles 1 and 2
/// are nested values with two more rules: amr/scope elements are strings, and
/// a direct `level` member of reliability_info is an unescaped string of at
/// most 256 bytes, at most once, captured as the assurance level.
fn scan_claims<let N: u32>(input: BoundedVec<u8, N>, profile: u8, read_iat: bool) -> ClaimsWithIat {
    assert(profile <= PROFILE_AMR_SCOPE_RELIABILITY, "unknown OIDC JSON profile");
    assert(input.len() <= N, "claims exceed capacity");
    assert_valid_utf8(input.storage(), input.len());
    let mut state =
        ClaimState { starts: [0; 7], lengths: [0; 7], seen: [0; 7], expiry: 0, not_before: 0 };
    let mut issued_at: Field = 0;
    let mut iat_seen = false;
    let mut key_prefix: Field = 0;
    let mut key_len = 0;
    let mut field_id = 7;
    let mut value_start = 0;
    let mut value_len = 0;
    let mut scalar =
        ScalarState { len: 0, packed: 0, leading_zero: false, number: 0, digits_only: false };
    // 0 leading ws, 1 object expects key or end, 2 key bytes, 3 colon,
    // 4 value (or `]` of an array), 5 string value, 6 scalar, 7 separator or
    // end after a value, 8 trailing ws.
    let mut phase = 0;
    let mut quoted = false;
    let mut after_comma = false;
    // The kind of the current root member: 1 amr, 2 scope, 3 reliability_info
    // (profiles 1 and 2 only), else 0. Nested keys do not change it.
    let mut extra_kind = 0;
    let mut extra_seen = [false; 3];
    let mut escape = false;
    let mut hex_left = 0;
    // `depth` open nested containers inside the current root member value;
    // bit k of `arrays` is 1 when the k-th innermost of them is an array.
    let mut depth: u32 = 0;
    let mut arrays: u32 = 0;
    // The last key was a direct `level` of reliability_info; `capture`: the
    // current string is that level.
    let mut level_key = false;
    let mut capture = false;
    let mut level_seen = false;
    let mut assurance_start = 0;
    let mut assurance_len = 0;

    for i in 0..N {
        if i < input.len() {
            let b = input.storage()[i];
            let nested = depth > 0;
            let in_array = (arrays & 1) == 1;
            // `b` follows a complete value: a separator, an end or whitespace.
            let mut after_value = false;
            // `b` ends the innermost open container (the root when not nested).
            let mut close = false;
            let mut record_this_byte = false;
            if phase == 0 {
                if ws(b) {} else {
                    assert(b == 123, "claims must be object");
                    phase = 1;
                }
            } else if phase == 1 {
                if ws(b) {} else if b == 125 {
                    assert(nested | !after_comma, "trailing comma in claims");
                    assert(!nested | !after_comma, "trailing comma in nested JSON");
                    close = true;
                } else {
                    assert(nested | (b == 34), "claim key must be string");
                    assert(!nested | (b == 34), "nested key must be string");
                    key_prefix = 0;
                    key_len = 0;
                    after_comma = false;
                    phase = 2;
                }
            } else if phase == 2 {
                if b == 92 {
                    assert(nested, "escaped JSON keys are unsupported");
                    assert(!nested, "escaped JSON strings are unsupported");
                } else if b == 34 {
                    if nested {
                        level_key = (depth == 1)
                            & (extra_kind == 3)
                            & (key_len == 5)
                            & (key_prefix == LEVEL_KEY_PREFIX);
                    } else {
                        field_id = claim_key_id(key_prefix, key_len);
                        if read_iat & (key_len == 3) & (key_prefix == IAT_KEY_PREFIX) {
                            field_id = IAT_ID;
                        }
                        extra_kind = 0;
                        if profile > 0 {
                            if (key_len == 3) & (key_prefix == 6385010) {
                                extra_kind = 1;
                            }
                            if profile == 2 {
                                if (key_len == 5) & (key_prefix == 495589486693) {
                                    extra_kind = 2;
                                }
                                if (key_len == 16)
                                    & (key_prefix == 152058612351525704010997417147246732911) {
                                    extra_kind = 3;
                                }
                            }
                        }
                        if extra_kind > 0 {
                            assert(!extra_seen[extra_kind - 1], "duplicate OIDC profile claim");
                            extra_seen[extra_kind - 1] = true;
                        }
                    }
                    phase = 3;
                } else {
                    assert(nested | (b >= 32), "control byte in key");
                    assert(!nested | (b >= 32), "control byte in nested JSON string");
                    assert(nested | (key_len < 256), "claim key too long");
                    assert(!nested | (key_len < 256), "nested JSON string too long");
                    // At most 16 bytes encode exactly in big-endian (<2^128 < Fr); longer keys retain only this prefix and remain gated by full key_len.
                    if key_len < 16 {
                        key_prefix = key_prefix * 256 + (b as Field);
                    }
                    key_len += 1;
                }
            } else if phase == 3 {
                if ws(b) {} else {
                    assert(nested | (b == 58), "claim key needs colon");
                    assert(!nested | (b == 58), "nested key needs colon");
                    phase = 4;
                }
            } else if phase == 4 {
                if ws(b) {} else if in_array & (b == 93) {
                    assert(!after_comma, "trailing comma in nested JSON");
                    close = true;
                } else {
                    after_comma = false;
                    if !nested & (extra_kind > 0) {
                        assert(
                            (extra_kind == 3) & (b == 123) | (extra_kind != 3) & (b == 91),
                            "OIDC profile claim has wrong type",
                        );
                    }
                    if (depth == 1) & ((extra_kind == 1) | (extra_kind == 2)) {
                        assert(b == 34, "OIDC profile array must contain strings");
                    }
                    if level_key {
                        assert(b == 34, "assurance level must be string");
                    }
                    if b == 34 {
                        if level_key {
                            assert(!level_seen, "duplicate assurance level");
                            level_seen = true;
                        }
                        capture = level_key;
                        quoted = true;
                        value_start = i + 1;
                        value_len = 0;
                        escape = false;
                        hex_left = 0;
                        phase = 5;
                    } else if (b == 123) | (b == 91) {
                        // Any other root member may hold a nested value.
                        assert(nested | (field_id == 7), "nested claim value unsupported");
                        assert(depth < 8, "nested JSON depth exceeds profile");
                        arrays = arrays * 2 + ((b == 91) as u32);
                        depth += 1;
                        phase = if b == 123 { 1 } else { 4 };
                    } else {
                        assert(
                            !nested | ((b != 125) & (b != 93) & (b != 44) & (b != 58)),
                            "nested value required",
                        );
                        quoted = false;
                        scalar = start_scalar(b);
                        phase = 6;
                    }
                    level_key = false;
                }
            } else if phase == 5 {
                // Value_len counts decoded bytes. A selected claim
                // (field_id != 7) holds at most 256 of them and admits only the
                // escaped solidus; the assurance level holds at most 256 and
                // admits no escape; any other string admits every JSON escape
                // and any length. Nested strings keep field_id 7.
                let free = (field_id == 7) & !capture;
                if hex_left > 0 {
                    assert(hex_digit(b), "invalid JSON unicode escape");
                    hex_left -= 1;
                } else if escape {
                    if free {
                        assert(json_escape_byte(b), "invalid JSON escape");
                    } else {
                        assert(b == 47, "OIDC claim escape unsupported");
                    }
                    escape = false;
                    if b == 117 {
                        hex_left = 4;
                    }
                    assert(free | (value_len < 256), "claim value too long");
                    value_len += 1;
                } else if b == 92 {
                    assert(!capture, "escaped JSON strings are unsupported");
                    escape = true;
                } else if b == 34 {
                    if capture {
                        assurance_start = value_start;
                        assurance_len = value_len;
                    }
                    capture = false;
                    phase = 7;
                } else {
                    assert(nested | (b >= 32), "control byte in value");
                    assert(!nested | (b >= 32), "control byte in nested JSON string");
                    assert(free | (value_len < 256), "claim value too long");
                    value_len += 1;
                }
            } else if phase == 6 {
                if ws(b) | (b == 44) | (b == 125) | (b == 93) {
                    assert(nested | (b != 93), "nested claim value unsupported");
                    assert(scalar_is_valid_any(scalar), "invalid JSON scalar");
                    after_value = true;
                } else {
                    // A scalar holding a bracket is never valid JSON.
                    assert((b != 123) & (b != 91), "nested claim value unsupported");
                    scalar = advance_scalar(scalar, b);
                }
            } else if phase == 7 {
                after_value = true;
            } else {
                assert(ws(b), "trailing claim bytes");
            }

            // One rule for what may follow any value.
            if after_value {
                if ws(b) {
                    phase = 7;
                } else if b == 44 {
                    record_this_byte = !nested;
                    after_comma = true;
                    phase = if in_array { 4 } else { 1 };
                } else {
                    assert(nested | (b == 125), "invalid claim separator");
                    assert(!nested | (b == 125) | (b == 93), "invalid nested JSON separator");
                    record_this_byte = !nested;
                    close = true;
                }
            }

            // One rule for closing a container: a nested one closes with its
            // own bracket kind and returns to its parent; the root ends.
            if close {
                if nested {
                    assert(in_array == (b == 93), "mismatched nested JSON delimiter");
                    arrays = arrays >> 1;
                    depth -= 1;
                    phase = 7;
                } else {
                    phase = 8;
                }
            }
            if record_this_byte {
                state = record_claim(state, field_id, quoted, value_start, value_len, scalar);
                // Record_claim treats IAT_ID as another key.
                if read_iat & (field_id == IAT_ID) {
                    assert(!iat_seen, "duplicate OIDC claim");
                    iat_seen = true;
                    assert(!quoted, "OIDC numeric claim must be a number");
                    assert(
                        scalar_is_short_uint(scalar),
                        "OIDC numeric claim must be an unsigned integer",
                    );
                    issued_at = scalar.number;
                }
            }
        }
    }

    assert(phase == 8, "incomplete claims");
    assert(
        (state.seen[0] == 1)
            & (state.seen[1] == 1)
            & (state.seen[2] == 1)
            & (state.seen[3] == 1)
            & (state.seen[4] == 1),
        "missing required claim",
    );
    let issuer = copy_claim(input, state.starts[0], state.lengths[0]);
    let audience = copy_claim(input, state.starts[1], state.lengths[1]);
    let subject = copy_claim(input, state.starts[2], state.lengths[2]);
    let nonce = copy_claim(input, state.starts[3], state.lengths[3]);
    let authorized_party = copy_claim(input, state.starts[5], state.lengths[5]);
    assert((subject.len() > 0) & (nonce.len() > 0), "empty subject or nonce");
    if state.seen[5] == 1 {
        assert(string_matches(authorized_party, audience), "azp must match aud");
    }
    assert(!read_iat | iat_seen, "missing OIDC iat claim");
    let claims = Claims {
        issuer,
        audience,
        subject,
        nonce,
        expiry: as_u64(state.expiry),
        authorized_party,
        not_before: as_u64(state.not_before),
        has_not_before: state.seen[6] == 1,
    };
    ClaimsWithIat {
        claims,
        assurance_level: copy_claim(input, assurance_start, assurance_len),
        issued_at: as_u64(issued_at),
    }
}

fn header_key_id(key: [u8; 3], len: u32) -> u32 {
    if len == 3 {
        if (key[0] == 97) & (key[1] == 108) & (key[2] == 103) {
            0
        } else if (key[0] == 116) & (key[1] == 121) & (key[2] == 112) {
            1
        } else if (key[0] == 107) & (key[1] == 105) & (key[2] == 100) {
            2
        } else if key == [99, 116, 121] {
            3
        } else {
            4
        }
    } else {
        4
    }
}

pub fn assert_jose_header<let N: u32>(input: BoundedVec<u8, N>) {
    assert_jose_header_algorithm(input, false);
}

pub fn assert_jose_header_algorithm<let N: u32>(input: BoundedVec<u8, N>, es256: bool) {
    assert_jose_header_typed(
        input,
        es256,
        BoundedVec::<u8, 32>::from_array("JWT".as_bytes()),
        false,
        false,
    );
}
/// Typed JWS profile. Default headers require typ=JWT when present and
/// reject cty. Typed consumers require the enrolled exact typ and
/// may require cty=JWT. No token-selected key URL or critical extension accepted.
pub fn assert_jose_header_typed<let N: u32>(
    input: BoundedVec<u8, N>,
    es256: bool,
    expected_typ: BoundedVec<u8, 32>,
    require_typ: bool,
    require_cty_jwt: bool,
) {
    assert_jose_header_rules(
        input,
        es256,
        expected_typ,
        require_typ,
        require_cty_jwt,
        require_cty_jwt,
    );
}

/// `allow_cty` admits one `cty` member equal to `JWT`; `require_cty_jwt`
/// requires it (and implies `allow_cty`). `allow_cty` with neither
/// `require_typ` nor `require_cty_jwt` is the ID-token header of a provider
/// that may omit both: each optional, and `JWT` when present.
pub(crate) fn assert_jose_header_rules<let N: u32>(
    input: BoundedVec<u8, N>,
    es256: bool,
    expected_typ: BoundedVec<u8, 32>,
    require_typ: bool,
    allow_cty: bool,
    require_cty_jwt: bool,
) {
    assert((expected_typ.len() > 0) & (expected_typ.len() <= 32), "invalid expected JWS type");
    assert(input.len() <= N, "header exceeds capacity");
    assert_valid_utf8(input.storage(), input.len());
    let mut key = [0; 3];
    let mut key_len = 0;
    let mut field_id = 4;
    let mut value_len = 0;
    let mut value_prefix = [0; 32];
    let mut counts = [0; 4];
    let mut phase = 0;
    let mut after_comma = false;
    for i in 0..N {
        if i < input.len() {
            let b = input.storage()[i];
            if phase == 0 {
                if ws(b) {} else {
                    assert(b == 123, "JWS header must be object");
                    phase = 1;
                }
            } else if phase == 1 {
                if ws(b) {} else if b == 125 {
                    assert(!after_comma, "trailing comma in JWS header");
                    phase = 8;
                } else {
                    assert(b == 34, "header key must be string");
                    key = [0; 3];
                    key_len = 0;
                    after_comma = false;
                    phase = 2;
                }
            } else if phase == 2 {
                if b == 92 {
                    assert(false, "escaped JWS header key unsupported");
                } else if b == 34 {
                    field_id = header_key_id(key, key_len);
                    assert(
                        (field_id < 3) | ((field_id == 3) & (allow_cty | require_cty_jwt)),
                        "unsupported JWS header key",
                    );
                    phase = 3;
                } else {
                    assert(b >= 32, "control byte in header key");
                    assert(key_len < 256, "header key too long");
                    if key_len < 3 {
                        key[key_len] = b;
                    }
                    key_len += 1;
                }
            } else if phase == 3 {
                if ws(b) {} else {
                    assert(b == 58, "header key needs colon");
                    phase = 4;
                }
            } else if phase == 4 {
                if ws(b) {} else {
                    assert(b == 34, "header values must be strings");
                    value_len = 0;
                    value_prefix = [0; 32];
                    phase = 5;
                }
            } else if phase == 5 {
                if b == 92 {
                    assert(false, "escaped JWS header value unsupported");
                } else if b == 34 {
                    phase = 6;
                } else {
                    assert(b >= 32, "control byte in header value");
                    assert(value_len < 256, "header value too long");
                    if value_len < 32 {
                        value_prefix[value_len] = b;
                    }
                    value_len += 1;
                }
            } else if phase == 6 {
                if ws(b) {} else if (b == 44) | (b == 125) {
                    assert(counts[field_id] == 0, "duplicate JWS header field");
                    counts[field_id] = 1;
                    if field_id == 0 {
                        assert(
                            (value_len == 5)
                                & (value_prefix[0] == (if es256 { 69 } else { 82 }))
                                & (value_prefix[1] == 83)
                                & (value_prefix[2] == 50)
                                & (value_prefix[3] == 53)
                                & (value_prefix[4] == 54),
                            "unexpected JWS algorithm",
                        );
                    } else if field_id == 1 {
                        assert(value_len == expected_typ.len(), "typ must match expected JWS type");
                        for j in 0..32 {
                            if j < expected_typ.len() {
                                assert(
                                    value_prefix[j] == expected_typ.storage()[j],
                                    "typ must match expected JWS type",
                                );
                            }
                        }
                    } else if field_id == 3 {
                        assert(
                            (value_len == 3)
                                & (value_prefix[0] == 74)
                                & (value_prefix[1] == 87)
                                & (value_prefix[2] == 84),
                            "cty must be JWT",
                        );
                    }
                    if b == 44 {
                        after_comma = true;
                        phase = 1;
                    } else {
                        phase = 8;
                    }
                } else {
                    assert(false, "invalid JWS header separator");
                }
            } else if phase == 8 {
                assert(ws(b), "trailing header bytes");
            }
        }
    }
    assert((phase == 8) & (counts[0] == 1), "JWS algorithm header is required");
    assert(!require_typ | (counts[1] == 1), "JWS type header is required");
    assert(!require_cty_jwt | (counts[3] == 1), "JWS content type header is required");
}

/// Reject malformed raw UTF-8 while preserving valid non-ASCII JSON text.
/// JSON escape sequences are handled separately by each scanner.
pub(crate) fn assert_valid_utf8<let N: u32>(bytes: [u8; N], len: u32) {
    assert(len <= N, "UTF-8 input exceeds capacity");
    let mut remaining = 0;
    let mut next_min: u8 = 128;
    let mut next_max: u8 = 191;
    for i in 0..N {
        if i < len {
            let b = bytes[i];
            if remaining == 0 {
                if b <= 127 {
                    // ASCII
                } else if (b >= 194) & (b <= 223) {
                    remaining = 1;
                    next_min = 128;
                    next_max = 191;
                } else if b == 224 {
                    remaining = 2;
                    next_min = 160;
                    next_max = 191;
                } else if ((b >= 225) & (b <= 236)) | ((b >= 238) & (b <= 239)) {
                    remaining = 2;
                    next_min = 128;
                    next_max = 191;
                } else if b == 237 {
                    remaining = 2;
                    next_min = 128;
                    next_max = 159;
                } else if b == 240 {
                    remaining = 3;
                    next_min = 144;
                    next_max = 191;
                } else if (b >= 241) & (b <= 243) {
                    remaining = 3;
                    next_min = 128;
                    next_max = 191;
                } else if b == 244 {
                    remaining = 3;
                    next_min = 128;
                    next_max = 143;
                } else {
                    assert(false, "invalid UTF-8");
                }
            } else {
                assert((b >= next_min) & (b <= next_max), "invalid UTF-8");
                remaining -= 1;
                next_min = 128;
                next_max = 191;
            }
        }
    }
    assert(remaining == 0, "truncated UTF-8");
}

#[test]
fn test_parse_flat_google_claims() {
    let payload = BoundedVec::<u8, 256>::from_array(
        "{\"iss\":\"https://accounts.google.com\",\"aud\":\"client-id\",\"sub\":\"user-42\",\"nonce\":\"one-time\",\"exp\":1799999999,\"email_verified\":true}"
            .as_bytes(),
    );
    let claims = parse_claims(payload);
    assert(claims.expiry == 1799999999);
    assert(string_matches(claims.issuer, literal_vec("https://accounts.google.com")));
    assert(string_matches(claims.audience, literal_vec("client-id")));
    assert(string_matches(claims.subject, literal_vec("user-42")));
    assert(string_matches(claims.nonce, literal_vec("one-time")));
}

#[test]
fn test_accept_utf8_subject_and_unknown_value() {
    let payload = BoundedVec::<u8, 128>::from_array(
        "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"é\",\"nonce\":\"n\",\"exp\":99,\"name\":\"雪\"}"
            .as_bytes(),
    );
    let claims = parse_claims(payload);
    assert(claims.subject.len() == 2);
    assert((claims.subject.storage()[0] == 195) & (claims.subject.storage()[1] == 169));
}

#[test(should_fail_with = "invalid UTF-8")]
fn test_reject_invalid_utf8_claim() {
    let payload =
        BoundedVec::<u8, 64>::from_array([123, 34, 105, 115, 115, 34, 58, 34, 255, 34, 125]);
    let _claims = parse_claims(payload);
}

#[test]
fn test_parse_optional_azp_and_nbf() {
    let payload = BoundedVec::<u8, 256>::from_array(
        "{\"iss\":\"provider\",\"aud\":\"client\",\"azp\":\"client\",\"sub\":\"u\",\"nonce\":\"n\",\"nbf\":12,\"exp\":99}"
            .as_bytes(),
    );
    let claims = parse_claims(payload);
    assert(claims.has_not_before & (claims.not_before == 12));
    assert(string_matches(claims.authorized_party, claims.audience));
}

#[test]
fn test_accept_256_byte_subject_boundary() {
    let prefix = "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"";
    let suffix = "\",\"nonce\":\"n\",\"exp\":99}";
    let mut payload = BoundedVec::<u8, 512>::new();
    for i in 0..28 {
        payload.push(prefix.as_bytes()[i]);
    }
    for _i in 0..256 {
        payload.push(120);
    }
    for i in 0..23 {
        payload.push(suffix.as_bytes()[i]);
    }
    let claims = parse_claims(payload);
    assert(claims.subject.len() == 256);
    assert((claims.subject.storage()[0] == 120) & (claims.subject.storage()[255] == 120));
}

#[test(should_fail_with = "duplicate OIDC claim")]
fn test_reject_duplicate_issuer() {
    let payload = BoundedVec::<u8, 256>::from_array(
        "{\"iss\":\"https://accounts.google.com\",\"iss\":\"https://evil.example\",\"aud\":\"client-id\",\"sub\":\"user-42\",\"nonce\":\"one-time\",\"exp\":1799999999}"
            .as_bytes(),
    );
    let _claims = parse_claims(payload);
}

#[test(should_fail_with = "escaped JSON keys are unsupported")]
fn test_reject_escaped_key_alias() {
    let payload = BoundedVec::<u8, 160>::from_array(
        "{\"iss\":\"i\",\"\\u0069ss\":\"evil\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":99}"
            .as_bytes(),
    );
    let _claims = parse_claims(payload);
}

#[test(should_fail_with = "trailing comma in claims")]
fn test_reject_trailing_claim_comma() {
    let payload = BoundedVec::<u8, 96>::from_array(
        "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":99,}".as_bytes(),
    );
    let _claims = parse_claims(payload);
}

// An unknown member may hold a nested value (Facebook cnf, Entra
// roles). A nested name cannot shadow a root claim.
#[test]
fn test_nested_shadow_claim_is_ignored() {
    let payload = BoundedVec::<u8, 256>::from_array(
        "{\"metadata\":{\"iss\":\"https://evil.example\",\"sub\":\"x\"},\"iss\":\"https://accounts.google.com\",\"aud\":\"client-id\",\"sub\":\"user-42\",\"nonce\":\"one-time\",\"exp\":1799999999}"
            .as_bytes(),
    );
    let claims = parse_claims(payload);
    assert(string_matches(claims.issuer, literal_vec("https://accounts.google.com")));
    assert(string_matches(claims.subject, literal_vec("user-42")));
}

#[test(should_fail_with = "missing required claim")]
fn nested_only_issuer_is_not_a_root_claim() {
    let _claims = parse_claims(literal_vec(
        "{\"metadata\":{\"iss\":\"https://accounts.google.com\"},\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}",
    ));
}

#[test(should_fail_with = "invalid JSON scalar")]
fn test_reject_scalar_suffix() {
    let payload = BoundedVec::<u8, 128>::from_array(
        "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":truegarbage}".as_bytes(),
    );
    let _claims = parse_claims(payload);
}

#[test(should_fail_with = "invalid JSON scalar")]
fn test_reject_leading_zero_number() {
    let payload = BoundedVec::<u8, 128>::from_array(
        "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":01}".as_bytes(),
    );
    let _claims = parse_claims(payload);
}

#[test]
fn record_whitespace_phase7_and_optional_claims() {
    let payload = literal_vec(
        "{\"iss\":\"i\" , \"aud\":\"a\", \"sub\":\"s\", \"nonce\":\"n\", \"exp\":99, \"nbf\":7 }",
    );
    let result = parse_claims_profile(payload, 0);
    assert(result.claims.has_not_before & (result.claims.not_before == 7));
}

#[test(should_fail_with = "duplicate OIDC claim")]
fn record_duplicate_mixed_type() {
    let payload = literal_vec(
        "{\"iss\":\"i\", \"iss\":9, \"aud\":\"a\", \"sub\":\"s\", \"nonce\":\"n\", \"exp\":99}",
    );
    let _claims = parse_claims_profile(payload, 0);
}

#[test]
fn test_copy_claim_empty_at_capacity() {
    let input = BoundedVec::<u8, 4>::from_parts([65, 66, 67, 68], 4);
    let out = copy_claim(input, 4, 0);
    assert((out.len() == 0) & (out.storage()[0] == 0));
}

#[test]
fn test_copy_claim_small_capacity_dirty_tail() {
    let input = BoundedVec::<u8, 4>::from_parts([65, 66, 201, 202], 2);
    let out = copy_claim(input, 1, 1);
    assert((out.len() == 1) & (out.storage()[0] == 66));
    assert((out.storage()[1] == 0) & (out.storage()[255] == 0));
}

#[test]
fn test_copy_claim_exact_256_nonzero_end() {
    let input = BoundedVec::<u8, 257>::from_parts([120; 257], 257);
    let out = copy_claim(input, 1, 256);
    assert(out.len() == 256);
    assert((out.storage()[0] == 120) & (out.storage()[255] == 120));
}

#[test]
fn test_parse_jose_header() {
    let header = BoundedVec::<u8, 128>::from_array(
        "{ \"alg\": \"RS256\", \"kid\": \"fixture-key\", \"typ\": \"JWT\" }".as_bytes(),
    );
    assert_jose_header(header);
}

#[test(should_fail_with = "duplicate JWS header field")]
fn test_reject_duplicate_alg() {
    let header =
        BoundedVec::<u8, 64>::from_array("{\"alg\":\"RS256\",\"alg\":\"RS256\"}".as_bytes());
    assert_jose_header(header);
}

#[test(should_fail_with = "trailing comma in JWS header")]
fn test_reject_trailing_comma_header() {
    let header = BoundedVec::<u8, 32>::from_array("{\"alg\":\"RS256\",}".as_bytes());
    assert_jose_header(header);
}

#[test(should_fail_with = "control byte in header value")]
fn test_reject_raw_control_in_kid() {
    let header = BoundedVec::<u8, 64>::from_array([
        123, 34, 97, 108, 103, 34, 58, 34, 82, 83, 50, 53, 54, 34, 44, 34, 107, 105, 100, 34, 58,
        34, 9, 34, 125,
    ]);
    assert_jose_header(header);
}

#[test(should_fail_with = "invalid UTF-8")]
fn test_reject_invalid_utf8_kid() {
    let header = BoundedVec::<u8, 32>::from_array([
        123, 34, 97, 108, 103, 34, 58, 34, 82, 83, 50, 53, 54, 34, 44, 34, 107, 105, 100, 34, 58,
        34, 128, 34, 125,
    ]);
    assert_jose_header(header);
}

#[test]
fn profile_amr_future_methods() {
    let result = parse_claims_profile(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"u\",\"nonce\":\"n\",\"exp\":9,\"amr\":[\"pwd\",\"future-method\"]}",
        ),
        1,
    );
    assert(result.claims.expiry == 9);
}
#[test]
fn profile_nested_assurance() {
    let result = parse_claims_profile(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"u\",\"nonce\":\"n\",\"exp\":9,\"amr\":[\"pwd\"],\"scope\":[\"openid\"],\"reliability_info\":{\"level\":\"gold\",\"reliabilities\":[{\"id\":\"601\",\"updatedAt\":\"date\"},{\"id\":\"626\"}]}}",
        ),
        2,
    );
    assert(string_matches(result.assurance_level, literal_vec("gold")));
}
#[test]
fn profile_nested_shadow_does_not_override_level_or_subject() {
    let result = parse_claims_profile(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"u\",\"nonce\":\"n\",\"exp\":9,\"reliability_info\":{\"level\":\"bronze\",\"other\":{\"level\":\"gold\",\"sub\":\"attacker\"}}}",
        ),
        2,
    );
    assert(string_matches(result.assurance_level, literal_vec("bronze")));
    assert(string_matches(result.claims.subject, literal_vec("u")));
}
#[test(should_fail_with = "OIDC profile array must contain strings")]
fn profile_reject_nested_amr() {
    let _r = parse_claims_profile(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"u\",\"nonce\":\"n\",\"exp\":9,\"amr\":[{}]}",
        ),
        1,
    );
}
#[test(should_fail_with = "duplicate OIDC profile claim")]
fn profile_reject_duplicate_amr() {
    let _r = parse_claims_profile(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"u\",\"nonce\":\"n\",\"exp\":9,\"amr\":[],\"amr\":[]}",
        ),
        1,
    );
}
#[test(should_fail_with = "duplicate assurance level")]
fn profile_reject_duplicate_level() {
    let _r = parse_claims_profile(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"u\",\"nonce\":\"n\",\"exp\":9,\"reliability_info\":{\"level\":\"bronze\",\"level\":\"gold\"}}",
        ),
        2,
    );
}
#[test(should_fail_with = "trailing comma in nested JSON")]
fn profile_reject_array_trailing_comma() {
    let _r = parse_claims_profile(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"u\",\"nonce\":\"n\",\"exp\":9,\"amr\":[\"pwd\",]}",
        ),
        1,
    );
}
// Another nested root member is checked and ignored; it cannot shadow `sub`.
#[test]
fn profile_other_nested_root_is_ignored() {
    let r = parse_claims_profile(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"u\",\"nonce\":\"n\",\"exp\":9,\"other\":{\"sub\":\"x\"}}",
        ),
        2,
    );
    assert(string_matches(r.claims.subject, literal_vec("u")));
}

#[test(should_fail_with = "nested JSON depth exceeds profile")]
fn profile_reject_excess_depth() {
    let _r = parse_claims_profile(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"u\",\"nonce\":\"n\",\"exp\":9,\"reliability_info\":{\"v\":[[[[[[[[0]]]]]]]]}}",
        ),
        2,
    );
}
#[test(should_fail_with = "mismatched nested JSON delimiter")]
fn profile_reject_mismatched_delimiter() {
    let _r = parse_claims_profile(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"u\",\"nonce\":\"n\",\"exp\":9,\"reliability_info\":{\"level\":\"gold\",\"v\":[0}}}",
        ),
        2,
    );
}

#[test]
fn profile_level_after_maximum_depth_child() {
    let result = parse_claims_profile(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"u\",\"nonce\":\"n\",\"exp\":9,\"reliability_info\":{\"v\":[[[[[[[0]]]]]]],\"level\":\"gold\"}}",
        ),
        2,
    );
    assert(string_matches(result.assurance_level, literal_vec("gold")));
}

#[test]
fn typed_resolver_header() {
    assert_jose_header_typed(
        literal_vec(
            "{\"alg\":\"RS256\",\"typ\":\"resolve-response+jwt\",\"kid\":\"root\"}",
        ),
        false,
        BoundedVec::<u8, 32>::from_array("resolve-response+jwt".as_bytes()),
        true,
        false,
    );
}
#[test]
fn typed_identity_content_header() {
    assert_jose_header_typed(
        literal_vec(
            "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"cty\":\"JWT\",\"kid\":\"op\"}",
        ),
        false,
        BoundedVec::<u8, 32>::from_array("JWT".as_bytes()),
        true,
        true,
    );
}
#[test]
fn default_header_type_remains_optional() {
    assert_jose_header(literal_vec("{\"alg\":\"RS256\",\"kid\":\"op\"}"));
}
#[test(should_fail_with = "unsupported JWS header key")]
fn default_header_rejects_content_type() {
    assert_jose_header(literal_vec("{\"alg\":\"RS256\",\"cty\":\"JWT\"}"));
}
#[test(should_fail_with = "typ must match expected JWS type")]
fn default_header_rejects_resolver_confusion() {
    assert_jose_header(
        literal_vec("{\"alg\":\"RS256\",\"typ\":\"resolve-response+jwt\"}"),
    );
}
#[test(should_fail_with = "JWS type header is required")]
fn typed_header_requires_type() {
    assert_jose_header_typed(
        literal_vec("{\"alg\":\"RS256\"}"),
        false,
        BoundedVec::<u8, 32>::from_array("JWT".as_bytes()),
        true,
        false,
    );
}
#[test(should_fail_with = "JWS content type header is required")]
fn typed_header_requires_content_type() {
    assert_jose_header_typed(
        literal_vec("{\"alg\":\"RS256\",\"typ\":\"JWT\"}"),
        false,
        BoundedVec::<u8, 32>::from_array("JWT".as_bytes()),
        true,
        true,
    );
}
#[test(should_fail_with = "duplicate JWS header field")]
fn typed_header_rejects_duplicate_content_type() {
    assert_jose_header_typed(
        literal_vec(
            "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"cty\":\"JWT\",\"cty\":\"JWT\"}",
        ),
        false,
        BoundedVec::<u8, 32>::from_array("JWT".as_bytes()),
        true,
        true,
    );
}
#[test(should_fail_with = "unsupported JWS header key")]
fn typed_header_rejects_key_url() {
    assert_jose_header_typed(
        literal_vec(
            "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"jku\":\"https://evil\"}",
        ),
        false,
        BoundedVec::<u8, 32>::from_array("JWT".as_bytes()),
        true,
        true,
    );
}

#[test]
fn packed_key_empty_short_and_prefix_collision() {
    let claims = parse_claims_profile(
        literal_vec(
            "{\"\":null,\"is\":true,\"iss\":\"i\",\"issx\":\"unknown\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}",
        ),
        0,
    );
    assert(string_matches(claims.claims.issuer, literal_vec("i")));
}

#[test]
fn packed_profile_long_prefix_collision() {
    let result = parse_claims_profile(
        literal_vec(
            "{\"reliability_infox\":true,\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9,\"reliability_info\":{\"level\":\"gold\"}}",
        ),
        2,
    );
    assert(string_matches(result.assurance_level, literal_vec("gold")));
}

#[test]
fn packed_key_accepts_maximum_unknown_key_length() {
    let mut payload = BoundedVec::<u8, 512>::new();
    for i in 0..5 {
        payload.push("{\"iss".as_bytes()[i]);
    }
    for _i in 0..253 {
        payload.push(120);
    }
    let suffix = "\":null,\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}";
    for i in 0..57 {
        payload.push(suffix.as_bytes()[i]);
    }
    let claims = parse_claims_profile(payload, 0);
    assert(string_matches(claims.claims.issuer, literal_vec("i")));
}

#[test(should_fail_with = "claim key too long")]
fn packed_key_rejects_overlength_unknown_key() {
    let mut payload = BoundedVec::<u8, 512>::new();
    for i in 0..5 {
        payload.push("{\"iss".as_bytes()[i]);
    }
    for _i in 0..254 {
        payload.push(120);
    }
    let suffix = "\":null,\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}";
    for i in 0..57 {
        payload.push(suffix.as_bytes()[i]);
    }
    let _claims = parse_claims_profile(payload, 0);
}

// The signed `iat` (parse_claims_profile_with_iat). parse_claims_profile
// keeps its domain: there `iat` is an unread member.
#[test]
fn reads_the_signed_iat() {
    let input = literal_vec(
        "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"iat\" : 1899999940 ,\"exp\":1900003600}",
    );
    let result = parse_claims_profile_with_iat(input, 0);
    assert(result.issued_at == 1899999940);
    assert(result.claims.expiry == 1900003600);
    assert(string_matches(result.claims.subject, literal_vec("s")));
    assert(result.assurance_level.len() == 0);
}

#[test]
fn reads_iat_with_the_profile_level() {
    let input = literal_vec(
        "{\"iat\":7,\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9,\"amr\":[\"iat\"],\"reliability_info\":{\"level\":\"gold\"}}",
    );
    let result = parse_claims_profile_with_iat(input, 2);
    assert(result.issued_at == 7);
    assert(string_matches(result.assurance_level, literal_vec("gold")));
}

#[test]
fn profile_parser_keeps_an_unread_iat() {
    // Without the iat rule a quoted or repeated iat is an ordinary member.
    let _ = parse_claims_profile(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9,\"iat\":\"x\",\"iat\":true}",
        ),
        0,
    );
}

#[test(should_fail_with = "missing OIDC iat claim")]
fn rejects_a_missing_iat() {
    let _ = parse_claims_profile_with_iat(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9,\"iatx\":1}",
        ),
        0,
    );
}

#[test(should_fail_with = "missing OIDC iat claim")]
fn rejects_an_iat_only_inside_an_array() {
    let _ = parse_claims_profile_with_iat(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9,\"amr\":[\"iat\"]}",
        ),
        1,
    );
}

#[test(should_fail_with = "duplicate OIDC claim")]
fn rejects_a_repeated_iat() {
    let _ = parse_claims_profile_with_iat(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9,\"iat\":1,\"iat\":2}",
        ),
        0,
    );
}

#[test(should_fail_with = "OIDC numeric claim must be a number")]
fn rejects_a_quoted_iat() {
    let _ = parse_claims_profile_with_iat(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9,\"iat\":\"1\"}",
        ),
        0,
    );
}

#[test(should_fail_with = "OIDC numeric claim must be an unsigned integer")]
fn rejects_a_null_iat() {
    let _ = parse_claims_profile_with_iat(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9,\"iat\":null}",
        ),
        0,
    );
}

#[test(should_fail_with = "OIDC numeric claim must be an unsigned integer")]
fn rejects_a_true_iat() {
    let _ = parse_claims_profile_with_iat(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9,\"iat\":true}",
        ),
        0,
    );
}

#[test(should_fail_with = "OIDC numeric claim must be an unsigned integer")]
fn rejects_an_iat_above_u64() {
    // 20 digits above 2^64 - 1: the u64 accumulation overflows and the cast-back check rejects it.
    let _ = parse_claims_profile_with_iat(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9,\"iat\":99999999999999999999}",
        ),
        0,
    );
}

#[test]
fn reads_the_largest_u64_iat() {
    let result = parse_claims_profile_with_iat(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9,\"iat\":18446744073709551615}",
        ),
        0,
    );
    assert(result.issued_at == 18446744073709551615);
}

#[test(should_fail_with = "missing OIDC iat claim")]
fn rejects_an_iat_only_inside_reliability_info() {
    let _ = parse_claims_profile_with_iat(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9,\"reliability_info\":{\"level\":\"gold\",\"iat\":5}}",
        ),
        2,
    );
}

#[test]
fn copy_agrees_with_the_profile_scanner() {
    // Both entry points run one scanner. On a token both accept they return
    // the same claims and level.
    let input = literal_vec(
        "{\"iss\":\"i\",\"aud\":\"a\",\"azp\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"iat\":7,\"nbf\":6,\"exp\":9,\"amr\":[\"x\"],\"reliability_info\":{\"level\":\"gold\"}}",
    );
    let a = parse_claims_profile(input, 2);
    let b = parse_claims_profile_with_iat(input, 2);
    assert(string_matches(a.claims.issuer, b.claims.issuer));
    assert(string_matches(a.claims.audience, b.claims.audience));
    assert(string_matches(a.claims.subject, b.claims.subject));
    assert(string_matches(a.claims.nonce, b.claims.nonce));
    assert(string_matches(a.claims.authorized_party, b.claims.authorized_party));
    assert(a.claims.expiry == b.claims.expiry);
    assert(
        (a.claims.not_before == b.claims.not_before)
            & (a.claims.has_not_before == b.claims.has_not_before),
    );
    assert(string_matches(a.assurance_level, b.assurance_level));
    assert(b.issued_at == 7);
}

#[test(should_fail_with = "invalid JSON scalar")]
fn rejects_a_leading_zero_iat() {
    let _ = parse_claims_profile_with_iat(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9,\"iat\":01}",
        ),
        0,
    );
}

// Escapes, nested values, value lengths and integers of the flat profile.
// The payloads below are what a provider signs. Both entry points
// (parse_claims_profile and parse_claims_profile_with_iat) run.
#[test]
fn escaped_solidus_is_decoded_in_claims() {
    // gov.br (Nimbus/json-smart) writes '/' as "\/".
    let input = literal_vec(
        "{\"sub\":\"12345678900\",\"iss\":\"https:\\/\\/sso.acesso.gov.br\\/\",\"aud\":\"rp\\/x\",\"nonce\":\"n\",\"iat\":7,\"exp\":9,\"picture\":\"https:\\/\\/p\\/q\"}",
    );
    let a = parse_claims_profile(input, 0);
    let b = parse_claims_profile_with_iat(input, 0);
    assert(string_matches(a.claims.issuer, literal_vec("https://sso.acesso.gov.br/")));
    assert(string_matches(a.claims.audience, literal_vec("rp/x")));
    assert(string_matches(b.claims.issuer, literal_vec("https://sso.acesso.gov.br/")));
    assert(string_matches(b.claims.audience, literal_vec("rp/x")));
    assert(b.issued_at == 7);
}

#[test]
fn escaped_solidus_is_not_a_backslash() {
    // "a\/b" decodes to "a/b"; it cannot equal the issuer "a\/b" (backslash).
    let claims = parse_claims(literal_vec(
        "{\"iss\":\"a\\/b\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}",
    ));
    assert(string_matches(claims.issuer, literal_vec("a/b")));
    assert(!string_matches(claims.issuer, literal_vec("a\\/b")));
    assert(claims.issuer.len() == 3);
}

#[test(should_fail_with = "OIDC claim escape unsupported")]
fn claim_rejects_an_escaped_backslash() {
    let _ = parse_claims(literal_vec(
        "{\"iss\":\"a\\\\b\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}",
    ));
}

#[test(should_fail_with = "OIDC claim escape unsupported")]
fn claim_rejects_a_unicode_escape() {
    // "\u002f" is '/' too, but the copy decodes only "\/".
    let _ = parse_claims(literal_vec(
        "{\"iss\":\"a\\u002fb\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}",
    ));
}

#[test(should_fail_with = "OIDC claim escape unsupported")]
fn claim_rejects_an_escaped_quote_in_the_copy() {
    let _ = parse_claims_profile_with_iat(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\\\"\",\"nonce\":\"n\",\"iat\":1,\"exp\":9}",
        ),
        0,
    );
}

#[test]
fn unknown_value_accepts_every_json_escape() {
    let input = literal_vec(
        "{\"name\":\"Q \\\"U\\\" \\\\ \\/ \\b\\f\\n\\r\\t \\u00e9\\uD83D\\ude00\",\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"iat\":1,\"exp\":9}",
    );
    let a = parse_claims_profile(input, 0);
    let b = parse_claims_profile_with_iat(input, 0);
    assert(string_matches(a.claims.subject, literal_vec("s")));
    assert(string_matches(b.claims.subject, literal_vec("s")));
}

#[test]
fn escaped_quote_does_not_end_an_unknown_value() {
    // The whole of "a\",\"iss\":\"evil" is one ignored string.
    let claims = parse_claims(literal_vec(
        "{\"name\":\"a\\\",\\\"iss\\\":\\\"evil\",\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}",
    ));
    assert(string_matches(claims.issuer, literal_vec("i")));
}

#[test(should_fail_with = "duplicate OIDC claim")]
fn escaped_quote_cannot_hide_a_duplicate_claim() {
    // Here the escaped backslash ends the value, so the second "iss" is a
    // real root member and the duplicate fails.
    let _ = parse_claims(literal_vec(
        "{\"name\":\"a\\\\\",\"iss\":\"evil\",\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}",
    ));
}

#[test(should_fail_with = "invalid JSON escape")]
fn unknown_value_rejects_an_invalid_escape() {
    let _ = parse_claims(literal_vec(
        "{\"x\":\"\\a\",\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}",
    ));
}

#[test(should_fail_with = "invalid JSON unicode escape")]
fn unknown_value_rejects_a_short_unicode_escape() {
    let _ = parse_claims_profile_with_iat(
        literal_vec(
            "{\"x\":\"\\u12g4\",\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"iat\":1,\"exp\":9}",
        ),
        0,
    );
}

#[test(should_fail_with = "escaped JSON keys are unsupported")]
fn keys_stay_unescaped() {
    let _ = parse_claims(literal_vec(
        "{\"x\\/\":1,\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}",
    ));
}

#[test]
fn facebook_dpop_and_permission_claims() {
    // Meta Limited Login: cnf (DPoP), user_age_range, user_location,
    // user_hometown and user_friends. Checked and ignored.
    let input = BoundedVec::<u8, 512>::from_array(
        "{\"nonce\":\"n\",\"iss\":\"https://www.facebook.com\",\"aud\":\"app\",\"sub\":\"s\",\"iat\":7,\"exp\":9,\"cnf\":{\"jkt\":\"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I\"},\"user_age_range\":{\"min\":21},\"user_location\":{\"id\":\"108424279189115\",\"name\":\"New York\"},\"user_hometown\":{\"id\":\"1\",\"name\":\"S\\u00e3o Paulo\"},\"user_friends\":[\"1234567890123456\"]}"
            .as_bytes(),
    );
    let a = parse_claims_profile(input, 0);
    let b = parse_claims_profile_with_iat(input, 0);
    assert(string_matches(a.claims.issuer, literal_vec("https://www.facebook.com")));
    assert(string_matches(b.claims.subject, literal_vec("s")));
    assert(b.issued_at == 7);
}

#[test]
fn entra_roles_and_wids_arrays() {
    let input = literal_vec(
        "{\"aud\":\"a\",\"iss\":\"i\",\"iat\":1,\"exp\":9,\"nonce\":\"n\",\"roles\":[\"Admin\",\"User\"],\"wids\":[\"b79fbf4d-3ef9-4689-8143-76b194e85509\"],\"sub\":\"s\"}",
    );
    let a = parse_claims_profile(input, 0);
    let b = parse_claims_profile_with_iat(input, 0);
    assert(a.claims.expiry == 9);
    assert(b.claims.expiry == 9);
}

#[test(should_fail_with = "nested claim value unsupported")]
fn selected_claim_cannot_be_nested() {
    let _ = parse_claims(literal_vec(
        "{\"iss\":\"i\",\"aud\":[\"a\"],\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}",
    ));
}

#[test(should_fail_with = "nested claim value unsupported")]
fn signed_iat_cannot_be_nested() {
    let _ = parse_claims_profile_with_iat(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"iat\":[1],\"exp\":9}",
        ),
        0,
    );
}

#[test]
fn nested_value_depth_eight_and_escapes() {
    let claims = parse_claims(literal_vec(
        "{\"x\":[[[[[[[{\"k\":\"a\\\"]}\\/\"}]]]]]]],\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}",
    ));
    assert(string_matches(claims.issuer, literal_vec("i")));
}

#[test(should_fail_with = "nested JSON depth exceeds profile")]
fn nested_value_depth_nine_rejected() {
    let _ = parse_claims(literal_vec(
        "{\"x\":[[[[[[[[[0]]]]]]]]],\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}",
    ));
}

#[test(should_fail_with = "escaped JSON strings are unsupported")]
fn nested_keys_stay_unescaped() {
    let _ = parse_claims(literal_vec(
        "{\"x\":{\"k\\/\":1},\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}",
    ));
}

#[test(should_fail_with = "mismatched nested JSON delimiter")]
fn nested_value_mismatched_delimiter() {
    let _ = parse_claims(literal_vec(
        "{\"x\":{\"k\":[1}},\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}",
    ));
}

#[test(should_fail_with = "invalid JSON scalar")]
fn nested_value_rejects_a_signed_number() {
    let _ = parse_claims(literal_vec(
        "{\"x\":{\"k\":-1},\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}",
    ));
}

#[test(should_fail_with = "escaped JSON strings are unsupported")]
fn assurance_level_stays_unescaped() {
    let _ = parse_claims_profile(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"u\",\"nonce\":\"n\",\"exp\":9,\"reliability_info\":{\"level\":\"go\\/ld\"}}",
        ),
        2,
    );
}

#[test]
fn profile_nested_strings_admit_escapes() {
    let r = parse_claims_profile(
        literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"u\",\"nonce\":\"n\",\"exp\":9,\"amr\":[\"p\\/w\"],\"reliability_info\":{\"level\":\"gold\",\"reliabilities\":[{\"id\":\"6\\/1\"}]}}",
        ),
        2,
    );
    assert(string_matches(r.assurance_level, literal_vec("gold")));
}

fn payload_with_value(key: str<4>, value_len: u32, escaped: bool) -> BoundedVec<u8, 1024> {
    // {"<key>":"x...x","iss":"i","aud":"a","sub":"s","nonce":"n","iat":1,"exp":9}
    // with `value_len` decoded bytes; with `escaped` the last one is "\/".
    let mut payload = BoundedVec::<u8, 1024>::new();
    payload.push(123);
    payload.push(34);
    for i in 0..4 {
        if key.as_bytes()[i] != 32 {
            payload.push(key.as_bytes()[i]);
        }
    }
    payload.push(34);
    payload.push(58);
    payload.push(34);
    for i in 0..600 {
        if i + 1 < value_len {
            payload.push(120);
        } else if i + 1 == value_len {
            if escaped {
                payload.push(92);
                payload.push(47);
            } else {
                payload.push(120);
            }
        }
    }
    let suffix = "\",\"iss\":\"i\",\"aud\":\"a\",\"nonce\":\"n\",\"iat\":1,\"exp\":9}";
    for i in 0..50 {
        payload.push(suffix.as_bytes()[i]);
    }
    payload
}

#[test]
fn unknown_value_has_no_256_byte_cap() {
    // A 600-byte unknown member; the subject is 256 decoded bytes, the
    // last of them an escaped solidus (257 raw bytes).
    let mut payload = payload_with_value("name", 600, false);
    let _ = payload.pop();
    let tail = ",\"sub\":\"";
    for i in 0..8 {
        payload.push(tail.as_bytes()[i]);
    }
    for _ in 0..255 {
        payload.push(121);
    }
    payload.push(92);
    payload.push(47);
    payload.push(34);
    payload.push(125);
    let a = parse_claims_profile(payload, 0);
    let b = parse_claims_profile_with_iat(payload, 0);
    assert(a.claims.subject.len() == 256);
    assert(a.claims.subject.storage()[254] == 121);
    assert(a.claims.subject.storage()[255] == 47);
    assert(string_matches(a.claims.subject, b.claims.subject));
}

#[test(should_fail_with = "claim value too long")]
fn subject_keeps_the_256_byte_cap() {
    let _ = parse_claims(payload_with_value("sub ", 257, false));
}

#[test(should_fail_with = "claim value too long")]
fn escaped_subject_keeps_the_256_byte_cap() {
    let _ = parse_claims_profile_with_iat(payload_with_value("sub ", 257, true), 0);
}

#[test]
fn unknown_integers_of_any_length() {
    // 2^64 and a 30-digit integer in ignored members, root and nested.
    let input = literal_vec(
        "{\"x\":18446744073709551616,\"y\":123456789012345678901234567890,\"z\":{\"n\":99999999999999999999999},\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"iat\":1,\"exp\":18446744073709551615}",
    );
    let a = parse_claims_profile(input, 0);
    let b = parse_claims_profile_with_iat(input, 0);
    assert(a.claims.expiry == 18446744073709551615);
    assert(b.claims.expiry == 18446744073709551615);
}

#[test(should_fail_with = "OIDC numeric claim must be an unsigned integer")]
fn expiry_above_u64_rejected() {
    let _ = parse_claims(literal_vec(
        "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":18446744073709551616}",
    ));
}

#[test(should_fail_with = "OIDC numeric claim must be an unsigned integer")]
fn not_before_of_21_digits_rejected() {
    let _ = parse_claims(literal_vec(
        "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9,\"nbf\":100000000000000000000}",
    ));
}

#[test(should_fail_with = "invalid JSON scalar")]
fn unknown_integer_keeps_canonical_form() {
    let _ = parse_claims(literal_vec(
        "{\"x\":0123,\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":9}",
    ));
}

#[test]
fn copy_agrees_on_escapes_and_nested_values() {
    let input = literal_vec(
        "{\"iss\":\"https:\\/\\/i\",\"aud\":\"a\\/b\",\"azp\":\"a\\/b\",\"sub\":\"s\",\"nonce\":\"n\\/\",\"iat\":7,\"exp\":9,\"cnf\":{\"jkt\":\"k\"},\"x\":\"\\u00e9\",\"amr\":[\"x\"]}",
    );
    let a = parse_claims_profile(input, 1);
    let b = parse_claims_profile_with_iat(input, 1);
    assert(string_matches(a.claims.issuer, b.claims.issuer));
    assert(string_matches(a.claims.audience, b.claims.audience));
    assert(string_matches(a.claims.authorized_party, b.claims.authorized_party));
    assert(string_matches(a.claims.nonce, b.claims.nonce));
    assert(string_matches(a.claims.issuer, literal_vec("https://i")));
    assert(string_matches(b.claims.nonce, literal_vec("n/")));
    assert(b.issued_at == 7);
}

#[test]
fn id_token_header_without_typ_or_cty() {
    assert_jose_header_rules(
        literal_vec("{\"alg\":\"RS256\",\"kid\":\"k\"}"),
        false,
        BoundedVec::<u8, 32>::from_array("JWT".as_bytes()),
        false,
        true,
        false,
    );
    assert_jose_header_rules(
        literal_vec("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"k\"}"),
        false,
        BoundedVec::<u8, 32>::from_array("JWT".as_bytes()),
        false,
        true,
        false,
    );
    assert_jose_header_rules(
        literal_vec(
            "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"cty\":\"JWT\",\"kid\":\"k\"}",
        ),
        false,
        BoundedVec::<u8, 32>::from_array("JWT".as_bytes()),
        false,
        true,
        false,
    );
}

#[test(should_fail_with = "typ must match expected JWS type")]
fn id_token_header_rejects_another_typ() {
    assert_jose_header_rules(
        literal_vec(
            "{\"alg\":\"RS256\",\"typ\":\"entity-statement+jwt\",\"kid\":\"k\"}",
        ),
        false,
        BoundedVec::<u8, 32>::from_array("JWT".as_bytes()),
        false,
        true,
        false,
    );
}

#[test(should_fail_with = "cty must be JWT")]
fn id_token_header_rejects_another_cty() {
    assert_jose_header_rules(
        literal_vec("{\"alg\":\"RS256\",\"cty\":\"json\",\"kid\":\"k\"}"),
        false,
        BoundedVec::<u8, 32>::from_array("JWT".as_bytes()),
        false,
        true,
        false,
    );
}

#[test(should_fail_with = "claims must be object")]
fn bom_signed_payload_rejected() {
    let mut input = BoundedVec::<u8, 8>::from_array([239, 187, 191]);
    input.push(123);
    input.push(125);
    let _ = parse_claims_profile(input, 0);
}
#[test(should_fail_with = "JWS header must be object")]
fn bom_signed_rs256_header_rejected() {
    let mut input = BoundedVec::<u8, 8>::from_array([239, 187, 191]);
    input.push(123);
    input.push(125);
    assert_jose_header_algorithm(input, false);
}
#[test(should_fail_with = "JWS header must be object")]
fn bom_signed_es256_header_rejected() {
    let mut input = BoundedVec::<u8, 8>::from_array([239, 187, 191]);
    input.push(123);
    input.push(125);
    assert_jose_header_algorithm(input, true);
}
