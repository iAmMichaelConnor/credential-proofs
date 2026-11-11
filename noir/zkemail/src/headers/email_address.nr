use crate::{
    EMAIL_ADDRESS_CHAR_TABLE, headers::constrain_header_field_detect_last_angle_bracket,
    MAX_EMAIL_ADDRESS_LENGTH, Sequence,
};

/// Extract the one mailbox of a bounded, DKIM-authenticated header field.
///
/// Accepted forms: a bare address (`[CFWS] addr-spec [CFWS]`, preceded by a
/// space or the field colon), or quoted display text before one angle-address,
/// with surrounding spaces and balanced comments. The unquoted display-name form
/// without brackets (`Bob Smith alice@x`) is rejected: it is not RFC 5322 and can
/// alias the mailbox (`bob . alice@x` names `bob.alice@x`). `@` or angle
/// characters inside quotes or comments cannot supply the identity. The span
/// must cover one complete unfolded field (unfold relaxed-canonicalized fields
/// first; folded simple-canonicalized fields are outside the profile) of at
/// most `MAX_EMAIL_ADDRESS_LENGTH + name length + 1` bytes; CR, LF and control
/// bytes other than tab are rejected. Addresses use letters, digits, `.`, `_`,
/// `-` and one non-edge `@` (no `+`).
///
/// The caller binds the field occurrence to DKIM's `h=` selection and enforces
/// its key/domain policy: global field uniqueness is not proved.
pub fn get_email_address<let MAX_HEADER_LENGTH: u32, let HEADER_FIELD_NAME_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    header_field_sequence: Sequence,
    email_address_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH],
) -> BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> {
    assert(header.len() <= MAX_HEADER_LENGTH, "Header length exceeds capacity");
    // The field constraint scans from immediately after `name:` and validates
    // CR/LF, quotes, comments, and angle-bracket structure across the full
    // active field value.
    let last_angle_bracket = constrain_header_field_detect_last_angle_bracket::<MAX_HEADER_LENGTH, MAX_EMAIL_ADDRESS_LENGTH + HEADER_FIELD_NAME_LENGTH + 1, HEADER_FIELD_NAME_LENGTH>(
        header,
        header_field_sequence,
        header_field_name,
    );
    let value_start = header_field_sequence.index + HEADER_FIELD_NAME_LENGTH + 1;
    let field_end = header_field_sequence.end_index();
    assert(email_address_sequence.index >= value_start, "Email address sequence out of bounds");
    assert(email_address_sequence.index <= field_end, "Email address sequence out of bounds");
    assert(
        email_address_sequence.length <= field_end - email_address_sequence.index,
        "Email address sequence out of bounds",
    );
    assert(email_address_sequence.length > 0, "Email address cannot be empty");
    let email_end = email_address_sequence.index + email_address_sequence.length;

    // For angle-address form the mailbox starts immediately after the sole
    // unquoted '<'. A '<' inside a quoted display name or comment is ignored.
    if last_angle_bracket != 0 {
        assert(
            email_address_sequence.index == last_angle_bracket + 1,
            "Email address must start immediately after '<' if bracket is present",
        );
    }
    let parsed_address = parse_email_address(header, email_address_sequence);

    // A mailbox address must be the only unquoted, uncommented address in the
    // selected header field. Quoted display names and comments may contain
    // email-like text, but they cannot supply the identity.
    let mut quote_open = false;
    let mut escaped = false;
    let mut comment_depth = 0;
    let mut at_count = 0;
    let mut unexpected_after_mailbox = false;
    let mut close_angle_count = 0;
    let mut close_angle_index = 0;
    let value_length = field_end - value_start;
    for i in 0..(MAX_EMAIL_ADDRESS_LENGTH + HEADER_FIELD_NAME_LENGTH + 1) {
        let index = value_start + i;
        if index < field_end {
            let byte = header.get_unchecked(index);
            if comment_depth > 0 {
                if escaped {
                    escaped = false;
                } else if byte == 0x5c {
                    escaped = true;
                } else if byte == 0x28 {
                    comment_depth += 1;
                } else if byte == 0x29 {
                    comment_depth -= 1;
                }
            } else if quote_open {
                if escaped {
                    escaped = false;
                } else if byte == 0x5c {
                    escaped = true;
                } else if byte == 0x22 {
                    quote_open = false;
                }
            } else if byte == 0x22 {
                assert(
                    index < email_address_sequence.index,
                    "Unexpected quoted text after mailbox address",
                );
                assert(
                    last_angle_bracket != 0,
                    "Bare mailbox address must be preceded only by whitespace or comments",
                );
                quote_open = true;
            } else if byte == 0x28 {
                comment_depth = 1;
            } else if byte == 0x40 {
                at_count += 1;
                assert(
                    index >= email_address_sequence.index & index < email_end,
                    "Mailbox field contains another address",
                );
            } else if byte == 0x3e {
                close_angle_count += 1;
                assert(close_angle_count == 1, "Multiple mailbox angle brackets are unsupported");
                assert(last_angle_bracket != 0, "Unmatched mailbox angle bracket");
                assert(index == email_end, "Email address must end at '>' if present");
                close_angle_index = index;
            } else if index >= email_end {
                if byte != 0x20 {
                    unexpected_after_mailbox = true;
                }
            } else if (last_angle_bracket == 0) & (index < email_address_sequence.index) {
                // Bare form is [CFWS] addr-spec [CFWS] (RFC 5322 section
                // 3.4). Any other byte before the address would make the
                // selected span a strict suffix of the real mailbox, for
                // example the obs-local-part "bob . alice@x" names
                // bob.alice@x, not alice@x.
                assert(
                    (byte == 0x20) | (byte == 0x09),
                    "Bare mailbox address must be preceded only by whitespace or comments",
                );
            }
        }
    }
    assert(!quote_open & !escaped, "Unterminated quoted display name");
    assert(comment_depth == 0, "Unterminated mailbox comment");
    assert(at_count == 1, "Email address must contain exactly one @");
    assert(!unexpected_after_mailbox, "Unexpected data after mailbox address");
    assert(value_length > 0, "Header field has an empty value");
    if last_angle_bracket != 0 {
        assert(close_angle_count == 1, "Angle-address mailbox must close with '>'");
    } else {
        assert(close_angle_count == 0, "Unmatched mailbox angle bracket");
    }
    if close_angle_count == 1 {
        assert(close_angle_index == email_end, "Email address must end at '>' if present");
    }

    parsed_address
}

/**
 * Check that a span is a well-formed address in the bounded alphabet and copy
 * it out. This alone does not pin the span to the field's mailbox: it checks
 * only the span and its two neighbouring bytes. Use get_email_address to
 * extract an identity from a header field.
 */
pub fn parse_email_address<let MAX_HEADER_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    email_address_sequence: Sequence,
) -> BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> {
    assert(header.len() <= MAX_HEADER_LENGTH, "Header length exceeds capacity");
    assert(email_address_sequence.length > 0, "Email address cannot be empty");
    assert(
        email_address_sequence.length <= MAX_EMAIL_ADDRESS_LENGTH,
        "Email address exceeds maximum length",
    );
    assert(email_address_sequence.index <= header.len(), "Email address starts out of bounds");
    assert(
        email_address_sequence.length <= header.len() - email_address_sequence.index,
        "Email address sequence out of bounds",
    );
    // check the sequence is proceeded by an acceptable character
    if email_address_sequence.index != 0 {
        let preceding_byte = header.get_unchecked(email_address_sequence.index - 1);
        assert(preceding_byte <= 122, "Email address has an unsupported leading delimiter");
        assert(
            EMAIL_ADDRESS_CHAR_TABLE[preceding_byte as u32] == 2,
            "Email address must start with an acceptable character",
        );
    }
    if email_address_sequence.end_index() < header.len() {
        let following_byte =
            header.get_unchecked(email_address_sequence.index + email_address_sequence.length);
        assert(following_byte <= 122, "Email address has an unsupported trailing delimiter");
        assert(
            (following_byte == 0x20) | (EMAIL_ADDRESS_CHAR_TABLE[following_byte as u32] == 3),
            "Email address must end with an acceptable character",
        );
    }
    // check the email address and assign
    let mut email_storage: [u8; MAX_EMAIL_ADDRESS_LENGTH] = [0; MAX_EMAIL_ADDRESS_LENGTH];
    let mut at_count = 0;
    let mut at_index = 0;
    let mut previous_byte = 0;
    for i in 0..MAX_EMAIL_ADDRESS_LENGTH {
        let index = email_address_sequence.index + i;
        if index < email_address_sequence.end_index() {
            let letter = header.get_unchecked(index);
            email_storage[i] = letter;
            assert(letter <= 122, "Email address contains unsupported byte");
            assert(
                EMAIL_ADDRESS_CHAR_TABLE[letter as u32] == 1,
                "Email address must only contain acceptable characters",
            );
            if letter == 0x40 {
                at_count += 1;
                at_index = i;
            }
            if letter == 0x2e {
                assert(i != 0, "Email address cannot start with a dot");
                assert(
                    (previous_byte != 0x2e) & (previous_byte != 0x40),
                    "Malformed email address dot",
                );
            }
            if letter == 0x40 {
                assert(previous_byte != 0x2e, "Malformed email address local part");
            }
            previous_byte = letter;
        }
    }
    assert(at_count == 1, "Email address must contain exactly one @");
    assert(at_index > 0, "Email address local part cannot be empty");
    assert(at_index + 1 < email_address_sequence.length, "Email address domain cannot be empty");
    assert(previous_byte != 0x2e, "Email address cannot end with a dot");
    assert(
        header.get_unchecked(email_address_sequence.index + at_index + 1) != 0x2e,
        "Email address domain cannot start with a dot",
    );
    BoundedVec::from_parts(email_storage, email_address_sequence.length)
}
