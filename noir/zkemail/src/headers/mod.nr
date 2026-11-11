use crate::{CR, LF, Sequence};

pub mod body_hash;
pub mod email_address;

/**
 * Constrain a sequence in a header to be within the correct bounds
 *
 * @param MAX_HEADER_LENGTH - The maximum length of the email header
 * @param MAX_HEADER_FIELD_LENGTH - The maximum length of the header field
 * @param HEADER_FIELD_NAME_LENGTH - The length of the header field name
 * @param header - The email header as validated in the DKIM signature
 * @param header_field_sequence - The sequence of the header field
 * @param header_field_name - The name of the header field
 */
pub(crate) fn check_header_field_bounds<let MAX_HEADER_LENGTH: u32, let MAX_HEADER_FIELD_LENGTH: u32, let HEADER_FIELD_NAME_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    header_field_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH],
) {
    assert(header.len() <= MAX_HEADER_LENGTH, "Header length exceeds capacity");
    assert(
        header_field_sequence.length >= HEADER_FIELD_NAME_LENGTH + 1,
        "Header field is shorter than its name and colon",
    );
    assert(
        header_field_sequence.length <= MAX_HEADER_FIELD_LENGTH,
        "Header field exceeds maximum length",
    );
    assert(header_field_sequence.index <= header.len(), "Header field starts out of bounds");
    assert(
        header_field_sequence.length <= header.len() - header_field_sequence.index,
        "Header field out of bounds of header",
    );
    // check the range of the sequence is within the header (so we can use get_unchecked)
    let end_index = header_field_sequence.end_index();
    assert(end_index <= header.len(), "Header field out of bounds of header");

    // if the sequence is not the start, check for a newline
    if header_field_sequence.index != 0 {
        assert(header_field_sequence.index >= 2, "Header field start lacks CRLF");
        assert(
            header.get_unchecked(header_field_sequence.index - 2) == CR,
            "Header field must start with CRLF",
        );
        assert(
            header.get_unchecked(header_field_sequence.index - 1) == LF,
            "Header field must start with CRLF",
        );
    }

    // if the sequence is not the end, check for a newline
    if end_index != header.len() {
        assert(end_index + 1 < header.len(), "Header field must end with CRLF");
        assert(header.get_unchecked(end_index) == CR, "Header field must end with CRLF");
        assert(header.get_unchecked(end_index + 1) == LF, "Header field must end with CRLF");
        if end_index + 2 < header.len() {
            let next = header.get_unchecked(end_index + 2);
            assert((next != 0x20) & (next != 0x09), "Header field continues on a folded line");
        }
    }

    // check that the header field name matches the expected name
    for i in 0..HEADER_FIELD_NAME_LENGTH {
        assert(
            header.get_unchecked(header_field_sequence.index + i) == header_field_name[i],
            "Header field name does not match",
        );
    }
    assert(
        header.get_unchecked(header_field_sequence.index + HEADER_FIELD_NAME_LENGTH) == 0x3a,
        "Header field name must be followed by a colon",
    );
}

/**
 * Constrain a sequence to one complete, unfolded header field.
 * Folded simple-canonicalized fields are unsupported; relaxed canonicalization
 * must unfold the full field before extraction.
 *
 * Constrain a sequence in a header to match the specific header field
 *
 * @param MAX_HEADER_LENGTH - The maximum length of the email header
 * @param MAX_HEADER_FIELD_LENGTH - The maximum length of the header field
 * @param HEADER_FIELD_NAME_LENGTH - The length of the header field name
 * @param header - The email header as validated in the DKIM signature
 * @param header_field_sequence - The sequence of the header field
 * @param header_field_name - The name of the header field
 */
pub fn constrain_header_field<let MAX_HEADER_LENGTH: u32, let MAX_HEADER_FIELD_LENGTH: u32, let HEADER_FIELD_NAME_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    header_field_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH],
) {
    // constrain beginning of header field
    check_header_field_bounds::<MAX_HEADER_LENGTH, MAX_HEADER_FIELD_LENGTH, HEADER_FIELD_NAME_LENGTH>(
        header,
        header_field_sequence,
        header_field_name,
    );

    // check the header field is uninterrupted
    let start_index = header_field_sequence.index + HEADER_FIELD_NAME_LENGTH + 1;
    for i in 0..MAX_HEADER_FIELD_LENGTH {
        let index = start_index + i;
        if (index < header_field_sequence.end_index()) {
            let byte = header.get_unchecked(index);
            assert(byte != CR, "Header field must not contain newlines");
            assert(byte != LF, "Header field must not contain newlines");
            assert(
                ((byte >= 0x20) & (byte != 0x7f)) | (byte == 0x09),
                "Header field contains a control byte",
            );
        }
    }
}

/**
 * constrain_header_field with checks for the last occurence of "<" inside the loop to save constraints
 */
pub fn constrain_header_field_detect_last_angle_bracket<let MAX_HEADER_LENGTH: u32, let MAX_HEADER_FIELD_LENGTH: u32, let HEADER_FIELD_NAME_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    header_field_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH],
) -> u32 {
    // constrain beginning of header field
    check_header_field_bounds::<MAX_HEADER_LENGTH, MAX_HEADER_FIELD_LENGTH, HEADER_FIELD_NAME_LENGTH>(
        header,
        header_field_sequence,
        header_field_name,
    );

    // check the header field is uninterrupted
    let mut last_angle_bracket = 0;
    let mut angle_bracket_count = 0;
    let mut quoted = false;
    let mut escaped = false;
    let mut comment_depth = 0;
    let start_index = header_field_sequence.index + HEADER_FIELD_NAME_LENGTH + 1;
    let value_length = header_field_sequence.end_index() - start_index;
    for i in 0..MAX_HEADER_FIELD_LENGTH {
        let index = start_index + i;
        if (index < header_field_sequence.end_index()) {
            let byte = header.get_unchecked(index);
            assert(byte != CR, "Header field must not contain newlines");
            assert(byte != LF, "Header field must not contain newlines");
            assert(
                ((byte >= 0x20) & (byte != 0x7f)) | (byte == 0x09),
                "Header field contains a control byte",
            );
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
            } else if quoted {
                if escaped {
                    escaped = false;
                } else if byte == 0x5c {
                    escaped = true;
                } else if byte == 0x22 {
                    quoted = false;
                }
            } else {
                if byte == 0x22 {
                    quoted = true;
                } else if byte == 0x28 {
                    comment_depth = 1;
                } else if byte == 0x29 {
                    assert(false, "Unmatched mailbox comment delimiter");
                } else if byte == 0x3c {
                    angle_bracket_count += 1;
                    assert(
                        angle_bracket_count == 1,
                        "Multiple mailbox angle brackets are unsupported",
                    );
                    last_angle_bracket = index;
                } else if byte == 0x3e {
                    assert(angle_bracket_count == 1, "Unmatched mailbox angle bracket");
                    assert(index > last_angle_bracket, "Unmatched mailbox angle bracket");
                }
            }
        }
    }
    assert(!quoted & !escaped, "Unterminated quoted display name");
    assert(comment_depth == 0, "Unterminated mailbox comment");
    assert(value_length > 0, "Header field has an empty value");
    last_angle_bracket
}
