use crate::{
    BODY_HASH_BASE64_LENGTH, CR, headers::check_header_field_bounds, LF,
    MAX_DKIM_HEADER_FIELD_LENGTH, Sequence,
};
use base64::BASE64_DECODER;

// ON DKIM-SIGNATURE PARSING:
// In the current version, DKIM-SIGNATURE tags are mostly ignored:
// c= is ignored, meaning we assume the canonicalization is relaxed. This can cause denial of service issues
// v= is ignored, meaning we do not check for a valid version of dkim signing
// l= is ignored, meaning we otherwise constrain the body length to be safe
// x= is ignored, meaning we accept signatures without expiration
// sdid= is ignored, meaning that we don't explicitly bind dkim keys to exact signing domains
// You will need to implement your own parsing for the tags' expected values.
//
// bh= is located by a tag-list scan, not by a byte pattern at a prover-chosen
// index (RFC 6376 sections 3.2 and 3.7):
// - The DKIM-Signature field must be the last field of the signed header. The
//   signing input of the signature being verified ends with that field and no
//   CRLF, so an earlier dkim-signature field cannot be selected.
// - A tag starts at the first byte of the field value or after ';' followed by
//   any spaces or tabs. A tag-value cannot contain ';', so text inside h=, i=
//   or z= cannot start a tag.
// - The field must contain exactly one tag named "bh" (followed by '=', a
//   space or a tab). It must be written "bh=" and its value must be exactly 44
//   base64 bytes, followed by ';' or the end of the field.

/**
 * Constrained access to the body hash in the header, with the default
 * DKIM-Signature field cap MAX_DKIM_HEADER_FIELD_LENGTH (300 bytes).
 *
 * @param MAX_HEADER_LENGTH - The maximum length of the email header
 * @param header - The email header as validated in the DKIM signature
 * @param dkim_header_field_sequence - The sequence of the DKIM header field
 * @param body_hash_index - The index of the body hash in the header
 */
pub fn get_body_hash<let MAX_HEADER_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    dkim_header_field_sequence: Sequence,
    body_hash_index: u32,
) -> [u8; 32] {
    get_body_hash_with_field_cap::<MAX_HEADER_LENGTH, MAX_DKIM_HEADER_FIELD_LENGTH>(
        header,
        dkim_header_field_sequence,
        body_hash_index,
    )
}

/**
 * Constrained access to the body hash in the header, with a caller-chosen
 * DKIM-Signature field cap.
 *
 * MAX_DKIM_FIELD_LENGTH bounds dkim_header_field_sequence.length: the
 * canonicalized field bytes from "dkim-signature:" up to the end of the
 * header, with the b= value empty. The field scan runs exactly
 * MAX_DKIM_FIELD_LENGTH iterations, so its cost is linear in the cap.
 *
 * @param MAX_HEADER_LENGTH - The maximum length of the email header
 * @param MAX_DKIM_FIELD_LENGTH - The maximum length of the DKIM-Signature field
 * @param header - The email header as validated in the DKIM signature
 * @param dkim_header_field_sequence - The sequence of the DKIM header field
 * @param body_hash_index - The index of the body hash in the header
 */
pub fn get_body_hash_with_field_cap<let MAX_HEADER_LENGTH: u32, let MAX_DKIM_FIELD_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    dkim_header_field_sequence: Sequence,
    body_hash_index: u32,
) -> [u8; 32] {
    // constrain the access of dkim signature field
    let header_field_name: [u8; 14] = comptime { "dkim-signature".as_bytes() };
    check_header_field_bounds::<MAX_HEADER_LENGTH, MAX_DKIM_FIELD_LENGTH, 14>(
        header,
        dkim_header_field_sequence,
        header_field_name,
    );
    let field_end = dkim_header_field_sequence.end_index();

    // Scan the field value: reject CR, LF and control bytes, and find every
    // tag named "bh". Position p is a tag start when p is the first value
    // byte, or the bytes since the last ';' are all spaces or tabs.
    let start_index = dkim_header_field_sequence.index + 14 + 1;
    let mut tag_start_0 = true; // tag start flag of the current index
    let mut tag_start_1 = false; // ... of index - 1
    let mut tag_start_2 = false; // ... of index - 2
    let mut byte_1: u8 = 0; // byte at index - 1
    let mut byte_2: u8 = 0; // byte at index - 2
    let mut bh_tag_count: u32 = 0;
    let mut bh_tag_has_equals = false;
    let mut bh_value_index: u32 = 0;
    for i in 0..MAX_DKIM_FIELD_LENGTH {
        let index = start_index + i;
        let mut byte: u8 = 0;
        if index < field_end {
            byte = header.get_unchecked(index);
            assert(byte != CR, "Header field must not contain newlines");
            assert(byte != LF, "Header field must not contain newlines");
            assert(
                ((byte >= 0x20) & (byte != 0x7f)) | (byte == 0x09),
                "Header field contains a control byte",
            );
        }
        let is_wsp = (byte == 0x20) | (byte == 0x09);
        // A tag named "bh" starts at index - 2. Inactive bytes read as 0.
        if tag_start_2 & (byte_2 == 0x62) & (byte_1 == 0x68) & ((byte == 0x3d) | is_wsp) {
            bh_tag_count += 1;
            bh_tag_has_equals = byte == 0x3d;
            bh_value_index = index + 1;
        }
        let next_tag_start = (byte == 0x3b) | (tag_start_0 & is_wsp);
        tag_start_2 = tag_start_1;
        tag_start_1 = tag_start_0;
        tag_start_0 = next_tag_start;
        byte_2 = byte_1;
        byte_1 = byte;
    }
    assert(field_end == header.len(), "DKIM-Signature must be the last signed header field");
    assert(bh_tag_count == 1, "DKIM-Signature must contain exactly one bh tag");
    assert(bh_tag_has_equals, "The bh tag must be written as 'bh='");
    assert(
        body_hash_index == bh_value_index,
        "Body hash index does not point at the bh= tag value",
    );

    // The value is exactly 44 bytes inside the field, followed by ';' or the
    // end of the field. The end of the field is the end of the header, so no
    // byte outside the active header is read.
    let body_hash_end = body_hash_index + BODY_HASH_BASE64_LENGTH;
    assert(body_hash_end <= field_end, "Body hash index accessed outside of DKIM header field");
    if body_hash_end != field_end {
        assert(
            header.get_unchecked(body_hash_end) == 0x3b,
            "No ';' suffix found at asserted bh index",
        );
    }
    // get the body hash
    get_body_hash_unsafe(header, body_hash_index)
}

/**
 * Get the body hash from the header without validating the access index.
 * The pinned base64 decoder rejects bytes outside the standard alphabet.
 *
 * @param MAX_HEADER_LENGTH - The maximum length of the email header
 * @param header - The email header as validated in the DKIM signature
 * @param body_hash_index - The asserted index to find the body hash at
 */
pub fn get_body_hash_unsafe<let MAX_HEADER_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    body_hash_index: u32,
) -> [u8; 32] {
    // get the body hash
    let mut body_hash_encoded: [u8; BODY_HASH_BASE64_LENGTH] = [0; BODY_HASH_BASE64_LENGTH];
    for i in 0..BODY_HASH_BASE64_LENGTH {
        body_hash_encoded[i] = header.get_unchecked(body_hash_index + i);
    }
    // return the decoded body hash
    BASE64_DECODER::decode(body_hash_encoded)
}
