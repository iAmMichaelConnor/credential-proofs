pub(crate) mod test_inputs;
mod header_parsing;

mod test_success {

    use crate::{
        headers::{body_hash::get_body_hash, email_address::get_email_address},
        MAX_EMAIL_ADDRESS_LENGTH,
        partial_hash::partial_sha256_var_end,
        tests::test_inputs::EmailLarge,
    };
    use sha256::sha256_var;

    #[test]
    fn test_dkim_signature() {
        EmailLarge::PUBKEY.verify_dkim_signature(EmailLarge::HEADER, EmailLarge::SIGNATURE);
    }

    #[test]
    fn test_body_hash() {
        // get the body hash from the header
        let signed_body_hash = get_body_hash(
            EmailLarge::HEADER,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX,
        );
        // compute the body hash
        let computed_body_hash: [u8; 32] =
            sha256_var(EmailLarge::BODY.storage(), EmailLarge::BODY.len());
        // compare the body hashes
        assert(
            signed_body_hash == computed_body_hash,
            "SHA256 hash computed over body does not match body hash found in DKIM-signed header",
        );
    }

    #[test]
    fn test_partial_hash() {
        // get the body hash from the header
        let signed_body_hash = get_body_hash(
            EmailLarge::HEADER,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX,
        );
        // finish the partial hash
        let computed_body_hash = partial_sha256_var_end(
            EmailLarge::PARTIAL_BODY_HASH,
            EmailLarge::PARTIAL_BODY.storage(),
            EmailLarge::PARTIAL_BODY.len() as u64,
            EmailLarge::PARTIAL_BODY_REAL_LENGTH as u64,
        );
        // compare the body hashes
        assert(
            signed_body_hash == computed_body_hash,
            "Sha256 hash computed over body does not match DKIM-signed header",
        );
    }

    #[test]
    fn test_address_extraction() {
        let from = comptime { "from".as_bytes() };
        let to = comptime { "to".as_bytes() };
        // 16k gate cost? has to be able to be brought down
        let from_address = get_email_address(
            EmailLarge::HEADER,
            EmailLarge::FROM_HEADER_SEQUENCE,
            EmailLarge::FROM_ADDRESS_SEQUENCE,
            from,
        );
        let to_address = get_email_address(
            EmailLarge::HEADER,
            EmailLarge::TO_HEADER_SEQUENCE,
            EmailLarge::TO_ADDRESS_SEQUENCE,
            to,
        );
        let expected_from_address: BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> =
            BoundedVec::from_array("runnier.leagues.0j@icloud.com".as_bytes());
        let expected_to_address: BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> =
            BoundedVec::from_array("zkewtest@gmail.com".as_bytes());
        assert_eq(
            expected_from_address,
            from_address,
            "From address does not match expected address",
        );
        assert_eq(expected_to_address, to_address, "To address does not match expected address");
    }
}

mod test_tampered_hash {
    use crate::{headers::body_hash::get_body_hash, tests::test_inputs::EmailLarge};
    use sha256::sha256_var;

    #[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
    fn test_tampered_header() {
        // get tampered header
        let mut tampered_header = unsafe { EmailLarge::tampered_header() };
        // attempt to verify the DKIM signature
        EmailLarge::PUBKEY.verify_dkim_signature(tampered_header, EmailLarge::SIGNATURE);
    }

    #[test]
    fn test_tampered_body() {
        // get the body hash from the header
        let signed_body_hash = get_body_hash(
            EmailLarge::HEADER,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX,
        );
        // get tampered body
        let mut tampered_body = unsafe { EmailLarge::tampered_body() };
        // compute the body hash
        let tampered_body_hash: [u8; 32] = sha256_var(tampered_body.storage(), tampered_body.len());
        // compare the body hashes
        assert(
            signed_body_hash != tampered_body_hash,
            "SHA256 hash should not match tampered body hash",
        );
    }

    #[test(should_fail_with = "all to assert_max_bit_size")]
    fn test_dkim_signature_unnormalized() {
        let mut sig = EmailLarge::SIGNATURE;
        let pubkey = EmailLarge::PUBKEY;
        let delta = 1;
        sig[0] += delta * 0x1000000000000000000000000000000;
        sig[1] -= delta;
        pubkey.verify_dkim_signature(EmailLarge::HEADER, sig);
    }
}

mod test_redc_binding_2048 {
    use crate::tests::test_inputs::EmailLarge;

    /// Regression test for Veridise vulnerability reintroduced by PR #52.
    /// Verifies that modifying redc changes hash[1] (redc hash) but NOT hash[0] (modulus hash).
    #[test]
    fn test_modified_redc_changes_hash_2048() {
        // Construct a pubkey with same modulus but tampered redc (flip one limb)
        let modulus = [1; crate::KEY_LIMBS_2048];
        let mut tampered_redc = [2; crate::KEY_LIMBS_2048];
        tampered_redc[0] = tampered_redc[0] + 1;
        let pubkey = crate::dkim::RSAPubkey::new(modulus, [2; crate::KEY_LIMBS_2048]);
        let original_hash = pubkey.hash();
        let tampered_pubkey = crate::dkim::RSAPubkey::new(modulus, tampered_redc);
        let tampered_hash = tampered_pubkey.hash();

        // hash[0] = poseidon(modulus) -- must be UNCHANGED since modulus is the same
        assert(
            original_hash[0] == tampered_hash[0],
            "modulus hash (hash[0]) must not change when only redc is modified",
        );
        // hash[1] = poseidon(redc) -- must DIFFER since redc was tampered
        assert(
            original_hash[1] != tampered_hash[1],
            "redc hash (hash[1]) must change when redc is modified",
        );
    }
}

mod test_redc_binding_1024 {
    use crate::tests::test_inputs::EmailSmall;

    /// Same regression test as test_redc_binding but for the 1024-bit code path,
    /// which uses poseidon_large_padded_1024 (pads 9 limbs to 18 before hashing).
    #[test]
    fn test_modified_redc_changes_hash_1024() {
        // Keep the modulus fixed while changing only the Montgomery redc limbs.
        let modulus = [1; crate::KEY_LIMBS_1024];
        let mut tampered_redc = [2; crate::KEY_LIMBS_1024];
        tampered_redc[0] = tampered_redc[0] + 1;
        let pubkey = crate::dkim::RSAPubkey::new(modulus, [2; crate::KEY_LIMBS_1024]);
        let original_hash = pubkey.hash();
        let tampered_pubkey = crate::dkim::RSAPubkey::new(modulus, tampered_redc);
        let tampered_hash = tampered_pubkey.hash();

        // hash[0] = poseidon_large_padded_1024(modulus) -- must be UNCHANGED
        assert(
            original_hash[0] == tampered_hash[0],
            "modulus hash (hash[0]) must not change when only redc is modified (1024-bit)",
        );
        // hash[1] = poseidon_large_padded_1024(redc) -- must DIFFER
        assert(
            original_hash[1] != tampered_hash[1],
            "redc hash (hash[1]) must change when redc is modified (1024-bit)",
        );
    }
}

mod header_field_access {

    use crate::{headers::body_hash::get_body_hash, Sequence, tests::test_inputs::EmailLarge};

    #[test(should_fail_with = "Body hash index does not point at the bh= tag value")]
    fn test_bad_body_hash_off_one_minus() {
        // attempt to get body hash with one off index
        let _ = get_body_hash(
            EmailLarge::HEADER,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX - 1,
        );
    }

    #[test(should_fail_with = "Body hash index does not point at the bh= tag value")]
    fn test_bad_body_hash_off_one_plus() {
        // attempt to get body hash with one off index
        let _ = get_body_hash(
            EmailLarge::HEADER,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX + 1,
        );
    }

    #[test(should_fail_with = "Header field name does not match")]
    fn test_bad_body_hash_not_in_dkim_field() {
        // create header field for malicious bh
        let mut dkim_storage = [0; EmailLarge::EMAIL_LARGE_MAX_HEADER_LENGTH];
        // craft a malicious "to" field where attacker tries to put bh in display name
        let mut malicious_to: [u8; 78] = comptime {
            "\r\nto:\"bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=;\" <zkewtest@gmail.com>\r\n"
                .as_bytes()
        };
        let mut malicious_sequence = Sequence {
            index: 8, // 8 to make it check for crlf on both sides (could be anything > 2)
            length: malicious_to.len() - 4, // 4 is the crlf on each end
        };
        for i in 0..malicious_to.len() {
            let index = malicious_sequence.index + i - 2;
            dkim_storage[index] = malicious_to[i];
        }
        let dkim_field: BoundedVec<u8, EmailLarge::EMAIL_LARGE_MAX_HEADER_LENGTH> =
            BoundedVec::from_parts(dkim_storage, EmailLarge::HEADER.len());
        let malicious_body_hash_index = 15;
        // copy the body hash to the beginning of the
        // attempt to get body hash
        let _ = get_body_hash(dkim_field, malicious_sequence, malicious_body_hash_index);
    }

    #[test]
    fn test_body_hash_at_start() {
        let mut dkim_field: [u8; 203] = comptime {
            "dkim-signature:bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=; v=1; a=rsa-sha256; c=relaxed/relaxed; d=icloud.com; s=1a1hai; t=1712141644; h=from:Content-Type:Mime-Version:Subject:Message-Id:Date:to; b="
                .as_bytes()
        };
        let header: BoundedVec<u8, 203> = BoundedVec::from_array(dkim_field);
        let mut dkim_field_sequence = Sequence { index: 0, length: 203 };
        let body_hash_index = 18;
        let _ = get_body_hash(header, dkim_field_sequence, body_hash_index);
    }

    // bh= is found by a tag-list scan, so the look-alike fails at the index
    // check.
    #[test(should_fail_with = "Body hash index does not point at the bh= tag value")]
    fn test_malicious_body_hash_index() {
        // Upstream copied-header spoof: a `From:bh=<hash>` look-alike inside
        // the z= tag value of the DKIM-Signature field.
        let (header, body_hash_index) = EmailLarge::tampered_dkim_field();
        let sequence = Sequence { index: 0, length: header.len() };
        let _ = get_body_hash(header, sequence, body_hash_index);
    }

    #[test(should_fail_with = "DKIM-Signature must contain exactly one bh tag")]
    fn test_corrupted_bh_prefix() {
        // Use an in-bounds, within-limit signed header but replace the ';'
        // before bh=. The bh text then does not start a tag, so the field
        // has no bh tag.
        let mut header = EmailLarge::HEADER;
        header.set(EmailLarge::BODY_HASH_INDEX - 5, 0x78);
        let _ = get_body_hash(
            header,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX,
        );
    }

    #[test(should_fail_with = "Header field must end with CRLF")]
    fn test_header_field_sequence_overflow_end() {
        // make sequence extend beyond the end of the header field
        let mut overflowed_sequence = EmailLarge::DKIM_HEADER_SEQUENCE;
        overflowed_sequence.length = overflowed_sequence.length + 1;
        // set header len to be a bit longer so it doesn't overflow
        let mut longer_storage = EmailLarge::HEADER.storage();
        longer_storage[EmailLarge::HEADER.len()] = 0;
        longer_storage[EmailLarge::HEADER.len() + 1] = 0;
        let longer_header = BoundedVec::from_parts(longer_storage, EmailLarge::HEADER.len() + 2);
        // attempt to get body hash
        let _ = get_body_hash(
            longer_header,
            overflowed_sequence,
            EmailLarge::BODY_HASH_INDEX,
        );
    }

    #[test(should_fail_with = "Header field must start with CRLF")]
    fn test_header_field_sequence_overflow_start() {
        // make sequence extend beyond the start of the header field
        let mut overflowed_sequence = EmailLarge::DKIM_HEADER_SEQUENCE;
        overflowed_sequence.index = overflowed_sequence.index - 1;
        // attempt to get body hash
        let _ = get_body_hash(
            EmailLarge::HEADER,
            overflowed_sequence,
            EmailLarge::BODY_HASH_INDEX,
        );
    }

    #[test(should_fail_with = "Header field must end with CRLF")]
    fn test_header_field_sequence_underflow_end() {
        // make sequence extend beyond the end of the header field
        let mut underflowed_sequence = EmailLarge::DKIM_HEADER_SEQUENCE;
        underflowed_sequence.length = underflowed_sequence.length - 1;
        // attempt to get body hash
        let _ = get_body_hash(
            EmailLarge::HEADER,
            underflowed_sequence,
            EmailLarge::BODY_HASH_INDEX,
        );
    }

    #[test(should_fail_with = "Header field must start with CRLF")]
    fn test_header_field_sequence_underflow_start() {
        // make sequence extend beyond the end of the header field
        let mut underflowed_sequence = EmailLarge::DKIM_HEADER_SEQUENCE;
        underflowed_sequence.index = underflowed_sequence.length + 1;
        // attempt to get body hash
        let _ = get_body_hash(
            EmailLarge::HEADER,
            underflowed_sequence,
            EmailLarge::BODY_HASH_INDEX,
        );
    }

    #[test(should_fail_with = "Header field must not contain newlines")]
    fn test_header_field_multiple_fields() {
        // combine to and dkim-signature fields together
        let combined_sequence = Sequence {
            index: 2,
            length: EmailLarge::TO_HEADER_SEQUENCE.length
                + EmailLarge::DKIM_HEADER_SEQUENCE.length
                + 2, // 2 for crlf in middle
        };
        let mut tampered_header: BoundedVec<u8, EmailLarge::EMAIL_LARGE_MAX_HEADER_LENGTH> = BoundedVec::from_parts(
            [0; EmailLarge::EMAIL_LARGE_MAX_HEADER_LENGTH],
            combined_sequence.length + 4,
        );
        // copy dkim-signature field
        for i in 0..EmailLarge::DKIM_HEADER_SEQUENCE.length + 2 {
            tampered_header.set(
                i,
                EmailLarge::HEADER.get(EmailLarge::DKIM_HEADER_SEQUENCE.index + i - 2),
            );
        }
        tampered_header.set(EmailLarge::DKIM_HEADER_SEQUENCE.length + 2, "\r".as_bytes()[0]);
        tampered_header.set(EmailLarge::DKIM_HEADER_SEQUENCE.length + 3, "\n".as_bytes()[0]);
        // copy to field
        for i in 0..EmailLarge::TO_HEADER_SEQUENCE.length + 2 {
            let index = EmailLarge::DKIM_HEADER_SEQUENCE.length + 4;
            tampered_header.set(
                index + i,
                EmailLarge::HEADER.get(EmailLarge::TO_HEADER_SEQUENCE.index + i),
            );
        }
        // set crlf at end
        tampered_header.set(combined_sequence.length + 2, "\r".as_bytes()[0]);
        tampered_header.set(combined_sequence.length + 3, "\n".as_bytes()[0]);
        let tampered_body_hash_index = 93; // just manually setting this
        // attempt to get body hash
        let _ = get_body_hash(tampered_header, combined_sequence, tampered_body_hash_index);
    }

    #[test(should_fail_with = "Header field out of bounds")]
    fn test_header_field_outside_header() {
        let shortened_header = BoundedVec::from_parts(
            EmailLarge::HEADER.storage(),
            EmailLarge::DKIM_HEADER_SEQUENCE.index + EmailLarge::DKIM_HEADER_SEQUENCE.length - 1,
        );
        // shorten header to be just under the end of the dkim field
        // attempt to get body hash
        let _ = get_body_hash(
            shortened_header,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX,
        );
    }
}

mod test_address_extraction {
    // header field constrains are not checked here, should work same as tests in header_field_access
    use crate::{
        headers::email_address::{get_email_address, parse_email_address},
        Sequence,
        tests::test_inputs::{EmailAddresses, EmailAddressUnderscore, EmailMailboxEdgeCases},
    };

    #[test]
    fn test_email_only() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::ADDRESS_ONLY);
        let address = get_email_address(
            header,
            EmailAddresses::ADDRESS_ONLY_FIELD_SEQUENCE,
            EmailAddresses::ADDRESS_ONLY_ADDRESS_SEQUENCE,
            from,
        );
        assert_eq(address, EmailAddresses::ADDRESS);
    }

    // The upstream unquoted display-name form without brackets is not
    // RFC 5322 (a bare mailbox is [CFWS] addr-spec [CFWS]), and its prefix
    // can alias the mailbox: "bob . alice@x" names bob.alice@x, but the span
    // after the last space is alice@x. Use the angle-address form instead.
    #[test(should_fail_with = "Bare mailbox address must be preceded only by whitespace or comments")]
    fn test_no_brackets() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::NO_BRACKETS);
        let address = get_email_address(
            header,
            EmailAddresses::NO_BRACKETS_FIELD_SEQUENCE,
            EmailAddresses::NO_BRACKETS_ADDRESS_SEQUENCE,
            from,
        );
        assert_eq(address, EmailAddresses::ADDRESS);
    }

    #[test]
    fn test_brackets() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::BRACKETS);
        let address = get_email_address(
            header,
            EmailAddresses::BRACKETS_FIELD_SEQUENCE,
            EmailAddresses::BRACKETS_ADDRESS_SEQUENCE,
            from,
        );
        assert_eq(address, EmailAddresses::ADDRESS);
    }

    #[test]
    fn test_quotes() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::QUOTES);
        let address = get_email_address(
            header,
            EmailAddresses::QUOTES_FIELD_SEQUENCE,
            EmailAddresses::QUOTES_ADDRESS_SEQUENCE,
            from,
        );
        assert_eq(address, EmailAddresses::ADDRESS);
    }

    #[test]
    fn test_underscore_address() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddressUnderscore::HEADER);
        let address = get_email_address(
            header,
            EmailAddressUnderscore::FIELD_SEQUENCE,
            EmailAddressUnderscore::ADDRESS_SEQUENCE,
            from,
        );
        assert_eq(address, EmailAddressUnderscore::ADDRESS);
    }

    #[test(should_fail_with = "Email address must start immediately after '<' if bracket is present")]
    fn test_malicious_display_name() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::QUOTES);
        let _ = get_email_address(
            header,
            EmailAddresses::QUOTES_FIELD_SEQUENCE,
            EmailAddresses::MALICIOUS_QUOTES_ADDRESS_SEQUENCE,
            from,
        );
    }

    #[test(should_fail_with = "Email address must start immediately after '<' if bracket is present")]
    fn test_not_full_address_bracket_start() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        // mutate index to remove "runnier." from address
        let mut malicious_sequence = EmailAddresses::QUOTES_ADDRESS_SEQUENCE;
        malicious_sequence.index = malicious_sequence.index + 8;
        malicious_sequence.length = malicious_sequence.length - 8;
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::QUOTES);
        let _ = get_email_address(
            header,
            EmailAddresses::QUOTES_FIELD_SEQUENCE,
            malicious_sequence,
            from,
        );
    }

    #[test(should_fail_with = "Email address must end with an acceptable character")]
    fn test_not_full_address_bracket_end() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        // mutate index to remove ".com" from address
        let mut malicious_sequence = EmailAddresses::QUOTES_ADDRESS_SEQUENCE;
        malicious_sequence.index = malicious_sequence.index;
        malicious_sequence.length = malicious_sequence.length - 4;
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::QUOTES);
        let _ = get_email_address(
            header,
            EmailAddresses::QUOTES_FIELD_SEQUENCE,
            malicious_sequence,
            from,
        );
    }

    #[test(should_fail_with = "Email address must start with an acceptable character")]
    fn test_not_full_address_start() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        // mutate index to remove "runnier." from address
        let mut malicious_sequence = EmailAddresses::ADDRESS_ONLY_ADDRESS_SEQUENCE;
        malicious_sequence.index = malicious_sequence.index + 8;
        malicious_sequence.length = malicious_sequence.length - 8;
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::ADDRESS_ONLY);
        let _ = get_email_address(
            header,
            EmailAddresses::ADDRESS_ONLY_FIELD_SEQUENCE,
            malicious_sequence,
            from,
        );
    }

    #[test(should_fail_with = "Email address must end with an acceptable character")]
    fn test_not_full_address_end() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        // mutate index to remove ".com" from address
        let mut malicious_sequence = EmailAddresses::ADDRESS_ONLY_ADDRESS_SEQUENCE;
        malicious_sequence.index = malicious_sequence.index;
        malicious_sequence.length = malicious_sequence.length - 4;
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::ADDRESS_ONLY);
        let _ = get_email_address(
            header,
            EmailAddresses::ADDRESS_ONLY_FIELD_SEQUENCE,
            malicious_sequence,
            from,
        );
    }

    #[test]
    fn test_comments_do_not_supply_identity() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailMailboxEdgeCases::COMMENTED);
        let actual = get_email_address(
            header,
            EmailMailboxEdgeCases::COMMENTED_FIELD,
            EmailMailboxEdgeCases::COMMENTED_ACTUAL,
            from,
        );
        assert_eq(actual, BoundedVec::from_array("attacker@example.com".as_bytes()));
    }

    #[test(should_fail_with = "Mailbox field contains another address")]
    fn test_comment_address_cannot_be_selected() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailMailboxEdgeCases::COMMENTED);
        let _ = get_email_address(
            header,
            EmailMailboxEdgeCases::COMMENTED_FIELD,
            EmailMailboxEdgeCases::COMMENTED_VICTIM,
            from,
        );
    }

    #[test(should_fail_with = "Header field contains a control byte")]
    fn test_control_byte_in_display_comment_is_rejected() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let mut header: BoundedVec<u8, 512> = BoundedVec::from_array(
            comptime { "\r\nfrom:attacker@example.com (ok)\r\n".as_bytes() },
        );
        header.set(29, 0x01);
        let field = Sequence { index: 2, length: 30 };
        let address = Sequence { index: 7, length: 20 };
        let _ = get_email_address(header, field, address, from);
    }

    #[test(should_fail_with = "Header field must not contain newlines")]
    fn test_address_cannot_cross_into_next_header() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> =
            BoundedVec::from_array(EmailMailboxEdgeCases::CROSS_FIELD);
        let _ = get_email_address(
            header,
            EmailMailboxEdgeCases::CROSS_FIELD_FROM,
            EmailMailboxEdgeCases::CROSS_FIELD_ADDRESS,
            from,
        );
    }

    #[test(should_fail_with = "Mailbox field contains another address")]
    fn test_multiple_mailboxes_are_rejected() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> =
            BoundedVec::from_array(EmailMailboxEdgeCases::MULTIPLE_MAILBOXES);
        let _ = get_email_address(
            header,
            EmailMailboxEdgeCases::MULTIPLE_FIELD,
            EmailMailboxEdgeCases::MULTIPLE_VICTIM,
            from,
        );
    }

    #[test(should_fail_with = "Email address must contain exactly one @")]
    fn test_malformed_multiple_at_address_is_rejected() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailMailboxEdgeCases::MALFORMED);
        let _ = get_email_address(
            header,
            EmailMailboxEdgeCases::MALFORMED_FIELD,
            EmailMailboxEdgeCases::MALFORMED_ADDRESS,
            from,
        );
    }

    #[test]
    fn test_whitespace_around_bare_mailbox() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailMailboxEdgeCases::WHITESPACE);
        let actual = get_email_address(
            header,
            EmailMailboxEdgeCases::WHITESPACE_FIELD,
            EmailMailboxEdgeCases::WHITESPACE_ADDRESS,
            from,
        );
        assert_eq(actual, BoundedVec::from_array("person@example.com".as_bytes()));
    }

    #[test(should_fail_with = "Angle-address mailbox must close with '>'")]
    fn test_unclosed_angle_address_is_rejected() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> =
            BoundedVec::from_array(EmailMailboxEdgeCases::UNCLOSED_ANGLE);
        let _ = get_email_address(
            header,
            EmailMailboxEdgeCases::UNCLOSED_ANGLE_FIELD,
            EmailMailboxEdgeCases::UNCLOSED_ANGLE_ADDRESS,
            from,
        );
    }

    #[test(should_fail_with = "Email address sequence out of bounds")]
    fn test_address_sequence_cannot_begin_before_colon() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::ADDRESS_ONLY);
        let bad_sequence = Sequence { index: 6, length: 29 };
        let _ = get_email_address(
            header,
            EmailAddresses::ADDRESS_ONLY_FIELD_SEQUENCE,
            bad_sequence,
            from,
        );
    }

    #[test(should_fail_with = "Email address exceeds maximum length")]
    fn test_parse_rejects_address_over_maximum_length() {
        let header: BoundedVec<u8, 400> = BoundedVec::from_array([0; 400]);
        let _ = parse_email_address(header, Sequence { index: 0, length: 321 });
    }

    #[test(should_fail_with = "Header field exceeds maximum length")]
    fn test_field_sequence_over_maximum_length_is_rejected() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailMailboxEdgeCases::COMMENTED);
        let mut too_long = EmailMailboxEdgeCases::COMMENTED_FIELD;
        too_long.length = 326;
        let _ = get_email_address(
            header,
            too_long,
            EmailMailboxEdgeCases::COMMENTED_ACTUAL,
            from,
        );
    }
}

mod test_masking {
    use crate::masking::mask_text;

    #[test]
    fn inactive_storage_does_not_affect_masked_output() {
        let first: BoundedVec<u8, 4> = BoundedVec::from_parts([65, 66, 70, 71], 2);
        let second: BoundedVec<u8, 4> = BoundedVec::from_parts([65, 66, 90, 91], 2);
        let mask = [false, true, true, true];

        let first_result = mask_text::<4>(first, mask);
        let second_result = mask_text::<4>(second, mask);

        assert_eq(first_result, [0, 66, 0, 0]);
        assert_eq(second_result, first_result);
    }

    #[test]
    fn full_length_message_preserves_mask_semantics() {
        let text: BoundedVec<u8, 4> = BoundedVec::from_array([65, 66, 67, 68]);
        let result = mask_text::<4>(text, [false, true, true, false]);

        assert_eq(result, [0, 66, 67, 0]);
    }

    #[test]
    fn empty_message_masks_to_zeroes() {
        let text: BoundedVec<u8, 4> = BoundedVec::from_parts([65, 66, 67, 68], 0);
        let result = mask_text::<4>(text, [true, true, true, true]);

        assert_eq(result, [0, 0, 0, 0]);
    }

    #[test]
    fn zero_capacity_accepts_empty_message() {
        let text: BoundedVec<u8, 0> = BoundedVec::from_array([]);
        let result = mask_text::<0>(text, []);

        assert_eq(result, []);
    }

}
