//! Exact simple/simple DKIM signing input for the action-mail account profile.

use sha256::sha256_var;
use zkemail::dkim::RSAPubkey;

pub fn signed_header(
    sender: [u8; 96],
    sender_len: u32,
    service_domain: [u8; 64],
    service_domain_len: u32,
    selector: [u8; 64],
    selector_len: u32,
    action_hex: [u8; 64],
) -> BoundedVec<u8, 512> {
    let mut body = BoundedVec::<u8, 96>::new();
    push_literal(&mut body, "CRED-PROOF-ACTION:");
    for i in 0..64 {
        body.push(action_hex[i]);
    }
    body.push(13);
    body.push(10);
    let body_hash_b64 = encode_body_hash(sha256_var(body.storage(), body.len()));

    let mut header = BoundedVec::<u8, 512>::new();
    push_literal(&mut header, "from:");
    for i in 0..96 {
        if i < sender_len {
            header.push(sender[i]);
        }
    }
    push_literal(
        &mut header,
        "\r\ndkim-signature:v=1; a=rsa-sha256; c=simple/simple; d=",
    );
    for i in 0..64 {
        if i < service_domain_len {
            header.push(service_domain[i]);
        }
    }
    push_literal(&mut header, "; s=");
    for i in 0..64 {
        if i < selector_len {
            header.push(selector[i]);
        }
    }
    push_literal(&mut header, "; h=from; bh=");
    for i in 0..44 {
        header.push(body_hash_b64[i]);
    }
    // RFC 6376 §3.7 hashes the DKIM-Signature field without its final CRLF.
    push_literal(&mut header, "; b=");
    header
}

fn push_literal<let N: u32, let M: u32>(out: &mut BoundedVec<u8, N>, value: str<M>) {
    for i in 0..M {
        out.push(value.as_bytes()[i]);
    }
}

fn encode_body_hash(hash: [u8; 32]) -> [u8; 44] {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".as_bytes();
    let mut encoded = [0; 44];
    for group in 0..11 {
        let i = group * 3;
        let b0 = hash[i];
        let b1 = if i + 1 < 32 { hash[i + 1] } else { 0 };
        let b2 = if i + 2 < 32 { hash[i + 2] } else { 0 };
        encoded[group * 4] = alphabet[(b0 >> 2) as u32];
        encoded[group * 4 + 1] = alphabet[(((b0 & 3) << 4) | (b1 >> 4)) as u32];
        if i + 1 < 32 {
            encoded[group * 4 + 2] = alphabet[(((b1 & 15) << 2) | (b2 >> 6)) as u32];
        } else {
            encoded[group * 4 + 2] = 61;
        }
        if i + 2 < 32 {
            encoded[group * 4 + 3] = alphabet[(b2 & 63) as u32];
        } else {
            encoded[group * 4 + 3] = 61;
        }
    }
    encoded
}

#[test]
fn test_reference_dkim_signing_input_bytes() {
    let sender = "alice@service.example".as_bytes();
    let domain = "service.example".as_bytes();
    let selector = "s1".as_bytes();
    let mut sender_storage = [0; 96];
    let mut domain_storage = [0; 64];
    let mut selector_storage = [0; 64];
    for i in 0..sender.len() {
        sender_storage[i] = sender[i];
    }
    for i in 0..domain.len() {
        domain_storage[i] = domain[i];
    }
    for i in 0..selector.len() {
        selector_storage[i] = selector[i];
    }
    let mut action = [0; 64];
    for i in 0..64 {
        action[i] = "0123456789abcdef".as_bytes()[i % 16];
    }
    let actual = signed_header(
        sender_storage,
        sender.len(),
        domain_storage,
        domain.len(),
        selector_storage,
        selector.len(),
        action,
    );
    let expected: BoundedVec<u8, 512> = BoundedVec::from_array(
        "from:alice@service.example\r\ndkim-signature:v=1; a=rsa-sha256; c=simple/simple; d=service.example; s=s1; h=from; bh=P3R/uxdzMiJPqV8TZkPn1HSMJQQ8sLODv95bpmr+9FA=; b="
            .as_bytes(),
    );
    assert_eq(actual, expected, "DKIM signing input bytes differ from RFC reference");
}

#[test]
fn test_ephemeral_rsa2048_dkim_signature() {
    let sender = "alice@service.example".as_bytes();
    let domain = "service.example".as_bytes();
    let selector = "s1".as_bytes();
    let mut sender_storage = [0; 96];
    let mut domain_storage = [0; 64];
    let mut selector_storage = [0; 64];
    for i in 0..sender.len() {
        sender_storage[i] = sender[i];
    }
    for i in 0..domain.len() {
        domain_storage[i] = domain[i];
    }
    for i in 0..selector.len() {
        selector_storage[i] = selector[i];
    }
    let mut action = [0; 64];
    for i in 0..64 {
        action[i] = "0123456789abcdef".as_bytes()[i % 16];
    }
    let header = signed_header(
        sender_storage,
        sender.len(),
        domain_storage,
        domain.len(),
        selector_storage,
        selector.len(),
        action,
    );
    let key = RSAPubkey::<18>::new(
        [
            0x33c7733029ed164b61909c58f47ad,
            0x288e4b4ce0a486606fb814f380a904,
            0xc165e01f473d97b4e0f01d81de49e5,
            0x2197344b81a898303fb7b855826ca5,
            0xc5bf0de768788a1a29325a1d56bb74,
            0x8b5bcb1e4b20c1e0c0e5e4b738526e,
            0x17758f3a3f1fa41c80234de9de116f,
            0x6f85f9d6ce76495fb31fb90a3456bc,
            0xc63abfe7b232beae42db755a51d2cc,
            0x1e6e9baf162f685d975291b79db6d7,
            0xb795fef996c9a4115e5706ff077414,
            0x7f2a4558989fa9aea25319e5467b52,
            0x17f68ed9bfe507b1850b7315c97380,
            0x636e2e93a04fa2a3abeec87a0f771b,
            0x98b2424e406dc4c80a3c9bfe615f6d,
            0x56dd5e0786c9b8d439fb3a80275ede,
            0xe2e815f3f3a45b9bb34221c1ddfc87,
            0xd3,
        ],
        [
            0x5323fd74d8c6ddf410958fa6ffa2d0,
            0xac2a656bf629676e1f5168435643e1,
            0xe60fcb44d3c1831fba4684b11a5fb6,
            0xd7dee615a8f10e04dba5f082c2c601,
            0x8293cef2116be77dee8c5ee4bf9126,
            0x9df4d672f25e7afc4916f611d4d60c,
            0xe4c7eca0dab292916de5426e50d180,
            0x32fb6865aa7687bbb3b1b1d79156f2,
            0x55377ba0fc61664f7a3f1a77e8642a,
            0x749a065765a5bf8e33f4739049653e,
            0x834a18c734b8a14148fa48c8dab124,
            0xf7c19b1b682f4a2b07b49fd2ae44dc,
            0x2b71b509c86f9f611b3db8136e043d,
            0xb12c5ef360727414d11d4de1681e0f,
            0x71e6e3b14268bdc75513d1aa11ec00,
            0xd7fdcf304e491566c9c0d855fb3e5c,
            0x10765d8720e7ade61b97c4b7b09c2e,
            0x4d53,
        ],
    );
    let signature: [Field; 18] = [
        0xe88e09bc658fb2e19c8ecb8d129e3d,
        0xb6a8babd5062eea04178b40a8144f0,
        0x90da35b7ffb1ec65e836c47ce72c6c,
        0x6b821922f9e88c8bc26c00dc2af4f2,
        0x119265a232d7866d25e2eae38d610c,
        0x33bd830e7799b2f67a4f4697985d34,
        0xd190cb8303eeb33f3ab139b994f33c,
        0xa3564d075285e5fbb93a9d5f015501,
        0x3436a9fb1d4f38643402b6ff85ae76,
        0xf98309f754333b5b256f4cb2ad5514,
        0x7540503dbccaa23a326e7e0a287669,
        0x15c53aff16f44d308d08888a189c3b,
        0x6d53044ed848f9ad351299ff56e2b6,
        0x55f2b020e65a777754ca3f5b87408f,
        0x88ef7f4447ca3e59b6142d045c31bc,
        0xd7b0ba5f7b764c7714babc3c607a62,
        0xed187ac690c06f2e26ddb21a129351,
        0x41,
    ];
    let _signed_header_hash = key.verify_dkim_signature(header, signature);
}
