use crate::{multiply_challenge, multiply_signature_scalar, PublicKey, Signature};
use holder_approval_fixture::{
    APPROVAL, APPROVAL_CONTENT_ID, APPROVAL_SIGNATURE, CONTENT_ID, DEPTH, EXTRA_ENTRY_SIGNATURE,
    HOLDER, INDICES, ISSUER, ISSUER_SIGNATURE, OTHER_ACCOUNT_SIGNATURE, OTHER_HOLDER,
    OTHER_HOLDER_APPROVAL_SIGNATURE, OWNER_NAME_HASH as APPROVAL_OWNER_NAME_HASH,
    RAW_ACTION_SIGNATURE, SIBLINGS,
};
use holder_login_fixture::{
    APPROVAL_AS_LOGIN_SIGNATURE, EXTRA_ENTRY_LOGIN_SIGNATURE, LOGIN, LOGIN_CONTENT_ID,
    LOGIN_SIGNATURE, OTHER_HOLDER_LOGIN_SIGNATURE, RAW_CHALLENGE_SIGNATURE,
};

mod holder_approval_fixture;
mod holder_login_fixture;
use edwards::{bjj::BabyJubJub, CurveTrait, ScalarField};

fn bitwise_reference(point: BabyJubJub, scalar: Field) -> BabyJubJub {
    let bits = scalar.to_le_bits::<254>();
    let mut acc = BabyJubJub::zero();
    for i in 0..254 {
        acc = acc.dbl();
        let added = acc + point;
        acc = if bits[253 - i] { added } else { acc };
    }
    acc
}

#[test]
fn challenge_bitwise_keeps_full_field_values() {
    let point = BabyJubJub::one();
    let high_challenge: Field =
        7237005577332262213973186563042994240829374041602535252466099000494570602496 + 123;
    let max_challenge: Field =
        21888242871839275222246405745257275088548364400416034343698204186575808495616;
    multiply_challenge(point, 0).assert_equal(BabyJubJub::zero());
    multiply_challenge(point, 1).assert_equal(point);
    multiply_challenge(point, 15).assert_equal(bitwise_reference(point, 15));
    multiply_challenge(point, 16).assert_equal(bitwise_reference(point, 16));
    multiply_challenge(point, high_challenge).assert_equal(bitwise_reference(point, high_challenge));
    multiply_challenge(point, max_challenge).assert_equal(bitwise_reference(point, max_challenge));
}

#[test]
fn signature_window_keeps_zero_and_subgroup_boundary() {
    let point = BabyJubJub::one();
    let last_canonical_scalar: Field = crate::SUBGROUP_ORDER - 1;
    multiply_signature_scalar(point, 0).assert_equal(BabyJubJub::zero());
    multiply_signature_scalar(point, last_canonical_scalar).assert_equal(bitwise_reference(
        point,
        last_canonical_scalar,
    ));
    let reconstructed: Field =
        ScalarField::<63>::into(ScalarField::<63>::from(last_canonical_scalar));
    assert_eq(reconstructed, last_canonical_scalar);
}

#[test]
fn multiplication_handles_identity_and_inverse() {
    let point = BabyJubJub::one();
    multiply_challenge(
        BabyJubJub::zero(),
        21888242871839275222246405745257275088548364400416034343698204186575808495616,
    )
        .assert_equal(BabyJubJub::zero());
    (point + (-point)).assert_equal(BabyJubJub::zero());
}
fn issuer() -> PublicKey {
    PublicKey {
        x: 13277427435165878497778222415993513565335242147425444199013288855685581939618,
        y: 13622229784656158136036771217484571176836296686641868549125388198837476602820,
    }
}
fn signature() -> Signature {
    Signature {
        rx: 17163103992447045602080223334042498359988039230529968367181189990475363595598,
        ry: 11253074619258175184877111286007131012225312052991598623590982036399747633749,
        s: 1584547678814640267019962606892543258483077665512516715717016140124794250169,
    }
}
global ROOT: Field = 18441329347722224401034539078533097600455389237942639133852716160941506550077;
#[test]
fn valid_identity_signature_equation() {
    crate::assert_pod_signature_equation(
        std::hint::black_box(issuer()),
        std::hint::black_box(Signature { rx: 0, ry: 1, s: 0 }),
        std::hint::black_box(0),
    );
}

#[test]
fn valid_sdk_pod() {
    crate::assert_pod_signature(ROOT, issuer(), signature());
}
#[test(should_fail_with = "EdDSA signature mismatch")]
fn wrong_root() {
    crate::assert_pod_signature(ROOT + 1, issuer(), signature());
}
#[test(should_fail_with = "Noncanonical EdDSA scalar")]
fn noncanonical_scalar() {
    let mut sig = signature();
    sig.s = crate::SUBGROUP_ORDER;
    crate::assert_pod_signature(ROOT, issuer(), sig);
}
#[test(should_fail_with = "Small-order issuer key")]
fn small_order_issuer() {
    crate::assert_pod_signature(ROOT, PublicKey { x: 0, y: 1 }, signature());
}
// Bare: the rejection is the message-less assert at noir-edwards main src/lib.nr:165.
#[test(should_fail)]
fn invalid_point() {
    let mut sig = signature();
    sig.rx = 0;
    sig.ry = 0;
    crate::assert_pod_signature(ROOT, issuer(), sig);
}
#[test(should_fail_with = "POD proof exceeds capacity")]
fn excessive_depth() {
    crate::assert_entry(ROOT, 1, 2, 2, [false; 1], [0; 1]);
}
#[test(should_fail_with = "POD entry mismatch")]
fn wrong_claim() {
    crate::assert_entry(
        ROOT,
        326659440160922603565259647365273768049060793192448832256436037437575522647,
        12326503012965816391338144612242952408728683609716147019497703475006801258307 + 1,
        1,
        [false, false, false, false, false, false, false, false],
        [
            20932835690836257440093237677220688940666275485882810761561732034935268977978,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    );
}

// A depth-0 holder POD and a holder signature over a raw field: the
// certified-holder and EdDSA components that the fixed-schema relations compose.
fn holder_fixture(action: Field) {
    let holder = PublicKey {
        x: 9440431475657676106925387551134166613460293550872202407848619688260076524910,
        y: 18802857856671063310072155031675529814523706692110324866972112339526217597261,
    };
    crate::assert_certified_holder(
        2725214088409620471357479159395719801185669447189592184201533126543895839241,
        PublicKey {
            x: 13277427435165878497778222415993513565335242147425444199013288855685581939618,
            y: 13622229784656158136036771217484571176836296686641868549125388198837476602820,
        },
        Signature {
            rx: 21260963709607590287837326301996144026098161288549306452562986457973175364203,
            ry: 3296829529544458232049709272368837267841446598812740232958137584484127741961,
            s: 432092264543335043954934763159730951117459982018658018600843661323002358005,
        },
        holder,
        134391921332508560099964544679493715295561887371159641958333364222734962117,
        0,
        [false; 1],
        [0; 1],
    );
    crate::assert_pod_signature(
        action,
        holder,
        Signature {
            rx: 4453012696574712227473013643127203431488172295009251239016615030422485876115,
            ry: 12094421740199570048882062399094729656638133269843952075515265286686275702471,
            s: 2581644173580496877355217578271486232400057160188079259512258894600746286721,
        },
    );
}
#[test]
fn holder_authorizes_action() {
    holder_fixture(123456789);
}
#[test(should_fail_with = "EdDSA signature mismatch")]
fn holder_wrong_action() {
    holder_fixture(123456790);
}
#[test]
fn pod_name_hash_matches_sdk() {
    assert(
        crate::bytes_hash("owner".as_bytes())
            == 134391921332508560099964544679493715295561887371159641958333364222734962117,
    );
}

// The raw entry relation also accepts a public-key value leaf as a pair.
// The holder POD has the single entry `owner` = holder key, so its content ID is
// hash_2([bytes_hash("owner"), hash_2([key.x, key.y])]).
global HOLDER_ROOT: Field =
    2725214088409620471357479159395719801185669447189592184201533126543895839241;
global OWNER_NAME_HASH: Field =
    134391921332508560099964544679493715295561887371159641958333364222734962117;
fn holder_key() -> PublicKey {
    PublicKey {
        x: 9440431475657676106925387551134166613460293550872202407848619688260076524910,
        y: 18802857856671063310072155031675529814523706692110324866972112339526217597261,
    }
}
#[test]
fn raw_entry_accepts_pubkey_value_leaf_as_pair() {
    let key = holder_key();
    crate::assert_entry(HOLDER_ROOT, key.x, key.y, 1, [true], [OWNER_NAME_HASH]);
}
#[test]
fn named_entry_accepts_typed_claim() {
    crate::assert_named_entry(
        HOLDER_ROOT,
        "owner".as_bytes(),
        crate::public_key_value_hash(holder_key()),
        0,
        [false],
        [0],
    );
}
#[test(should_fail_with = "POD entry mismatch")]
fn named_entry_rejects_pubkey_value_leaf_as_pair() {
    crate::assert_named_entry(
        HOLDER_ROOT,
        "owner".as_bytes(),
        holder_key().y,
        1,
        [true],
        [OWNER_NAME_HASH],
    );
}
#[test(should_fail_with = "POD entry mismatch")]
fn named_entry_rejects_other_name() {
    crate::assert_named_entry(
        HOLDER_ROOT,
        "event".as_bytes(),
        crate::public_key_value_hash(holder_key()),
        0,
        [false],
        [0],
    );
}

// The holder signs a fixed-schema approval POD, not a raw field. The
// vectors come from scripts/fixtures/generate-zupass-holder-approval.mjs.
fn approve(holder: PublicKey, approval: crate::HolderApproval, signature: Signature) {
    crate::assert_holder_approval(
        CONTENT_ID,
        ISSUER,
        ISSUER_SIGNATURE,
        holder,
        APPROVAL_OWNER_NAME_HASH,
        DEPTH,
        INDICES,
        SIBLINGS,
        approval,
        signature,
    );
}
#[test]
fn approval_content_id_matches_sdk() {
    // Fixes the entry names, value types and POD's sorted order.
    assert_eq(crate::holder_approval_content_id(APPROVAL), APPROVAL_CONTENT_ID);
}
#[test]
fn holder_approval_accepted() {
    approve(HOLDER, APPROVAL, APPROVAL_SIGNATURE);
}
#[test(should_fail_with = "EdDSA signature mismatch")]
fn holder_raw_action_signature_rejected() {
    // A raw signature over the action field, not over the approval POD.
    approve(HOLDER, APPROVAL, RAW_ACTION_SIGNATURE);
}
#[test]
fn raw_action_signature_is_a_valid_eddsa_signature() {
    // The rejected signature is valid over the raw action field, so the
    // rejection comes from the approval schema.
    crate::assert_pod_signature(APPROVAL.action, HOLDER, RAW_ACTION_SIGNATURE);
}
#[test(should_fail_with = "EdDSA signature mismatch")]
fn holder_approval_other_action_rejected() {
    let mut approval = APPROVAL;
    approval.action += 1;
    approve(HOLDER, approval, APPROVAL_SIGNATURE);
}
#[test(should_fail_with = "EdDSA signature mismatch")]
fn holder_approval_other_account_rejected() {
    let mut approval = APPROVAL;
    approval.account += 1;
    approve(HOLDER, approval, APPROVAL_SIGNATURE);
}
#[test(should_fail_with = "EdDSA signature mismatch")]
fn holder_approval_for_other_account_rejected() {
    // The holder signed the approval with account + 1; the caller's account differs.
    approve(HOLDER, APPROVAL, OTHER_ACCOUNT_SIGNATURE);
}
#[test(should_fail_with = "EdDSA signature mismatch")]
fn holder_approval_later_expiry_rejected() {
    let mut approval = APPROVAL;
    approval.expires += 1;
    approve(HOLDER, approval, APPROVAL_SIGNATURE);
}
#[test(should_fail_with = "EdDSA signature mismatch")]
fn holder_approval_extra_entry_rejected() {
    approve(HOLDER, APPROVAL, EXTRA_ENTRY_SIGNATURE);
}
#[test(should_fail_with = "POD entry mismatch")]
fn holder_approval_by_key_the_pod_does_not_name_rejected() {
    approve(OTHER_HOLDER, APPROVAL, OTHER_HOLDER_APPROVAL_SIGNATURE);
}
#[test(should_fail_with = "Noncanonical EdDSA scalar")]
fn holder_approval_noncanonical_scalar_rejected() {
    let mut signature = APPROVAL_SIGNATURE;
    signature.s += crate::SUBGROUP_ORDER;
    approve(HOLDER, APPROVAL, signature);
}

// For a login link the holder signs a fixed-schema login POD, not a raw
// field. The vectors come from scripts/fixtures/generate-zupass-holder-approval.mjs.
fn log_in(holder: PublicKey, login: crate::HolderLogin, signature: Signature) {
    crate::assert_holder_login(
        CONTENT_ID,
        ISSUER,
        ISSUER_SIGNATURE,
        holder,
        APPROVAL_OWNER_NAME_HASH,
        DEPTH,
        INDICES,
        SIBLINGS,
        login,
        signature,
    );
}
#[test]
fn login_content_id_matches_sdk() {
    // Fixes the entry names, value types and POD's sorted order.
    assert_eq(crate::holder_login_content_id(LOGIN), LOGIN_CONTENT_ID);
}
#[test]
fn holder_login_accepted() {
    log_in(HOLDER, LOGIN, LOGIN_SIGNATURE);
}
#[test]
fn raw_challenge_signature_is_a_valid_eddsa_signature() {
    crate::assert_pod_signature(LOGIN.challenge, HOLDER, RAW_CHALLENGE_SIGNATURE);
}
#[test(should_fail_with = "EdDSA signature mismatch")]
fn holder_login_raw_challenge_signature_rejected() {
    // A raw signature over the challenge field, as a field-signing oracle gives.
    log_in(HOLDER, LOGIN, RAW_CHALLENGE_SIGNATURE);
}
#[test(should_fail_with = "EdDSA signature mismatch")]
fn holder_login_other_challenge_rejected() {
    let mut login = LOGIN;
    login.challenge += 1;
    log_in(HOLDER, login, LOGIN_SIGNATURE);
}
#[test(should_fail_with = "EdDSA signature mismatch")]
fn holder_login_restated_issue_time_rejected() {
    let mut login = LOGIN;
    login.issued_at += 1;
    log_in(HOLDER, login, LOGIN_SIGNATURE);
}
#[test(should_fail_with = "EdDSA signature mismatch")]
fn holder_login_extra_entry_rejected() {
    log_in(HOLDER, LOGIN, EXTRA_ENTRY_LOGIN_SIGNATURE);
}
#[test]
fn approval_as_login_signature_is_a_valid_approval_signature() {
    // The rejected signature below is valid on the approval POD with the same
    // values, so the rejection comes from the login schema.
    let approval = crate::HolderApproval {
        account: APPROVAL.account,
        action: LOGIN.challenge,
        expires: LOGIN.issued_at,
    };
    crate::assert_pod_signature(
        crate::holder_approval_content_id(approval),
        HOLDER,
        APPROVAL_AS_LOGIN_SIGNATURE,
    );
}
#[test(should_fail_with = "EdDSA signature mismatch")]
fn holder_approval_pod_is_not_a_login() {
    // An approval POD with action = challenge and expires = issued_at.
    log_in(HOLDER, LOGIN, APPROVAL_AS_LOGIN_SIGNATURE);
}
#[test(should_fail_with = "POD entry mismatch")]
fn holder_login_by_key_the_pod_does_not_name_rejected() {
    log_in(OTHER_HOLDER, LOGIN, OTHER_HOLDER_LOGIN_SIGNATURE);
}
