// Generated synthetic local issuer root, never provider-issued.
use crate::{AuthInput, AuthPolicy};
use oidc::TrustedRsaKey;
pub fn fixture() -> (AuthInput, TrustedRsaKey, AuthPolicy, BoundedVec<u8, 64>) {
    (
        AuthInput {
            header_b64: BoundedVec::from_array(
                "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImxvY2FsLXN5bnRoZXRpYy11bml2ZXJzaXR5In0"
                    .as_bytes(),
            ),
            payload_b64: BoundedVec::from_array(
                "eyJpc3MiOiJodHRwczovL2NpbG9nb24ub3JnIiwiYXVkIjoiY2lsb2dvbjovY2xpZW50X2lkL2xvY2FsLXN5bnRoZXRpYy11bml2ZXJzaXR5Iiwic3ViIjoiaHR0cDovL2NpbG9nb24ub3JnL3NlcnZlckEvdXNlcnMvbG9jYWwtc3ludGhldGljLXVuaXZlcnNpdHkiLCJub25jZSI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJpYXQiOjE4OTk5OTk5NDAsImV4cCI6MTkwMDAwMzYwMCwiaWRwIjoidXJuOm1hY2U6aW5jb21tb246dWl1Yy5lZHUiLCJhZmZpbGlhdGlvbiI6InN0dWRlbnRAZXhhbXBsZS5lZHU7bWVtYmVyQGV4YW1wbGUuZWR1IiwiZ3JvdXBzIjpbInN5bnRoZXRpYy1ncm91cCJdfQ"
                    .as_bytes(),
            ),
            signature_b64: BoundedVec::from_array(
                "XZLisFBiF6ndDyAeSd92Zs_LQjbPXfuZ7bz161L8nt1f3DhuFpaohBBxGz3JN1sNhtl867sfv1pSz_gNUa2Y0xXRrg7qaqMF37Ee37s2mFFnoA9i5jFYF6V8mqYTdf4oPeAoBCrllwUKS1NZ0Sk4Fwa9MNdmz_zlNypY-ACyZBpMyNP66bQKps5AagDH_GtGheI940B_qP1PQAWObh3BsmnrChP85SXtpESs7suDU9nwaVBGvCkL7-9POrcWnbDY0qkPqZK9KDE_5EDgLH6HQSs1FfSjiwRvXd2Ag809uNwF7g7UutsRN7Wue3f4ju4O3K-qsJiS4WIGRv99DmVICA"
                    .as_bytes(),
            ),
        },
        TrustedRsaKey {
            modulus_limbs: [
                686960734889576486665416000638658607,
                1139792891755935123353199251713810391,
                1048209596646475784672120094280390029,
                1061114958847954223242271955303464574,
                844739545652913590500774900206437286,
                985761967162707384460175531108809772,
                772262017629303911129098004245517706,
                400525590868342151741974134310033728,
                799570113870029920806184486588461222,
                414190823455872756477066166432325490,
                55525609504500570532349523145576852,
                171842033956493158680699468999253202,
                128081611090730251355302782401022429,
                238378484135620871988318978835997216,
                1127264784793188298032767104220835750,
                1216194514543942228671039802343267979,
                991654821870727518612400778970407862,
                178,
            ],
            redc_params_limbs: [
                338378225578435841255408828477253293,
                1157112507697726291071796401218519593,
                902576485009663128345915727535536034,
                1031491723256760721199058094739338554,
                977437958568031246996871939904761248,
                27650306241630923545525026816765613,
                216946797155284179452508124806909963,
                736314749775252882644851879469033640,
                744562932787205665202649943619234638,
                959820532738222875789453118751202643,
                1287114429520828229764204599703304775,
                1222187030763728588278289909612338092,
                450384867283296102064565170580557553,
                884835491146011569235992405469544325,
                1057161764898744477295727702761432372,
                818665814250121578322758863819014587,
                209813225960091232695987678683814774,
                23465,
            ],
        },
        AuthPolicy {
            issuer: BoundedVec::from_array([
                104, 116, 116, 112, 115, 58, 47, 47, 99, 105, 108, 111, 103, 111, 110, 46, 111, 114,
                103,
            ]),
            audience: BoundedVec::from_array([
                99, 105, 108, 111, 103, 111, 110, 58, 47, 99, 108, 105, 101, 110, 116, 95, 105, 100,
                47, 108, 111, 99, 97, 108, 45, 115, 121, 110, 116, 104, 101, 116, 105, 99, 45, 117,
                110, 105, 118, 101, 114, 115, 105, 116, 121,
            ]),
            subject: BoundedVec::from_array([
                104, 116, 116, 112, 58, 47, 47, 99, 105, 108, 111, 103, 111, 110, 46, 111, 114, 103,
                47, 115, 101, 114, 118, 101, 114, 65, 47, 117, 115, 101, 114, 115, 47, 108, 111, 99,
                97, 108, 45, 115, 121, 110, 116, 104, 101, 116, 105, 99, 45, 117, 110, 105, 118,
                101, 114, 115, 105, 116, 121,
            ]),
            institutional_idp: BoundedVec::from_array([
                117, 114, 110, 58, 109, 97, 99, 101, 58, 105, 110, 99, 111, 109, 109, 111, 110, 58,
                117, 105, 117, 99, 46, 101, 100, 117,
            ]),
        },
        BoundedVec::from_array([
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        ]),
    )
}
pub fn fixture_payload() -> BoundedVec<u8, 512> {
    BoundedVec::from_array(
        "{\"iss\":\"https://cilogon.org\",\"aud\":\"cilogon:/client_id/local-synthetic-university\",\"sub\":\"http://cilogon.org/serverA/users/local-synthetic-university\",\"nonce\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"iat\":1899999940,\"exp\":1900003600,\"idp\":\"urn:mace:incommon:uiuc.edu\",\"affiliation\":\"student@example.edu;member@example.edu\",\"groups\":[\"synthetic-group\"]}"
            .as_bytes(),
    )
}
pub fn direct_issuer_fixture() -> (AuthInput, TrustedRsaKey, AuthPolicy, BoundedVec<u8, 64>) {
    (
        AuthInput {
            header_b64: BoundedVec::from_array(
                "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImxvY2FsLXN5bnRoZXRpYy11bml2ZXJzaXR5In0"
                    .as_bytes(),
            ),
            payload_b64: BoundedVec::from_array(
                "eyJpc3MiOiJodHRwczovL29pZGMuZXhhbXBsZS5lZHUiLCJhdWQiOiJjaWxvZ29uOi9jbGllbnRfaWQvbG9jYWwtc3ludGhldGljLXVuaXZlcnNpdHkiLCJzdWIiOiJodHRwOi8vY2lsb2dvbi5vcmcvc2VydmVyQS91c2Vycy9sb2NhbC1zeW50aGV0aWMtdW5pdmVyc2l0eSIsIm5vbmNlIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsImlhdCI6MTg5OTk5OTk0MCwiZXhwIjoxOTAwMDAzNjAwLCJpZHAiOiJ1cm46bWFjZTppbmNvbW1vbjp1aXVjLmVkdSIsImFmZmlsaWF0aW9uIjoic3R1ZGVudEBleGFtcGxlLmVkdTttZW1iZXJAZXhhbXBsZS5lZHUiLCJncm91cHMiOlsic3ludGhldGljLWdyb3VwIl19"
                    .as_bytes(),
            ),
            signature_b64: BoundedVec::from_array(
                "VTbsdL3eRfBDENlefeAsShM4sp1kFwYIWMLlhttyJR09LWfNf-QnTXJ3E72l-NWR_5YhtetZB-8lkbzb71BkoixetvybhkMB1HPtsaRzLEsfAhOK7qPaKFnk4tj4ymRo2fYiPEHOxbia0-ct_N1jkFgcB3hT2MmFPNadyYz8a-J-RNhBlOtmaT0NZShkpI6egFHHG7AQXq7I5VhSmHDavl_KuxKLsCe2jZCKUC6v0SXbLNz-d5CSLJuo6BTV5XxA240wWMaub2Kll-4xEfKh5DbZZiDqoZ8K_MatjdWx4gi1M0J5uXcJ6om_YAaE2d5OJrdMwyupIeZ5yHIC3QUKyQ"
                    .as_bytes(),
            ),
        },
        TrustedRsaKey {
            modulus_limbs: [
                686960734889576486665416000638658607,
                1139792891755935123353199251713810391,
                1048209596646475784672120094280390029,
                1061114958847954223242271955303464574,
                844739545652913590500774900206437286,
                985761967162707384460175531108809772,
                772262017629303911129098004245517706,
                400525590868342151741974134310033728,
                799570113870029920806184486588461222,
                414190823455872756477066166432325490,
                55525609504500570532349523145576852,
                171842033956493158680699468999253202,
                128081611090730251355302782401022429,
                238378484135620871988318978835997216,
                1127264784793188298032767104220835750,
                1216194514543942228671039802343267979,
                991654821870727518612400778970407862,
                178,
            ],
            redc_params_limbs: [
                338378225578435841255408828477253293,
                1157112507697726291071796401218519593,
                902576485009663128345915727535536034,
                1031491723256760721199058094739338554,
                977437958568031246996871939904761248,
                27650306241630923545525026816765613,
                216946797155284179452508124806909963,
                736314749775252882644851879469033640,
                744562932787205665202649943619234638,
                959820532738222875789453118751202643,
                1287114429520828229764204599703304775,
                1222187030763728588278289909612338092,
                450384867283296102064565170580557553,
                884835491146011569235992405469544325,
                1057161764898744477295727702761432372,
                818665814250121578322758863819014587,
                209813225960091232695987678683814774,
                23465,
            ],
        },
        AuthPolicy {
            issuer: BoundedVec::from_array([
                104, 116, 116, 112, 115, 58, 47, 47, 99, 105, 108, 111, 103, 111, 110, 46, 111, 114,
                103,
            ]),
            audience: BoundedVec::from_array([
                99, 105, 108, 111, 103, 111, 110, 58, 47, 99, 108, 105, 101, 110, 116, 95, 105, 100,
                47, 108, 111, 99, 97, 108, 45, 115, 121, 110, 116, 104, 101, 116, 105, 99, 45, 117,
                110, 105, 118, 101, 114, 115, 105, 116, 121,
            ]),
            subject: BoundedVec::from_array([
                104, 116, 116, 112, 58, 47, 47, 99, 105, 108, 111, 103, 111, 110, 46, 111, 114, 103,
                47, 115, 101, 114, 118, 101, 114, 65, 47, 117, 115, 101, 114, 115, 47, 108, 111, 99,
                97, 108, 45, 115, 121, 110, 116, 104, 101, 116, 105, 99, 45, 117, 110, 105, 118,
                101, 114, 115, 105, 116, 121,
            ]),
            institutional_idp: BoundedVec::from_array([
                117, 114, 110, 58, 109, 97, 99, 101, 58, 105, 110, 99, 111, 109, 109, 111, 110, 58,
                117, 105, 117, 99, 46, 101, 100, 117,
            ]),
        },
        BoundedVec::from_array([
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        ]),
    )
}
pub fn direct_issuer_payload() -> BoundedVec<u8, 512> {
    BoundedVec::from_array(
        "{\"iss\":\"https://oidc.example.edu\",\"aud\":\"cilogon:/client_id/local-synthetic-university\",\"sub\":\"http://cilogon.org/serverA/users/local-synthetic-university\",\"nonce\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"iat\":1899999940,\"exp\":1900003600,\"idp\":\"urn:mace:incommon:uiuc.edu\",\"affiliation\":\"student@example.edu;member@example.edu\",\"groups\":[\"synthetic-group\"]}"
            .as_bytes(),
    )
}
pub fn missing_idp_fixture() -> (AuthInput, TrustedRsaKey, AuthPolicy, BoundedVec<u8, 64>) {
    (
        AuthInput {
            header_b64: BoundedVec::from_array(
                "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImxvY2FsLXN5bnRoZXRpYy11bml2ZXJzaXR5In0"
                    .as_bytes(),
            ),
            payload_b64: BoundedVec::from_array(
                "eyJpc3MiOiJodHRwczovL2NpbG9nb24ub3JnIiwiYXVkIjoiY2lsb2dvbjovY2xpZW50X2lkL2xvY2FsLXN5bnRoZXRpYy11bml2ZXJzaXR5Iiwic3ViIjoiaHR0cDovL2NpbG9nb24ub3JnL3NlcnZlckEvdXNlcnMvbG9jYWwtc3ludGhldGljLXVuaXZlcnNpdHkiLCJub25jZSI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJpYXQiOjE4OTk5OTk5NDAsImV4cCI6MTkwMDAwMzYwMCwiYWZmaWxpYXRpb24iOiJzdHVkZW50QGV4YW1wbGUuZWR1O21lbWJlckBleGFtcGxlLmVkdSIsImdyb3VwcyI6WyJzeW50aGV0aWMtZ3JvdXAiXX0"
                    .as_bytes(),
            ),
            signature_b64: BoundedVec::from_array(
                "LyiyYFLkjN7k-Hh-WB3bA2YfUWPG_4uAQ1_q8sJVVeM4oQ3eKv96iaRNNyg0kgNCKqoEOqDDxxHDTMej2mzNdDcbxODy9fjQx8Uyxtwx0-xF4cpO9wX6Sv5cTQs51l-O6r8_zS6-McivI4SVvJchPvpVO1ZYm_U6PddMcOh8ZYoP7jJ5Y7laIaxg_0OQLoNDuItWYC6KPukcn6yuMhsDoSgIhK_4B9tdz3pr2JYwMl6gGOr5dkKDXCKLfQWMICYJYBFOS4Kb0th2sYTETGd9kMHB4O8Ri2AdG0ijThfMIm6hpMRQOKhlB-Eel_iOWXV8XT-SOB7getVdTEvBh4WsAQ"
                    .as_bytes(),
            ),
        },
        TrustedRsaKey {
            modulus_limbs: [
                686960734889576486665416000638658607,
                1139792891755935123353199251713810391,
                1048209596646475784672120094280390029,
                1061114958847954223242271955303464574,
                844739545652913590500774900206437286,
                985761967162707384460175531108809772,
                772262017629303911129098004245517706,
                400525590868342151741974134310033728,
                799570113870029920806184486588461222,
                414190823455872756477066166432325490,
                55525609504500570532349523145576852,
                171842033956493158680699468999253202,
                128081611090730251355302782401022429,
                238378484135620871988318978835997216,
                1127264784793188298032767104220835750,
                1216194514543942228671039802343267979,
                991654821870727518612400778970407862,
                178,
            ],
            redc_params_limbs: [
                338378225578435841255408828477253293,
                1157112507697726291071796401218519593,
                902576485009663128345915727535536034,
                1031491723256760721199058094739338554,
                977437958568031246996871939904761248,
                27650306241630923545525026816765613,
                216946797155284179452508124806909963,
                736314749775252882644851879469033640,
                744562932787205665202649943619234638,
                959820532738222875789453118751202643,
                1287114429520828229764204599703304775,
                1222187030763728588278289909612338092,
                450384867283296102064565170580557553,
                884835491146011569235992405469544325,
                1057161764898744477295727702761432372,
                818665814250121578322758863819014587,
                209813225960091232695987678683814774,
                23465,
            ],
        },
        AuthPolicy {
            issuer: BoundedVec::from_array([
                104, 116, 116, 112, 115, 58, 47, 47, 99, 105, 108, 111, 103, 111, 110, 46, 111, 114,
                103,
            ]),
            audience: BoundedVec::from_array([
                99, 105, 108, 111, 103, 111, 110, 58, 47, 99, 108, 105, 101, 110, 116, 95, 105, 100,
                47, 108, 111, 99, 97, 108, 45, 115, 121, 110, 116, 104, 101, 116, 105, 99, 45, 117,
                110, 105, 118, 101, 114, 115, 105, 116, 121,
            ]),
            subject: BoundedVec::from_array([
                104, 116, 116, 112, 58, 47, 47, 99, 105, 108, 111, 103, 111, 110, 46, 111, 114, 103,
                47, 115, 101, 114, 118, 101, 114, 65, 47, 117, 115, 101, 114, 115, 47, 108, 111, 99,
                97, 108, 45, 115, 121, 110, 116, 104, 101, 116, 105, 99, 45, 117, 110, 105, 118,
                101, 114, 115, 105, 116, 121,
            ]),
            institutional_idp: BoundedVec::from_array([
                117, 114, 110, 58, 109, 97, 99, 101, 58, 105, 110, 99, 111, 109, 109, 111, 110, 58,
                117, 105, 117, 99, 46, 101, 100, 117,
            ]),
        },
        BoundedVec::from_array([
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        ]),
    )
}
pub fn missing_idp_payload() -> BoundedVec<u8, 512> {
    BoundedVec::from_array(
        "{\"iss\":\"https://cilogon.org\",\"aud\":\"cilogon:/client_id/local-synthetic-university\",\"sub\":\"http://cilogon.org/serverA/users/local-synthetic-university\",\"nonce\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"iat\":1899999940,\"exp\":1900003600,\"affiliation\":\"student@example.edu;member@example.edu\",\"groups\":[\"synthetic-group\"]}"
            .as_bytes(),
    )
}
pub fn social_idp_fixture() -> (AuthInput, TrustedRsaKey, AuthPolicy, BoundedVec<u8, 64>) {
    (
        AuthInput {
            header_b64: BoundedVec::from_array(
                "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImxvY2FsLXN5bnRoZXRpYy11bml2ZXJzaXR5In0"
                    .as_bytes(),
            ),
            payload_b64: BoundedVec::from_array(
                "eyJpc3MiOiJodHRwczovL2NpbG9nb24ub3JnIiwiYXVkIjoiY2lsb2dvbjovY2xpZW50X2lkL2xvY2FsLXN5bnRoZXRpYy11bml2ZXJzaXR5Iiwic3ViIjoiaHR0cDovL2NpbG9nb24ub3JnL3NlcnZlckEvdXNlcnMvbG9jYWwtc3ludGhldGljLXVuaXZlcnNpdHkiLCJub25jZSI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJpYXQiOjE4OTk5OTk5NDAsImV4cCI6MTkwMDAwMzYwMCwiaWRwIjoiaHR0cDovL2dpdGh1Yi5jb20vbG9naW4vb2F1dGgvYXV0aG9yaXplIiwiYWZmaWxpYXRpb24iOiJzdHVkZW50QGV4YW1wbGUuZWR1O21lbWJlckBleGFtcGxlLmVkdSIsImdyb3VwcyI6WyJzeW50aGV0aWMtZ3JvdXAiXX0"
                    .as_bytes(),
            ),
            signature_b64: BoundedVec::from_array(
                "JTgVh5o73sV19XVy8GMNLdzdccFIdNecvrk7U4ruYyu13V81N0cWgf_fpfgNPVeCs0kS1aEoMLg3m-4Z3fs1wiu0fmR2ziiM56ErQ-sB4Wm8QW9xA1G0gmEdh9aKZz_6b4w3I3tLS00k1eBmEcUxoonZm71VbF4cuTDVznRIeKsGZOKWO41BpPz2ufpfRfEgaTYuFhSka_118h7ypi8fb3M4haktyN_FQUBlr3a2e_5Zp5PkwnX6X7zRc_vS0_Sanv5vh3RxOlz7WVRGvIrbMPGEK8vvqEHK7vqGkWoxzY4Ou_YqGDYYu7goNqoD29--Ddo2wSbXhcMQERzPJNsfwA"
                    .as_bytes(),
            ),
        },
        TrustedRsaKey {
            modulus_limbs: [
                686960734889576486665416000638658607,
                1139792891755935123353199251713810391,
                1048209596646475784672120094280390029,
                1061114958847954223242271955303464574,
                844739545652913590500774900206437286,
                985761967162707384460175531108809772,
                772262017629303911129098004245517706,
                400525590868342151741974134310033728,
                799570113870029920806184486588461222,
                414190823455872756477066166432325490,
                55525609504500570532349523145576852,
                171842033956493158680699468999253202,
                128081611090730251355302782401022429,
                238378484135620871988318978835997216,
                1127264784793188298032767104220835750,
                1216194514543942228671039802343267979,
                991654821870727518612400778970407862,
                178,
            ],
            redc_params_limbs: [
                338378225578435841255408828477253293,
                1157112507697726291071796401218519593,
                902576485009663128345915727535536034,
                1031491723256760721199058094739338554,
                977437958568031246996871939904761248,
                27650306241630923545525026816765613,
                216946797155284179452508124806909963,
                736314749775252882644851879469033640,
                744562932787205665202649943619234638,
                959820532738222875789453118751202643,
                1287114429520828229764204599703304775,
                1222187030763728588278289909612338092,
                450384867283296102064565170580557553,
                884835491146011569235992405469544325,
                1057161764898744477295727702761432372,
                818665814250121578322758863819014587,
                209813225960091232695987678683814774,
                23465,
            ],
        },
        AuthPolicy {
            issuer: BoundedVec::from_array([
                104, 116, 116, 112, 115, 58, 47, 47, 99, 105, 108, 111, 103, 111, 110, 46, 111, 114,
                103,
            ]),
            audience: BoundedVec::from_array([
                99, 105, 108, 111, 103, 111, 110, 58, 47, 99, 108, 105, 101, 110, 116, 95, 105, 100,
                47, 108, 111, 99, 97, 108, 45, 115, 121, 110, 116, 104, 101, 116, 105, 99, 45, 117,
                110, 105, 118, 101, 114, 115, 105, 116, 121,
            ]),
            subject: BoundedVec::from_array([
                104, 116, 116, 112, 58, 47, 47, 99, 105, 108, 111, 103, 111, 110, 46, 111, 114, 103,
                47, 115, 101, 114, 118, 101, 114, 65, 47, 117, 115, 101, 114, 115, 47, 108, 111, 99,
                97, 108, 45, 115, 121, 110, 116, 104, 101, 116, 105, 99, 45, 117, 110, 105, 118,
                101, 114, 115, 105, 116, 121,
            ]),
            institutional_idp: BoundedVec::from_array([
                117, 114, 110, 58, 109, 97, 99, 101, 58, 105, 110, 99, 111, 109, 109, 111, 110, 58,
                117, 105, 117, 99, 46, 101, 100, 117,
            ]),
        },
        BoundedVec::from_array([
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        ]),
    )
}
pub fn social_idp_payload() -> BoundedVec<u8, 512> {
    BoundedVec::from_array(
        "{\"iss\":\"https://cilogon.org\",\"aud\":\"cilogon:/client_id/local-synthetic-university\",\"sub\":\"http://cilogon.org/serverA/users/local-synthetic-university\",\"nonce\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"iat\":1899999940,\"exp\":1900003600,\"idp\":\"http://github.com/login/oauth/authorize\",\"affiliation\":\"student@example.edu;member@example.edu\",\"groups\":[\"synthetic-group\"]}"
            .as_bytes(),
    )
}
pub fn future_nbf_fixture() -> (AuthInput, TrustedRsaKey, AuthPolicy, BoundedVec<u8, 64>) {
    (
        AuthInput {
            header_b64: BoundedVec::from_array(
                "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImxvY2FsLXN5bnRoZXRpYy11bml2ZXJzaXR5In0"
                    .as_bytes(),
            ),
            payload_b64: BoundedVec::from_array(
                "eyJpc3MiOiJodHRwczovL2NpbG9nb24ub3JnIiwiYXVkIjoiY2lsb2dvbjovY2xpZW50X2lkL2xvY2FsLXN5bnRoZXRpYy11bml2ZXJzaXR5Iiwic3ViIjoiaHR0cDovL2NpbG9nb24ub3JnL3NlcnZlckEvdXNlcnMvbG9jYWwtc3ludGhldGljLXVuaXZlcnNpdHkiLCJub25jZSI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJpYXQiOjE4OTk5OTk5NDAsImV4cCI6MTkwMDAwMzYwMCwiaWRwIjoidXJuOm1hY2U6aW5jb21tb246dWl1Yy5lZHUiLCJhZmZpbGlhdGlvbiI6InN0dWRlbnRAZXhhbXBsZS5lZHU7bWVtYmVyQGV4YW1wbGUuZWR1IiwiZ3JvdXBzIjpbInN5bnRoZXRpYy1ncm91cCJdLCJuYmYiOjE5MDAwMDAwMDF9"
                    .as_bytes(),
            ),
            signature_b64: BoundedVec::from_array(
                "Jgxloz_jW7yaX7GlblnNdy5-NzcfPw-NXcRTKtSVNOBOWIwOnjgFLr6FhazAd2d0kIGh7Yprz19ESK2ZI2AxJKAQvrLq2YYciBjQD5RGQtSd2epLO3XdLDOJFwQaDT7DuubM1Qm9eBjOEdDOnlUxwQKjgdKu-Hp6qEuC9Bnh-ssw7CH_PVnCYlc0-u_wVVx8QLiZgk-dDOHBzCJyCRzUNg3wYUl_1Q_2Q-ZTeZ3S2DAjMFdvNfjRJiumzLfGnOZsxCPZ8NbLeGVVJN_FQGMzmaEHgJJSSi6T56GEKFoNx1WbOLK36P_8KxgOWeP9pEofyoRMf_LZO22wKoS7VPsaRA"
                    .as_bytes(),
            ),
        },
        TrustedRsaKey {
            modulus_limbs: [
                686960734889576486665416000638658607,
                1139792891755935123353199251713810391,
                1048209596646475784672120094280390029,
                1061114958847954223242271955303464574,
                844739545652913590500774900206437286,
                985761967162707384460175531108809772,
                772262017629303911129098004245517706,
                400525590868342151741974134310033728,
                799570113870029920806184486588461222,
                414190823455872756477066166432325490,
                55525609504500570532349523145576852,
                171842033956493158680699468999253202,
                128081611090730251355302782401022429,
                238378484135620871988318978835997216,
                1127264784793188298032767104220835750,
                1216194514543942228671039802343267979,
                991654821870727518612400778970407862,
                178,
            ],
            redc_params_limbs: [
                338378225578435841255408828477253293,
                1157112507697726291071796401218519593,
                902576485009663128345915727535536034,
                1031491723256760721199058094739338554,
                977437958568031246996871939904761248,
                27650306241630923545525026816765613,
                216946797155284179452508124806909963,
                736314749775252882644851879469033640,
                744562932787205665202649943619234638,
                959820532738222875789453118751202643,
                1287114429520828229764204599703304775,
                1222187030763728588278289909612338092,
                450384867283296102064565170580557553,
                884835491146011569235992405469544325,
                1057161764898744477295727702761432372,
                818665814250121578322758863819014587,
                209813225960091232695987678683814774,
                23465,
            ],
        },
        AuthPolicy {
            issuer: BoundedVec::from_array([
                104, 116, 116, 112, 115, 58, 47, 47, 99, 105, 108, 111, 103, 111, 110, 46, 111, 114,
                103,
            ]),
            audience: BoundedVec::from_array([
                99, 105, 108, 111, 103, 111, 110, 58, 47, 99, 108, 105, 101, 110, 116, 95, 105, 100,
                47, 108, 111, 99, 97, 108, 45, 115, 121, 110, 116, 104, 101, 116, 105, 99, 45, 117,
                110, 105, 118, 101, 114, 115, 105, 116, 121,
            ]),
            subject: BoundedVec::from_array([
                104, 116, 116, 112, 58, 47, 47, 99, 105, 108, 111, 103, 111, 110, 46, 111, 114, 103,
                47, 115, 101, 114, 118, 101, 114, 65, 47, 117, 115, 101, 114, 115, 47, 108, 111, 99,
                97, 108, 45, 115, 121, 110, 116, 104, 101, 116, 105, 99, 45, 117, 110, 105, 118,
                101, 114, 115, 105, 116, 121,
            ]),
            institutional_idp: BoundedVec::from_array([
                117, 114, 110, 58, 109, 97, 99, 101, 58, 105, 110, 99, 111, 109, 109, 111, 110, 58,
                117, 105, 117, 99, 46, 101, 100, 117,
            ]),
        },
        BoundedVec::from_array([
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        ]),
    )
}
pub fn future_nbf_payload() -> BoundedVec<u8, 512> {
    BoundedVec::from_array(
        "{\"iss\":\"https://cilogon.org\",\"aud\":\"cilogon:/client_id/local-synthetic-university\",\"sub\":\"http://cilogon.org/serverA/users/local-synthetic-university\",\"nonce\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"iat\":1899999940,\"exp\":1900003600,\"idp\":\"urn:mace:incommon:uiuc.edu\",\"affiliation\":\"student@example.edu;member@example.edu\",\"groups\":[\"synthetic-group\"],\"nbf\":1900000001}"
            .as_bytes(),
    )
}
pub fn duplicate_idp_fixture() -> (AuthInput, TrustedRsaKey, AuthPolicy, BoundedVec<u8, 64>) {
    (
        AuthInput {
            header_b64: BoundedVec::from_array(
                "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImxvY2FsLXN5bnRoZXRpYy11bml2ZXJzaXR5In0"
                    .as_bytes(),
            ),
            payload_b64: BoundedVec::from_array(
                "eyJpc3MiOiJodHRwczovL2NpbG9nb24ub3JnIiwiYXVkIjoiY2lsb2dvbjovY2xpZW50X2lkL2xvY2FsLXN5bnRoZXRpYy11bml2ZXJzaXR5Iiwic3ViIjoiaHR0cDovL2NpbG9nb24ub3JnL3NlcnZlckEvdXNlcnMvbG9jYWwtc3ludGhldGljLXVuaXZlcnNpdHkiLCJub25jZSI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJpYXQiOjE4OTk5OTk5NDAsImV4cCI6MTkwMDAwMzYwMCwiaWRwIjpudWxsLCJpZHAiOiJ1cm46bWFjZTppbmNvbW1vbjp1aXVjLmVkdSIsImFmZmlsaWF0aW9uIjoic3R1ZGVudEBleGFtcGxlLmVkdTttZW1iZXJAZXhhbXBsZS5lZHUiLCJncm91cHMiOlsic3ludGhldGljLWdyb3VwIl19"
                    .as_bytes(),
            ),
            signature_b64: BoundedVec::from_array(
                "bTmW3F4iAIE36rFdVqWMn6r0lSOGPc6CXxcO652riMEBOrcjvPD89OobWmDABUX1PdqIqKuvuKHfeekyF-6qgqDOKPPXKhhSUOUn6NcRz2o2fVQF5zYOmYn2k9cFOi5bqyzPSCKE5XdJsu0ekjSBFSILmV5AyKswLIJhJtmJLUVApHrpie7S05iU2ksSCAE5zMd82I6JL7zDlQ81eo5VlErVuQnghaasnJpdyXKgO3OxMMXMlAU75jGFppnlrOC2aQYxNu86icxQ9CGlHG7NL1WIJ0ntHVfPrsxL-s9g5tZbT8e4x1KacI6mklOwkQMg2uoWhuR3yUQG56W-uJr8Cw"
                    .as_bytes(),
            ),
        },
        TrustedRsaKey {
            modulus_limbs: [
                686960734889576486665416000638658607,
                1139792891755935123353199251713810391,
                1048209596646475784672120094280390029,
                1061114958847954223242271955303464574,
                844739545652913590500774900206437286,
                985761967162707384460175531108809772,
                772262017629303911129098004245517706,
                400525590868342151741974134310033728,
                799570113870029920806184486588461222,
                414190823455872756477066166432325490,
                55525609504500570532349523145576852,
                171842033956493158680699468999253202,
                128081611090730251355302782401022429,
                238378484135620871988318978835997216,
                1127264784793188298032767104220835750,
                1216194514543942228671039802343267979,
                991654821870727518612400778970407862,
                178,
            ],
            redc_params_limbs: [
                338378225578435841255408828477253293,
                1157112507697726291071796401218519593,
                902576485009663128345915727535536034,
                1031491723256760721199058094739338554,
                977437958568031246996871939904761248,
                27650306241630923545525026816765613,
                216946797155284179452508124806909963,
                736314749775252882644851879469033640,
                744562932787205665202649943619234638,
                959820532738222875789453118751202643,
                1287114429520828229764204599703304775,
                1222187030763728588278289909612338092,
                450384867283296102064565170580557553,
                884835491146011569235992405469544325,
                1057161764898744477295727702761432372,
                818665814250121578322758863819014587,
                209813225960091232695987678683814774,
                23465,
            ],
        },
        AuthPolicy {
            issuer: BoundedVec::from_array([
                104, 116, 116, 112, 115, 58, 47, 47, 99, 105, 108, 111, 103, 111, 110, 46, 111, 114,
                103,
            ]),
            audience: BoundedVec::from_array([
                99, 105, 108, 111, 103, 111, 110, 58, 47, 99, 108, 105, 101, 110, 116, 95, 105, 100,
                47, 108, 111, 99, 97, 108, 45, 115, 121, 110, 116, 104, 101, 116, 105, 99, 45, 117,
                110, 105, 118, 101, 114, 115, 105, 116, 121,
            ]),
            subject: BoundedVec::from_array([
                104, 116, 116, 112, 58, 47, 47, 99, 105, 108, 111, 103, 111, 110, 46, 111, 114, 103,
                47, 115, 101, 114, 118, 101, 114, 65, 47, 117, 115, 101, 114, 115, 47, 108, 111, 99,
                97, 108, 45, 115, 121, 110, 116, 104, 101, 116, 105, 99, 45, 117, 110, 105, 118,
                101, 114, 115, 105, 116, 121,
            ]),
            institutional_idp: BoundedVec::from_array([
                117, 114, 110, 58, 109, 97, 99, 101, 58, 105, 110, 99, 111, 109, 109, 111, 110, 58,
                117, 105, 117, 99, 46, 101, 100, 117,
            ]),
        },
        BoundedVec::from_array([
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        ]),
    )
}
pub fn duplicate_idp_payload() -> BoundedVec<u8, 512> {
    BoundedVec::from_array(
        "{\"iss\":\"https://cilogon.org\",\"aud\":\"cilogon:/client_id/local-synthetic-university\",\"sub\":\"http://cilogon.org/serverA/users/local-synthetic-university\",\"nonce\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"iat\":1899999940,\"exp\":1900003600,\"idp\":null,\"idp\":\"urn:mace:incommon:uiuc.edu\",\"affiliation\":\"student@example.edu;member@example.edu\",\"groups\":[\"synthetic-group\"]}"
            .as_bytes(),
    )
}
