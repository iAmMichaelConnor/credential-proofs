// Regression and boundary tests for the partial SHA-256 helpers.
//
// Each case hashes the first `total` bytes of a position-dependent pattern
// ((i * 7 + 1) % 256) as a prefix of whole blocks plus a suffix, and checks the
// constrained result and the unconstrained result against a SHA-256 digest of
// the same bytes computed outside Noir (Python hashlib). Lengths are passed
// through an unconstrained identity so the circuit treats them as witnesses,
// as a caller's BoundedVec length would be. The suffix array is filled past the
// suffix with more pattern bytes, which must not affect the digest.
use super::{partial_sha256_var_end, partial_sha256_var_interstitial, partial_sha256_var_start};
use sha256::sha256_var;

global IV: [u32; 8] =
    [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225];

fn pattern<let N: u32>() -> [u8; N] {
    let mut data = [0; N];
    for i in 0..N {
        data[i] = ((i * 7 + 1) % 256) as u8;
    }
    data
}

unconstrained fn opaque(x: u32) -> u32 {
    x
}

unconstrained fn end_unconstrained<let N: u32>(
    h: [u32; 8],
    msg: [u8; N],
    message_size: u64,
    real_message_size: u64,
) -> [u8; 32] {
    partial_sha256_var_end(h, msg, message_size, real_message_size)
}

unconstrained fn interstitial_unconstrained<let N: u32>(
    h: [u32; 8],
    msg: [u8; N],
    message_size: u32,
) -> [u32; 8] {
    partial_sha256_var_interstitial(h, msg, message_size)
}

unconstrained fn start_unconstrained<let N: u32>(msg: [u8; N]) -> [u32; 8] {
    partial_sha256_var_start(msg)
}

// Hash `prefix_blocks` whole blocks with the interstitial helper, then finish
// with the remaining `total - 64 * prefix_blocks` bytes held in an `N`-byte array.
fn check_split<let N: u32>(total: u32, prefix_blocks: u32, expected: [u8; 32]) {
    let full: [u8; 768] = pattern();
    // Safety: test inputs, made witnesses on purpose.
    let (total, prefix_len) = unsafe { (opaque(total), opaque(prefix_blocks * 64)) };
    let h = partial_sha256_var_interstitial(IV, full, prefix_len);
    // Safety: test function
    let h_unconstrained = unsafe { interstitial_unconstrained(IV, full, prefix_len) };
    assert_eq(h, h_unconstrained);
    let mut suffix = [0; N];
    for i in 0..N {
        suffix[i] = full[prefix_len + i];
    }
    let suffix_len = (total - prefix_len) as u64;
    let circuit = partial_sha256_var_end(h, suffix, suffix_len, total as u64);
    // Safety: test function
    let oracle = unsafe { end_unconstrained(h, suffix, suffix_len, total as u64) };
    assert_eq(circuit, expected);
    assert_eq(oracle, expected);
}

#[test]
fn split_standalone_short() {
    check_split::<192>(
        0,
        0,
        [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65,
            228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ],
    );
    check_split::<192>(
        1,
        0,
        [
            75, 245, 18, 47, 52, 69, 84, 197, 59, 222, 46, 187, 140, 210, 183, 227, 209, 96, 10,
            214, 49, 195, 133, 165, 215, 204, 226, 60, 119, 133, 69, 154,
        ],
    );
    check_split::<192>(
        33,
        0,
        [
            71, 51, 17, 149, 10, 217, 214, 24, 131, 218, 233, 138, 162, 93, 41, 57, 187, 54, 111,
            96, 35, 216, 204, 179, 60, 141, 163, 22, 142, 100, 198, 57,
        ],
    );
    check_split::<192>(
        54,
        0,
        [
            85, 86, 190, 28, 32, 75, 228, 190, 2, 102, 210, 77, 6, 91, 0, 99, 67, 236, 211, 39, 192,
            173, 188, 12, 152, 219, 58, 53, 158, 183, 169, 182,
        ],
    );
    check_split::<192>(
        55,
        0,
        [
            22, 250, 87, 160, 163, 66, 58, 113, 93, 89, 69, 22, 51, 159, 54, 24, 157, 107, 95, 147,
            117, 74, 151, 20, 254, 242, 2, 97, 106, 159, 171, 254,
        ],
    );
    check_split::<192>(
        56,
        0,
        [
            195, 123, 68, 229, 241, 177, 133, 84, 179, 105, 102, 244, 248, 224, 139, 251, 243, 22,
            76, 75, 108, 16, 55, 77, 18, 216, 152, 80, 137, 32, 115, 197,
        ],
    );
    check_split::<192>(
        57,
        0,
        [
            18, 178, 52, 146, 37, 2, 2, 47, 117, 90, 184, 85, 10, 61, 78, 32, 42, 211, 156, 129,
            217, 97, 164, 245, 158, 195, 157, 95, 216, 61, 21, 167,
        ],
    );
}

#[test]
fn split_standalone_block() {
    check_split::<192>(
        63,
        0,
        [
            187, 186, 153, 45, 44, 133, 175, 150, 15, 178, 152, 122, 31, 208, 94, 10, 168, 42, 61,
            179, 199, 64, 221, 137, 130, 169, 226, 115, 183, 94, 54, 163,
        ],
    );
    check_split::<192>(
        64,
        0,
        [
            102, 189, 70, 51, 237, 111, 113, 196, 236, 250, 71, 99, 191, 123, 161, 200, 236, 118,
            18, 222, 154, 166, 192, 87, 138, 123, 103, 82, 7, 199, 30, 11,
        ],
    );
    check_split::<192>(
        65,
        0,
        [
            159, 125, 196, 113, 7, 183, 80, 161, 243, 211, 93, 181, 217, 84, 127, 36, 239, 64, 218,
            91, 115, 27, 149, 64, 212, 244, 55, 16, 161, 84, 246, 201,
        ],
    );
    check_split::<192>(
        100,
        0,
        [
            67, 3, 160, 219, 8, 5, 101, 127, 148, 137, 108, 190, 112, 113, 34, 132, 221, 61, 116,
            177, 50, 74, 146, 182, 119, 183, 146, 182, 59, 93, 117, 56,
        ],
    );
    check_split::<192>(
        118,
        0,
        [
            214, 54, 18, 190, 180, 151, 179, 145, 126, 249, 107, 162, 120, 182, 239, 246, 101, 47,
            14, 206, 99, 74, 129, 3, 102, 249, 5, 179, 165, 243, 199, 50,
        ],
    );
    check_split::<192>(
        119,
        0,
        [
            163, 237, 48, 123, 115, 15, 167, 124, 7, 83, 19, 0, 198, 228, 162, 130, 51, 0, 17, 212,
            212, 202, 246, 187, 123, 99, 174, 5, 149, 15, 75, 102,
        ],
    );
}

#[test]
fn split_standalone_two_blocks() {
    check_split::<192>(
        120,
        0,
        [
            142, 59, 21, 217, 254, 167, 71, 38, 85, 170, 6, 150, 32, 183, 248, 194, 229, 94, 225,
            73, 159, 118, 50, 0, 167, 81, 95, 232, 38, 233, 157, 32,
        ],
    );
    check_split::<192>(
        121,
        0,
        [
            168, 50, 13, 151, 54, 200, 165, 167, 68, 92, 135, 196, 209, 140, 13, 162, 250, 143, 179,
            179, 35, 237, 131, 24, 199, 36, 165, 179, 226, 48, 248, 123,
        ],
    );
    check_split::<192>(
        127,
        0,
        [
            68, 72, 15, 185, 103, 40, 69, 23, 127, 83, 104, 160, 139, 105, 234, 38, 50, 117, 242,
            165, 236, 66, 224, 106, 147, 51, 112, 254, 13, 41, 104, 164,
        ],
    );
    check_split::<192>(
        128,
        0,
        [
            228, 98, 193, 48, 254, 248, 201, 126, 52, 247, 220, 63, 243, 173, 47, 139, 53, 51, 171,
            132, 154, 242, 28, 16, 83, 21, 82, 162, 133, 35, 135, 164,
        ],
    );
    check_split::<192>(
        129,
        0,
        [
            170, 126, 164, 232, 191, 137, 20, 106, 235, 103, 255, 25, 95, 216, 24, 42, 14, 80, 76,
            157, 88, 10, 167, 175, 141, 44, 134, 46, 20, 185, 132, 5,
        ],
    );
    check_split::<192>(
        183,
        0,
        [
            70, 191, 99, 51, 18, 150, 177, 52, 12, 155, 81, 106, 145, 15, 216, 130, 157, 62, 39,
            150, 61, 3, 219, 129, 190, 142, 23, 10, 153, 122, 89, 2,
        ],
    );
}

#[test]
fn split_standalone_full() {
    check_split::<192>(
        184,
        0,
        [
            99, 81, 211, 237, 127, 127, 239, 10, 167, 49, 145, 241, 230, 229, 165, 36, 164, 20, 9,
            73, 174, 79, 232, 203, 207, 142, 102, 99, 220, 158, 88, 212,
        ],
    );
    check_split::<192>(
        185,
        0,
        [
            232, 183, 81, 44, 74, 219, 207, 17, 172, 35, 180, 160, 94, 175, 72, 185, 10, 26, 84,
            202, 92, 105, 204, 136, 187, 45, 187, 104, 226, 158, 76, 111,
        ],
    );
    check_split::<192>(
        191,
        0,
        [
            225, 120, 228, 252, 226, 192, 213, 152, 80, 158, 94, 211, 230, 144, 82, 140, 194, 237,
            226, 77, 154, 43, 132, 85, 248, 22, 169, 70, 103, 87, 83, 217,
        ],
    );
    check_split::<192>(
        192,
        0,
        [
            65, 22, 64, 174, 161, 208, 78, 145, 96, 84, 214, 1, 56, 106, 9, 74, 10, 74, 144, 7, 207,
            46, 35, 245, 162, 93, 33, 107, 140, 234, 210, 139,
        ],
    );
}

#[test]
fn split_standalone_capacity_100() {
    check_split::<100>(
        0,
        0,
        [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65,
            228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ],
    );
    check_split::<100>(
        36,
        0,
        [
            60, 59, 242, 21, 143, 219, 32, 18, 44, 195, 206, 28, 54, 149, 137, 3, 202, 72, 151, 212,
            2, 212, 88, 52, 235, 100, 139, 113, 242, 100, 3, 67,
        ],
    );
    check_split::<100>(
        55,
        0,
        [
            22, 250, 87, 160, 163, 66, 58, 113, 93, 89, 69, 22, 51, 159, 54, 24, 157, 107, 95, 147,
            117, 74, 151, 20, 254, 242, 2, 97, 106, 159, 171, 254,
        ],
    );
    check_split::<100>(
        56,
        0,
        [
            195, 123, 68, 229, 241, 177, 133, 84, 179, 105, 102, 244, 248, 224, 139, 251, 243, 22,
            76, 75, 108, 16, 55, 77, 18, 216, 152, 80, 137, 32, 115, 197,
        ],
    );
    check_split::<100>(
        63,
        0,
        [
            187, 186, 153, 45, 44, 133, 175, 150, 15, 178, 152, 122, 31, 208, 94, 10, 168, 42, 61,
            179, 199, 64, 221, 137, 130, 169, 226, 115, 183, 94, 54, 163,
        ],
    );
    check_split::<100>(
        64,
        0,
        [
            102, 189, 70, 51, 237, 111, 113, 196, 236, 250, 71, 99, 191, 123, 161, 200, 236, 118,
            18, 222, 154, 166, 192, 87, 138, 123, 103, 82, 7, 199, 30, 11,
        ],
    );
    check_split::<100>(
        99,
        0,
        [
            241, 168, 17, 148, 47, 71, 177, 55, 114, 22, 85, 97, 234, 100, 185, 230, 217, 48, 154,
            243, 175, 131, 227, 130, 120, 217, 211, 34, 49, 79, 222, 217,
        ],
    );
    check_split::<100>(
        100,
        0,
        [
            67, 3, 160, 219, 8, 5, 101, 127, 148, 137, 108, 190, 112, 113, 34, 132, 221, 61, 116,
            177, 50, 74, 146, 182, 119, 183, 146, 182, 59, 93, 117, 56,
        ],
    );
}

#[test]
fn split_standalone_capacity_191() {
    check_split::<191>(
        119,
        0,
        [
            163, 237, 48, 123, 115, 15, 167, 124, 7, 83, 19, 0, 198, 228, 162, 130, 51, 0, 17, 212,
            212, 202, 246, 187, 123, 99, 174, 5, 149, 15, 75, 102,
        ],
    );
    check_split::<191>(
        120,
        0,
        [
            142, 59, 21, 217, 254, 167, 71, 38, 85, 170, 6, 150, 32, 183, 248, 194, 229, 94, 225,
            73, 159, 118, 50, 0, 167, 81, 95, 232, 38, 233, 157, 32,
        ],
    );
    check_split::<191>(
        128,
        0,
        [
            228, 98, 193, 48, 254, 248, 201, 126, 52, 247, 220, 63, 243, 173, 47, 139, 53, 51, 171,
            132, 154, 242, 28, 16, 83, 21, 82, 162, 133, 35, 135, 164,
        ],
    );
    check_split::<191>(
        183,
        0,
        [
            70, 191, 99, 51, 18, 150, 177, 52, 12, 155, 81, 106, 145, 15, 216, 130, 157, 62, 39,
            150, 61, 3, 219, 129, 190, 142, 23, 10, 153, 122, 89, 2,
        ],
    );
    check_split::<191>(
        184,
        0,
        [
            99, 81, 211, 237, 127, 127, 239, 10, 167, 49, 145, 241, 230, 229, 165, 36, 164, 20, 9,
            73, 174, 79, 232, 203, 207, 142, 102, 99, 220, 158, 88, 212,
        ],
    );
    check_split::<191>(
        191,
        0,
        [
            225, 120, 228, 252, 226, 192, 213, 152, 80, 158, 94, 211, 230, 144, 82, 140, 194, 237,
            226, 77, 154, 43, 132, 85, 248, 22, 169, 70, 103, 87, 83, 217,
        ],
    );
}

#[test]
fn split_one_block_prefix() {
    check_split::<192>(
        64,
        1,
        [
            102, 189, 70, 51, 237, 111, 113, 196, 236, 250, 71, 99, 191, 123, 161, 200, 236, 118,
            18, 222, 154, 166, 192, 87, 138, 123, 103, 82, 7, 199, 30, 11,
        ],
    );
    check_split::<192>(
        65,
        1,
        [
            159, 125, 196, 113, 7, 183, 80, 161, 243, 211, 93, 181, 217, 84, 127, 36, 239, 64, 218,
            91, 115, 27, 149, 64, 212, 244, 55, 16, 161, 84, 246, 201,
        ],
    );
    check_split::<192>(
        100,
        1,
        [
            67, 3, 160, 219, 8, 5, 101, 127, 148, 137, 108, 190, 112, 113, 34, 132, 221, 61, 116,
            177, 50, 74, 146, 182, 119, 183, 146, 182, 59, 93, 117, 56,
        ],
    );
    check_split::<192>(
        119,
        1,
        [
            163, 237, 48, 123, 115, 15, 167, 124, 7, 83, 19, 0, 198, 228, 162, 130, 51, 0, 17, 212,
            212, 202, 246, 187, 123, 99, 174, 5, 149, 15, 75, 102,
        ],
    );
    check_split::<192>(
        120,
        1,
        [
            142, 59, 21, 217, 254, 167, 71, 38, 85, 170, 6, 150, 32, 183, 248, 194, 229, 94, 225,
            73, 159, 118, 50, 0, 167, 81, 95, 232, 38, 233, 157, 32,
        ],
    );
    check_split::<192>(
        121,
        1,
        [
            168, 50, 13, 151, 54, 200, 165, 167, 68, 92, 135, 196, 209, 140, 13, 162, 250, 143, 179,
            179, 35, 237, 131, 24, 199, 36, 165, 179, 226, 48, 248, 123,
        ],
    );
    check_split::<192>(
        127,
        1,
        [
            68, 72, 15, 185, 103, 40, 69, 23, 127, 83, 104, 160, 139, 105, 234, 38, 50, 117, 242,
            165, 236, 66, 224, 106, 147, 51, 112, 254, 13, 41, 104, 164,
        ],
    );
    check_split::<192>(
        128,
        1,
        [
            228, 98, 193, 48, 254, 248, 201, 126, 52, 247, 220, 63, 243, 173, 47, 139, 53, 51, 171,
            132, 154, 242, 28, 16, 83, 21, 82, 162, 133, 35, 135, 164,
        ],
    );
    check_split::<192>(
        129,
        1,
        [
            170, 126, 164, 232, 191, 137, 20, 106, 235, 103, 255, 25, 95, 216, 24, 42, 14, 80, 76,
            157, 88, 10, 167, 175, 141, 44, 134, 46, 20, 185, 132, 5,
        ],
    );
}

#[test]
fn split_two_block_prefix() {
    check_split::<192>(
        128,
        2,
        [
            228, 98, 193, 48, 254, 248, 201, 126, 52, 247, 220, 63, 243, 173, 47, 139, 53, 51, 171,
            132, 154, 242, 28, 16, 83, 21, 82, 162, 133, 35, 135, 164,
        ],
    );
    check_split::<192>(
        183,
        2,
        [
            70, 191, 99, 51, 18, 150, 177, 52, 12, 155, 81, 106, 145, 15, 216, 130, 157, 62, 39,
            150, 61, 3, 219, 129, 190, 142, 23, 10, 153, 122, 89, 2,
        ],
    );
    check_split::<192>(
        184,
        2,
        [
            99, 81, 211, 237, 127, 127, 239, 10, 167, 49, 145, 241, 230, 229, 165, 36, 164, 20, 9,
            73, 174, 79, 232, 203, 207, 142, 102, 99, 220, 158, 88, 212,
        ],
    );
    check_split::<192>(
        192,
        2,
        [
            65, 22, 64, 174, 161, 208, 78, 145, 96, 84, 214, 1, 56, 106, 9, 74, 10, 74, 144, 7, 207,
            46, 35, 245, 162, 93, 33, 107, 140, 234, 210, 139,
        ],
    );
    check_split::<192>(
        247,
        2,
        [
            142, 44, 127, 59, 76, 26, 161, 79, 186, 39, 62, 152, 149, 9, 55, 54, 20, 163, 88, 70,
            184, 20, 133, 106, 142, 167, 239, 122, 106, 109, 161, 167,
        ],
    );
    check_split::<192>(
        248,
        2,
        [
            243, 6, 233, 251, 141, 58, 66, 164, 31, 139, 134, 165, 248, 91, 145, 151, 198, 144, 161,
            121, 226, 30, 212, 218, 25, 6, 169, 86, 200, 226, 138, 126,
        ],
    );
    check_split::<192>(
        256,
        2,
        [
            45, 127, 88, 15, 212, 113, 6, 84, 94, 36, 241, 4, 241, 238, 241, 14, 117, 129, 138, 135,
            71, 63, 254, 154, 67, 172, 105, 138, 57, 221, 231, 242,
        ],
    );
    check_split::<192>(
        292,
        2,
        [
            67, 14, 159, 228, 180, 109, 82, 11, 52, 119, 20, 238, 84, 157, 208, 29, 103, 99, 217,
            176, 123, 148, 126, 237, 42, 123, 125, 252, 147, 8, 55, 207,
        ],
    );
}

#[test]
fn split_three_block_prefix() {
    check_split::<192>(
        192,
        3,
        [
            65, 22, 64, 174, 161, 208, 78, 145, 96, 84, 214, 1, 56, 106, 9, 74, 10, 74, 144, 7, 207,
            46, 35, 245, 162, 93, 33, 107, 140, 234, 210, 139,
        ],
    );
    check_split::<192>(
        193,
        3,
        [
            189, 214, 75, 92, 150, 131, 117, 146, 10, 7, 105, 86, 208, 50, 170, 164, 20, 17, 116,
            119, 171, 6, 248, 220, 186, 147, 162, 175, 221, 77, 219, 72,
        ],
    );
    check_split::<192>(
        248,
        3,
        [
            243, 6, 233, 251, 141, 58, 66, 164, 31, 139, 134, 165, 248, 91, 145, 151, 198, 144, 161,
            121, 226, 30, 212, 218, 25, 6, 169, 86, 200, 226, 138, 126,
        ],
    );
    check_split::<192>(
        312,
        3,
        [
            255, 229, 22, 176, 234, 64, 101, 123, 184, 149, 114, 137, 84, 243, 112, 239, 158, 244,
            250, 105, 157, 84, 248, 232, 20, 140, 79, 99, 97, 7, 101, 132,
        ],
    );
    check_split::<192>(
        375,
        3,
        [
            228, 4, 4, 9, 28, 121, 197, 78, 151, 137, 217, 101, 101, 226, 82, 99, 31, 12, 233, 87,
            31, 163, 53, 109, 145, 142, 1, 159, 190, 229, 94, 253,
        ],
    );
    check_split::<192>(
        376,
        3,
        [
            148, 57, 110, 46, 108, 46, 96, 241, 241, 31, 137, 167, 32, 124, 121, 93, 23, 45, 13, 47,
            22, 191, 148, 245, 140, 80, 127, 248, 192, 175, 240, 164,
        ],
    );
    check_split::<192>(
        384,
        3,
        [
            44, 248, 115, 196, 181, 67, 129, 155, 136, 219, 95, 171, 208, 102, 45, 208, 254, 113,
            33, 67, 183, 136, 50, 119, 251, 105, 168, 14, 252, 224, 73, 163,
        ],
    );
}

#[test]
fn split_one_block_prefix_capacity_100() {
    check_split::<100>(
        64,
        1,
        [
            102, 189, 70, 51, 237, 111, 113, 196, 236, 250, 71, 99, 191, 123, 161, 200, 236, 118,
            18, 222, 154, 166, 192, 87, 138, 123, 103, 82, 7, 199, 30, 11,
        ],
    );
    check_split::<100>(
        100,
        1,
        [
            67, 3, 160, 219, 8, 5, 101, 127, 148, 137, 108, 190, 112, 113, 34, 132, 221, 61, 116,
            177, 50, 74, 146, 182, 119, 183, 146, 182, 59, 93, 117, 56,
        ],
    );
    check_split::<100>(
        119,
        1,
        [
            163, 237, 48, 123, 115, 15, 167, 124, 7, 83, 19, 0, 198, 228, 162, 130, 51, 0, 17, 212,
            212, 202, 246, 187, 123, 99, 174, 5, 149, 15, 75, 102,
        ],
    );
    check_split::<100>(
        120,
        1,
        [
            142, 59, 21, 217, 254, 167, 71, 38, 85, 170, 6, 150, 32, 183, 248, 194, 229, 94, 225,
            73, 159, 118, 50, 0, 167, 81, 95, 232, 38, 233, 157, 32,
        ],
    );
    check_split::<100>(
        127,
        1,
        [
            68, 72, 15, 185, 103, 40, 69, 23, 127, 83, 104, 160, 139, 105, 234, 38, 50, 117, 242,
            165, 236, 66, 224, 106, 147, 51, 112, 254, 13, 41, 104, 164,
        ],
    );
    check_split::<100>(
        128,
        1,
        [
            228, 98, 193, 48, 254, 248, 201, 126, 52, 247, 220, 63, 243, 173, 47, 139, 53, 51, 171,
            132, 154, 242, 28, 16, 83, 21, 82, 162, 133, 35, 135, 164,
        ],
    );
    check_split::<100>(
        163,
        1,
        [
            167, 67, 49, 51, 176, 27, 35, 69, 76, 73, 105, 130, 62, 149, 118, 196, 134, 104, 219,
            109, 80, 190, 112, 57, 238, 155, 94, 167, 42, 16, 234, 113,
        ],
    );
    check_split::<100>(
        164,
        1,
        [
            242, 13, 103, 13, 91, 173, 81, 4, 241, 255, 213, 40, 105, 238, 210, 69, 87, 179, 6, 32,
            182, 32, 78, 171, 109, 216, 9, 58, 254, 134, 149, 6,
        ],
    );
}

#[test]
fn split_nine_block_prefix_capacity_191() {
    check_split::<191>(
        576,
        9,
        [
            234, 49, 71, 216, 153, 19, 7, 154, 57, 16, 34, 126, 51, 159, 160, 137, 80, 226, 220,
            203, 247, 239, 43, 75, 80, 46, 164, 189, 119, 42, 157, 88,
        ],
    );
    check_split::<191>(
        577,
        9,
        [
            56, 111, 197, 141, 36, 42, 169, 243, 47, 35, 141, 133, 6, 48, 101, 23, 232, 157, 223,
            185, 220, 89, 10, 200, 76, 76, 177, 15, 141, 239, 54, 132,
        ],
    );
    check_split::<191>(
        632,
        9,
        [
            11, 85, 255, 21, 40, 154, 13, 252, 10, 135, 9, 154, 43, 245, 40, 117, 151, 39, 7, 64,
            161, 35, 0, 87, 153, 251, 65, 39, 155, 201, 75, 6,
        ],
    );
    check_split::<191>(
        696,
        9,
        [
            79, 208, 176, 248, 190, 8, 109, 5, 151, 21, 158, 237, 95, 135, 229, 82, 66, 159, 173,
            150, 117, 193, 32, 9, 134, 17, 128, 223, 159, 80, 48, 97,
        ],
    );
    check_split::<191>(
        740,
        9,
        [
            204, 124, 24, 90, 19, 217, 23, 49, 4, 105, 186, 112, 79, 25, 184, 147, 165, 85, 218, 49,
            8, 42, 34, 161, 124, 198, 129, 49, 168, 221, 82, 26,
        ],
    );
    check_split::<191>(
        759,
        9,
        [
            252, 219, 79, 88, 201, 197, 171, 69, 14, 171, 177, 1, 59, 181, 82, 227, 23, 226, 135, 5,
            131, 4, 45, 246, 55, 170, 158, 29, 197, 48, 125, 56,
        ],
    );
    check_split::<191>(
        760,
        9,
        [
            195, 101, 158, 93, 159, 241, 96, 46, 244, 64, 248, 184, 137, 232, 31, 175, 197, 11, 180,
            50, 110, 144, 97, 155, 92, 229, 147, 58, 108, 63, 150, 14,
        ],
    );
    check_split::<191>(
        767,
        9,
        [
            160, 57, 126, 13, 102, 167, 162, 204, 86, 178, 10, 134, 71, 132, 122, 97, 22, 41, 1,
            244, 135, 22, 160, 197, 192, 150, 234, 24, 168, 146, 197, 166,
        ],
    );
}

#[test]
fn split_nine_block_prefix_short() {
    check_split::<192>(
        576,
        9,
        [
            234, 49, 71, 216, 153, 19, 7, 154, 57, 16, 34, 126, 51, 159, 160, 137, 80, 226, 220,
            203, 247, 239, 43, 75, 80, 46, 164, 189, 119, 42, 157, 88,
        ],
    );
    check_split::<192>(
        577,
        9,
        [
            56, 111, 197, 141, 36, 42, 169, 243, 47, 35, 141, 133, 6, 48, 101, 23, 232, 157, 223,
            185, 220, 89, 10, 200, 76, 76, 177, 15, 141, 239, 54, 132,
        ],
    );
    check_split::<192>(
        631,
        9,
        [
            181, 184, 238, 223, 52, 40, 158, 112, 153, 116, 53, 45, 205, 55, 93, 76, 241, 90, 102,
            26, 184, 244, 123, 250, 31, 209, 119, 88, 193, 119, 221, 95,
        ],
    );
    check_split::<192>(
        632,
        9,
        [
            11, 85, 255, 21, 40, 154, 13, 252, 10, 135, 9, 154, 43, 245, 40, 117, 151, 39, 7, 64,
            161, 35, 0, 87, 153, 251, 65, 39, 155, 201, 75, 6,
        ],
    );
    check_split::<192>(
        633,
        9,
        [
            59, 41, 239, 166, 78, 76, 115, 148, 16, 65, 23, 231, 107, 173, 125, 115, 158, 122, 140,
            46, 18, 217, 244, 66, 169, 219, 85, 148, 245, 233, 60, 251,
        ],
    );
    check_split::<192>(
        639,
        9,
        [
            191, 90, 105, 70, 110, 157, 252, 119, 72, 144, 225, 94, 177, 254, 110, 160, 213, 52,
            250, 126, 142, 216, 203, 139, 54, 226, 71, 182, 102, 190, 220, 215,
        ],
    );
    check_split::<192>(
        640,
        9,
        [
            7, 107, 61, 117, 237, 234, 42, 60, 134, 28, 84, 231, 49, 252, 62, 31, 236, 245, 132, 12,
            152, 119, 78, 142, 152, 38, 135, 208, 159, 21, 105, 102,
        ],
    );
}

#[test]
fn split_nine_block_prefix_long() {
    check_split::<192>(
        641,
        9,
        [
            54, 253, 190, 43, 181, 43, 243, 19, 145, 193, 186, 223, 18, 171, 100, 8, 96, 120, 217,
            248, 191, 183, 110, 157, 148, 187, 239, 118, 240, 196, 35, 253,
        ],
    );
    check_split::<192>(
        695,
        9,
        [
            215, 37, 81, 57, 31, 124, 77, 87, 208, 126, 97, 190, 40, 111, 226, 78, 246, 207, 173,
            149, 151, 184, 90, 50, 107, 202, 159, 31, 218, 38, 46, 79,
        ],
    );
    check_split::<192>(
        696,
        9,
        [
            79, 208, 176, 248, 190, 8, 109, 5, 151, 21, 158, 237, 95, 135, 229, 82, 66, 159, 173,
            150, 117, 193, 32, 9, 134, 17, 128, 223, 159, 80, 48, 97,
        ],
    );
    check_split::<192>(
        704,
        9,
        [
            235, 124, 223, 68, 132, 166, 15, 94, 58, 144, 74, 95, 216, 133, 33, 212, 154, 96, 3, 42,
            189, 46, 103, 197, 30, 100, 142, 180, 55, 241, 87, 225,
        ],
    );
    check_split::<192>(
        740,
        9,
        [
            204, 124, 24, 90, 19, 217, 23, 49, 4, 105, 186, 112, 79, 25, 184, 147, 165, 85, 218, 49,
            8, 42, 34, 161, 124, 198, 129, 49, 168, 221, 82, 26,
        ],
    );
    check_split::<192>(
        760,
        9,
        [
            195, 101, 158, 93, 159, 241, 96, 46, 244, 64, 248, 184, 137, 232, 31, 175, 197, 11, 180,
            50, 110, 144, 97, 155, 92, 229, 147, 58, 108, 63, 150, 14,
        ],
    );
    check_split::<192>(
        767,
        9,
        [
            160, 57, 126, 13, 102, 167, 162, 204, 86, 178, 10, 134, 71, 132, 122, 97, 22, 41, 1,
            244, 135, 22, 160, 197, 192, 150, 234, 24, 168, 146, 197, 166,
        ],
    );
    check_split::<192>(
        768,
        9,
        [
            27, 159, 91, 76, 126, 148, 167, 88, 74, 251, 51, 172, 54, 180, 223, 151, 220, 126, 250,
            167, 20, 138, 21, 201, 2, 126, 64, 2, 210, 212, 26, 109,
        ],
    );
}

// The start helper must agree with the interstitial helper from the initial
// state, in both runtimes, for the block counts used above.
#[test]
fn start_matches_interstitial() {
    {
        let prefix: [u8; 64] = pattern();
        let started = partial_sha256_var_start(prefix);
        // Safety: test function
        let started_unconstrained = unsafe { start_unconstrained(prefix) };
        let continued = partial_sha256_var_interstitial(IV, prefix, 64);
        assert_eq(started, continued);
        assert_eq(started_unconstrained, continued);
    }
    {
        let prefix: [u8; 128] = pattern();
        let started = partial_sha256_var_start(prefix);
        // Safety: test function
        let started_unconstrained = unsafe { start_unconstrained(prefix) };
        let continued = partial_sha256_var_interstitial(IV, prefix, 128);
        assert_eq(started, continued);
        assert_eq(started_unconstrained, continued);
    }
    {
        let prefix: [u8; 192] = pattern();
        let started = partial_sha256_var_start(prefix);
        // Safety: test function
        let started_unconstrained = unsafe { start_unconstrained(prefix) };
        let continued = partial_sha256_var_interstitial(IV, prefix, 192);
        assert_eq(started, continued);
        assert_eq(started_unconstrained, continued);
    }
    {
        let prefix: [u8; 576] = pattern();
        let started = partial_sha256_var_start(prefix);
        // Safety: test function
        let started_unconstrained = unsafe { start_unconstrained(prefix) };
        let continued = partial_sha256_var_interstitial(IV, prefix, 576);
        assert_eq(started, continued);
        assert_eq(started_unconstrained, continued);
    }
}

// Start (nine blocks) then end with the 164-byte suffix of a 740-byte message:
// the shape of the zkemail partial body-hash test.
#[test]
fn start_then_end_caller_shape() {
    let full: [u8; 768] = pattern();
    let mut prefix = [0; 576];
    for i in 0..576 {
        prefix[i] = full[i];
    }
    let mut suffix = [0; 192];
    for i in 0..192 {
        suffix[i] = full[576 + i];
    }
    let h = partial_sha256_var_start(prefix);
    let circuit = partial_sha256_var_end(h, suffix, 164, 740);
    // Safety: test function
    let oracle = unsafe { end_unconstrained(h, suffix, 164, 740) };
    let expected = [
        204, 124, 24, 90, 19, 217, 23, 49, 4, 105, 186, 112, 79, 25, 184, 147, 165, 85, 218, 49, 8,
        42, 34, 161, 124, 198, 129, 49, 168, 221, 82, 26,
    ];
    assert_eq(circuit, expected);
    assert_eq(oracle, expected);
}

// Ports of the regression tests of noir-lang/sha256 commit a82d3ea6. That API
// passes the block-aligned part of the final chunk as `message_size` and takes
// the trailing bytes from `real_message_size % 64`; here `message_size` is the
// whole remaining length, so upstream's (64, 100) becomes (100, 100).
#[test]
fn upstream_regression_partial_hash_non_block_aligned() {
    let data: [u8; 100] = pattern();
    let hash = partial_sha256_var_end(IV, data, 100, 100);
    // Safety: test function
    let oracle = unsafe { end_unconstrained(IV, data, 100, 100) };
    let correct_hash = sha256_var(data, 100);
    assert_eq(hash, correct_hash);
    assert_eq(oracle, correct_hash);
}

fn assert_partial_end_matches_reference(real_message_size: u32) {
    let msg: [u8; 192] = pattern();
    let hash = partial_sha256_var_end(IV, msg, real_message_size as u64, real_message_size as u64);
    // Safety: test function
    let oracle =
        unsafe { end_unconstrained(IV, msg, real_message_size as u64, real_message_size as u64) };
    let reference = sha256_var(msg, real_message_size);
    assert_eq(hash, reference);
    assert_eq(oracle, reference);
}

#[test]
fn upstream_partial_end_sizes() {
    assert_partial_end_matches_reference(1);
    assert_partial_end_matches_reference(33);
    assert_partial_end_matches_reference(63);
    assert_partial_end_matches_reference(65);
    assert_partial_end_matches_reference(100);
    assert_partial_end_matches_reference(127);
    assert_partial_end_matches_reference(129);
    assert_partial_end_matches_reference(191);
    assert_partial_end_matches_reference(64);
    assert_partial_end_matches_reference(128);
}

#[test]
fn upstream_composed_non_aligned_tail_only() {
    let full: [u8; 100] = pattern();
    let state = partial_sha256_var_interstitial(IV, full, 64);
    let mut tail = [0; 36];
    for i in 0..36 {
        tail[i] = full[64 + i];
    }
    let circuit = partial_sha256_var_end(state, tail, 36, 100);
    // Safety: test function
    let oracle = unsafe { end_unconstrained(state, tail, 36, 100) };
    let reference = sha256_var(full, 100);
    assert_eq(circuit, reference);
    assert_eq(oracle, reference);
}

#[test]
fn upstream_composed_non_aligned_block_plus_tail() {
    let full: [u8; 200] = pattern();
    let state = partial_sha256_var_interstitial(IV, full, 128);
    let mut chunk = [0; 72];
    for i in 0..72 {
        chunk[i] = full[128 + i];
    }
    let circuit = partial_sha256_var_end(state, chunk, 72, 200);
    // Safety: test function
    let oracle = unsafe { end_unconstrained(state, chunk, 72, 200) };
    let reference = sha256_var(full, 200);
    assert_eq(circuit, reference);
    assert_eq(oracle, reference);
}

// The size arguments must not describe bytes outside `msg`, in either runtime.
#[test(should_fail_with = "Message size exceeds end input capacity")]
fn upstream_regression_partial_end_tail_beyond_capacity() {
    let msg = [7; 64];
    let _ = partial_sha256_var_end(IV, msg, 100, 100);
}

#[test(should_fail_with = "Message size exceeds end input capacity")]
fn upstream_regression_partial_end_tail_beyond_capacity_unconstrained() {
    let msg = [7; 64];
    // Safety: test function
    let _ = unsafe { end_unconstrained(IV, msg, 100, 100) };
}

#[test(should_fail_with = "Message size exceeds interstitial input capacity")]
fn upstream_regression_partial_interstitial_message_beyond_capacity() {
    let msg = [7; 64];
    let _ = partial_sha256_var_interstitial(IV, msg, 128);
}

#[test(should_fail_with = "Message size exceeds interstitial input capacity")]
fn upstream_regression_partial_interstitial_message_beyond_capacity_unconstrained() {
    let msg = [7; 64];
    // Safety: test function
    let _ = unsafe { interstitial_unconstrained(IV, msg, 128) };
}

#[test(should_fail_with = "Message size must be a multiple of the block size")]
fn interstitial_rejects_partial_block() {
    let msg: [u8; 128] = pattern();
    let _ = partial_sha256_var_interstitial(IV, msg, 100);
}

#[test(should_fail_with = "Message size must be a multiple of the block size")]
fn interstitial_rejects_partial_block_unconstrained() {
    let msg: [u8; 128] = pattern();
    // Safety: test function
    let _ = unsafe { interstitial_unconstrained(IV, msg, 100) };
}
