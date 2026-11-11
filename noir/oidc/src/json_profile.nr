//! Bounded nested JSON for the structured document of `json_document.nr`:
//! unescaped keys and strings of at most 4096 bytes, nesting of at most 8, and
//! the scalars of `scalar_is_valid` (unsigned canonical u64 integers, true,
//! false, null). The flat OIDC claim profiles scan their nested values in the
//! claims scanner of `json.nr`.
use crate::json::{advance_scalar, scalar_is_valid, ScalarState, start_scalar};

pub(crate) struct NestedState {
    pub depth: u32,
    kinds: [u8; 8], // 0 object, 1 array
    // Every suspended parent has consumed its value and awaits a separator.
    phase: u8,
    comma: bool,
    container: u8,
    mode: u8, // 0 grammar, 1 key, 2 string, 3 scalar
    len: u32,
    scalar: ScalarState,
    pub done: bool,
}

/// The state after the document's opening '{'.
pub(crate) fn nested_start() -> NestedState {
    NestedState {
        depth: 1,
        kinds: [0; 8],
        phase: 0,
        comma: false,
        container: 0,
        mode: 0,
        len: 0,
        scalar: start_scalar(0),
        done: false,
    }
}
fn ws(b: u8) -> bool {
    (b == 32) | (b == 9) | (b == 10) | (b == 13)
}
fn close(mut s: NestedState, b: u8) -> NestedState {
    assert(
        (s.container == 0) & (b == 125) | (s.container == 1) & (b == 93),
        "mismatched nested JSON delimiter",
    );
    s.depth -= 1;
    if s.depth == 0 {
        s.done = true;
    } else {
        s.container = s.kinds[s.depth - 1];
        s.phase = 3;
        s.comma = false;
    }
    s
}

pub(crate) fn nested_byte(mut s: NestedState, b: u8) -> NestedState {
    assert(!s.done & (s.depth > 0), "invalid nested JSON state");
    let mut consumed = false;
    if (s.mode == 1) | (s.mode == 2) {
        consumed = true;
        assert(b != 92, "escaped JSON strings are unsupported");
        if b == 34 {
            s.phase = if s.mode == 1 { 1 } else { 3 };
            s.mode = 0;
        } else {
            assert(b >= 32, "control byte in nested JSON string");
            assert(s.len < 4096, "nested JSON string too long");
            s.len += 1;
        }
    } else if s.mode == 3 {
        if ws(b) | (b == 44) | (b == 125) | (b == 93) {
            assert(scalar_is_valid(s.scalar), "invalid JSON scalar");
            s.mode = 0;
            s.phase = 3;
        } else {
            s.scalar = advance_scalar(s.scalar, b);
            consumed = true;
        }
    }
    if !consumed {
        if ws(b) {} else if (s.container == 0) & (s.phase == 0) {
            if b == 125 {
                assert(!s.comma, "trailing comma in nested JSON");
                s = close(s, b);
            } else {
                assert(b == 34, "nested key must be string");
                s.mode = 1;
                s.len = 0;
                s.comma = false;
            }
        } else if (s.container == 0) & (s.phase == 1) {
            assert(b == 58, "nested key needs colon");
            s.phase = 2;
        } else if s.phase == 2 {
            if (s.container == 1) & (b == 93) {
                assert(!s.comma, "trailing comma in nested JSON");
                s = close(s, b);
            } else {
                s.comma = false;
                if b == 34 {
                    s.len = 0;
                    s.mode = 2;
                } else if (b == 123) | (b == 91) {
                    assert(s.depth < 8, "nested JSON depth exceeds profile");
                    let next = s.depth;
                    s.container = if b == 123 { 0 } else { 1 };
                    s.kinds[next] = s.container;
                    s.phase = if b == 123 { 0 } else { 2 };
                    s.comma = false;
                    s.depth += 1;
                } else {
                    assert((b != 125) & (b != 93) & (b != 44) & (b != 58), "nested value required");
                    s.scalar = start_scalar(b);
                    s.mode = 3;
                }
            }
        } else {
            assert(s.phase == 3, "invalid nested JSON grammar");
            if b == 44 {
                s.phase = if s.container == 0 { 0 } else { 2 };
                s.comma = true;
            } else {
                assert((b == 125) | (b == 93), "invalid nested JSON separator");
                s = close(s, b);
            }
        }
    }
    s
}
