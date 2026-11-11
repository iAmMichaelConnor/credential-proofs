pub struct Tlv {
    pub tag: u8,
    pub start: u32,
    pub content: u32,
    pub len: u32,
    pub end: u32,
}
/// DER low-tag form, with canonical short, one-byte or two-byte lengths.
/// Two length octets cover the full bounded certificate/OCSP input capacities.
/// A BoundedVec supplied as a circuit input is not range-checked against its
/// capacity, so `read` rejects `len() > N` before trusting `len()` as a bound.
pub fn read<let N: u32>(data: BoundedVec<u8, N>, start: u32, parent_end: u32) -> Tlv {
    assert(data.len() <= N, "DER input exceeds capacity");
    assert(parent_end <= data.len(), "DER parent exceeds input");
    assert(start < parent_end, "missing DER element");
    assert(parent_end - start >= 2, "truncated DER header");
    let tag = data.storage()[start];
    assert((tag & 31) != 31, "unsupported DER high-tag form");
    let first = data.storage()[start + 1];
    let mut len = first as u32;
    let mut content = start + 2;
    if first >= 128 {
        let count = (first & 127) as u32;
        assert((count == 1) | (count == 2), "invalid or unsupported DER length");
        assert(parent_end - content >= count, "truncated DER length");
        assert(data.storage()[content] != 0, "noncanonical DER length");
        len = data.storage()[content] as u32;
        if count == 2 {
            len = len * 256 + data.storage()[content + 1] as u32;
        }
        assert(len >= 128, "noncanonical DER long length");
        if count == 2 {
            assert(len >= 256, "nonminimal DER long length");
        }
        content += count;
    }
    assert(len <= parent_end - content, "DER child exceeds parent");
    Tlv { tag, start, content, len, end: content + len }
}
pub fn expect<let N: u32>(data: BoundedVec<u8, N>, start: u32, parent_end: u32, tag: u8) -> Tlv {
    let node = read(data, start, parent_end);
    assert(node.tag == tag, "unexpected DER tag");
    node
}
pub fn literal<let N: u32, let M: u32>(data: BoundedVec<u8, N>, node: Tlv, expected: [u8; M]) {
    assert(node.len == M, "wrong DER value length");
    for i in 0..M {
        assert(data.storage()[node.content + i] == expected[i], "wrong DER value");
    }
}
/// Copy `len` bytes of `data` from `start`. The output storage after `len` is
/// zero whatever `data` holds, so the result meets the zero-tail precondition
/// of zkpassport sha512 v0.2.0 `sha512_var` (unlike `sha256_var`, it hashes
/// the storage after the length).
pub fn slice<let N: u32, let OUT: u32>(
    data: BoundedVec<u8, N>,
    start: u32,
    len: u32,
) -> BoundedVec<u8, OUT> {
    assert(len <= OUT, "DER value exceeds output capacity");
    assert(start <= data.len(), "DER slice start exceeds input");
    assert(len <= data.len() - start, "DER slice exceeds input");
    let mut out = [0u8; OUT];
    for i in 0..OUT {
        if i < len {
            out[i] = data.storage()[start + i];
        }
    }
    BoundedVec::from_parts(out, len)
}
#[test]
fn slice_zero_fills_tail() {
    // Nonzero bytes everywhere, also in the storage after the source length.
    let data = BoundedVec::<u8, 6>::from_parts([1, 2, 3, 4, 5, 6], 5);
    let out: BoundedVec<u8, 4> = slice(data, 1, 2);
    assert(out.len() == 2);
    assert(out.storage() == [2, 3, 0, 0]);
}
#[test]
fn nested_boundary() {
    let data = BoundedVec::<u8, 5>::from_array([48, 3, 2, 1, 7]);
    let outer = expect(data, 0, 5, 48);
    let integer = expect(data, outer.content, outer.end, 2);
    literal(data, integer, [7]);
    assert(integer.end == outer.end);
}
#[test(should_fail_with = "DER child exceeds parent")]
fn reject_wrapped_overrun() {
    let data = BoundedVec::<u8, 5>::from_array([48, 2, 2, 1, 7]);
    let outer = expect(data, 0, 5, 48);
    let _child = read(data, outer.content, outer.end);
}
#[test(should_fail_with = "noncanonical DER long length")]
fn reject_nonminimal_length() {
    let data = BoundedVec::<u8, 4>::from_array([4, 129, 1, 0]);
    let _node = read(data, 0, 4);
}
#[test(should_fail_with = "invalid or unsupported DER length")]
fn reject_indefinite_length() {
    let data = BoundedVec::<u8, 4>::from_array([48, 128, 0, 0]);
    let _node = read(data, 0, 4);
}

#[test]
fn slice_zero_capacity_and_empty_end() {
    let empty = slice::<1, 0>(BoundedVec::from_array([7u8]), 1, 0);
    assert(empty.len() == 0);
    let source = BoundedVec::<u8, 0>::new();
    assert(slice::<0, 0>(source, 0, 0).len() == 0);
}
#[test]
fn slice_exact_prefix_and_zero_padding() {
    let data = BoundedVec::<u8, 4>::from_array([1u8, 2, 3, 4]);
    let out = slice::<4, 4>(data, 2, 2);
    assert(out.len() == 2);
    assert(out.storage() == [3u8, 4, 0, 0]);
}

fn slice_boundary_input() -> BoundedVec<u8, 4096> {
    let mut bytes = [0u8; 4096];
    for i in 0..4096 {
        bytes[i] = (i % 256) as u8;
    }
    std::hint::black_box(BoundedVec::from_array(bytes))
}

#[test]
fn slice_boundary_empty() {
    let out = slice::<4096, 4096>(
        slice_boundary_input(),
        std::hint::black_box(0),
        std::hint::black_box(0),
    );
    assert(out.len() == 0);
    assert(out.storage() == [0u8; 4096]);
}

#[test]
fn slice_boundary_full() {
    let data = slice_boundary_input();
    let out = slice::<4096, 4096>(data, std::hint::black_box(0), std::hint::black_box(4096));
    assert(out.len() == 4096);
    assert(out.storage() == data.storage());
}

#[test]
fn slice_boundary_exact_end_empty() {
    let out = slice::<4096, 4096>(
        slice_boundary_input(),
        std::hint::black_box(4096),
        std::hint::black_box(0),
    );
    assert(out.len() == 0);
    assert(out.storage() == [0u8; 4096]);
}

#[test]
fn slice_boundary_last_byte() {
    let out = slice::<4096, 4096>(
        slice_boundary_input(),
        std::hint::black_box(4095),
        std::hint::black_box(1),
    );
    let mut expected = [0u8; 4096];
    expected[0] = 255;
    assert(out.len() == 1);
    assert(out.storage() == expected);
}

#[test(should_fail_with = "DER slice exceeds input")]
fn slice_boundary_rejects_overrun() {
    let _out = slice::<4096, 4096>(
        slice_boundary_input(),
        std::hint::black_box(4095),
        std::hint::black_box(2),
    );
}

#[test(should_fail_with = "DER value exceeds output capacity")]
fn slice_boundary_rejects_capacity() {
    let _out = slice::<4096, 4096>(
        slice_boundary_input(),
        std::hint::black_box(0),
        std::hint::black_box(4097),
    );
}

#[test(should_fail_with = "DER slice start exceeds input")]
fn slice_boundary_rejects_bad_start() {
    let _out = slice::<4096, 4096>(
        slice_boundary_input(),
        std::hint::black_box(4097),
        std::hint::black_box(0),
    );
}

#[test(should_fail_with = "DER slice start exceeds input")]
fn slice_boundary_rejects_wrapped_start() {
    let _out = slice::<4096, 4096>(
        slice_boundary_input(),
        std::hint::black_box(4294967295),
        std::hint::black_box(2),
    );
}
