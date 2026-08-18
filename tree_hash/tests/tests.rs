use alloy_primitives::{Address, U128, U160, U256};
use ssz::ProgressiveBitList;
use ssz_derive::Encode;
use std::str::FromStr;
use tree_hash::{
    merkle_root, mix_in_active_fields, Hash256, MerkleHasher, PackedEncoding,
    ProgressiveMerkleHasher, TreeHash, BYTES_PER_CHUNK,
};
use tree_hash_derive::TreeHash;

#[derive(Encode)]
struct HashVec {
    vec: Vec<u8>,
}

impl From<Vec<u8>> for HashVec {
    fn from(vec: Vec<u8>) -> Self {
        Self { vec }
    }
}

impl tree_hash::TreeHash for HashVec {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_root(&self) -> Hash256 {
        let mut hasher = MerkleHasher::with_leaves(self.vec.len().div_ceil(BYTES_PER_CHUNK));

        for item in &self.vec {
            hasher.write(&item.tree_hash_packed_encoding()).unwrap()
        }

        let root = hasher.finish().unwrap();

        tree_hash::mix_in_length(&root, self.vec.len())
    }
}

fn mix_in_selector(a: Hash256, selector: u8) -> Hash256 {
    let mut b = [0; 32];
    b[0] = selector;

    Hash256::from_slice(&ethereum_hashing::hash32_concat(a.as_slice(), &b))
}

fn u8_hash_concat(v1: u8, v2: u8) -> Hash256 {
    let mut a = [0; 32];
    let mut b = [0; 32];

    a[0] = v1;
    b[0] = v2;

    Hash256::from_slice(&ethereum_hashing::hash32_concat(&a, &b))
}

fn u8_hash(x: u8) -> Hash256 {
    let mut a = [0; 32];
    a[0] = x;
    Hash256::from_slice(&a)
}

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "transparent")]
enum FixedTrans {
    A(u8),
    B(u8),
}

#[test]
fn fixed_trans() {
    assert_eq!(FixedTrans::A(2).tree_hash_root(), u8_hash(2));
    assert_eq!(FixedTrans::B(2).tree_hash_root(), u8_hash(2));
}

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "union")]
enum FixedUnion {
    A(u8),
    B(u8),
}

#[test]
fn fixed_union() {
    assert_eq!(FixedUnion::A(2).tree_hash_root(), u8_hash_concat(2, 0));
    assert_eq!(FixedUnion::B(2).tree_hash_root(), u8_hash_concat(2, 1));
}

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "transparent")]
enum VariableTrans {
    A(HashVec),
    B(HashVec),
}

#[test]
fn variable_trans() {
    assert_eq!(
        VariableTrans::A(HashVec::from(vec![2])).tree_hash_root(),
        u8_hash_concat(2, 1)
    );
    assert_eq!(
        VariableTrans::B(HashVec::from(vec![2])).tree_hash_root(),
        u8_hash_concat(2, 1)
    );
}

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "union")]
enum VariableUnion {
    A(HashVec),
    B(HashVec),
}

#[test]
fn variable_union() {
    assert_eq!(
        VariableUnion::A(HashVec::from(vec![2])).tree_hash_root(),
        mix_in_selector(u8_hash_concat(2, 1), 0)
    );
    assert_eq!(
        VariableUnion::B(HashVec::from(vec![2])).tree_hash_root(),
        mix_in_selector(u8_hash_concat(2, 1), 1)
    );
}

/// Computes the expected root of a container by merkleizing its field roots, one leaf per field.
fn container_root(field_roots: &[Hash256]) -> Hash256 {
    let mut leaves = Vec::with_capacity(field_roots.len() * BYTES_PER_CHUNK);
    for root in field_roots {
        leaves.extend_from_slice(root.as_slice());
    }
    merkle_root(&leaves, field_roots.len())
}

#[derive(TreeHash)]
struct Basic {
    a: u8,
    b: u64,
    c: Hash256,
}

#[test]
fn struct_basic() {
    let x = Basic {
        a: 1,
        b: 2,
        c: Hash256::repeat_byte(3),
    };
    assert_eq!(
        x.tree_hash_root(),
        container_root(&[
            x.a.tree_hash_root(),
            x.b.tree_hash_root(),
            x.c.tree_hash_root(),
        ])
    );
}

#[test]
fn struct_is_container_type() {
    assert_eq!(Basic::tree_hash_type(), tree_hash::TreeHashType::Container);
}

#[derive(TreeHash)]
struct Single {
    only: Hash256,
}

#[test]
fn struct_single_field() {
    // A one-field container hashes to that field's root unchanged.
    let x = Single {
        only: Hash256::repeat_byte(7),
    };
    assert_eq!(x.tree_hash_root(), x.only.tree_hash_root());
    assert_eq!(
        x.tree_hash_root(),
        container_root(&[x.only.tree_hash_root()])
    );
}

#[derive(TreeHash)]
struct WithSkip {
    a: u8,
    // Never read; only present to prove `skip_hashing` excludes it from the root.
    #[allow(dead_code)]
    #[tree_hash(skip_hashing)]
    b: u64,
    c: u8,
}

#[test]
fn struct_skip_hashing() {
    let x = WithSkip { a: 1, b: 999, c: 3 };

    // The skipped field is absent from the tree: the root is a two-leaf container of `a` and `c`.
    assert_eq!(
        x.tree_hash_root(),
        container_root(&[x.a.tree_hash_root(), x.c.tree_hash_root()])
    );

    // Mutating only the skipped field must not change the root.
    let y = WithSkip {
        a: 1,
        b: 12345,
        c: 3,
    };
    assert_eq!(x.tree_hash_root(), y.tree_hash_root());
}

#[derive(TreeHash)]
struct Nested {
    inner: Basic,
    tag: u8,
}

#[test]
fn struct_nested() {
    let x = Nested {
        inner: Basic {
            a: 1,
            b: 2,
            c: Hash256::repeat_byte(3),
        },
        tag: 9,
    };
    assert_eq!(
        x.tree_hash_root(),
        container_root(&[x.inner.tree_hash_root(), x.tag.tree_hash_root()])
    );
}

#[derive(TreeHash)]
struct Generic<T: TreeHash> {
    value: T,
    count: u64,
}

#[test]
fn struct_generic() {
    let x = Generic {
        value: 42u16,
        count: 7,
    };
    assert_eq!(
        x.tree_hash_root(),
        container_root(&[x.value.tree_hash_root(), x.count.tree_hash_root()])
    );
}

/// Test that the packed encodings for different types are equal.
#[test]
fn packed_encoding_example() {
    let val = 0xfff0eee0ddd0ccc0bbb0aaa099908880_u128;
    let canonical = U256::from(val).tree_hash_packed_encoding();
    let encodings = [
        (0x8880_u16.tree_hash_packed_encoding(), 0),
        (0x9990_u16.tree_hash_packed_encoding(), 2),
        (0xaaa0_u16.tree_hash_packed_encoding(), 4),
        (0xbbb0_u16.tree_hash_packed_encoding(), 6),
        (0xccc0_u16.tree_hash_packed_encoding(), 8),
        (0xddd0_u16.tree_hash_packed_encoding(), 10),
        (0xeee0_u16.tree_hash_packed_encoding(), 12),
        (0xfff0_u16.tree_hash_packed_encoding(), 14),
        (U128::from(val).tree_hash_packed_encoding(), 0),
        (U128::from(0).tree_hash_packed_encoding(), 16),
        (
            Hash256::from_slice(U256::from(val).as_le_slice())
                .tree_hash_root()
                .0
                .into(),
            0,
        ),
        (U256::from(val).tree_hash_root().0.into(), 0),
        (
            Address::from(U160::from(val).to_le_bytes::<20>())
                .tree_hash_root()
                .0
                .into(),
            0,
        ),
    ];
    for (i, (encoding, offset)) in encodings.into_iter().enumerate() {
        assert_eq!(
            &encoding[..],
            &canonical[offset..offset + encoding.len()],
            "encoding {i} is wrong"
        );
    }
}

#[derive(TreeHash)]
#[tree_hash(struct_behaviour = "progressive_container", active_fields(1))]
struct ProgressiveContainerOneField {
    x: u8,
}

#[test]
fn progressive_container_one_field() {
    let container = ProgressiveContainerOneField { x: 125 };
    assert_eq!(
        container.tree_hash_root(),
        Hash256::from_str("0xb6a2f148c33179dec1bdaa979a11776ff2d881fca93974b286443a8539dc0872")
            .unwrap()
    );
}

/// Reference merkleization of a progressive container's leaves, via the public hasher.
fn progressive_merkle_root(leaves: &[Hash256]) -> Hash256 {
    let mut hasher = ProgressiveMerkleHasher::new();
    for leaf in leaves {
        hasher.write(leaf.as_slice()).unwrap();
    }
    hasher.finish().unwrap()
}

/// Pack `active_fields` bits LSB-first into a single 32-byte chunk.
fn packed_active_fields(bits: &[bool]) -> [u8; BYTES_PER_CHUNK] {
    let mut packed = [0u8; BYTES_PER_CHUNK];
    for (i, bit) in bits.iter().enumerate() {
        if *bit {
            packed[i / 8] |= 1 << (i % 8);
        }
    }
    packed
}

#[derive(TreeHash)]
#[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 1, 1))]
struct ProgressiveContainerThreeFields {
    a: u8,
    b: u64,
    c: Hash256,
}

#[test]
fn progressive_container_multi_field() {
    let container = ProgressiveContainerThreeFields {
        a: 7,
        b: 0x0102_0304_0506_0708,
        c: Hash256::repeat_byte(0xcd),
    };

    let leaves = [
        container.a.tree_hash_root(),
        container.b.tree_hash_root(),
        container.c.tree_hash_root(),
    ];
    let expected = mix_in_active_fields(
        &progressive_merkle_root(&leaves),
        packed_active_fields(&[true, true, true]),
    );

    assert_eq!(container.tree_hash_root(), expected);
}

#[derive(TreeHash)]
#[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 0, 1))]
struct ProgressiveContainerWithGap {
    a: u8,
    c: u16,
}

#[test]
fn progressive_container_inactive_field() {
    let container = ProgressiveContainerWithGap { a: 9, c: 0xbeef };

    // The inactive middle position must contribute a zero leaf so chunk positions stay stable.
    let leaves = [
        container.a.tree_hash_root(),
        Hash256::ZERO,
        container.c.tree_hash_root(),
    ];
    let expected = mix_in_active_fields(
        &progressive_merkle_root(&leaves),
        packed_active_fields(&[true, false, true]),
    );

    assert_eq!(container.tree_hash_root(), expected);
}

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "compatible_union")]
enum CompatUnion {
    #[tree_hash(selector = "1")]
    A(u8),
    #[tree_hash(selector = "4")]
    B(HashVec),
}

#[test]
fn compatible_union() {
    // The root is `mix_in_selector(inner_root, selector)` using the explicit per-variant selectors.
    assert_eq!(
        CompatUnion::A(2).tree_hash_root(),
        mix_in_selector(u8_hash(2), 1)
    );
    assert_eq!(
        CompatUnion::B(HashVec::from(vec![2])).tree_hash_root(),
        mix_in_selector(u8_hash_concat(2, 1), 4)
    );
}

#[derive(Encode, TreeHash)]
#[ssz(enum_behaviour = "compatible_union")]
#[tree_hash(enum_behaviour = "compatible_union")]
enum CompatUnionSszSelectors {
    #[ssz(selector = "3")]
    A(u8),
    #[ssz(selector = "5")]
    B(u8),
}

#[test]
fn compatible_union_reads_ssz_selectors() {
    // These variants carry no `tree_hash(selector)`, so `tree_hash` must read the selectors from
    // the sibling `ssz` attribute (the `(None, Some(ssz))` fallback in `parse_variant_opts`).
    assert_eq!(
        CompatUnionSszSelectors::A(2).tree_hash_root(),
        mix_in_selector(u8_hash(2), 3)
    );
    assert_eq!(
        CompatUnionSszSelectors::B(2).tree_hash_root(),
        mix_in_selector(u8_hash(2), 5)
    );
}

#[derive(Encode, TreeHash)]
#[ssz(enum_behaviour = "compatible_union")]
#[tree_hash(enum_behaviour = "compatible_union")]
enum CompatUnionBothSelectors {
    #[ssz(selector = "3")]
    #[tree_hash(selector = "3")]
    A(u8),
}

#[test]
fn compatible_union_consistent_selectors_in_both_attributes() {
    // Setting the same selector in both the `ssz` and `tree_hash` attributes is permitted (the
    // derive only rejects *inconsistent* selectors).
    assert_eq!(
        CompatUnionBothSelectors::A(2).tree_hash_root(),
        mix_in_selector(u8_hash(2), 3)
    );
}

/// Merkleize raw bytes (zero-padded into chunks) via the public progressive hasher.
fn progressive_merkle_root_bytes(bytes: &[u8]) -> Hash256 {
    let mut hasher = ProgressiveMerkleHasher::new();
    hasher.write(bytes).unwrap();
    hasher.finish().unwrap()
}

#[test]
fn progressive_bitlist_empty() {
    // An empty bitlist must hash as mix_in_length(merkleize_progressive([]) = ZERO, 0), exercising
    // the empty-list workaround (an empty bitlist still stores a single zero byte internally).
    let bitlist = ProgressiveBitList::with_capacity(0);
    assert_eq!(
        bitlist.tree_hash_root(),
        tree_hash::mix_in_length(&Hash256::ZERO, 0)
    );
}

#[test]
fn progressive_bitlist_matches_packed_progressive() {
    // The root must equal mix_in_length(merkleize_progressive(pack_bits(value)), len) for a range
    // of lengths, including byte- and chunk-aligned cases and progressive level crossings.
    for len in [1usize, 7, 8, 9, 16, 100, 256, 257, 1024] {
        let mut bitlist = ProgressiveBitList::with_capacity(len);
        for i in (0..len).step_by(3) {
            bitlist.set(i, true).unwrap();
        }

        let expected =
            tree_hash::mix_in_length(&progressive_merkle_root_bytes(bitlist.as_slice()), len);
        assert_eq!(bitlist.tree_hash_root(), expected, "len = {len}");
    }
}

#[test]
fn progressive_bitlist_nonempty_all_false_differs_from_empty() {
    // A non-empty all-false bitlist must NOT short-circuit to the empty value.
    let bitlist = ProgressiveBitList::with_capacity(8);
    let empty = ProgressiveBitList::with_capacity(0);

    assert_ne!(bitlist.tree_hash_root(), empty.tree_hash_root());
    assert_eq!(
        bitlist.tree_hash_root(),
        tree_hash::mix_in_length(&progressive_merkle_root_bytes(bitlist.as_slice()), 8)
    );
}
