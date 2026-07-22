use alloy_primitives::{Address, U128, U160, U256};
use ssz_derive::Encode;
use tree_hash::{merkle_root, Hash256, MerkleHasher, PackedEncoding, TreeHash, BYTES_PER_CHUNK};
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

/// Independent oracle for a derived container's root: merkleize the concatenated field roots,
/// padded out to one leaf per hashed field. This mirrors the SSZ container definition without
/// reusing the derive macro's own `MerkleHasher` call.
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
