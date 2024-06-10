use ssz_derive::Encode;
use ssz_types::BitVector;
use tree_hash::{self, Hash256, MerkleHasher, PackedEncoding, TreeHash, BYTES_PER_CHUNK};
use tree_hash_derive::TreeHash;
use typenum::Unsigned;

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
        let mut hasher =
            MerkleHasher::with_leaves((self.vec.len() + BYTES_PER_CHUNK - 1) / BYTES_PER_CHUNK);

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

    Hash256::from_slice(&ethereum_hashing::hash32_concat(a.as_bytes(), &b))
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

#[derive(TreeHash)]
#[tree_hash(struct_behaviour = "stable_container")]
#[tree_hash(max_fields = "typenum::U8")]
struct Shape {
    side: Option<u16>,
    color: Option<u8>,
    radius: Option<u16>,
}

#[derive(TreeHash, Clone)]
#[tree_hash(struct_behaviour = "profile")]
#[tree_hash(max_fields = "typenum::U8")]
struct Square {
    #[tree_hash(stable_index = 0)]
    side: u16,
    #[tree_hash(stable_index = 1)]
    color: u8,
}

#[derive(TreeHash, Clone)]
#[tree_hash(struct_behaviour = "profile")]
#[tree_hash(max_fields = "typenum::U8")]
struct Circle {
    #[tree_hash(stable_index = 1)]
    color: u8,
    #[tree_hash(stable_index = 2)]
    radius: u16,
}

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "transparent_stable")]
enum ShapeEnum {
    SquareVariant(Square),
    CircleVariant(Circle),
}

#[test]
fn shape_1() {
    let shape_1 = Shape {
        side: Some(16),
        color: Some(2),
        radius: None,
    };

    let square = Square { side: 16, color: 2 };

    assert_eq!(shape_1.tree_hash_root(), square.tree_hash_root());
}

#[test]
fn shape_2() {
    let shape_2 = Shape {
        side: None,
        color: Some(1),
        radius: Some(42),
    };

    let circle = Circle {
        color: 1,
        radius: 42,
    };

    assert_eq!(shape_2.tree_hash_root(), circle.tree_hash_root());
}

#[test]
fn shape_enum() {
    let square = Square { side: 16, color: 2 };

    let circle = Circle {
        color: 1,
        radius: 14,
    };

    let enum_square = ShapeEnum::SquareVariant(square.clone());
    let enum_circle = ShapeEnum::CircleVariant(circle.clone());

    assert_eq!(square.tree_hash_root(), enum_square.tree_hash_root());
    assert_eq!(circle.tree_hash_root(), enum_circle.tree_hash_root());
}
